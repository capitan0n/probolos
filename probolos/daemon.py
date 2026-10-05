"""
The core loop: listen for USB attachments, hold them, ask, decide.

    plug in  ──►  kernel enumerates, reads descriptors, does NOT configure
                             │
                             ▼
                  udev 'add' event (usb_device)
                             │
                             ▼
                  read /sys .../descriptors  ──►  identity report
                             │
                             ▼
                  prompt on the ALREADY-TRUSTED terminal
                             │
                   ┌─────────┴─────────┐
                   ▼                   ▼
             authorized=1         stays authorized=0
             (device lives)       (device stays dead)

The prompt being on the existing terminal is not a shortcut, it is the security
property: a malicious HID that has just been plugged in is still unauthorized,
so it cannot press its own "yes". The device is never allowed to answer the
question that is about itself.
"""

from __future__ import annotations

import os
import select
import threading
from collections import OrderedDict
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Set

try:
    import pyudev
except ImportError:  # pragma: no cover - import guard for offline linting
    pyudev = None

from . import deferred_bind
from . import (agentlink, analyzers, gate, ledger as ledger_mod, quarantine,
               report, rules, safety, session as session_mod, storage, sysfs,
               trust as trust_mod, usbclass)

# How long a CRITICAL device's "Allow" stays disabled in the desktop prompt.
# Enforced here as well as in the dialog: an approval that arrives sooner is
# not honoured, whatever sent it.
CRITICAL_COUNTDOWN = 10.0



@dataclass
class Decision:
    device: sysfs.UsbDevice
    authorized: bool
    reason: str
    timestamp: float


def _gate_keeps_trust(store) -> bool:
    """
    Whether the privileged gate would keep "always" for this process.

    Only under --privsep (a backend that can trust), and only where the gate
    would not refuse anyway: it never rewrites a store that failed its checks
    (load_error), and it never creates the store's directory (see
    gate_server._do_trust), so offering "always" then would only lose the
    answer. os.path.isdir rather than Path.is_dir: an EACCES must answer
    False here, not raise.
    """
    return (sysfs.backend_can_trust() and not store.load_error
            and os.path.isdir(store.path.parent))


class Probolos:
    def __init__(self,
                 dry_run: bool = False,
                 timeout: float = 0.0,
                 json_log: Optional[Path] = None,
                 rule_config: Optional[rules.RuleConfig] = None,
                 observe: float = 3.0,
                 policy: Optional[safety.SafetyPolicy] = None,
                 ledger: Optional[object] = None,
                 capture_payload: bool = False,
                 watchdog: Optional[safety.Watchdog] = None,
                 stop_event=None,
                 trust_store=None,
                 inspect_storage: bool = True,
                 monitor=None,
                 lock_policy: str = session_mod.POLICY_QUEUE,
                 agent=None,
                 close_race_window: bool = False,
                 media_watch=None):
        self.dry_run = dry_run
        self.timeout = timeout          # 0 == wait forever
        self.json_log = json_log
        self.rule_config = rule_config
        self.observe = observe          # seconds of behavioural quarantine
        self.policy = policy or safety.SafetyPolicy()
        self.ledger = ledger
        self.capture_payload = capture_payload
        self.watchdog = watchdog
        self.stop_event = stop_event
        self.trust = trust_store
        self.inspect_storage = inspect_storage
        self.monitor = monitor or session_mod.AlwaysUnlocked()
        self.lock_policy = lock_policy
        self.agent = agent
        # Experimental bus-wide binding control, not race-free isolation.
        self.close_race_window = close_race_window
        # Media changes inside admitted storage hosts (mediawatch.py). None
        # unless --watch-media: a separate detection layer, not the gate.
        self.media_watch = media_watch
        # Devices attached while the screen was locked, or while nobody could
        # be asked at all (no desktop agent connected and no terminal). They
        # are held blocked and asked about when someone can answer, so nobody
        # has to unplug and replug hardware just because they stepped away or
        # had not logged in yet.
        #
        # The value is (syspath, instance_id), not the path alone. A held
        # device is identified by the kernel directory INSTANCE it had when it
        # was queued -- (st_dev, st_ino) -- because a sysfs name like "1-4" is
        # a PORT, not a device. Between queueing and unlocking, the original
        # can be pulled and something else enumerated at the same port; the
        # name is then identical and the directory is a different inode. With
        # only the path recorded, _drain_pending would inspect and prompt for
        # the new device under the queue entry belonging to the old one, and
        # the operator would be answering about hardware they never saw
        # arrive. That is the same port-recycling hole already closed in
        # _on_remove and in sysfs.admit_device; the queue is the third place
        # the port/device distinction matters and it was the one still using
        # a bare name.
        self.pending: "OrderedDict[str, tuple]" = OrderedDict()
        self._was_locked = False
        self._stream_failing = False    # udev event stream overflowed
        self.known: Set[str] = set()    # devices present at startup
        # Device name -> (instance, reason) of the last decision recorded for
        # it, so a device held again for the reason it is already held under
        # is not recorded again (see _hold).
        self._last_recorded: dict = {}
        # Device name -> (instance, count): how often a held device was
        # inspected and then not asked because the agent went away first
        # (see _may_hold_again).
        self._unseen_asks: dict = {}

    # ------------------------------------------------------------------
    # startup
    # ------------------------------------------------------------------

    def snapshot(self) -> None:
        """
        Record what is already attached.

        We chose 'new devices only' scope: anything present now keeps working
        untouched. This is what makes it safe to run on a laptop whose keyboard
        or mouse is USB -- they are already authorized and we never look at
        them again.
        """
        stranded = []
        for dev in sysfs.list_devices():
            # A device sitting at authorized=0 is NOT a device that is working
            # fine and should be left alone -- it is one something already
            # blocked, almost always a previous Probolos run that exited before
            # a decision was made. Treating it as baseline would leave it dead
            # AND never ask about it, so its owner would have to unplug and
            # replug hardware to get a question they never got the chance to
            # answer. Those devices are queued for decision instead.
            if dev.authorized == 0 and not dev.is_root_hub:
                stranded.append(dev)
                continue
            self.known.add(dev.name)
            # Left untouched does not mean unwatched: a card reader present at
            # startup is the slot most likely to be used by someone else.
            if self.media_watch is not None:
                self.media_watch.register(dev, "present at startup")

        print(f"[*] Baseline: {len(self.known)} USB device(s) already attached, "
              f"all left untouched")

        if stranded:
            print(f"[*] {len(stranded)} device(s) are attached but blocked "
                  f"(left over from an earlier run):")
            for dev in stranded:
                print(f"      {report.one_liner(dev)}")
                self.pending[dev.name] = (dev.syspath, dev.instance_id)
            print("    You will be asked about them without unplugging "
                  "anything.\n")

    # ------------------------------------------------------------------
    # main loop
    # ------------------------------------------------------------------

    def run(self) -> None:
        if pyudev is None:
            raise RuntimeError(
                "pyudev is not installed. On Manjaro: sudo pacman -S python-pyudev")

        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        # We filter at the netlink level rather than in Python: the kernel
        # sends a lot of uevents, and 'usb_device' excludes the per-interface
        # nodes (1-4:1.0) which would otherwise duplicate every attachment.
        monitor.filter_by(subsystem="usb", device_type="usb_device")
        # A card inserted into an admitted reader produces no USB event at
        # all; its only trace is a `change` on the reader's whole disk. The
        # filters are OR'd, so one loop still serves both.
        if self.media_watch is not None:
            monitor.filter_by(subsystem="block", device_type="disk")
        monitor.start()

        print("[*] Listening. Plug in a device. Ctrl-C to stop.\n")

        # Devices found blocked at startup are decided immediately -- unless
        # the screen is locked, in which case they simply stay queued until
        # someone is back, exactly like a device attached while away. A
        # service starting at boot has no agent and no terminal yet; they
        # then stay queued until one connects, instead of being "asked" on a
        # stdin that reads EOF and denied.
        if self.pending and not self.dry_run:
            if (self.lock_policy == session_mod.POLICY_IGNORE
                    or not self.monitor.is_locked()):
                self._drain_pending()

        while True:
            # poll() with a timeout instead of a blocking iterator, so signals
            # are delivered promptly and shutdown stays responsive.
            # Once the safety net has opened the gate, carrying on would be
            # worse than stopping: every new device is already live, yet the
            # daemon would still print a prompt as though it were holding one.
            # A tool that looks like it is protecting you while it is not is
            # more dangerous than one that has plainly stopped.
            if self.stop_event is not None and self.stop_event.is_set():
                print("[*] Safety net fired — the gate is open. Stopping.")
                return
            if self.watchdog:
                self.watchdog.beat()

            # Watch for the screen unlocking so held devices can be asked
            # about. Polling once a second is plenty: this is a human-timescale
            # event, and polling avoids depending on a session bus the
            # unprivileged analyzer cannot reach.
            drained = False
            if self.lock_policy == session_mod.POLICY_QUEUE and not self.dry_run:
                locked = self.monitor.is_locked()
                if locked is not None:
                    if self._was_locked and not locked:
                        self._drain_pending("Screen unlocked")
                        drained = True
                    self._was_locked = bool(locked)

            # Devices held because nobody could be asked are asked about once
            # a desktop agent is there to ask. Polled like the lock: the agent
            # connects on the accept thread, whenever its owner logs in. One
            # drain per pass, and it cannot spin -- _drain_pending empties the
            # queue before it starts, and whatever _on_add puts back is held
            # for a reason (agent gone again, screen locked) that also stops
            # the next pass from draining.
            if not drained and self._agent_can_take_held():
                self._drain_pending("Desktop agent connected")

            # The event stream itself can fail, and that must not end the gate
            # either. When the netlink receive buffer overflows -- events
            # arriving faster than this loop drains them, e.g. while it waits
            # on a prompt -- the kernel flags ENOBUFS on the socket, and pyudev
            # raises from EVERY poll() until that error is consumed. Uncaught,
            # that left run(), the gate reopened and the daemon exited.
            try:
                device = monitor.poll(timeout=1.0)
            except OSError as exc:
                if not self._recover_event_stream(monitor, exc):
                    raise
                continue
            self._stream_failing = False
            if device is None:
                continue
            # One device must never be able to end the gate. Everything below
            # this line touches hardware that can vanish mid-call: sysfs writes
            # return ENODEV, a dialog backend dies, a descriptor read races the
            # unplug. Those raise OSError and worse, and until now they left
            # the loop entirely -- the daemon exited, every subsequent device
            # was admitted by the kernel with no question asked, and the user
            # saw a traceback rather than a closed gate. Handling it here keeps
            # the failure to the one device it belongs to.
            #
            # KeyboardInterrupt and SystemExit are deliberately NOT caught:
            # shutdown must stay immediate.
            try:
                self._dispatch(device)
            except Exception as exc:   # noqa: BLE001 -- see above
                import traceback
                print(f"[!] {Path(device.sys_path).name}: unhandled error "
                      f"while gating this device: {exc!r}")
                print("[!] It stays BLOCKED. The gate is still running.")
                traceback.print_exc()

    def _dispatch(self, device) -> None:
        """Route one uevent: USB devices to the gate, disks to the watcher."""
        if getattr(device, "subsystem", "usb") == "block":
            if self.media_watch is None or self.dry_run:
                return
            properties = dict(getattr(device, "properties", {}) or {})
            # Bounded like stage 4 at admission; the watchdog must not count
            # a card that stalls its reads as the daemon wedging.
            if self.watchdog:
                with self.watchdog.paused():
                    self.media_watch.handle(device.action, device.sys_path,
                                            properties)
            else:
                self.media_watch.handle(device.action, device.sys_path,
                                        properties)
            return
        if device.action == "add":
            self._on_add(device.sys_path)
        elif device.action == "remove":
            self._on_remove(device.sys_path)

    def _watch_if_storage(self, dev: sysfs.UsbDevice, why: str) -> None:
        """An admitted pure storage host: keep watching what is put in it."""
        if self.media_watch is not None and not self.dry_run:
            self.media_watch.register(dev, why)

    def _media_policy_deauthorized(self, dev: sysfs.UsbDevice,
                                   findings) -> None:
        """The watcher switched a reader off: it is no longer past the gate."""
        self.known.discard(dev.name)
        self._record(Decision(dev, False, "media policy: reader deauthorized",
                              time.time()), findings)

    def _recover_event_stream(self, monitor, exc: OSError) -> bool:
        """
        Survive a netlink overflow; True if the loop may carry on.

        Only ENOBUFS is recovered from. It means events were DROPPED, not that
        the stream is broken: reading SO_ERROR consumes the flag and the socket
        works again. Devices whose events were lost stay blocked (they never
        got an 'add' here), which is the safe direction, and the operator is
        told so. Anything else is re-raised exactly as before.
        """
        import errno
        import socket as _socket
        pending = 0
        try:
            sock = _socket.fromfd(monitor.fileno(), _socket.AF_NETLINK,
                                  _socket.SOCK_RAW)
            try:
                pending = sock.getsockopt(_socket.SOL_SOCKET,
                                          _socket.SO_ERROR)
            finally:
                sock.close()
        except (OSError, AttributeError, ValueError):
            return False
        if errno.ENOBUFS not in (exc.errno, pending):
            return False
        if not self._stream_failing:
            print("[!] USB event queue overflowed; some attach/remove events "
                  "were lost.")
            print("[!] The gate is still closed. A device attached meanwhile "
                  "stays BLOCKED -- replug it to be asked about it.")
        self._stream_failing = True
        time.sleep(0.05)
        return True

    def _on_add(self, sys_path: str, was_held: bool = False) -> None:
        """
        Handle a device attachment.

        `was_held` marks a device that spent time blocked in the queue -- it
        arrived while the screen was locked or while nobody could be asked,
        or was left undecided by an earlier run. Such a device is always asked
        about, even if remembered.

        The reason is that trust was granted while its owner was present and
        watching. A device that turned up while nobody was there has not earned
        the shortcut, and deferring the question must not quietly become
        approving it: otherwise "nothing is admitted while you are away" would
        really mean "nothing is admitted until you get back, then everything".
        """
        path = Path(sys_path)
        name = path.name

        if name in self.known:
            return  # a device we deliberately ignore

        # Already held? udev replays 'add' (`udevadm trigger`, a settle, a
        # rescan) for a device that is sitting in the queue just as for one
        # that is live, and the queue entry stands: gating the replay would
        # ask about the device now AND again when the queue drains, and for
        # one held behind a locked screen it would skip what was_held exists
        # to force -- after an unlock, a remembered device would be admitted
        # on trust without the question. Only a different device at the port
        # (the held one left and its 'remove' was lost) makes the entry stale.
        queued = None if was_held else self.pending.get(name)
        if queued is not None:
            _held_path, held_instance = queued
            if held_instance is None or self._still_same_device(
                    path, held_instance):
                print(f"[*] {name}: already held; it is asked about when "
                      f"someone can answer")
                return
            del self.pending[name]

        # Already live and already decided? Then this is a repeat 'add' for a
        # device that is past the gate, and re-running the gate on it is
        # actively harmful rather than merely redundant: _quarantine() writes
        # authorized=0 and back to 1 on hardware the user is USING, dropping
        # a keyboard mid-keystroke or a stick mid-write, and it takes an
        # EVIOCGRAB on a device whose input the user expects to reach their
        # session. udev delivers duplicate 'add' events routinely -- a
        # `udevadm trigger`, a settle, a subsystem rescan -- and nothing here
        # recorded that a device had been admitted, so `known` only ever held
        # the startup baseline. The device we let through is added to it at
        # the point of admission below.
        dev = self._load_with_retry(path)
        if dev is None:
            print(f"[!] {name}: vanished before it could be read")
            return
        if dev.is_root_hub:
            return

        # ---- nobody is at the machine ------------------------------------
        # Neither quarantine nor the storage scan runs while the screen is
        # locked: both require switching the device on, and powering up unknown
        # hardware while its owner is absent is the exact situation being
        # defended against. Only the identity is recorded; the device stays
        # dead until a human is back.
        if self.lock_policy != session_mod.POLICY_IGNORE and not self.dry_run:
            if self.monitor.is_locked():
                self._hold_until_unlocked(dev)
                return

        # SAFETY BEFORE SECURITY. A device on an internal port or on the
        # operator's allowlist is admitted without a question, because the cost
        # of being wrong here is somebody with no keyboard and no way to answer
        # the prompt that would give them one.
        protection = self.policy.is_protected(dev)
        if protection and not self.dry_run:
            try:
                sysfs.admit_device(dev)
            except OSError as exc:
                print(f"[!] could not authorize protected device: {exc}")
                return
            print(f"[=] ADMITTED WITHOUT PROMPT ({protection}) — "
                  f"{report.one_liner(dev)}\n")
            # Past the gate: a later duplicate 'add' must not re-gate live
            # hardware. Cleared again by _on_remove when the device leaves.
            self.known.add(dev.name)
            self._record(Decision(dev, True, f"protected: {protection}",
                                  time.time()))
            self._watch_if_storage(dev, "admitted without prompt")
            return

        findings = analyzers.run(analyzers.Context(
            device=dev, ledger=self.ledger, config=self.rule_config))

        # ---- previously approved devices go straight through --------------
        # Trust is checked AFTER the identity analysers have run, never before,
        # so that a remembered device producing a CRITICAL finding is still
        # stopped. Trust decides whether to ask a question with no troubling
        # answer; it cannot silence one that has.
        if (self.trust is not None and not self.dry_run and not was_held
                and self.trust.is_trusted(dev)
                and rules.worst(findings) < rules.Severity.CRITICAL):
            try:
                sysfs.admit_device(dev)
                # last_seen / times_admitted / ports are bookkeeping, nothing
                # decides on them. Under --privsep this process cannot write
                # the store, and the gate deliberately takes no such writes --
                # its trust surface is one entry per admission, kept small --
                # so trying here only printed "could not update trust store"
                # once per run, about something that was never going to work.
                # Not over a store that failed to load: the rewrite would
                # drop what could not be read, for bookkeeping.
                if self.trust.writable() and not self.trust.load_error:
                    self.trust.record_admission(dev)
                    error = self.trust.save()
                    if error and not self.trust.repeated_save_error:
                        print(f"[!] could not update trust store: {error}")
                print(f"[=] TRUSTED — {report.one_liner(dev, findings)}\n")
                self.known.add(dev.name)
                self._record(Decision(dev, True, "trusted", time.time()),
                             findings)
                self._watch_if_storage(dev, "trusted")
            except OSError as exc:
                print(f"[!] failed to authorize trusted device: {exc}")
            return

        # ---- nobody can be asked ------------------------------------------
        # The service has no terminal: its stdin is /dev/null. With no desktop
        # agent connected -- before anyone has logged in, after a logout,
        # while the agent restarts -- the terminal fallback read EOF and
        # denied the device on the spot, so a keyboard plugged in at the login
        # screen was dead by the time its owner could have been asked, and
        # the only way to get the question was to unplug and replug it. It is
        # held instead, like a device attached behind a locked screen, and
        # for the same reason BEFORE stages 3 and 4: both switch it on, and
        # powering up unknown hardware that nobody can be asked about is what
        # the screen-lock hold exists to avoid. After the trust fast path, so
        # a remembered keyboard at the login screen is still just admitted.
        if self._nobody_can_be_asked():
            self._hold_for_agent(dev, findings)
            return

        print()
        print(report.render(dev, findings))
        print()

        if self.dry_run:
            print("[dry-run] no authorization change made\n")
            self._record(Decision(dev, False, "dry-run", time.time()), findings)
            return

        # ---- stage 3: behavioural quarantine, for input devices only ----
        # An input device is the only kind that can act against you the instant
        # it is authorized, so it is the only kind worth the risk of switching
        # on early -- and even then only under an EVIOCGRAB that swallows its
        # events. This MUST run before stage 4: stage 4 authorizes the whole
        # device to read its medium, and on a composite storage+keyboard device
        # that same authorization would switch the keyboard on as well.
        has_input = usbclass.KIND_INPUT in dev.kinds
        complete = dev.inspection_safe
        if not complete:
            print("  Incomplete descriptors: early activation is disabled.")
        if complete and self.observe > 0 and has_input:
            if self.watchdog:
                with self.watchdog.paused():
                    obs = self._quarantine(dev)
            else:
                obs = self._quarantine(dev)
            # quarantine() re-blocks before releasing any captured descriptor.
            behaviour = analyzers.run(
                analyzers.Context(device=dev, observation=obs,
                                  ledger=self.ledger, config=self.rule_config),
                analyzers=[analyzers.BehaviourAnalyzer(),
                           analyzers.PayloadAnalyzer()])
            print()
            print(report.render_behaviour(obs, behaviour))
            print()
            findings = sorted(list(findings) + behaviour,
                              key=lambda f: f.severity, reverse=True)

        # ---- stage 4: look inside storage media, without mounting --------
        # Storage inspection authorizes the whole device so its block node
        # appears. That is safe for a pure storage device, but on a composite
        # storage+input device it would switch the input half on WITHOUT a grab,
        # handing a BadUSB up to ~3 seconds of live keystrokes. There is nothing
        # to gain either: such a device has already earned a CRITICAL "storage
        # device that can also type" finding, and its partition table cannot
        # make that verdict any safer. So storage is read only when the device
        # cannot also type.
        #
        # "Cannot also type" was not enough: the condition only excluded HID,
        # so a storage device that ALSO declared a network function (RNDIS /
        # CDC-ECM -- a Pi Zero running g_multi), a serial port or a vendor
        # interface was switched on whole, with no decision, for the 1.5 s node
        # wait plus a scan the device itself can stall for the full 10 s
        # timeout. Long enough for NetworkManager to DHCP a hostile gateway.
        # The medium is read only when storage is ALL the device declares.
        storage_only = set(dev.kinds) == {usbclass.KIND_STORAGE}
        medium = None
        if (complete and self.inspect_storage and storage_only
                and not has_input):
            # BOTH guards are needed and they do different jobs. The timeout
            # inside inspect_safely guarantees the scan ENDS; paused() stops
            # the watchdog from counting the (now bounded) scan as the daemon
            # wedging. paused() alone would be the obvious but WRONG fix: it
            # converts a hostile stall from a fail-open into a permanent
            # freeze. Mirrors the existing paused() around _ask().
            if self.watchdog:
                with self.watchdog.paused():
                    medium = self._inspect_medium(dev)
            else:
                medium = self._inspect_medium(dev)
            if medium is not None:
                storage_findings = analyzers.run(
                    analyzers.Context(device=dev, config=self.rule_config,
                                      extra={"medium": medium}),
                    analyzers=[analyzers.StorageAnalyzer()])
                print()
                print(report.render_medium(medium, storage_findings))
                print()
                findings = sorted(list(findings) + storage_findings,
                                  key=lambda f: f.severity, reverse=True)
        elif (self.inspect_storage and usbclass.KIND_STORAGE in dev.kinds
                and has_input):
            print("  This device declares BOTH storage and an input interface.")
            print("  Its contents will NOT be read: authorizing it to look would")
            print("  also switch the input half on without a grab. It is held")
            print("  for your decision on the strength of that alone.\n")
        elif (self.inspect_storage and usbclass.KIND_STORAGE in dev.kinds
                and not storage_only):
            print("  This device declares storage AND other functions.")
            print("  Its contents will NOT be read: authorizing it to look would")
            print("  also switch those functions (network, serial, vendor) on")
            print("  before you decide. It is held for your decision as is.\n")

        if was_held and self.trust is not None and self.trust.is_trusted(dev):
            print("  Note: this device is on your remembered list, but it was")
            print("  attached while you were away, so it is being asked about")
            print("  anyway.\n")

        self._remember = False
        # Set by _ask when nobody saw the question at all: a reason to hold
        # the device, not to refuse it. Reset here so a stale value from an
        # earlier device can never decide this one.
        self._hold_instead = False
        if self.watchdog:
            with self.watchdog.paused():
                approved = self._ask(dev, findings)
        else:
            approved = self._ask(dev, findings)
        if not approved and self._hold_instead:
            if self._may_hold_again(dev):
                self._hold_for_agent(dev, findings, medium, inspected=True)
                return
            # Falls through to the refusal below: _answered is False, so it
            # is recorded as "no answer", never as a refusal.
            print(f"  The desktop agent went away {self.MAX_UNSEEN_ASKS} "
                  f"times before this device could be decided; it is no "
                  f"longer held and stays blocked. Replug it to be asked "
                  f"again.")
        if approved:
            if (self.stop_event is not None and self.stop_event.is_set()):
                print("[!] Safety stop active; approval discarded.")
                return
            if (self.lock_policy != session_mod.POLICY_IGNORE
                    and self.monitor.is_locked()):
                self._hold_until_unlocked(dev)
                return
            try:
                sysfs.admit_device(dev)
            except OSError as exc:
                print(f"[!] failed to authorize: {exc}\n")
                self._record(Decision(dev, False, "admission failed", time.time()),
                             findings, medium)
                return
            self.known.add(dev.name)
            self._record(Decision(dev, True, "user approved", time.time()),
                         findings, medium)
            if getattr(self, "_remember", False) and self.trust is not None:
                self._remember_admitted(dev)
            print(f"[+] AUTHORIZED — {report.one_liner(dev, findings)}\n")
            self._watch_if_storage(dev, "approved")
        else:
            # "user rejected" only when someone actually said no. A timeout,
            # an EOF (the service's stdin is /dev/null) or an unanswered
            # dialog denies the device just the same, but recording it as a
            # refusal made the next plug warn "You have refused this device
            # before" about a refusal nobody made. The journal line says the
            # same thing the record does.
            answered = getattr(self, "_answered", True)
            reason = "user rejected" if answered else "no answer"
            self._record(Decision(dev, False, reason, time.time()),
                         findings, medium)
            self._switch_off(dev)
            verdict = "REJECTED" if answered else "DENIED, NOT ANSWERED"
            print(f"[-] {verdict} — {report.one_liner(dev, findings)}\n")

    @staticmethod
    def _interfaces(dev):
        """(class, subclass, protocol) per interface; [] if unreadable."""
        try:
            return [(int(i.interface_class), int(i.interface_subclass),
                     int(i.interface_protocol)) for i in dev.interfaces]
        except (TypeError, ValueError, AttributeError):
            return []

    @classmethod
    def _agent_title(cls, dev: sysfs.UsbDevice) -> str:
        """What it is and where, in words: "USB storage (…) · port 3-9"."""
        names = list(dict.fromkeys(usbclass.plain_name(*i)
                                   for i in cls._interfaces(dev)))
        if not names:
            names = list(dev.claims) if dev.claims else ["unknown device"]
        return f"{' + '.join(names)} · port {dev.name}"

    # Shown in the dialog, so there is room for every finding a real device
    # produces; the cap only stops a pathological list from pushing the
    # buttons off the screen.
    MAX_DIALOG_FINDINGS = 8
    _SYMBOL = {rules.Severity.CRITICAL: "\u26d4", rules.Severity.WARNING: "\u26a0",
               rules.Severity.NOTICE: "\u2022"}

    @classmethod
    def _agent_body(cls, dev: sysfs.UsbDevice, findings) -> str:
        """
        Identity, then EVERY finding, most severe first. "...and 1 more
        finding(s)" used to hide warnings on the one screen where the decision
        is made. Details stay in the journal; the dialog lists what was found.
        """
        ident = [dev.label(), f"{dev.vendor_id}:{dev.product_id}"]
        if getattr(dev, "serial", None):
            ident.append(f"serial {dev.serial}")
        lines = [" \u00b7 ".join(ident)]
        shown = sorted((f for f in findings
                        if f.severity >= rules.Severity.NOTICE),
                       key=lambda f: f.severity, reverse=True)
        if shown:
            lines.append("")
        for finding in shown[:cls.MAX_DIALOG_FINDINGS]:
            lines.append(f"{cls._SYMBOL[finding.severity]} {finding.title}")
        extra = len(shown) - cls.MAX_DIALOG_FINDINGS
        if extra > 0:
            lines.append(f"\u2026and {extra} more: journalctl -u probolos")
        return "\n".join(lines)

    @classmethod
    def _agent_capabilities(cls, dev: sysfs.UsbDevice) -> str:
        """What THIS device will be able to do, from the interfaces it
        declared -- not a generic list of everything a device might do."""
        classes = list(dict.fromkeys(i[0] for i in cls._interfaces(dev)))
        if not classes:
            return ""
        return "; ".join(dict.fromkeys(usbclass.capability(c)
                                       for c in classes))

    # What the countdown window says above its buttons, by finding. "Matches
    # an attack pattern" is right for storage that can type and wrong for a
    # stick you once refused, and a warning that overstates is one people
    # learn to skip.
    # The finding's own title is listed just above, so these say only what
    # to do about it.
    _CRITICAL_NOTES = {
        "previously-rejected":
            "Allow it only if refusing it was a mistake.",
        "descriptor-drift":
            "Allow it only if you know why it changed, for example your own "
            "device after a firmware update.",
    }
    _ATTACK_NOTE = ("This device matches an attack pattern. Allow it only if "
                    "you know exactly why these findings appear.")

    @classmethod
    def _critical_note(cls, findings) -> str:
        ids = list(dict.fromkeys(f.rule_id for f in findings
                                 if f.severity == rules.Severity.CRITICAL))
        if not ids:
            return ""
        if all(i in cls._CRITICAL_NOTES for i in ids):
            return " ".join(cls._CRITICAL_NOTES[i] for i in ids)
        return cls._ATTACK_NOTE

    @classmethod
    def _prompt_steps(cls, dev: sysfs.UsbDevice, findings) -> str:
        """
        How much friction this question earns. Two dialogs for everything
        trains the reflex to click through both; so one dialog for a device
        that can neither type nor carry traffic and showed nothing suspicious,
        two when it can or did, and a countdown when it matches an attack
        pattern.
        """
        worst = rules.worst(findings)
        if worst == rules.Severity.CRITICAL:
            return agentlink.STEPS_COUNTDOWN
        classes = {i[0] for i in cls._interfaces(dev)}
        if (worst < rules.Severity.WARNING and classes
                and classes <= usbclass.ONE_STEP_CLASSES):
            return agentlink.STEPS_ONE
        return agentlink.STEPS_TWO

    def report_blocked_on_exit(self) -> None:
        """
        Say plainly which devices are being left switched off.

        Probolos will not silently authorize a device nobody approved, so
        anything undecided stays blocked. But leaving hardware dead without
        saying so is how a tool earns a reputation for breaking things, and the
        user has no way to guess why a stick stopped working.
        """
        if not self.pending:
            return
        print(f"\n[!] {len(self.pending)} device(s) are still blocked because "
              f"no decision was made:")
        for name in self.pending:
            print(f"      {name}")
        print("    They stay blocked on purpose. Start Probolos again and you "
              "will be asked,")
        print("    or release them now with:  sudo python -m probolos --release")

    def _hold(self, dev: sysfs.UsbDevice, reason: str, findings=(),
              medium: Optional["storage.MediumReport"] = None, *,
              inspected: bool = False) -> None:
        """
        Keep a device blocked and queue it, to be asked about once someone
        can be. Shared by every reason a question is put off -- the screen is
        locked, or nobody can be asked at all -- so they cannot drift apart
        in how a held device is identified or recorded.

        The reason always starts "held:", and it is recorded with approved
        False: a held device is neither endorsed (the drift baseline does not
        move) nor refused (the previously-rejected rule matches only "user
        rejected"), because nobody has decided anything about it yet.

        `inspected` says stages 3 or 4 may have switched the device on before
        it came to this, so the write that keeps it blocked is checked as
        loudly as a refusal's. Otherwise the device has never been switched on
        and the write only makes the state explicit.
        """
        # Instance recorded alongside the path: the entry is about THIS
        # device, not about whatever later occupies this port.
        self.pending[dev.name] = (dev.syspath, dev.instance_id)
        if inspected:
            self._switch_off(dev)
        else:
            try:
                sysfs.set_authorized(dev.syspath, 0)
            except OSError:
                pass
        # Recorded once per device and reason. A held device goes back
        # through _on_add when the queue drains, and is held again if the
        # agent leaves before answering. That is not news, and each record
        # costs one of the ledger's MAX_DECISIONS: enough of them would push
        # a real "user rejected" out of the history, and the
        # previously-rejected countdown with it, without anyone having
        # decided anything.
        if self._last_recorded.get(dev.name) != (dev.instance_id, reason):
            self._record(Decision(dev, False, reason, time.time()),
                         findings, medium)

    # How often one held device may be put through inspection and then lose
    # its question because the desktop agent went away, before it is refused
    # as unanswered instead of held again. Each round can switch it on for
    # stages 3 and 4; an agent that crashes on the question and is restarted
    # by systemd would otherwise power up the same unknown hardware every few
    # seconds, for as long as the crash lasts.
    MAX_UNSEEN_ASKS = 3

    def _may_hold_again(self, dev: sysfs.UsbDevice) -> bool:
        """Count one lost question for this instance; False once at the cap."""
        instance, count = self._unseen_asks.get(dev.name, (None, 0))
        if instance != dev.instance_id:
            count = 0
        count += 1
        self._unseen_asks[dev.name] = (dev.instance_id, count)
        return count < self.MAX_UNSEEN_ASKS

    def _hold_until_unlocked(self, dev: sysfs.UsbDevice) -> None:
        """Keep a device blocked and remember to ask about it later."""
        if self.lock_policy == session_mod.POLICY_QUEUE:
            print(f"[⏸] SCREEN LOCKED — holding {report.one_liner(dev)}")
            print("    It stays blocked. You will be asked when you unlock.\n")
            self._hold(dev, "held: screen locked")
            return
        print(f"[-] SCREEN LOCKED — denied {report.one_liner(dev)}\n")
        try:
            sysfs.set_authorized(dev.syspath, 0)
        except OSError:
            pass
        self._record(Decision(dev, False, "denied: screen locked", time.time()))

    def _hold_for_agent(self, dev: sysfs.UsbDevice, findings=(),
                        medium: Optional["storage.MediumReport"] = None, *,
                        inspected: bool = False) -> None:
        """Nobody can be asked about this device yet: hold it until someone
        can. The run loop asks about it once a desktop agent connects."""
        print(f"[⏸] NO DESKTOP AGENT — holding "
              f"{report.one_liner(dev, findings)}")
        print("    No desktop agent is connected and there is no terminal, so "
              "nobody can be asked.")
        print("    It stays blocked. You will be asked when the agent "
              "connects.\n")
        self._hold(dev, "held: no desktop agent", findings, medium,
                   inspected=inspected)

    @staticmethod
    def _switch_off(dev: sysfs.UsbDevice) -> None:
        """
        Block a device a question has just ended for without admitting it.

        For a quarantined device this write genuinely matters: it was switched
        on for the observation and is alive right now if quarantine could not
        put it back. For every other device it is a no-op that makes the state
        explicit.
        """
        try:
            sysfs.set_authorized(dev.syspath, 0)
        except OSError as exc:
            # Never swallowed. Failing to switch off a device that just
            # typed at you is the most dangerous outcome in this program.
            print(f"\n[!!] COULD NOT DEAUTHORIZE {dev.name}: {exc}")
            print("[!!] The device may still be live. Unplug it now, or "
                  "run as root:")
            print(f"[!!]   echo 0 > {dev.syspath}/authorized\n")

    @staticmethod
    def _has_terminal() -> bool:
        """
        Whether a person could answer on this process's stdin.

        The service has none -- systemd gives it /dev/null -- and there a
        terminal prompt is not a fallback at all: it reads EOF at once and
        the device is denied, a refusal in everything but name. Anything that
        is not a terminal (a closed or replaced stdin included) counts as
        none. Tests replace this.
        """
        try:
            return os.isatty(sys.stdin.fileno())
        except (AttributeError, ValueError, OSError):
            return False

    def _nobody_can_be_asked(self) -> bool:
        """
        True when a desktop agent is configured but not there, and there is
        no terminal either: a question put now would have no one to see it.

        With no agent configured at all this stays False and the terminal is
        used exactly as before -- that is the setup someone chose to answer
        in a terminal, and an EOF there is theirs to arrange.
        """
        if self.dry_run or self.agent is None:
            return False
        return not self.agent.is_live() and not self._has_terminal()

    def _agent_can_take_held(self) -> bool:
        """
        Whether the held queue can be put to the desktop agent now: something
        is held, an agent is connected and alive, and the screen is not
        holding questions back.

        Not drained while the screen is locked under ANY lock policy that
        looks at it, not only "queue": under "deny" a drain then would deny,
        as "screen locked", a device that did not arrive behind a locked
        screen and that nobody has been asked about. It waits for the unlock.

        Cheapest first, since this runs every pass while anything is held:
        under "queue" the loop has just read the lock state, then the socket
        probe, and only under "deny" a lock lookup of its own.
        """
        if not self.pending or self.dry_run or self.agent is None:
            return False
        if self.lock_policy == session_mod.POLICY_QUEUE and self._was_locked:
            return False
        if not self.agent.is_live():
            return False
        if self.lock_policy in (session_mod.POLICY_QUEUE,
                                session_mod.POLICY_IGNORE):
            return True
        return not self.monitor.is_locked()

    def _drain_pending(self, cause: str = "") -> None:
        """
        Someone can be asked again -- the screen unlocked, a desktop agent
        connected, or a new run started: put the held questions now.

        Each device is re-read from sysfs rather than replayed from the earlier
        snapshot. It has been blocked the whole time so nothing about it can
        have changed, but reading it again is what makes the full inspection --
        quarantine, storage scan -- run now, at the moment there is a human to
        see the result.

        What re-reading does NOT establish is that the thing at that path is
        still the thing that was queued, which is why the recorded instance is
        checked first. "It has been blocked the whole time" is true of the
        device that was held and says nothing about the port: an attacker with
        physical access -- the threat this whole lock policy exists for -- can
        pull the held device and insert their own at the same port while the
        screen is locked. Both are named "1-4". Without the instance check the
        queue entry, and the operator's expectation of what they are being
        asked about, silently transfers to the substitute.
        """
        if not self.pending:
            return
        # Nobody can be asked yet (an agent is expected, none is there, no
        # terminal): putting the queue through _on_add now would only hold
        # every device again, after re-reading it, at each unlock and each
        # restart. It stays queued as it is, and the run loop drains it when
        # an agent connects.
        if self._nobody_can_be_asked():
            print(f"[⏸] {len(self.pending)} held device(s) stay blocked "
                  f"until the desktop agent connects.\n")
            return
        what = f"{len(self.pending)} held device(s)"
        print(f"\n[▶] {cause} — asking about {what} now.\n" if cause
              else f"\n[▶] Asking about {what} now.\n")
        # Swapped out before the first question, so a device _on_add holds
        # again during this pass lands in the NEW queue and is not drained a
        # second time by the very pass that re-held it.
        held, self.pending = self.pending, OrderedDict()
        for name, (syspath, instance) in held.items():
            if not syspath.exists():
                print(f"[*] {name} was removed while held; nothing to decide\n")
                continue
            # The kernel directory instance is the identity. A mismatch means
            # the port was recycled, so this is NOT the held device; it is
            # dropped from the queue and left blocked. It is not silently
            # inspected instead, and it is not admitted -- a new device gets a
            # fresh 'add' event of its own if the kernel still has one to give,
            # and if it does not, staying blocked is the safe direction.
            #
            # Skipped entirely when no instance was recorded (load_device could
            # not stat the directory at queue time). There is then nothing to
            # compare against, and inventing a comparison would only refuse
            # devices for a reason that does not exist.
            if instance is not None and not self._still_same_device(
                    syspath, instance):
                print(f"[!] {name}: a DIFFERENT device now occupies this port "
                      f"than the one that was held.")
                print("    It stays blocked and is not being asked about "
                      "under the old entry. Replug it to have it gated "
                      "normally.\n")
                continue
            # Same reasoning as the poll loop: one held device failing must not
            # abandon the rest of the queue, and must not end the daemon.
            try:
                self._on_add(str(syspath), was_held=True)
            except Exception as exc:   # noqa: BLE001
                import traceback
                print(f"[!] {name}: unhandled error while gating this held "
                      f"device: {exc!r}. It stays BLOCKED.")
                traceback.print_exc()

    @staticmethod
    def _still_same_device(syspath: Path, instance: tuple) -> bool:
        """
        Is the kernel directory at `syspath` still the one recorded as
        `instance`?

        A sysfs name such as "1-4" names a PORT. The (st_dev, st_ino) pair
        names the directory the kernel created for one particular enumeration
        of one particular device, and it changes when the device is unplugged
        and another is inserted at the same port. That distinction is what the
        held queue needs and what it did not have.

        An unreadable path answers False: if we cannot prove it is the same
        device, we do not treat it as one.
        """
        try:
            st = syspath.stat()
        except OSError:
            return False
        return (st.st_dev, st.st_ino) == instance

    def _inspect_medium(self, dev: sysfs.UsbDevice):
        """
        Switch the medium on just long enough to read its partition table.

        Same discipline as the behavioural quarantine: authorize, look, and put
        it straight back to blocked before anyone is asked anything. The medium
        is opened read-only and never mounted by Probolos. Another service may
        still mount it during this activation window.
        """
        print("  This is a storage device. Probolos will read its partition")
        print("  table directly, without mounting it.")

        try:
            sysfs.activate_device(dev)
        except OSError as exc:
            # This used to print the raw exception -- errno text and the full
            # sysfs path -- at the decision prompt and return None, so no
            # MEDIUM block and no "judged on identity alone" notice followed:
            # the operator was asked to authorize with nothing saying the
            # medium had never been looked at. It now takes the same path as
            # every other failure below.
            return self._medium_not_examined(
                dev, "it could not be switched on to look",
                detail=f"{type(exc).__name__}: {exc}")

        medium = None
        try:
            # The block node appears shortly after authorization. Poll FAST and
            # briefly: every millisecond the device is authorized is a
            # millisecond udisks2 may use to automount it (see the honest
            # caveat below). 20 ms steps up to 1.5 s finds the node about as
            # quickly as the kernel can create it, without a 100 ms coarse wait
            # sitting open for no reason.
            #
            # NOTE (known limitation, tracked as the interface-authorization
            # work): this authorizes the WHOLE device to make its block node
            # visible, so a race with udisks2 automount exists for the length of
            # this window. The real fix is interface-level authorization --
            # authorize the device but hold the mass-storage interface at 0, so
            # no block node is ever created for udisks2 to see. Until then the
            # window is kept as short as possible and the device is re-blocked
            # in the finally below the instant the read returns.
            #
            # The wait is for the NODE, not the sysfs entry. `block/sdX`
            # appears in sysfs before /dev/sdX exists, and opening in that gap
            # was refused as "not a whole-disk block device" -- a healthy disk
            # sent down the could-not-read path, stage 4 skipped. So the loop
            # keeps polling while the node is merely late
            # (sysfs.block_node_pending), and stops the moment waiting would not
            # help: ready, or refused for a reason open_block_device reports.
            devices = []
            pending = None
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                devices = storage.find_block_devices(dev.syspath)
                if devices:
                    pending = sysfs.block_node_pending(devices[0])
                    if pending is None:
                        break
                time.sleep(0.02)
            if devices and pending is None:
                medium = storage.inspect_safely(
                    devices[0], open_fn=sysfs.open_block_device)
                if medium.error:
                    medium = self._medium_not_examined(
                        dev,
                        medium.error if medium.timed_out
                        else "its block device could not be read",
                        detail=f"{devices[0]}: {medium.error}",
                        device=devices[0])
            elif devices:
                medium = self._medium_not_examined(
                    dev, "its block device did not become ready",
                    detail=f"{devices[0]}: {pending}", device=devices[0])
            else:
                medium = self._medium_not_examined(
                    dev, "no block device appeared")
        finally:
            # REPORTED, never raised. Raising here -- and raising from a
            # `finally`, which also swallows whatever went wrong inside the
            # scan -- propagated straight out of _on_add into the udev poll
            # loop, which has no handler, so the daemon died. The most common
            # cause is not an attack but ENODEV: the stick was pulled during
            # the 1.5 s the block node takes to appear. Killing the gate over
            # an ordinary unplug is a fail-open, and a far worse outcome than
            # the condition being reported.
            try:
                sysfs.set_authorized(dev.syspath, 0)
            except OSError as exc:
                if not dev.syspath.exists():
                    # The device is gone. There is nothing left to re-block and
                    # nothing left switched on; this is the benign case.
                    print(f"  ({dev.name} was removed during inspection)")
                else:
                    print(f"\n[!!] COULD NOT RE-BLOCK {dev.name} after "
                          f"inspection.\n"
                          f"[!!] It is still switched on. Unplug it now; do "
                          f"not rely on the prompt below.\n")
                    left_on = "it could not be switched back off afterwards"
                    why = f"re-block: {type(exc).__name__}: {exc}"
                    if medium is None or not medium.error:
                        medium = self._medium_not_examined(
                            dev, left_on, detail=why,
                            device=medium.device if medium else "")
                    else:
                        medium.error = f"{medium.error}; and {left_on}"
                        medium.detail = "; ".join(
                            filter(None, (medium.detail, why)))
        return medium

    @staticmethod
    def _medium_not_examined(dev: sysfs.UsbDevice, reason: str,
                             detail: Optional[str] = None,
                             device: str = "") -> "storage.MediumReport":
        """
        The one way a medium inspection fails.

        Every failure -- the switch-on write, a node that never appears or is
        never ready, an unreadable or stalled block device, a removal mid-scan
        -- converges here, so every one of them reaches the operator the same
        way: a MEDIUM block saying "not inspected", followed by the notice that
        the device was judged on its declared identity alone.

        `reason` comes from a fixed vocabulary and is all the operator sees.
        `detail` (exception text, sysfs and /dev paths) is kept for the audit
        log and never printed at the prompt: raw errno strings and internal
        paths are noise at a security decision, and a device that can shape
        them should not get to write into it.

        A device that has disappeared is reported as removed whatever step
        noticed it first: the same root cause used to surface as two different
        messages depending on which branch lost the race.
        """
        try:
            gone = not dev.syspath.exists()
        except OSError:
            gone = False
        if gone:
            reason = "the device was removed during inspection"
        return storage.MediumReport(device=device, error=reason, detail=detail)

    def _quarantine(self, dev: sysfs.UsbDevice):
        """
        Switch the device on inside a closed room and watch it.

        The instruction to the user is the experiment: if nobody touches the
        device, then anything it sends is something it decided to send.
        """
        print("  This is an input device. Probolos will switch it on with its")
        print("  input captured after EVIOCGRAB succeeds. Input can escape")
        print("  before capture, including when deferred binding is enabled.")
        print(f"  >>> DO NOT TOUCH IT for the next {self.observe:.0f} seconds. <<<")
        print()

        # A listening monitor does not make driver binding and grabbing atomic.
        # Keep the legacy experimental flag, with its limitation visible.
        if self.close_race_window:
            if deferred_bind.supported(dev.syspath):
                db = deferred_bind.DeferredBind(dev.syspath, log=print,
                                                instance=dev.instance_id)
                return quarantine.quarantine(
                    dev.syspath,
                    authorize_fn=db.authorize_device,
                    release_fn=db.release_interfaces,
                    bind_context=db,
                    duration=self.observe,
                    capture=self.capture_payload,
                    deauthorize_fn=lambda: sysfs.set_authorized(dev.syspath, 0),
                )
            print("  ! --close-race-window requested but unavailable: "
                  f"{deferred_bind.unsupported_reason()}")
            print("  ! falling back to authorize-then-grab; the exposure "
                  "window below is real.")
        else:
            print("  Note: the driver binds before the grab, so a short "
                  "exposure window applies.")
            print("  Time until capture is printed below; it is not a proof "
                  "that no input escaped.")

        return quarantine.quarantine(
            dev.syspath,
            authorize_fn=lambda: sysfs.activate_device(dev),
            duration=self.observe,
            capture=self.capture_payload,
            deauthorize_fn=lambda: sysfs.set_authorized(dev.syspath, 0),
        )

    def _on_remove(self, sys_path: str) -> None:
        name = Path(sys_path).name
        if name in self.pending:
            del self.pending[name]
            print(f"[*] {name} removed while held; question withdrawn")
        # Whatever is plugged in next at this port is a new device: it gets
        # its own hold record and its own count of lost questions.
        self._last_recorded.pop(name, None)
        self._unseen_asks.pop(name, None)
        self.known.discard(name)
        if self.media_watch is not None:
            self.media_watch.unregister(name)
        print(f"[*] removed: {name}")

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_with_retry(path: Path, attempts: int = 5,
                         delay: float = 0.05) -> Optional[sysfs.UsbDevice]:
        """
        Read the device, retrying briefly.

        The uevent can reach us a hair before every sysfs attribute is
        readable. A few short retries cost nothing and avoid a spurious
        "unreadable descriptors" finding, which would be a false alarm in a
        tool whose whole value is that its alarms mean something.
        """
        for _ in range(attempts):
            dev = sysfs.load_device(path)
            if dev is not None and dev.descriptor_set is not None:
                return dev
            time.sleep(delay)
        return sysfs.load_device(path)

    @staticmethod
    def _discard_typeahead() -> int:
        """
        Throw away terminal input queued before the prompt was shown.

        Returns how many bytes of complete lines were waiting (FIONREAD counts
        only those in canonical mode; a partial line is discarded too, just
        not counted). Not a terminal, or not one that answers: nothing to do.
        """
        try:
            fd = sys.stdin.fileno()
            if not os.isatty(fd):
                return 0
            import fcntl
            import struct
            import termios
            waiting = struct.unpack(
                "i", fcntl.ioctl(fd, termios.FIONREAD, b"\0\0\0\0"))[0]
            termios.tcflush(fd, termios.TCIFLUSH)
            return max(0, waiting)
        except (AttributeError, ValueError, OSError):
            return 0

    def _can_remember(self) -> bool:
        """
        Whether "always" can be kept. An option whose answer would be lost is
        not offered, and what is not offered is not accepted.

        Either this process writes the store, or (under --privsep) the gate
        does it for us -- see _gate_keeps_trust for when it would refuse.
        """
        if self.trust is None:
            return False
        # Never over a store that failed to load, as the gate refuses to
        # (gate_server._do_trust): saving it would keep only what was read
        # -- after one stray comma, nothing -- plus the new entry.
        if self.trust.load_error:
            return False
        return self.trust.writable() or _gate_keeps_trust(self.trust)

    def _remember_admitted(self, dev: sysfs.UsbDevice) -> None:
        """
        Keep "always" for a device that has just been admitted.

        Called only after admit_device() succeeded: the device is admitted
        once whatever happens here, and every failure is printed rather than
        raised, because the person who clicked "always" needs to know their
        answer was not kept.
        """
        if self.trust.writable():
            entry = self.trust.trust(dev)
            if entry is not None:
                self.trust.record_admission(dev)
                error = self.trust.save()
                print(f"  trust could not be saved: {error}" if error
                      else "  remembered for future admissions")
            return

        # Under --privsep: the analyzer cannot write the store, so the root
        # gate does, against a fingerprint it took itself. The key sent is
        # only what this side believes; the gate refuses it unless it equals
        # its own.
        key = trust_mod.key_for(dev)
        if key is None:
            print("  trust could not be saved: this device's descriptors "
                  "could not be read, so there is nothing to pin it to")
            return
        try:
            sysfs.remember_via_backend(dev, key, dev.label())
        except OSError as exc:
            print(f"  trust could not be saved: {exc}")
            return
        # The gate replaced the file; refresh() sees the new inode and reads
        # it, so the next plug of this device is admitted without a question.
        # Checked rather than assumed: a store the gate wrote but this process
        # cannot read back (permissions, an integrity refusal) would otherwise
        # be reported as remembered and then ask again anyway.
        self.trust.refresh()
        if key in self.trust.devices:
            print("  remembered for future admissions")
        else:
            why = self.trust.load_error or "the new entry is not there"
            print(f"  trust was saved by the gate but cannot be read back "
                  f"here ({why}); this device will be asked about again")

    def _ask(self, dev: sysfs.UsbDevice,
             findings=()) -> bool:
        """
        Ask on the trusted terminal. Default is ALWAYS deny.

        Deny-by-default matters on every path: timeout, EOF, closed pipe,
        unparseable answer. A security gate that fails open is not a gate.

        For CRITICAL findings the answer must be the whole word "authorize".
        A single 'y' is muscle memory; a typed word is a decision. The friction
        is the point, and it is applied only where it is earned -- prompting
        hard for everything would just retrain the reflex on a longer word.
        """
        critical = rules.worst(findings) == rules.Severity.CRITICAL
        # Set to True only where a person's answer was actually received.
        self._answered = False
        # Set when nobody could see the question at all: _on_add then holds
        # the device rather than refusing it.
        self._hold_instead = False

        # ---- ask through the desktop agent, if one is listening -----------
        # A CRITICAL device used to be never offered to the agent: it could
        # only be approved by typing 'authorize' in the terminal -- which the
        # service does not have, so under the service such a device could not
        # be approved at all, even a known one after a firmware update. It is
        # now offered with a countdown: "Allow anyway" stays disabled for
        # CRITICAL_COUNTDOWN seconds, long enough that approving takes a
        # decision rather than a reflex, and never with "always".
        #
        # is_live(), not `connected`: an agent whose session ended leaves a
        # connection object behind, and a question sent into it only comes
        # back as "no answer" -- which the paths below must tell apart from a
        # question somebody saw.
        agent = self.agent
        if agent is not None and agent.is_live():
            title = self._agent_title(dev)
            steps = self._prompt_steps(dev, findings)
            asked_at = time.monotonic()
            answer = agent.ask(
                title=title,
                body=self._agent_body(dev, findings),
                severity=rules.worst(findings).label if findings else "none",
                allow_always=self._can_remember() and not critical,
                timeout=self.timeout if self.timeout else 60.0,
                steps=steps,
                capabilities=self._agent_capabilities(dev),
                countdown=CRITICAL_COUNTDOWN if critical else 0,
                note=self._critical_note(findings))
            if (critical and answer in (agentlink.ANSWER_YES,
                                        agentlink.ANSWER_ALWAYS)
                    and time.monotonic() - asked_at < CRITICAL_COUNTDOWN):
                # The dialog cannot produce this; something answered for it.
                print("  [!] an approval arrived before the countdown ended "
                      "and was ignored")
                answer = None
            if answer in (agentlink.ANSWER_ALWAYS, agentlink.ANSWER_YES,
                          agentlink.ANSWER_NO):
                self._answered = True
            if answer == agentlink.ANSWER_ALWAYS and not critical:
                self._remember = True
                return True
            if answer in (agentlink.ANSWER_YES, agentlink.ANSWER_ALWAYS):
                return True
            if answer == agentlink.ANSWER_NO:
                return False
            # answer is None: the agent could not answer at all. That is not
            # a decision, so it must not be treated as one -- ask in the
            # terminal rather than silently refusing something the user never
            # saw. Only where there IS a terminal: see _unanswered.
            if not self._has_terminal():
                return self._unanswered(title, critical=critical)
            print("  (no answer from the desktop agent; asking here)")
        elif agent is not None and not self._has_terminal():
            # _on_add found the agent there, and stages 3 and 4 then took
            # seconds in which it went away. The terminal would only read EOF
            # and deny; nobody has seen this question, so the device is held.
            print("  (the desktop agent went away before it could be asked; "
                  "the device is held until it is back)")
            self._hold_instead = True
            return False

        if critical:
            # No "always" option here on purpose. Remembering a device that
            # matches an attack pattern is not a choice worth offering in one
            # keystroke, and trust never overrides a CRITICAL finding anyway.
            # If a rules.py rule really is a false positive for this hardware,
            # its severity can be lowered deliberately with --rules; the
            # analyzer findings (descriptor-drift, previously-rejected,
            # payload-captured, analyzer-failed:*) are not configurable.
            prompt = ("  This device matches an attack pattern.\n"
                      "  Type the word 'authorize' to allow it, anything else "
                      "to reject: ")
        elif self._can_remember():
            prompt = ("  Authorize this device? "
                      "[y]es once / [a]lways / [N]o: ")
        else:
            prompt = "  Authorize this device? [y/N] "
        if self.timeout > 0 and not critical:
            # The countdown variant used to replace the prompt wholesale with
            # "[y/N]", which DROPPED the [a]lways option from the text while
            # the parser below went on accepting it. The result was a hidden
            # control on the one prompt in the tool that grants something
            # permanent: a user typing `a` -- for "abort", which is what [y/N]
            # invites you to assume it is not -- created a trust entry that
            # admits that device silently from then on. An option that is not
            # offered must not be accepted, so it is offered.
            choices = ("[y]es once / [a]lways / [N]o"
                       if self._can_remember() else "[y/N]")
            prompt = (f"  Authorize this device? {choices} "
                      f"({self.timeout:.0f}s, default N) ")
        # The timeout applies to critical prompts too. It expires into DENIAL,
        # which is the safe direction, and it stops one suspicious device from
        # blocking the event loop indefinitely.

        # Only what is typed AFTER the question may answer it. Stage 3 switches
        # the device on before EVIOCGRAB can take it, and keystrokes sent in
        # that window go to the focused window -- usually this terminal, which
        # has just told the operator not to touch anything. "y<Enter>" queued
        # there was read below as the operator's answer, so a keyboard could
        # approve itself ("authorize<Enter>" on a CRITICAL prompt).
        discarded = self._discard_typeahead()
        if discarded:
            print(f"  [!] Discarded {discarded} byte(s) of input that reached "
                  f"this terminal before the question was asked.")
            print("  [!] If you did not type them, this device probably did.")

        sys.stdout.write(prompt)
        sys.stdout.flush()

        if self.timeout > 0:
            ready, _, _ = select.select([sys.stdin], [], [], self.timeout)
            if not ready:
                print("\n  (timed out — denied)")
                return False

        try:
            answer = sys.stdin.readline()
        except (KeyboardInterrupt, EOFError):
            print("\n  (interrupted — denied)")
            return False

        if not answer:  # EOF
            print("\n  (no input — denied)")
            return False

        self._answered = True
        answer = answer.strip().lower()
        if critical:
            return answer == "authorize"
        if answer in ("a", "always") and self._can_remember():
            self._remember = True
            return True
        return answer in ("y", "yes")

    def _unanswered(self, title: str, critical: bool = False) -> bool:
        """
        The agent was asked and gave no decision, and there is no terminal to
        ask in instead. Never an approval: returns False either way.

        Two cases look alike here. If the agent went away mid-question --
        logout, crash -- nobody saw the question, and the device is HELD
        (_on_add queues it) to be asked when an agent is back. If the agent
        is still there, the question was on screen and nobody answered it in
        time: the device is denied, recorded as "no answer" and never as a
        refusal, and the agent is told that it is still blocked.

        It is not put back in the queue. Re-queueing would re-ask, forever, a
        person who is not there, and keep a question open indefinitely. A
        replug is a deliberate physical act by someone at the machine, and it
        brings a fresh enumeration that is gated normally -- which is what the
        notice tells them to do. Falling back to the terminal, as this used
        to, was the same denial in disguise: the service's stdin is /dev/null.

        A CRITICAL device's notice goes out at critical urgency, which a
        notification server keeps on screen until it is dismissed. Its dialog
        was the countdown, and an approval that arrived inside the countdown
        also ends here, so this is the one notice that may mean something
        answered for the person.
        """
        if not self.agent.is_live():
            print("  (the desktop agent went away before answering; the "
                  "device is held until it is back)")
            self._hold_instead = True
            return False
        print("  (no answer from the desktop agent, and no terminal to ask "
              "in; it stays blocked until it is plugged in again)")
        notify = self.agent.notify_critical if critical else self.agent.notify
        notify(
            "USB device still blocked",
            f"{title}\nNobody answered in time. Unplug it and plug it in "
            f"again to be asked.")
        return False

    def _record(self, decision: Decision, findings=(),
                medium: Optional["storage.MediumReport"] = None) -> None:
        """
        Persist one decision: to the ledger, then to the JSON audit log.

        (The docstring used to sit BELOW the ledger block, where Python treats
        it as a discarded string expression rather than documentation -- so the
        method had none, and `help()` showed nothing for the one function that
        writes both persistent stores.)
        """
        # What _hold compares against, so that holding a device again for the
        # reason it is already held under writes nothing new.
        self._last_recorded[decision.device.name] = (
            getattr(decision.device, "instance_id", None), decision.reason)
        # In dry-run we change nothing that persists, and the ledger is
        # persistent state. Recording a decision that was never actually made
        # would also poison the history with dry-run noise.
        if self.ledger is not None and not self.dry_run:
            # `approved` is passed, not inferred from the reason string: it is
            # what moves the drift baseline, and deriving something that
            # load-bearing from prose that also has to read well in a log is
            # how "held: screen locked" ends up counting as an endorsement.
            self.ledger.record(decision.device, decision.reason,
                               approved=bool(decision.authorized))
            error = self.ledger.save()
            if error:
                print(f"[!] could not write ledger: {error}")

        # Audit trail first, pretty output second.
        if not self.json_log:
            return
        dev = decision.device
        entry = {
            "time": decision.timestamp,
            "device": dev.name,
            "vendor_id": dev.vendor_id,
            "product_id": dev.product_id,
            "manufacturer": dev.manufacturer,
            "product": dev.product,
            "serial": dev.serial,
            "claims": dev.claims,
            "kinds": dev.kinds,
            "authorized": decision.authorized,
            "reason": decision.reason,
            "verdict": rules.worst(findings).label,
            "findings": [
                {"rule": f.rule_id, "severity": f.severity.label,
                 "title": f.title}
                for f in findings
            ],
        }
        if medium is not None:
            # The raw failure detail lives here and only here; the prompt got
            # the fixed-vocabulary reason (see _medium_not_examined).
            entry["medium"] = {
                "examined": medium.error is None,
                "reason": medium.error,
                "detail": medium.detail,
            }
        try:
            from .securefs import append_json_line
            append_json_line(self.json_log, entry)
        except OSError as exc:
            print(f"[!] could not write log: {exc}")


def serve(dry_run: bool = False, timeout: float = 0.0,
          json_log: Optional[Path] = None,
          rule_config: Optional[rules.RuleConfig] = None,
          observe: float = 3.0,
          policy: Optional[safety.SafetyPolicy] = None,
          ledger_path: Optional[Path] = None,
          capture_payload: bool = False,
          watchdog_timeout: float = 0.0,
          trust_path: Optional[Path] = None,
          inspect_storage: bool = True,
          lock_policy: str = session_mod.POLICY_QUEUE,
          force_locked: Optional[bool] = None,
          agent_socket: Optional[Path] = None,
          agent_uid: Optional[int] = None,
          agent_gid: Optional[int] = None,
          close_race_window: bool = False,
          watch_media: bool = False,
          media_policy: str = "log") -> None:
    """Wire the gate, the safety net and the loop together."""
    policy = policy or safety.SafetyPolicy()
    link = None
    if agent_socket is not None:
        # uid 0 is included because refusing it buys nothing: root can write
        # sysfs `authorized` directly and does not need the socket to admit a
        # device. Excluding it would only make `sudo python -m probolos.agent`
        # fail confusingly while debugging. The uid that matters is the desktop
        # one -- everything else is refused and logged.
        permitted = None if agent_uid is None else {agent_uid, 0}
        link = agentlink.AgentLink(agent_socket, allowed_uids=permitted,
                                   owner_uid=agent_uid, owner_gid=agent_gid)
        if link.start():
            who = "any local process" if permitted is None else f"uid {agent_uid}"
            print(f"  - desktop agent socket: {agent_socket} "
                  f"(answers accepted from {who})")
            print("    start the agent in your session with: "
                  "python -m probolos.agent")
        else:
            link = None

    monitor = session_mod.detect(force_locked)
    if lock_policy != session_mod.POLICY_IGNORE:
        print(f"  - screen-lock policy: {lock_policy} "
              f"via {monitor.describe}")

    trust_store = None
    if trust_path is not None:
        # Under --privsep (a backend that can trust) only a root-owned store
        # counts, as it does for the gate: this process is the shared
        # `nobody`, and what `nobody` owns any `nobody` process could write.
        trust_store = trust_mod.TrustStore(
            trust_path, owners=(0,) if sysfs.backend_can_trust() else None)
        if trust_store.load_error:
            print(f"[!] trust store unreadable ({trust_store.load_error}); "
                  f"nothing will be treated as trusted")
        elif trust_store.devices:
            print(f"  - {len(trust_store.devices)} remembered device(s) will "
                  f"be admitted without asking")
        # serve() runs inside the analyzer, after __main__ installed the gate
        # backend, so the backend can be asked. Under --privsep the root gate
        # writes "always"; saying it is not offered there was true until the
        # gate learned to (REQ_TRUST), and is not now.
        if not trust_store.writable():
            if _gate_keeps_trust(trust_store):
                print("  - \"always\" is saved by the privileged gate (this "
                      "process cannot write the trust store itself)")
            else:
                print("  - \"always\" is not offered: this process cannot "
                      "write the trust store")

    store = None
    if ledger_path is not None:
        # Held until the process exits, and taken before the load: it is how
        # `--remove-all` knows this process would write the history back.
        # Not in --dry-run, which never writes the ledger.
        ledger_claim = None if dry_run else ledger_mod.claim(ledger_path)  # noqa: F841
        store = ledger_mod.Ledger(ledger_path)
        if store.load_error:
            print(f"[!] ledger unreadable ({store.load_error}); "
                  f"continuing without history")

    # A panic file left behind by a previous run would fire the watchdog the
    # instant it starts, which looks like a malfunction rather than the
    # deliberate signal it is. Refuse clearly instead.
    #
    # lexists, not exists: exists() follows symlinks, so a DANGLING symlink at
    # the panic path read as absent here while the watchdog -- which uses
    # lstat -- saw it, refused it, and complained about it twice a second for
    # the whole run. The two checks look at the same path and must agree about
    # what is there; anything left at the path is the operator's to clear.
    if os.path.lexists(policy.panic_file) and not dry_run:
        raise SystemExit(
            f"A panic file already exists at {policy.panic_file}.\n"
            f"It would force the gate open immediately. Remove it first:\n"
            f"    rm {policy.panic_file}")

    if close_race_window and not dry_run:
        if deferred_bind.supported():
            print("  - experimental deferred binding enabled; "
                  "the input grab race still exists")
        else:
            print(f"[!] --close-race-window is not available here: "
                  f"{deferred_bind.unsupported_reason()}")
            print("    Devices will be observed with the exposure window open; "
                  "it is measured and printed per device.")

    # Checked here, not only in run(): run() is reached after the gate has
    # closed, so a missing pyudev closed every hub, reopened it, and ended in a
    # traceback. Refuse before touching anything instead.
    if pyudev is None:
        if link:
            link.stop()
        raise SystemExit("pyudev is not installed; it drives the event loop.\n"
                         "Install it (Manjaro/Arch: sudo pacman -S python-pyudev, "
                         "or: pip install pyudev) and try again.")

    print("[*] Closing the USB authorization gate:")
    with gate.AuthorizationGate(dry_run=dry_run) as opened:
        dog = None
        stop_event = threading.Event()
        if watchdog_timeout > 0 and not dry_run:
            def on_stall(reason: str) -> None:
                print(f"\n[!!] WATCHDOG: {reason} — reopening the gate now")
                opened.restore()
                stop_event.set()
            dog = safety.Watchdog(watchdog_timeout, on_stall, policy)
            dog.start()
            print(f"  - watchdog armed ({watchdog_timeout:.0f}s), "
                  f"panic file: {policy.panic_file}")

        engine = Probolos(dry_run=dry_run, timeout=timeout, json_log=json_log,
                          rule_config=rule_config, observe=observe,
                          policy=policy, ledger=store,
                          capture_payload=capture_payload, watchdog=dog,
                          stop_event=stop_event, trust_store=trust_store,
                          inspect_storage=inspect_storage, monitor=monitor,
                          lock_policy=lock_policy, agent=link,
                          close_race_window=close_race_window)
        if watch_media and not dry_run:
            from . import mediawatch
            engine.media_watch = mediawatch.MediaWatch(
                policy=media_policy, ledger=store, json_log=json_log,
                rule_config=rule_config, is_locked=monitor.is_locked,
                on_deauthorized=engine._media_policy_deauthorized)
            print(f"  - media watch: cards in admitted readers are inspected "
                  f"read-only and alerted on (policy: {media_policy}); they "
                  f"are NOT gated")
        elif watch_media:
            print("  - media watch: off in --dry-run")
        engine.snapshot()
        try:
            engine.run()
        except KeyboardInterrupt:
            print("\n[*] Interrupted.")
        finally:
            if dog:
                dog.stop()
            engine.report_blocked_on_exit()
            if link:
                link.stop()
            print("[*] Reopening the gate:")

    # A stall the watchdog ended is a failure, and the exit status says so.
    # It used to be 0, so systemd's Restart=on-failure never started the gate
    # again: protection stayed off and the unit read "inactive (dead)" rather
    # than "failed". The panic file is the operator's own off switch, and
    # still ends the run normally.
    if dog is not None and dog.fired and not dog.panicked:
        raise SystemExit("[!!] The watchdog reopened the gate; exiting with a "
                         "failure status so a supervisor can start it again.")
