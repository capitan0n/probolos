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

import json
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


@dataclass
class Decision:
    device: sysfs.UsbDevice
    authorized: bool
    reason: str
    timestamp: float


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
                 close_race_window: bool = False):
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
        # Devices attached while the screen was locked. They are held blocked
        # and asked about when someone returns, so nobody has to unplug and
        # replug hardware just because they stepped away.
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
        self.known: Set[str] = set()    # devices present at startup

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

        print(f"[*] Baseline: {len(self.known)} USB device(s) already attached, "
              f"all left untouched")

        if stranded:
            print(f"[*] {len(stranded)} device(s) are attached but blocked "
                  f"(left over from an earlier run):")
            for dev in stranded:
                print(f"      {report.one_liner(dev)}")
                self.pending[dev.name] = (dev.syspath, dev.instance_id)
            print("    You will be asked about them now, without unplugging "
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
        monitor.start()

        print("[*] Listening. Plug in a device. Ctrl-C to stop.\n")

        # Devices found blocked at startup are decided immediately -- unless
        # the screen is locked, in which case they simply stay queued until
        # someone is back, exactly like a device attached while away.
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
            if self.lock_policy == session_mod.POLICY_QUEUE and not self.dry_run:
                locked = self.monitor.is_locked()
                if locked is not None:
                    if self._was_locked and not locked:
                        self._drain_pending()
                    self._was_locked = bool(locked)

            device = monitor.poll(timeout=1.0)
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
                if device.action == "add":
                    self._on_add(device.sys_path)
                elif device.action == "remove":
                    self._on_remove(device.sys_path)
            except Exception as exc:   # noqa: BLE001 -- see above
                import traceback
                print(f"[!] {Path(device.sys_path).name}: unhandled error "
                      f"while gating this device: {exc!r}")
                print(f"[!] It stays BLOCKED. The gate is still running.")
                traceback.print_exc()

    def _on_add(self, sys_path: str, was_held: bool = False) -> None:
        """
        Handle a device attachment.

        `was_held` marks a device that spent time blocked in the queue -- it
        arrived while the screen was locked, or was left undecided by an
        earlier run. Such a device is always asked about, even if remembered.

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
                self.trust.record_admission(dev)
                error = self.trust.save()
                if error:
                    print(f"[!] could not update trust store: {error}")
                print(f"[=] TRUSTED — {report.one_liner(dev, findings)}\n")
                self.known.add(dev.name)
                self._record(Decision(dev, True, "trusted", time.time()),
                             findings)
            except OSError as exc:
                print(f"[!] failed to authorize trusted device: {exc}")
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
        if (complete and self.inspect_storage and usbclass.KIND_STORAGE in dev.kinds
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
            print("  Its medium will NOT be read: authorizing it to look would")
            print("  also switch the input half on without a grab. It is held")
            print("  for your decision on the strength of that alone.\n")

        if was_held and self.trust is not None and self.trust.is_trusted(dev):
            print("  Note: this device is on your remembered list, but it was")
            print("  attached while you were away, so it is being asked about")
            print("  anyway.\n")

        self._remember = False
        if self.watchdog:
            with self.watchdog.paused():
                approved = self._ask(dev, findings)
        else:
            approved = self._ask(dev, findings)
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
                             findings)
                return
            self.known.add(dev.name)
            self._record(Decision(dev, True, "user approved", time.time()), findings)
            if getattr(self, "_remember", False) and self.trust is not None:
                entry = self.trust.trust(dev)
                if entry is not None:
                    self.trust.record_admission(dev)
                    error = self.trust.save()
                    print(f"  trust could not be saved: {error}" if error
                          else "  remembered for future admissions")
            print(f"[+] AUTHORIZED — {report.one_liner(dev, findings)}\n")
        else:
            # For a quarantined device this write genuinely matters: it was
            # switched on for the observation and is alive right now. For every
            # other device it is a no-op that makes the state explicit.
            self._record(Decision(dev, False, "user rejected", time.time()),
                         findings)
            try:
                sysfs.set_authorized(dev.syspath, 0)
            except OSError as exc:
                # Never swallowed. Failing to switch off a device that just
                # typed at you is the most dangerous outcome in this program.
                print(f"\n[!!] COULD NOT DEAUTHORIZE {dev.name}: {exc}")
                print(f"[!!] The device may still be live. Unplug it now, or "
                      f"run as root:")
                print(f"[!!]   echo 0 > {dev.syspath}/authorized\n")
            print(f"[-] REJECTED — {report.one_liner(dev, findings)}\n")

    @staticmethod
    def _agent_title(dev: sysfs.UsbDevice) -> str:
        claims = ", ".join(dev.claims) if dev.claims else "unknown type"
        return f"New USB device: {claims}"

    @staticmethod
    def _agent_body(dev: sysfs.UsbDevice, findings) -> str:
        """
        A few lines, not a report. A notification that has to be scrolled will
        not be read, and an unread warning is worse than none: it trains the
        habit of clicking through.
        """
        lines = [dev.label()]
        if getattr(dev, "serial", None):
            lines.append(f"serial {dev.serial}")
        for finding in list(findings)[:2]:
            lines.append(f"{finding.severity.label}: {finding.title}")
        extra = len(list(findings)) - 2
        if extra > 0:
            lines.append(f"…and {extra} more finding(s)")
        return "\n".join(lines)

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

    def _hold_until_unlocked(self, dev: sysfs.UsbDevice) -> None:
        """Keep a device blocked and remember to ask about it later."""
        if self.lock_policy == session_mod.POLICY_QUEUE:
            # Instance recorded alongside the path: the entry is about THIS
            # device, not about whatever later occupies this port.
            self.pending[dev.name] = (dev.syspath, dev.instance_id)
            print(f"[⏸] SCREEN LOCKED — holding {report.one_liner(dev)}")
            print("    It stays blocked. You will be asked when you unlock.\n")
            reason = "held: screen locked"
        else:
            print(f"[-] SCREEN LOCKED — denied {report.one_liner(dev)}\n")
            reason = "denied: screen locked"
        try:
            sysfs.set_authorized(dev.syspath, 0)
        except OSError:
            pass
        self._record(Decision(dev, False, reason, time.time()))

    def _drain_pending(self) -> None:
        """
        Someone unlocked the screen: put the held questions now.

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
        print(f"\n[▶] Screen unlocked — {len(self.pending)} device(s) were "
              f"held while you were away.\n")
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
                      f"than the one held while you were away.")
                print(f"    It stays blocked and is not being asked about "
                      f"under the old entry. Replug it to have it gated "
                      f"normally.\n")
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
            sysfs.set_authorized(dev.syspath, 1)
        except OSError as exc:
            print(f"  (could not switch it on to look: {exc})")
            return None

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
            devices = []
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline and not devices:
                devices = storage.find_block_devices(dev.syspath)
                if not devices:
                    time.sleep(0.02)
            if devices:
                medium = storage.inspect_safely(
                    devices[0], open_fn=sysfs.open_block_device)
            else:
                medium = storage.MediumReport(error="no block device appeared")
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
                          f"inspection: {exc}\n"
                          f"[!!] It is still switched on. Unplug it now; do "
                          f"not rely on the prompt below.\n")
                    if medium is None:
                        medium = storage.MediumReport(
                            device=str(dev.syspath),
                            error=f"device left authorized: {exc}")
                    else:
                        medium.error = (f"{medium.error + '; ' if medium.error else ''}"
                                        f"device left authorized: {exc}")
        return medium

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
                db = deferred_bind.DeferredBind(dev.syspath, log=print)
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
            authorize_fn=lambda: sysfs.set_authorized(dev.syspath, 1),
            duration=self.observe,
            capture=self.capture_payload,
            deauthorize_fn=lambda: sysfs.set_authorized(dev.syspath, 0),
        )

    def _on_remove(self, sys_path: str) -> None:
        name = Path(sys_path).name
        if name in self.pending:
            del self.pending[name]
            print(f"[*] {name} removed while held; question withdrawn")
        self.known.discard(name)
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

        # ---- ask through the desktop agent, if one is listening -----------
        # A CRITICAL device is never offered to the agent as a question. Two
        # clicks are too cheap for something matching an attack pattern, and a
        # person clicking a popup is not in the same state of attention as one
        # typing a word. The agent is told to warn instead, and the decision
        # stays in the terminal.
        if self.agent is not None and self.agent.connected:
            if critical:
                self.agent.notify_critical(
                    f"Dangerous USB device blocked",
                    report.one_liner(dev, findings))
                print("  (a warning was sent to your desktop; this device "
                      "cannot be approved from a notification)")
            else:
                answer = self.agent.ask(
                    title=self._agent_title(dev),
                    body=self._agent_body(dev, findings),
                    severity=rules.worst(findings).label if findings else "none",
                    allow_always=self.trust is not None,
                    timeout=self.timeout if self.timeout else 60.0)
                if answer == agentlink.ANSWER_ALWAYS:
                    self._remember = True
                    return True
                if answer == agentlink.ANSWER_YES:
                    return True
                if answer == agentlink.ANSWER_NO:
                    return False
                # answer is None: the agent could not answer at all. That is not
                # a decision, so it must not be treated as one -- fall through
                # to the terminal rather than silently refusing something the
                # user never saw.
                print("  (no answer from the desktop agent; asking here)")

        if critical:
            # No "always" option here on purpose. Remembering a device that
            # matches an attack pattern is not a choice worth offering in one
            # keystroke; if it really is a false positive, the user can trust
            # it deliberately with --trust after understanding why it fired.
            prompt = ("  This device matches an attack pattern.\n"
                      "  Type the word 'authorize' to allow it, anything else "
                      "to reject: ")
        elif self.trust is not None:
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
                       if self.trust is not None else "[y/N]")
            prompt = (f"  Authorize this device? {choices} "
                      f"({self.timeout:.0f}s, default N) ")
        # The timeout applies to critical prompts too. It expires into DENIAL,
        # which is the safe direction, and it stops one suspicious device from
        # blocking the event loop indefinitely.

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

        answer = answer.strip().lower()
        if critical:
            return answer == "authorize"
        if answer in ("a", "always") and self.trust is not None:
            self._remember = True
            return True
        return answer in ("y", "yes")

    def _record(self, decision: Decision, findings=()) -> None:
        """
        Persist one decision: to the ledger, then to the JSON audit log.

        (The docstring used to sit BELOW the ledger block, where Python treats
        it as a discarded string expression rather than documentation -- so the
        method had none, and `help()` showed nothing for the one function that
        writes both persistent stores.)
        """
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
          close_race_window: bool = False) -> None:
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
            print(f"    start the agent in your session with: "
                  f"python -m probolos.agent")
        else:
            link = None

    monitor = session_mod.detect(force_locked)
    if lock_policy != session_mod.POLICY_IGNORE:
        print(f"  - screen-lock policy: {lock_policy} "
              f"via {monitor.describe}")

    trust_store = None
    if trust_path is not None:
        trust_store = trust_mod.TrustStore(trust_path)
        if trust_store.load_error:
            print(f"[!] trust store unreadable ({trust_store.load_error}); "
                  f"nothing will be treated as trusted")
        elif trust_store.devices:
            print(f"  - {len(trust_store.devices)} remembered device(s) will "
                  f"be admitted without asking")

    store = None
    if ledger_path is not None:
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
    import os as _os
    if _os.path.lexists(policy.panic_file) and not dry_run:
        raise SystemExit(
            f"A panic file already exists at {policy.panic_file}.\n"
            f"It would force the gate open immediately. Remove it first:\n"
            f"    rm {policy.panic_file}")

    if close_race_window and not dry_run:
        from . import deferred_bind
        if deferred_bind.supported():
            print("  - experimental deferred binding enabled; "
                  "the input grab race still exists")
        else:
            print(f"[!] --close-race-window is not available here: "
                  f"{deferred_bind.unsupported_reason()}")
            print("    Devices will be observed with the exposure window open; "
                  "it is measured and printed per device.")

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
