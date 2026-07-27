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
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Set

try:
    import pyudev
except ImportError:  # pragma: no cover - import guard for offline linting
    pyudev = None

from . import (analyzers, gate, ledger as ledger_mod, quarantine,
               report, rules, safety, sysfs, usbclass)


@dataclass
class Decision:
    device: sysfs.UsbDevice
    authorized: bool
    reason: str
    timestamp: float


class Cerberus:
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
                 stop_event=None):
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
        for dev in sysfs.list_devices():
            self.known.add(dev.name)
        print(f"[*] Baseline: {len(self.known)} USB device(s) already attached, "
              f"all left untouched")

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
            device = monitor.poll(timeout=1.0)
            if device is None:
                continue
            if device.action == "add":
                self._on_add(device.sys_path)
            elif device.action == "remove":
                self._on_remove(device.sys_path)

    def _on_add(self, sys_path: str) -> None:
        path = Path(sys_path)
        name = path.name

        if name in self.known:
            return  # a device we deliberately ignore

        dev = self._load_with_retry(path)
        if dev is None:
            print(f"[!] {name}: vanished before it could be read")
            return
        if dev.is_root_hub:
            return

        # SAFETY BEFORE SECURITY. A device on an internal port or on the
        # operator's allowlist is admitted without a question, because the cost
        # of being wrong here is somebody with no keyboard and no way to answer
        # the prompt that would give them one.
        protection = self.policy.is_protected(dev)
        if protection and not self.dry_run:
            try:
                sysfs.set_authorized(dev.syspath, 1)
            except OSError as exc:
                print(f"[!] could not authorize protected device: {exc}")
            print(f"[=] ADMITTED WITHOUT PROMPT ({protection}) — "
                  f"{report.one_liner(dev)}\n")
            self._record(Decision(dev, True, f"protected: {protection}",
                                  time.time()))
            return

        findings = analyzers.run(analyzers.Context(
            device=dev, ledger=self.ledger, config=self.rule_config))

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
        # on early. Storage and everything else stay blocked until approved.
        quarantined = False
        if self.observe > 0 and usbclass.KIND_INPUT in dev.kinds:
            obs = self._quarantine(dev)
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
            quarantined = obs.observed

        if self.watchdog:
            with self.watchdog.paused():
                approved = self._ask(dev, findings)
        else:
            approved = self._ask(dev, findings)
        if approved:
            # The user's decision is a fact the moment it is made, so it is
            # recorded BEFORE the sysfs write. This matters for the ledger:
            # if the device is yanked between the prompt and the write (a
            # short-lived test gadget, or a real device pulled at the wrong
            # moment), the authorization fails -- but the history of "this
            # identity was seen and approved" must survive regardless, or drift
            # detection silently forgets devices that were briefly present.
            self._record(Decision(dev, True, "user approved", time.time()),
                         findings)
            try:
                if quarantined:
                    # Already authorized for the observation; nothing to do but
                    # let it go, which happened when the grab was released.
                    print(f"[+] AUTHORIZED — {report.one_liner(dev, findings)}\n")
                    return
                sysfs.set_authorized(dev.syspath, 1)
                print(f"[+] AUTHORIZED — {report.one_liner(dev, findings)}\n")
            except OSError as exc:
                print(f"[!] failed to authorize: {exc}\n")
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

    def _quarantine(self, dev: sysfs.UsbDevice):
        """
        Switch the device on inside a closed room and watch it.

        The instruction to the user is the experiment: if nobody touches the
        device, then anything it sends is something it decided to send.
        """
        print("  This is an input device. Cerberus will switch it on with its")
        print("  input captured, so nothing it sends can reach your session.")
        print(f"  >>> DO NOT TOUCH IT for the next {self.observe:.0f} seconds. <<<")
        print()

        return quarantine.quarantine(
            dev.syspath,
            authorize_fn=lambda: sysfs.set_authorized(dev.syspath, 1),
            duration=self.observe,
            capture=self.capture_payload,
        )

    def _on_remove(self, sys_path: str) -> None:
        name = Path(sys_path).name
        if name not in self.known:
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
        if critical:
            prompt = ("  This device matches an attack pattern.\n"
                      "  Type the word 'authorize' to allow it, anything else "
                      "to reject: ")
        else:
            prompt = "  Authorize this device? [y/N] "
        if self.timeout > 0 and not critical:
            prompt = f"  Authorize this device? [y/N] ({self.timeout:.0f}s, default N) "
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
        return answer in ("y", "yes")

    def _record(self, decision: Decision, findings=()) -> None:
        # In dry-run we change nothing that persists, and the ledger is
        # persistent state. Recording a decision that was never actually made
        # would also poison the history with dry-run noise.
        if self.ledger is not None and not self.dry_run:
            self.ledger.record(decision.device, decision.reason)
            error = self.ledger.save()
            if error:
                print(f"[!] could not write ledger: {error}")
        """Append one JSON line. Audit trail first, pretty output second."""
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
            with open(self.json_log, "a") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError as exc:
            print(f"[!] could not write log: {exc}")


def serve(dry_run: bool = False, timeout: float = 0.0,
          json_log: Optional[Path] = None,
          rule_config: Optional[rules.RuleConfig] = None,
          observe: float = 3.0,
          policy: Optional[safety.SafetyPolicy] = None,
          ledger_path: Optional[Path] = None,
          capture_payload: bool = False,
          watchdog_timeout: float = 0.0) -> None:
    """Wire the gate, the safety net and the loop together."""
    policy = policy or safety.SafetyPolicy()
    store = None
    if ledger_path is not None:
        store = ledger_mod.Ledger(ledger_path)
        if store.load_error:
            print(f"[!] ledger unreadable ({store.load_error}); "
                  f"continuing without history")

    # A panic file left behind by a previous run would fire the watchdog the
    # instant it starts, which looks like a malfunction rather than the
    # deliberate signal it is. Refuse clearly instead.
    if policy.panic_file.exists() and not dry_run:
        raise SystemExit(
            f"A panic file already exists at {policy.panic_file}.\n"
            f"It would force the gate open immediately. Remove it first:\n"
            f"    rm {policy.panic_file}")

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

        engine = Cerberus(dry_run=dry_run, timeout=timeout, json_log=json_log,
                          rule_config=rule_config, observe=observe,
                          policy=policy, ledger=store,
                          capture_payload=capture_payload, watchdog=dog,
                          stop_event=stop_event)
        engine.snapshot()
        try:
            engine.run()
        except KeyboardInterrupt:
            print("\n[*] Interrupted.")
        finally:
            if dog:
                dog.stop()
            print("[*] Reopening the gate:")
