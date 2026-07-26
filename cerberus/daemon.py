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
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Set

try:
    import pyudev
except ImportError:  # pragma: no cover - import guard for offline linting
    pyudev = None

from . import gate, report, rules, sysfs


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
                 rule_config: Optional[rules.RuleConfig] = None):
        self.dry_run = dry_run
        self.timeout = timeout          # 0 == wait forever
        self.json_log = json_log
        self.rule_config = rule_config
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

        findings = rules.evaluate(dev, self.rule_config)

        print()
        print(report.render(dev, findings))
        print()

        if self.dry_run:
            print("[dry-run] no authorization change made\n")
            self._record(Decision(dev, False, "dry-run", time.time()), findings)
            return

        approved = self._ask(dev, findings)
        if approved:
            try:
                sysfs.set_authorized(dev.syspath, 1)
                print(f"[+] AUTHORIZED — {report.one_liner(dev, findings)}\n")
                self._record(Decision(dev, True, "user approved", time.time()),
                             findings)
            except OSError as exc:
                print(f"[!] failed to authorize: {exc}\n")
        else:
            # It is already unauthorized; we simply leave it that way. Writing
            # 0 again is harmless and makes the state explicit in the logs.
            try:
                sysfs.set_authorized(dev.syspath, 0)
            except OSError:
                pass
            print(f"[-] REJECTED — {report.one_liner(dev, findings)}\n")
            self._record(Decision(dev, False, "user rejected", time.time()),
                         findings)

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
          rule_config: Optional[rules.RuleConfig] = None) -> None:
    """Wire the gate and the loop together."""
    engine = Cerberus(dry_run=dry_run, timeout=timeout, json_log=json_log,
                      rule_config=rule_config)

    print("[*] Closing the USB authorization gate:")
    with gate.AuthorizationGate(dry_run=dry_run) as _g:
        engine.snapshot()
        try:
            engine.run()
        except KeyboardInterrupt:
            print("\n[*] Interrupted.")
        finally:
            print("[*] Reopening the gate:")
