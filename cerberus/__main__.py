"""
Command line entry point.

    sudo python -m cerberus                 # run the gate
    sudo python -m cerberus --dry-run       # observe only, gate stays open
    python -m cerberus --list               # what is attached right now
    sudo python -m cerberus --release       # free devices stranded by a crash
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import (daemon, gate, ledger as ledger_mod, report, rules, safety,
               session as session_mod, sysfs, trust as trust_mod, usbclass)

BANNER = r"""
   ___         _
  / __|___ _ _| |__  ___ _ _ _  _ ___
 | (__/ -_) '_| '_ \/ -_) '_| || (_-<
  \___\___|_| |_.__/\___|_|  \_,_/__/   identity · consistency · behaviour
"""


def require_root() -> None:
    if os.geteuid() != 0:
        sys.exit("This needs root: writing to /sys/bus/usb/.../authorized "
                 "is a privileged operation.\nTry: sudo python -m cerberus")


def require_usb() -> None:
    if not sysfs.usb_subsystem_available():
        sys.exit(f"{sysfs.USB_DEVICES} does not exist — no USB subsystem here "
                 "(container? kernel without USB support?)")


def cmd_list(verbose: bool = False) -> None:
    """Inventory of attached devices. Read-only, no privileges needed."""
    require_usb()
    devices = [d for d in sysfs.list_devices() if not d.is_root_hub]
    if not devices:
        print("No USB devices attached.")
        return
    print(f"{len(devices)} USB device(s) attached:\n")
    for dev in devices:
        state = {1: "authorized", 0: "BLOCKED"}.get(dev.authorized, "unknown")
        findings = rules.evaluate(dev)
        print(f"  [{state:>10}] {report.one_liner(dev, findings)}")
        if not verbose:
            continue
        # The per-interface breakdown is the raw material for stage 2 rules.
        # Rules invented without looking at real hardware produce false
        # positives on ordinary devices, which trains users to ignore alarms.
        print(f"               manufacturer : {dev.manufacturer or '-'}")
        print(f"               product      : {dev.product or '-'}")
        print(f"               serial       : {dev.serial or '-'}")
        print(f"               speed        : {dev.speed or '?'} Mbps")
        print(f"               kinds        : {', '.join(dev.kinds)}")
        ds = dev.descriptor_set
        if ds and ds.configs:
            c = ds.configs[0]
            src = "self-powered" if c.self_powered else "bus-powered"
            print(f"               declares     : {c.max_power_ma} mA "
                  f"({src}, raw {c.max_power_raw} × {c.power_unit_ma} mA)")
        if dev.parse_error:
            print(f"               PARSE ERROR  : {dev.parse_error}")
        for iface in dev.interfaces:
            desc = usbclass.describe_interface(iface.interface_class,
                                               iface.interface_subclass,
                                               iface.interface_protocol)
            print(f"               iface {iface.number}      : "
                  f"class 0x{iface.interface_class:02x} "
                  f"sub 0x{iface.interface_subclass:02x} "
                  f"proto 0x{iface.interface_protocol:02x}  → {desc}")
        for f in findings:
            print(f"               {f.severity.label:<8} : {f.title}")
        print()


def cmd_release() -> None:
    """
    Recovery path. If Cerberus was SIGKILLed while the gate was closed, devices
    plugged in afterwards are sitting dead. This authorizes them in one go.

    It exists because a security tool that can brick your peripherals owes you
    an obvious way out.
    """
    require_root()
    stranded = gate.unauthorized_devices()
    if not stranded:
        print("Nothing stranded — no blocked devices found.")
        return
    for dev in stranded:
        try:
            sysfs.set_authorized(dev.syspath, 1)
            print(f"  released: {report.one_liner(dev)}")
        except OSError as exc:
            print(f"  failed {dev.name}: {exc}")

    for hub in sysfs.list_root_hubs():
        current = sysfs.get_authorized_default(hub)
        if current == 0:
            sysfs.set_authorized_default(hub, 1)
            print(f"  {hub.name}: authorized_default reset to 1")


def cmd_trusted(path) -> None:
    """Show what this machine currently lets in without asking."""
    store = trust_mod.TrustStore(path)
    if store.load_error:
        sys.exit(f"trust store unreadable: {store.load_error}")
    if not store.devices:
        print("No remembered devices. Every device will be asked about.")
        return
    import datetime
    print(f"{len(store.devices)} remembered device(s):\n")
    for entry in store.devices.values():
        when = datetime.datetime.fromtimestamp(entry.trusted_at)
        print(f"  {entry.label}")
        print(f"    identity   : {entry.identity}")
        print(f"    descriptors: {entry.descriptor_hash[:16]}…")
        print(f"    trusted    : {when:%Y-%m-%d %H:%M}, admitted "
              f"{entry.times_admitted} time(s)")
        print(f"    ports      : {', '.join(entry.ports) or '-'}")
        print()


def cmd_forget(path, pattern: str) -> None:
    store = trust_mod.TrustStore(path)
    if pattern.lower() == "all":
        count = store.clear()
        print(f"Forgot {count} device(s).")
    else:
        removed = store.forget(pattern)
        if not removed:
            print(f"Nothing matched {pattern!r}.")
            return
        for identity in removed:
            print(f"  forgot {identity}")
    error = store.save()
    if error:
        sys.exit(f"could not write trust store: {error}")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        prog="cerberus",
        description="Hold new USB devices unauthorized until a human decides.")
    parser.add_argument("--list", action="store_true",
                        help="show attached devices and exit")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="with --list: full per-interface breakdown")
    parser.add_argument("--release", action="store_true",
                        help="authorize all blocked devices and reopen the gate")
    parser.add_argument("--dry-run", action="store_true",
                        help="report devices without ever blocking or authorizing")
    parser.add_argument("--timeout", type=float, default=0.0, metavar="SEC",
                        help="auto-deny after SEC seconds of no answer (0 = wait)")
    parser.add_argument("--log", type=Path, metavar="FILE",
                        help="append decisions as JSON lines to FILE")
    parser.add_argument("--rules", type=Path, metavar="FILE",
                        help="YAML file tuning rule severities (optional)")
    parser.add_argument("--observe", type=float, default=3.0, metavar="SEC",
                        help="seconds of behavioural quarantine for input "
                             "devices (0 disables stage 3)")
    parser.add_argument("--capture-payload", action="store_true",
                        help="reconstruct what a quarantined device typed. "
                             "OFF by default: this records key content, and "
                             "only ever from devices never authorized")
    parser.add_argument("--ledger", type=Path, metavar="FILE",
                        default=None,
                        help="device history file for drift detection "
                             "(default: XDG state dir, or /var/lib/cerberus "
                             "as root)")
    parser.add_argument("--no-ledger", action="store_true",
                        help="keep no history between runs")
    parser.add_argument("--allow-port", action="append", default=[],
                        metavar="PORT",
                        help="port that is never gated, e.g. 1-4 (repeatable). "
                             "Keep a rescue keyboard in one")
    parser.add_argument("--gate-fixed-ports", action="store_true",
                        help="also gate internal, non-removable ports. "
                             "This can lock you out of a laptop keyboard")
    parser.add_argument("--watchdog", type=float, default=60.0, metavar="SEC",
                        help="reopen the gate if the daemon stops making "
                             "progress for SEC seconds (0 disables)")
    parser.add_argument("--panic-file", type=Path,
                        default=safety.DEFAULT_PANIC_FILE,
                        help="create this file from another terminal to force "
                             "the gate open")
    parser.add_argument("--trusted", action="store_true",
                        help="list remembered devices and exit")
    parser.add_argument("--forget", metavar="PATTERN",
                        help="remove remembered devices matching PATTERN "
                             "(use 'all' to clear the store)")
    parser.add_argument("--no-trust", action="store_true",
                        help="ask about every device, ignore what is remembered")
    parser.add_argument("--trust-file", type=Path, metavar="FILE",
                        help="where remembered devices are stored")
    parser.add_argument("--no-storage-scan", action="store_true",
                        help="skip reading the partition table of storage "
                             "devices (stage 4)")
    parser.add_argument("--lock-policy", default=session_mod.POLICY_QUEUE,
                        choices=[session_mod.POLICY_QUEUE,
                                 session_mod.POLICY_DENY,
                                 session_mod.POLICY_IGNORE],
                        help="what to do when a device arrives while the "
                             "screen is locked: hold it and ask on unlock "
                             "(default), deny outright, or take no notice")
    parser.add_argument("--force-locked", action="store_true",
                        help="pretend the screen is locked (to test the policy)")
    parser.add_argument("--force-unlocked", action="store_true",
                        help="pretend the screen is unlocked")
    parser.add_argument("--privsep", action="store_true",
                        help="run with privilege separation: a small root gate "
                             "and an unprivileged analyzer. Recommended")
    parser.add_argument("--privsep-user", default="nobody", metavar="USER",
                        help="user the analyzer drops to under --privsep")
    args = parser.parse_args(argv)

    require_usb()

    trust_path = args.trust_file or trust_mod.default_path()

    if args.trusted:
        cmd_trusted(trust_path)
        return
    if args.forget:
        cmd_forget(trust_path, args.forget)
        return
    if args.release:
        cmd_release()
        return

    print(BANNER)
    if not args.dry_run:
        require_root()
        print("[!] The gate will close: NEW USB devices will not work until")
        print("[!] you approve them here. Keep a second way in (SSH, or your")
        print("[!] built-in keyboard) while testing.\n")

    forced_lock = None
    if args.force_locked:
        forced_lock = True
    elif args.force_unlocked:
        forced_lock = False

    rule_config = None
    if args.rules:
        try:
            rule_config = rules.load_config(args.rules)
        except (RuntimeError, ValueError, OSError) as exc:
            sys.exit(f"rule config: {exc}")

    policy = safety.SafetyPolicy(
        allowed_ports=args.allow_port,
        protect_fixed_ports=not args.gate_fixed_ports,
        panic_file=args.panic_file,
    )
    if args.gate_fixed_ports:
        print("[!] --gate-fixed-ports: internal devices WILL be blocked.")
        print("[!] If this machine's keyboard is internal USB, make sure you")
        print("[!] have SSH access before continuing.\n")

    ledger_path = (None if args.no_ledger
                   else (args.ledger or ledger_mod.default_path()))

    def _serve():
        daemon.serve(dry_run=args.dry_run, timeout=args.timeout,
                     json_log=args.log, rule_config=rule_config,
                     observe=args.observe,
                     policy=policy,
                     ledger_path=ledger_path,
                     capture_payload=args.capture_payload,
                     watchdog_timeout=args.watchdog,
                     trust_path=None if args.no_trust else trust_path,
                     inspect_storage=not args.no_storage_scan,
                     lock_policy=args.lock_policy,
                     force_locked=forced_lock)

    if args.privsep:
        from . import privsep
        from .gate_client import GateBackend

        def analyzer_main(gate_client):
            # Runs in the UNPRIVILEGED child. Every privileged sysfs write from
            # here on is routed to the root gate over the socket.
            sysfs.install_backend(GateBackend(gate_client))
            _serve()
            return 0

        try:
            rc = privsep.start(analyzer_main, drop_to=args.privsep_user,
                               state_paths=[p for p in (ledger_path, trust_path)
                                            if p])
        except privsep.PrivsepError as exc:
            sys.exit(f"privsep: {exc}")
        sys.exit(rc)
    else:
        _serve()


if __name__ == "__main__":
    main()
