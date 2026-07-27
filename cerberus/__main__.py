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

from . import daemon, gate, ledger as ledger_mod, report, rules, safety, sysfs, usbclass

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
    args = parser.parse_args(argv)

    require_usb()

    if args.list:
        cmd_list(verbose=args.verbose)
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

    daemon.serve(dry_run=args.dry_run, timeout=args.timeout,
                 json_log=args.log, rule_config=rule_config,
                 observe=args.observe,
                 policy=policy,
                 ledger_path=None if args.no_ledger
                             else (args.ledger or ledger_mod.default_path()),
                 capture_payload=args.capture_payload,
                 watchdog_timeout=args.watchdog)


if __name__ == "__main__":
    main()
