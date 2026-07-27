#!/usr/bin/env python3
"""
The offline interrogation study.

Purpose: find out, with data, whether USB stacks are distinguishable at the
control-transfer layer -- BEFORE building a detector on the assumption that
they are. If twenty ordinary devices and three microcontroller boards produce
overlapping distributions, that is a week well spent and a year saved.

    sudo python interrogation_study.py --list
    sudo python interrogation_study.py --bus 3 --device 4 --label "logitech-k120"
    sudo python interrogation_study.py --all --out study.csv

WHAT TO COLLECT
---------------
As many devices as you can borrow, each labelled honestly:

    real keyboards      several vendors, cheap and expensive
    real mice           the same
    flash drives        several controller vendors
    microcontrollers    Pico/TinyUSB, Arduino, Digispark, ESP32-S2
    known attack tools  Rubber Ducky, O.MG cable, if you have access

The interesting comparison is not attack-tool versus keyboard. It is
GENERAL-PURPOSE MICROCONTROLLER versus CONSUMER PERIPHERAL, because that is the
distinction an attacker cannot easily erase: a Ducky is a microcontroller
whatever its descriptors say.

BEFORE YOU RUN THIS
-------------------
Probing wakes devices up. Some probes deliberately send requests outside normal
enumeration, and a sophisticated implant could use exactly that as a trigger.
Run the study on devices you are willing to have react.

The kernel driver is detached for the duration and reattached afterwards. On a
keyboard you are actively using, that means it stops working for a few seconds.
Do not study your only keyboard.
"""

import argparse
import csv
import json
import sys
from pathlib import Path

try:
    import usb.core
    import usb.util
except ImportError:
    sys.exit("pyusb is required: sudo pacman -S python-pyusb")

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cerberus import interrogate  # noqa: E402


def describe(dev) -> str:
    def safe(getter):
        try:
            return getter() or "-"
        except Exception:
            return "-"
    manufacturer = safe(lambda: usb.util.get_string(dev, dev.iManufacturer))
    product = safe(lambda: usb.util.get_string(dev, dev.iProduct))
    return (f"{dev.idVendor:04x}:{dev.idProduct:04x} bus {dev.bus} "
            f"dev {dev.address}  {manufacturer} {product}")


def cmd_list() -> None:
    for dev in usb.core.find(find_all=True):
        print(" ", describe(dev))


def study_one(dev, label: str, intrusive: bool) -> dict:
    detached = []
    # A bound kernel driver owns the interface; control transfers on the
    # default endpoint would fight it. Detaching is reversible and is undone in
    # the finally block whatever happens.
    for cfg in dev:
        for intf in cfg:
            try:
                if dev.is_kernel_driver_active(intf.bInterfaceNumber):
                    dev.detach_kernel_driver(intf.bInterfaceNumber)
                    detached.append(intf.bInterfaceNumber)
            except Exception:
                pass

    try:
        results = interrogate.interrogate(dev, include_intrusive=intrusive)
    finally:
        for number in detached:
            try:
                dev.attach_kernel_driver(number)
            except Exception:
                print(f"  ! could not reattach driver on interface {number}",
                      file=sys.stderr)

    row = {
        "label": label,
        "vendor_id": f"{dev.idVendor:04x}",
        "product_id": f"{dev.idProduct:04x}",
        "bus": dev.bus,
        "address": dev.address,
        "speed": getattr(dev, "speed", ""),
        "bDeviceClass": dev.bDeviceClass,
    }
    row.update(interrogate.summarize(results))
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--list", action="store_true",
                        help="list attached devices and exit")
    parser.add_argument("--bus", type=int)
    parser.add_argument("--device", type=int, help="device address")
    parser.add_argument("--all", action="store_true",
                        help="study every attached device")
    parser.add_argument("--label", default="",
                        help="what this device really is, e.g. 'pico-tinyusb'")
    parser.add_argument("--out", type=Path, default=Path("study.csv"))
    parser.add_argument("--json", type=Path,
                        help="also write the full result objects here")
    parser.add_argument("--gentle", action="store_true",
                        help="skip the intrusive probes")
    args = parser.parse_args()

    if args.list:
        cmd_list()
        return

    if args.all:
        targets = list(usb.core.find(find_all=True))
    elif args.bus is not None and args.device is not None:
        found = usb.core.find(bus=args.bus, address=args.device)
        targets = [found] if found else []
    else:
        parser.error("choose --list, --all, or both --bus and --device")

    if not targets:
        sys.exit("no matching device")

    rows = []
    for dev in targets:
        label = args.label or f"unlabelled-{dev.idVendor:04x}{dev.idProduct:04x}"
        print(f"[*] {describe(dev)}")
        try:
            rows.append(study_one(dev, label, intrusive=not args.gentle))
        except Exception as exc:
            print(f"  ! failed: {exc}", file=sys.stderr)

    if not rows:
        sys.exit("nothing collected")

    header = ["label", "vendor_id", "product_id", "bus", "address", "speed",
              "bDeviceClass"] + interrogate.fieldnames()
    exists = args.out.exists()
    with open(args.out, "a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=header, extrasaction="ignore")
        if not exists:
            writer.writeheader()
        writer.writerows(rows)
    print(f"[+] appended {len(rows)} row(s) to {args.out}")

    if args.json:
        args.json.write_text(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
