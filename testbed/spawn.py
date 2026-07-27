#!/usr/bin/env python3
"""
Spawn emulated USB devices for testing Cerberus, with no hardware.

Requires dummy_hcd and raw_gadget loaded, and root:

    sudo modprobe dummy_hcd raw_gadget
    sudo python -m testbed.spawn --list
    sudo python -m testbed.spawn badusb
    sudo python -m testbed.spawn flashdrive

Run Cerberus in another terminal first:

    sudo python -m cerberus --dry-run          # watch it appear, block nothing
    sudo python -m cerberus                     # the real gate

WHY --dry-run ON THE CERBERUS SIDE
----------------------------------
The emulated device lives only as long as this process holds the gadget open.
If Cerberus blocks it (authorized=0) and waits for you to answer, the device is
frozen mid-enumeration and this side may stall. For a first look, run Cerberus
with --dry-run so it reports and releases; switch to the real gate once you
have seen the report you expect.

Each preset also PRINTS the blob it will present and runs it through the parser
locally, so if a device does not enumerate you can still see what it would have
said -- separating "the gadget failed" from "the parser disagreed".
"""

import argparse
import sys
import time

from cerberus import descriptors, rules, usbclass
from testbed.emulate import EmulatedDevice, Interface, Responder
from testbed.rawgadget import RawGadget, RawGadgetError


def flashdrive() -> EmulatedDevice:
    """An honest mass-storage device. Should produce no findings."""
    return EmulatedDevice(
        vendor_id=0x0781, product_id=0x5567,
        manufacturer="SanDisk", product="Cruzer Blade", serial="TB-STICK-1",
        max_power_ma=200,
        interfaces=[Interface(0x08, 0x06, 0x50)])


def badusb() -> EmulatedDevice:
    """
    The signature attack: storage that is also a boot keyboard.

    This is the device you cannot easily test without hardware, and the whole
    reason the testbed exists. Cerberus should raise storage-with-keyboard at
    CRITICAL.
    """
    return EmulatedDevice(
        vendor_id=0x0781, product_id=0x5567,
        manufacturer="SanDisk", product="Cruzer Blade", serial="TB-STICK-1",
        max_power_ma=200,
        interfaces=[Interface(0x08, 0x06, 0x50),
                    Interface(0x03, 0x01, 0x01)])


def keyboard() -> EmulatedDevice:
    """A plain boot keyboard. Silent except possibly the high-speed notice."""
    return EmulatedDevice(
        vendor_id=0x046d, product_id=0xc31c,
        manufacturer="Logitech", product="USB Keyboard", serial="TB-KBD-1",
        bcd_usb=0x0110, max_power_ma=100,
        interfaces=[Interface(0x03, 0x01, 0x01)])


def overpowered() -> EmulatedDevice:
    """Declares more current than USB 2.0 permits: power-exceeds-bus-limit."""
    return EmulatedDevice(
        manufacturer="Generic", product="Hungry Device", serial="TB-PWR-1",
        max_power_ma=800,
        interfaces=[Interface(0x03, 0x01, 0x01)])


def drift_innocent() -> EmulatedDevice:
    """Phase 1 of a drift demo: an innocent stick."""
    return EmulatedDevice(
        vendor_id=0x0781, product_id=0x5567,
        manufacturer="SanDisk", product="Cruzer Blade", serial="TB-DRIFT-1",
        max_power_ma=200,
        interfaces=[Interface(0x08, 0x06, 0x50)])


def drift_weaponized() -> EmulatedDevice:
    """
    Phase 2: SAME identity, new keyboard interface.

    Present drift_innocent first (and approve it), then this. The ledger keys
    on vendor:product:serial, all identical here, so the changed descriptor
    hash must trigger descriptor-drift at CRITICAL.
    """
    return EmulatedDevice(
        vendor_id=0x0781, product_id=0x5567,
        manufacturer="SanDisk", product="Cruzer Blade", serial="TB-DRIFT-1",
        max_power_ma=200,
        interfaces=[Interface(0x08, 0x06, 0x50),
                    Interface(0x03, 0x01, 0x01)])


PRESETS = {
    "flashdrive": flashdrive,
    "badusb": badusb,
    "keyboard": keyboard,
    "overpowered": overpowered,
    "drift-innocent": drift_innocent,
    "drift-weaponized": drift_weaponized,
}


def preview(dev: EmulatedDevice) -> None:
    """Parse the device locally and print what Cerberus should conclude."""
    blob = dev.full_descriptors_blob()
    parsed = descriptors.parse(blob)
    claims = [usbclass.describe_interface(i.interface_class,
                                          i.interface_subclass,
                                          i.interface_protocol)
              for i in parsed.primary_interfaces()]
    print(f"  identity : {dev.vendor_id:04x}:{dev.product_id:04x} "
          f"'{dev.manufacturer} {dev.product}' serial {dev.serial}")
    print(f"  claims   : {', '.join(claims) or 'none'}")

    class _Shim:
        descriptor_set = parsed
        manufacturer = dev.manufacturer
        product = dev.product
        speed = "480"
        parse_error = None
        vendor_id = f"{dev.vendor_id:04x}"
        product_id = f"{dev.product_id:04x}"
        interfaces = parsed.primary_interfaces()
        interface_classes = parsed.interface_classes()
        def label(self):
            return f"{dev.manufacturer} {dev.product}"

    findings = rules.evaluate(_Shim())
    if findings:
        print(f"  parser predicts: {rules.worst(findings).label}")
        for f in findings:
            print(f"     [{f.severity.label}] {f.title}")
    else:
        print("  parser predicts: no findings")


def spawn(dev: EmulatedDevice, hold: float, wait: bool = False) -> None:
    if wait:
        print("[*] Presenting emulated device — will stay until you press "
              "Enter here")
    else:
        print(f"[*] Presenting emulated device for {hold:.0f}s "
              f"(Ctrl-C to remove early)")
    try:
        with RawGadget(driver="dummy_udc", device="dummy_udc.0") as g:
            responder = Responder(g, dev)
            ok = responder.serve()
            if not ok:
                print("[!] device did not reach 'configured'. It may still "
                      "have enumerated far enough for Cerberus to see it.")
            else:
                print("[+] device is live and visible to the kernel")
            # Hold it plugged in so the other terminal can inspect it AND so
            # the user has time to answer the prompt. With --wait this blocks
            # on input; a short default hold was the reason authorize() timed
            # out mid-decision in early tests.
            if wait:
                try:
                    input("    (press Enter to remove the device) ")
                except (EOFError, KeyboardInterrupt):
                    pass
            else:
                deadline = time.monotonic() + hold
                while time.monotonic() < deadline:
                    time.sleep(0.2)
    except RawGadgetError as exc:
        sys.exit(f"[!] raw-gadget error: {exc}\n"
                 f"    Are dummy_hcd and raw_gadget loaded? Are you root?")
    except KeyboardInterrupt:
        print("\n[*] removing device")
    print("[*] device removed (gadget released)")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("preset", nargs="?", choices=sorted(PRESETS),
                        help="which device to emulate")
    parser.add_argument("--list", action="store_true",
                        help="show presets and what each should trigger")
    parser.add_argument("--preview", action="store_true",
                        help="parse locally and print the prediction, do not "
                             "actually spawn (no root needed)")
    parser.add_argument("--hold", type=float, default=20.0,
                        help="seconds to keep the device plugged in")
    parser.add_argument("--wait", action="store_true",
                        help="keep the device present until Enter is pressed, "
                             "so you have time to read the report and answer "
                             "the prompt in the other terminal")
    args = parser.parse_args()

    if args.list or not args.preset:
        print("Presets:")
        for name, fn in sorted(PRESETS.items()):
            print(f"  {name:18} {fn.__doc__.strip().splitlines()[0]}")
        return

    dev = PRESETS[args.preset]()
    print(f"[*] preset: {args.preset}")
    preview(dev)

    if args.preview:
        return
    spawn(dev, args.hold, wait=args.wait)


if __name__ == "__main__":
    main()
