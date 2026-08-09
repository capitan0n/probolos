#!/usr/bin/env python3
"""
Standalone verbose USB inventory.

Run from the project root (the directory containing probolos/ and tests/):

    python usbinv.py

Read-only. No root, no kernel flags touched, nothing blocked. It exists to
collect real-hardware data before stage 2 rules are written, on the principle
that rules invented without looking at real devices produce false positives on
ordinary hardware -- and a tool that cries wolf about your own mouse teaches
you to ignore it.
"""

import sys

try:
    from probolos import sysfs, usbclass
except ImportError:
    sys.exit("Run this from the project root — the folder that contains "
             "the probolos/ package directory.")


def main():
    if not sysfs.usb_subsystem_available():
        sys.exit(f"{sysfs.USB_DEVICES} does not exist — no USB subsystem here.")

    devices = [d for d in sysfs.list_devices() if not d.is_root_hub]
    if not devices:
        print("No USB devices attached.")
        return

    print(f"{len(devices)} USB device(s) attached\n")

    for dev in devices:
        state = {1: "authorized", 0: "BLOCKED"}.get(dev.authorized, "unknown")
        print("=" * 66)
        print(f"{dev.name}   {dev.vendor_id}:{dev.product_id}   [{state}]")
        print(f"  manufacturer : {dev.manufacturer or '-'}")
        print(f"  product      : {dev.product or '-'}")
        print(f"  serial       : {'(present)' if dev.serial else '-'}")
        print(f"  speed        : {dev.speed or '?'} Mbps")
        print(f"  bDeviceClass : 0x{(dev.device_class or 0):02x}")
        print(f"  kinds        : {', '.join(dev.kinds)}")

        if dev.parse_error:
            print(f"  PARSE ERROR  : {dev.parse_error}")

        ifaces = dev.interfaces
        print(f"  interfaces   : {len(ifaces)}")
        for i in ifaces:
            desc = usbclass.describe_interface(i.interface_class,
                                               i.interface_subclass,
                                               i.interface_protocol)
            print(f"     [{i.number}] class 0x{i.interface_class:02x} "
                  f"sub 0x{i.interface_subclass:02x} "
                  f"proto 0x{i.interface_protocol:02x}  -> {desc}")

        if dev.descriptor_set:
            ds = dev.descriptor_set
            print(f"  configs      : {len(ds.configs)} "
                  f"(device declares {ds.device.num_configurations})")
            if ds.declared_interface_mismatch():
                print("  ANOMALY      : declared interface count != actual")
            # Alternate settings are stripped from the analysis; showing the
            # raw total makes it obvious when a device has many of them, so a
            # future rule about "many interfaces" is not written in ignorance.
            raw = sum(len(c.interfaces) for c in ds.configs)
            if raw != len(ifaces):
                print(f"  note         : {raw} raw interface descriptors "
                      f"(incl. alternate settings), {len(ifaces)} logical")
        print()

    # A first look at how a naive stage-2 rule would behave on this machine.
    print("=" * 66)
    print("Naive-rule dry run (what a careless rule engine would flag):\n")
    for dev in devices:
        classes = set(dev.interface_classes())
        flags = []
        if len(classes) > 1:
            flags.append("multiple interface classes")
        if 0x08 in classes and 0x03 in classes:
            flags.append("STORAGE + HID  <-- the real signal")
        if flags:
            print(f"  {dev.name} {dev.vendor_id}:{dev.product_id} "
                  f"'{dev.label()}': {'; '.join(flags)}")
    print("\nEverything listed above under 'multiple interface classes' that")
    print("is ordinary hardware is a false positive we must design away.")


if __name__ == "__main__":
    main()
