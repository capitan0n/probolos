# Testbed: emulated USB devices, no hardware

Creates USB devices in software with `dummy_hcd` (a virtual USB host
controller) and `raw_gadget` (a userspace gadget interface), and plugs them
into the local kernel. This is how the CRITICAL and drift paths are tested
without a Rubber Ducky.

## Setup

```bash
sudo modprobe -a dummy_hcd raw_gadget
ls /sys/class/udc/          # expect dummy_udc.0
ls -l /dev/raw-gadget       # expect a character device
```

To load both at every boot:

```bash
echo -e "dummy_hcd\nraw_gadget" | sudo tee /etc/modules-load.d/probolos-testbed.conf
```

`dummy_hcd` adds a virtual root hub, so Probolos's startup lists an extra
`usbN`. That is expected.

## Presets

| Preset | Should trigger |
|---|---|
| `flashdrive` | nothing |
| `keyboard` | nothing, or the high-speed notice |
| `badusb` | `storage-with-keyboard` (CRITICAL) |
| `overpowered` | `power-exceeds-bus-limit` (WARNING) |
| `drift-innocent` → `drift-weaponized` | `descriptor-drift` (CRITICAL) |

Preview what Probolos should conclude, without root and without spawning
anything:

```bash
python -m testbed.spawn badusb --preview
```

If the preview predicts CRITICAL but a live run stays silent, the problem is
the enumeration, not the rules.

## The CRITICAL demo

```bash
sudo python -m probolos --dry-run          # terminal 1: report, block nothing
sudo python -m testbed.spawn badusb        # terminal 2
```

Terminal 1 should show `✖ CRITICAL · Storage device that can also type`.

Start with `--dry-run`: a blocked device waiting for an answer is frozen
mid-enumeration, which can stall the gadget. With the real gate
(`sudo python -m probolos`), a CRITICAL device needs the typed word
`authorize` instead of `y`.

## The drift demo

```bash
sudo python -m testbed.spawn drift-innocent      # approve it
sudo python -m testbed.spawn drift-weaponized    # same serial, now with a keyboard
```

The second raises `descriptor-drift` (CRITICAL): the vendor, product and
serial are the same, the descriptors are not.

## The leakage experiment

`hidexp/` builds a real HID keyboard gadget and counts how many keystrokes
reach the session before Probolos captures it. See
[hidexp/EXPERIMENT.md](hidexp/EXPERIMENT.md).

## Troubleshooting

A gadget that will not enumerate, or `RUN failed: Errno 16 Device or resource
busy` (the UDC `dummy_udc.0` is still claimed): reset the modules.

```bash
sudo rmmod raw_gadget dummy_hcd
sudo modprobe -a dummy_hcd raw_gadget
cat /sys/class/udc/dummy_udc.0/state    # want: not attached
```

If `state` still reads `configured` or `addressed`, remove any configfs gadget
in `/sys/kernel/config/usb_gadget/`, or reboot. The spawn tool releases its
gadget on exit, so this is only needed after a hard kill.
