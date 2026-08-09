# Testbed — emulated USB devices, no hardware

Uses `dummy_hcd` (a virtual USB host controller) and `raw_gadget` (a userspace
gadget interface) to conjure arbitrary USB devices in software and plug them
into the local kernel. This is how the CRITICAL and drift paths get tested
without a Rubber Ducky.

## Setup

```bash
sudo modprobe dummy_hcd raw_gadget
ls /sys/class/udc/          # expect dummy_udc.0
ls -l /dev/raw-gadget       # expect a character device
```

To load on every boot:

```bash
echo -e "dummy_hcd\nraw_gadget" | sudo tee /etc/modules-load.d/probolos-testbed.conf
```

## Preview without root or hardware

Every preset can be parsed locally, printing what Probolos should conclude,
without spawning anything:

```bash
python -m testbed.spawn badusb --preview
```

This separates "the emulated descriptors are wrong" from "the gadget failed to
enumerate" — if the preview predicts CRITICAL but a live run stays silent, the
problem is enumeration, not the rules.

## The CRITICAL demo

Two terminals.

Terminal 1 — watch, block nothing:

```bash
sudo python -m probolos --dry-run
```

Terminal 2 — present the attack:

```bash
sudo python -m testbed.spawn badusb
```

Terminal 1 should show `!! CRITICAL: Storage device that can also type`.

Start with `--dry-run` on the Probolos side: a blocked device waiting for your
answer is frozen mid-enumeration, which can stall the gadget. Once you have seen
the report, switch to the real gate (`sudo python -m probolos`) and, because the
finding is CRITICAL, the prompt will require you to type the whole word
`authorize` rather than `y`.

## The descriptor-drift demo

The ledger remembers devices across plug-ins. Present an innocent stick, approve
it, then present a weaponized one with the *same* identity:

```bash
sudo python -m testbed.spawn drift-innocent      # approve it
sudo python -m testbed.spawn drift-weaponized    # same serial, new keyboard
```

The second should raise `descriptor-drift` at CRITICAL, because
vendor:product:serial are identical but the descriptor hash changed.

## Presets

| preset | should trigger |
|---|---|
| `flashdrive` | nothing |
| `keyboard` | nothing, or the high-speed notice |
| `badusb` | `storage-with-keyboard` (CRITICAL) |
| `overpowered` | `power-exceeds-bus-limit` (WARNING) |
| `drift-innocent` → `drift-weaponized` | `descriptor-drift` (CRITICAL) |

## If a device will not enumerate

`raw_gadget` is low-level and `dummy_hcd` can wedge if a gadget is left
half-initialised. Reset with:

```bash
sudo rmmod raw_gadget dummy_hcd
sudo modprobe dummy_hcd raw_gadget
```

The spawn tool always releases the gadget on exit, so this is only needed after
a hard kill.

## Troubleshooting: `RUN failed: Errno 16 Device or resource busy`

The UDC `dummy_udc.0` is already claimed — usually by dummy_hcd's own host
side, or by a gadget left over from a previous run. raw-gadget needs the UDC
free. Reset the modules:

```bash
sudo rmmod raw_gadget dummy_hcd
sudo modprobe dummy_hcd raw_gadget
cat /sys/class/udc/dummy_udc.0/state    # want: not attached
```

If `state` reads `configured` or `addressed`, something still holds it; check
`ls /sys/kernel/config/usb_gadget/` for a configfs gadget and remove it, or
reboot to clear the module state entirely.

Note that loading dummy_hcd adds a virtual root hub (you will see an extra
`usbN` in Probolos's baseline). That is expected and harmless.
