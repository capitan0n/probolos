#!/usr/bin/env bash
#
# hid_gadget_up.sh -- Assembles an HID keyboard gadget on top of dummy_udc.
#
# WHY configfs AND NOT raw_gadget:
#   The configfs gadget interface is just files. You write values to
#   attributes, symlink the function into the configuration, bind the
#   gadget to a UDC, and the kernel does ALL the enumeration/endpoint work.
#   No ioctls, no struct layouts, nothing to guess. The result is a REAL
#   HID keyboard: Probolos sees it exactly as it sees a physical Rubber
#   Ducky.
#
# WHY dummy_udc:
#   Host and device are the SAME machine (loopback). The "keyboard" we
#   create appears on our own system as if we had plugged it into a USB
#   port. Nothing leaves the box, zero risk.
#
# Run as root:   sudo ./hid_gadget_up.sh
# Tear down:     sudo ./hid_gadget_down.sh
#
set -euo pipefail

G=/sys/kernel/config/usb_gadget/probolos_test
UDC_NAME=dummy_udc.0

# --- 1. Load the modules and mount configfs -------------------------------
# libcomposite creates /sys/kernel/config/usb_gadget/ once loaded.
modprobe libcomposite
modprobe usb_f_hid || true          # libcomposite often pulls this in

if [ ! -d /sys/kernel/config/usb_gadget ]; then
    # configfs exists but is not mounted -- mount it.
    mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
fi

# --- 2. Create the gadget -------------------------------------------------
mkdir -p "$G"
echo 0x1d6b > "$G/idVendor"          # Linux Foundation (neutral test VID)
echo 0x0104 > "$G/idProduct"         # Multifunction Composite Gadget
echo 0x0100 > "$G/bcdDevice"
echo 0x0200 > "$G/bcdUSB"            # USB 2.0

# Strings -- English. The "PROBOLOSTEST" marker makes the device
# recognisable in the report, so it cannot be mistaken for real hardware.
mkdir -p "$G/strings/0x409"
echo "0000PROBOLOSTEST" > "$G/strings/0x409/serialnumber"
echo "Probolos Testbed"  > "$G/strings/0x409/manufacturer"
echo "HID Attack Dummy"  > "$G/strings/0x409/product"

# --- 3. The HID function: boot keyboard -----------------------------------
# protocol=1, subclass=1 => boot keyboard. This is EXACTLY what a Rubber
# Ducky declares, and it is what Probolos's is_keyboard() checks for.
mkdir -p "$G/functions/hid.usb0"
echo 1 > "$G/functions/hid.usb0/protocol"        # 1 = keyboard
echo 1 > "$G/functions/hid.usb0/subclass"        # 1 = boot interface
echo 8 > "$G/functions/hid.usb0/report_length"   # 8-byte boot keyboard report

# The standard boot-keyboard HID report descriptor (63 bytes). Every
# legitimate keyboard declares the same thing -- which is exactly why
# BadUSB copies it. Written as raw bytes.
printf '\x05\x01\x09\x06\xa1\x01\x05\x07\x19\xe0\x29\xe7\x15\x00\x25\x01\x75\x01\x95\x08\x81\x02\x95\x01\x75\x08\x81\x03\x95\x05\x75\x01\x05\x08\x19\x01\x29\x05\x91\x02\x95\x01\x75\x03\x91\x03\x95\x06\x75\x08\x15\x00\x25\x65\x05\x07\x19\x00\x29\x65\x81\x00\xc0' \
    > "$G/functions/hid.usb0/report_desc"

# --- 4. Configuration + link the function ---------------------------------
mkdir -p "$G/configs/c.1/strings/0x409"
echo "Probolos HID test config" > "$G/configs/c.1/strings/0x409/configuration"
echo 250 > "$G/configs/c.1/MaxPower"             # 250 mA, reasonable for a keyboard

ln -sf "$G/functions/hid.usb0" "$G/configs/c.1/"

# --- 5. Bind the gadget to the virtual controller -------------------------
# The moment the UDC name is written, the kernel makes the gadget "live":
# enumeration starts, the evdev node is created. THAT is the moment
# Probolos (if running) sees a new device.
echo "$UDC_NAME" > "$G/UDC"

echo "[+] HID keyboard gadget live on $UDC_NAME"
echo "    /dev/hidg* created:"
ls -l /dev/hidg* 2>/dev/null || echo "    (no /dev/hidg -- see troubleshooting below)"
