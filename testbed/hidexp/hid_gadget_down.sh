#!/usr/bin/env bash
#
# hid_gadget_down.sh -- Tears the HID gadget down.
#
# ORDER MATTERS. configfs will not let you remove anything that is in use.
# The teardown is the setup in REVERSE:
#   1. detach from the UDC (takes the gadget offline)
#   2. remove the function->config symlink
#   3. delete strings, configs, functions, then the gadget itself
# Skip a step and rmdir returns "Device or resource busy".
#
set -uo pipefail

G=/sys/kernel/config/usb_gadget/probolos_test

if [ ! -d "$G" ]; then
    echo "[i] No gadget to clean up."
    exit 0
fi

# 1. Offline: empty the UDC attribute. Does not delete, just detaches.
echo "" > "$G/UDC" 2>/dev/null || true

# 2. Break the symlink from the config to the function.
rm -f "$G/configs/c.1/hid.usb0"

# 3. Delete in reverse order. rmdir NEEDS the directories empty.
rmdir "$G/configs/c.1/strings/0x409" 2>/dev/null || true
rmdir "$G/configs/c.1"               2>/dev/null || true
rmdir "$G/functions/hid.usb0"        2>/dev/null || true
rmdir "$G/strings/0x409"             2>/dev/null || true
rmdir "$G"                           2>/dev/null || true

if [ -d "$G" ]; then
    echo "[!] Something is still busy. See: find $G"
else
    echo "[+] Cleaned up."
fi
