#!/usr/bin/env bash
#
# hid_gadget_down.sh — Αποσυναρμολογεί το HID gadget.
#
# Η ΣΕΙΡΑ ΕΧΕΙ ΣΗΜΑΣΙΑ. Το configfs δεν σε αφήνει να σβήσεις κάτι που
# χρησιμοποιείται. Πρέπει να λύσεις με ΑΝΤΙΣΤΡΟΦΗ σειρά από το στήσιμο:
#   1. αποσύνδεσε από τον UDC (κάνει το gadget offline)
#   2. διάγραψε το symlink function->config
#   3. σβήσε strings, configs, functions, το ίδιο το gadget
# Αν παραλείψεις ένα βήμα, το rmdir δίνει "Device or resource busy".
#
set -uo pipefail

G=/sys/kernel/config/usb_gadget/cerberus_test

if [ ! -d "$G" ]; then
    echo "[i] Δεν υπάρχει gadget να καθαρίσω."
    exit 0
fi

# 1. Offline: άδειασε το UDC attribute. Δεν σβήνει, απλώς αποσυνδέει.
echo "" > "$G/UDC" 2>/dev/null || true

# 2. Λύσε το symlink της function από τη config.
rm -f "$G/configs/c.1/hid.usb0"

# 3. Σβήσε με αντίστροφη σειρά. Τα rmdir ΘΕΛΟΥΝ τους καταλόγους άδειους.
rmdir "$G/configs/c.1/strings/0x409" 2>/dev/null || true
rmdir "$G/configs/c.1"               2>/dev/null || true
rmdir "$G/functions/hid.usb0"        2>/dev/null || true
rmdir "$G/strings/0x409"             2>/dev/null || true
rmdir "$G"                           2>/dev/null || true

if [ -d "$G" ]; then
    echo "[!] Κάτι έμεινε busy. Δες: find $G"
else
    echo "[+] Καθαρίστηκε."
fi
