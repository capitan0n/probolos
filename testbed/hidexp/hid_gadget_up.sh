#!/usr/bin/env bash
#
# hid_gadget_up.sh — Στήνει ένα HID keyboard gadget πάνω στο dummy_udc.
#
# ΓΙΑΤΙ configfs ΚΑΙ ΟΧΙ raw_gadget:
#   Το configfs gadget interface είναι καθαρά αρχεία. Γράφεις τιμές σε
#   attributes, κάνεις symlink τη function στη configuration, δένεις το
#   gadget σε έναν UDC, και ο kernel κάνει ΟΛΗ τη δουλειά enumeration/
#   endpoint. Κανένα ioctl, κανένα struct layout, τίποτα να μαντέψουμε.
#   Το αποτέλεσμα είναι ΠΡΑΓΜΑΤΙΚΟ HID keyboard: ο Probolos το βλέπει
#   ακριβώς όπως ένα φυσικό Rubber Ducky.
#
# ΓΙΑΤΙ dummy_udc:
#   Host και device είναι το ΙΔΙΟ μηχάνημα (loopback). Το "πληκτρολόγιο"
#   που δημιουργούμε εμφανίζεται στο δικό μας σύστημα σαν να το βάλαμε
#   σε θύρα USB. Τίποτα δεν βγαίνει έξω, μηδενικό ρίσκο.
#
# Τρέξε ως root:   sudo ./hid_gadget_up.sh
# Καθάρισε με:     sudo ./hid_gadget_down.sh
#
set -euo pipefail

G=/sys/kernel/config/usb_gadget/probolos_test
UDC_NAME=dummy_udc.0

# --- 1. Φόρτωσε τα modules και mount το configfs ---------------------------
# libcomposite δημιουργεί το /sys/kernel/config/usb_gadget/ όταν φορτωθεί.
modprobe libcomposite
modprobe usb_f_hid || true          # συχνά το τραβά το libcomposite μόνο του

if [ ! -d /sys/kernel/config/usb_gadget ]; then
    # Το configfs υπάρχει αλλά δεν είναι mounted — mount το.
    mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
fi

# --- 2. Δημιούργησε το gadget ---------------------------------------------
mkdir -p "$G"
echo 0x1d6b > "$G/idVendor"          # Linux Foundation (ουδέτερο test VID)
echo 0x0104 > "$G/idProduct"         # Multifunction Composite Gadget
echo 0x0100 > "$G/bcdDevice"
echo 0x0200 > "$G/bcdUSB"            # USB 2.0

# Strings — αγγλικά. Ο marker "PROBOLOS-TEST" κάνει τη συσκευή αναγνωρίσιμη
# στο report, ώστε να μην μπερδευτεί με πραγματικό hardware.
mkdir -p "$G/strings/0x409"
echo "0000PROBOLOSTEST" > "$G/strings/0x409/serialnumber"
echo "Probolos Testbed"  > "$G/strings/0x409/manufacturer"
echo "HID Attack Dummy"  > "$G/strings/0x409/product"

# --- 3. Η HID function: boot keyboard -------------------------------------
# protocol=1, subclass=1 => boot keyboard. Αυτό ΑΚΡΙΒΩΣ δηλώνει ένα
# Rubber Ducky, και αυτό ελέγχει το is_keyboard() του Probolos.
mkdir -p "$G/functions/hid.usb0"
echo 1 > "$G/functions/hid.usb0/protocol"        # 1 = keyboard
echo 1 > "$G/functions/hid.usb0/subclass"        # 1 = boot interface
echo 8 > "$G/functions/hid.usb0/report_length"   # 8-byte boot keyboard report

# Το standard boot-keyboard HID report descriptor (63 bytes). Είναι το ίδιο
# που δηλώνει κάθε νόμιμο πληκτρολόγιο — γι' αυτό το BadUSB το αντιγράφει.
# Το γράφουμε ως raw bytes.
printf '\x05\x01\x09\x06\xa1\x01\x05\x07\x19\xe0\x29\xe7\x15\x00\x25\x01\x75\x01\x95\x08\x81\x02\x95\x01\x75\x08\x81\x03\x95\x05\x75\x01\x05\x08\x19\x01\x29\x05\x91\x02\x95\x01\x75\x03\x91\x03\x95\x06\x75\x08\x15\x00\x25\x65\x05\x07\x19\x00\x29\x65\x81\x00\xc0' \
    > "$G/functions/hid.usb0/report_desc"

# --- 4. Configuration + σύνδεση της function ------------------------------
mkdir -p "$G/configs/c.1/strings/0x409"
echo "Probolos HID test config" > "$G/configs/c.1/strings/0x409/configuration"
echo 250 > "$G/configs/c.1/MaxPower"             # 250 mA, εύλογο για keyboard

ln -sf "$G/functions/hid.usb0" "$G/configs/c.1/"

# --- 5. Δέσε το gadget στον εικονικό controller ---------------------------
# Μόλις γραφτεί το UDC name, ο kernel κάνει το gadget "live": enumeration
# ξεκινά, evdev node δημιουργείται. ΑΥΤΗ είναι η στιγμή που ο Probolos
# (αν τρέχει) βλέπει νέα συσκευή.
echo "$UDC_NAME" > "$G/UDC"

echo "[+] HID keyboard gadget live στο $UDC_NAME"
echo "    /dev/hidg* που δημιουργήθηκε:"
ls -l /dev/hidg* 2>/dev/null || echo "    (κανένα /dev/hidg — δες troubleshooting παρακάτω)"
