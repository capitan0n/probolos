"""
Translation of raw USB class/subclass/protocol codes into human language.

The whole point of Probolos is that a human is asked a question they can
actually answer.  "bInterfaceClass=0x03, bInterfaceProtocol=0x01" is not a
question anyone can answer.  "This device claims to be a KEYBOARD" is.
"""

# Base class codes, as assigned by USB-IF.
# Reference: https://www.usb.org/defined-class-codes
CLASS_NAMES = {
    0x00: "Per-Interface",       # device defers its identity to its interfaces
    0x01: "Audio",
    0x02: "Communications",      # CDC: modems, network adapters
    0x03: "HID",                 # Human Interface Device: keyboard, mouse...
    0x05: "Physical",
    0x06: "Image",               # scanners, PTP cameras
    0x07: "Printer",
    0x08: "Mass Storage",        # flash drives, external disks
    0x09: "Hub",
    0x0A: "CDC-Data",
    0x0B: "Smart Card",
    0x0D: "Content Security",
    0x0E: "Video",               # webcams
    0x0F: "Personal Healthcare",
    0x10: "Audio/Video",
    0x11: "Billboard",
    0x12: "USB Type-C Bridge",
    0xDC: "Diagnostic",
    0xE0: "Wireless Controller", # Bluetooth adapters, RF dongles
    0xEF: "Miscellaneous",
    0xFE: "Application Specific",
    0xFF: "Vendor Specific",
}

# HID is the class that matters most for BadUSB, so we resolve it further.
# In the "boot interface" subclass (0x01) the protocol byte tells us exactly
# what kind of input device we are dealing with.
HID_BOOT_PROTOCOLS = {
    0x00: "HID (no boot protocol)",
    0x01: "KEYBOARD",
    0x02: "MOUSE",
}

# Subclass/protocol resolution for classes where the base name is uselessly
# vague. Added after inventorying real hardware: a Realtek Bluetooth radio and
# a Chicony UVC camera both reported two interfaces whose base class alone said
# nothing about what they actually do.
SUBCLASS_DETAIL = {
    # Video (UVC): the standard mandates a control + streaming pair, so seeing
    # two 0x0e interfaces is normal and must never read as suspicious.
    (0x0E, 0x01): "Webcam (control)",
    (0x0E, 0x02): "Webcam (video stream)",
    (0x0E, 0x03): "Webcam (interface collection)",
    # Wireless: 0xe0/0x01/0x01 is the Bluetooth programming interface.
    (0xE0, 0x01): "Bluetooth radio",
    (0xE0, 0x02): "Wireless (RF controller)",
    # Audio, where a headset legitimately also exposes HID for its buttons.
    (0x01, 0x01): "Audio (control)",
    (0x01, 0x02): "Audio (stream)",
    # Mass storage: 0x06/0x50 is SCSI transparent over bulk-only, i.e. every
    # ordinary flash drive.
    (0x08, 0x06): "Mass Storage (SCSI)",
}


# Broad behavioural buckets.  The daemon routes on these, not on raw codes,
# because stage 2 of the pipeline differs per bucket:
#   INPUT   -> behavioural quarantine (evdev grab + timing analysis)
#   STORAGE -> read-only raw inspection (blkid -p / dumpe2fs, never mount)
#   OTHER   -> no deep check available yet, decided on identity alone
KIND_INPUT = "input"
KIND_STORAGE = "storage"
KIND_HUB = "hub"
KIND_OTHER = "other"

KIND_WIRELESS = "wireless"

_KIND_BY_CLASS = {
    0x03: KIND_INPUT,
    0x08: KIND_STORAGE,
    0x09: KIND_HUB,
    # Wireless controllers get their own bucket because they are gateways:
    # a Bluetooth adapter can admit a keyboard later, with no USB event at all.
    # Probolos cannot see that happen. Naming the bucket keeps the blind spot
    # visible instead of hiding it inside "other".
    0xE0: KIND_WIRELESS,
}


def class_name(code: int) -> str:
    """Human name for a base class code, with a fallback for unknown codes."""
    return CLASS_NAMES.get(code, f"Unknown(0x{code:02x})")


def describe_interface(cls: int, subcls: int, proto: int) -> str:
    """
    Human description of a single interface.

    We special-case HID because "keyboard" versus "mouse" is exactly the
    distinction a user needs in order to answer the confirmation prompt.
    """
    if cls == 0x03:
        # subclass 1 == boot interface subclass; only then is proto meaningful
        if subcls == 0x01 and proto in HID_BOOT_PROTOCOLS:
            return HID_BOOT_PROTOCOLS[proto]
        return "HID (generic input device)"
    detail = SUBCLASS_DETAIL.get((cls, subcls))
    if detail:
        return detail
    return class_name(cls)


def is_keyboard(cls: int, subcls: int, proto: int) -> bool:
    """
    True only for an interface that can actually type.

    This is deliberately narrow. The BadUSB threat is keystroke injection, so
    the rule that matters keys on the boot-keyboard protocol rather than on HID
    in general -- HID also covers mice, headset buttons, UPS units, and vendor
    configuration channels, all of which are innocuous company for other
    functions.
    """
    return cls == 0x03 and subcls == 0x01 and proto == 0x01


def kind_of(cls: int) -> str:
    """Map a class code to the behavioural bucket used for routing."""
    return _KIND_BY_CLASS.get(cls, KIND_OTHER)
