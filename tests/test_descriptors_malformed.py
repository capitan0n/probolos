"""
test_descriptors_malformed.py — Regression tests για το αμυντικό parsing.

Στη λογική των υπόλοιπων tests του Probolos, κάθε test ονομάζεται από το
σενάριο που το γέννησε. Εδώ όμως τα σενάρια δεν ήρθαν από πραγματικό υλικό
αλλά από ανάλυση απειλών — γι' αυτό ονομάζονται από την επίθεση.

Τρέχει και με pytest και σκέτο:
    python test_descriptors_malformed.py
    pytest test_descriptors_malformed.py -v
"""

import sys

# Δουλεύει και ως μέρος του πακέτου (pytest από τη ρίζα του repo)
# και σκέτο (python test_descriptors_malformed.py μέσα στον φάκελο).
try:
    from probolos.descriptors_safe import (        # type: ignore
        DescriptorParsingError,
        effective_total_length,
        safe_parse,
        take,
        walk_descriptors,
        walk_hid_items,
        wtotallength_mismatch,
    )
except ImportError:
    from descriptors_safe import (                 # type: ignore
        DescriptorParsingError,
        effective_total_length,
        safe_parse,
        take,
        walk_descriptors,
        walk_hid_items,
        wtotallength_mismatch,
    )


def _expect_error(fn, *args, **kwargs):
    try:
        result = fn(*args, **kwargs)
        # Οι generators δεν εκτελούνται μέχρι να καταναλωθούν.
        if hasattr(result, "__iter__") and not isinstance(result, (bytes, str)):
            list(result)
    except DescriptorParsingError:
        return True
    raise AssertionError(f"περίμενα DescriptorParsingError από {fn.__name__}")


# --------------------------------------------------------------------------
# take() — το σιωπηλό slicing της Python
# --------------------------------------------------------------------------
def test_take_rejects_read_past_end():
    """Η ρίζα του προβλήματος: b"abc"[0:100] επιστρέφει b"abc" χωρίς σφάλμα."""
    buf = b"\x12\x01\x00\x02"
    assert buf[0:100] == buf          # τεκμηρίωση της συμπεριφοράς της Python
    _expect_error(take, buf, 0, 100, "device descriptor")


def test_take_rejects_negative_offset():
    _expect_error(take, b"\x00\x01", -1, 1, "x")


# --------------------------------------------------------------------------
# walk_descriptors — ο πραγματικός DoS
# --------------------------------------------------------------------------
def test_zero_blength_does_not_hang():
    """bLength=0: χωρίς έλεγχο ο δείκτης δεν προχωρά ποτέ.

    Αν αυτό το test κρεμάσει αντί να αποτύχει, η επίθεση δουλεύει.
    """
    hostile = b"\x00\x02\xff\xff\xff\xff"
    _expect_error(walk_descriptors, hostile)


def test_blength_one_rejected():
    """bLength=1 είναι επίσης μικρότερο από το ελάχιστο header."""
    _expect_error(walk_descriptors, b"\x01\x02\x00\x00")


def test_descriptor_overruns_buffer():
    """Δηλώνει 64 bytes ενώ υπάρχουν 4."""
    _expect_error(walk_descriptors, b"\x40\x02\x00\x00")


def test_truncated_header():
    """Απομένει ένα μόνο byte στο τέλος της αλυσίδας."""
    valid = b"\x04\x02\x00\x00"
    _expect_error(walk_descriptors, valid + b"\x09")


def test_item_flood_rejected():
    """Χιλιάδες ελάχιστα descriptors — exhaustion μέσω πλήθους, όχι μεγέθους."""
    flood = b"\x02\x02" * 5000
    _expect_error(walk_descriptors, flood)


def test_valid_chain_parses():
    """Θετικός έλεγχος: μια νόμιμη αλυσίδα δεν πρέπει να απορρίπτεται.

    Config (9B) + Interface (9B). Χωρίς αυτό το test, ένας υπερβολικά
    αυστηρός parser θα «περνούσε» απορρίπτοντας τα πάντα.
    """
    config = bytes([0x09, 0x02, 0x12, 0x00, 0x01, 0x01, 0x00, 0x80, 0x32])
    iface = bytes([0x09, 0x04, 0x00, 0x00, 0x01, 0x03, 0x01, 0x01, 0x00])
    items = list(walk_descriptors(config + iface))
    assert len(items) == 2
    assert items[0][0] == 0x02          # CONFIGURATION
    assert items[1][0] == 0x04          # INTERFACE
    assert len(items[0][1]) == 9


# --------------------------------------------------------------------------
# wTotalLength
# --------------------------------------------------------------------------
def test_wtotallength_clamped_to_reality():
    """Δηλώνει 0xFFFF ενώ στέλνει 9 bytes."""
    cfg = bytes([0x09, 0x02, 0xFF, 0xFF, 0x01, 0x01, 0x00, 0x80, 0x32])
    assert effective_total_length(cfg) == 9
    assert wtotallength_mismatch(cfg) == 0xFFFF - 9


# --------------------------------------------------------------------------
# HID items
# --------------------------------------------------------------------------
def test_hid_push_without_pop_rejected():
    """0xA4 = Global/Push με μηδέν bytes δεδομένων."""
    _expect_error(walk_hid_items, b"\xa4" * 100)


def test_hid_pop_without_push_rejected():
    _expect_error(walk_hid_items, b"\xb4")


def test_hid_collection_depth_limited():
    """0xA1 0x01 = Main/Collection (Application), επαναλαμβανόμενο."""
    _expect_error(walk_hid_items, b"\xa1\x01" * 200)


def test_hid_end_collection_without_open():
    """0xC0 = Main/End Collection."""
    _expect_error(walk_hid_items, b"\xc0")


def test_hid_unbalanced_collection_at_eof():
    """Ανοίγει Collection και δεν το κλείνει ποτέ."""
    _expect_error(walk_hid_items, b"\xa1\x01")


def test_hid_absurd_report_size_rejected():
    """ReportSize=32 (0x75 0x20), ReportCount=0xFFFF (0x96), μετά Input (0x81).

    2 Mbit «report» — memory exhaustion κατά την κατανομή buffers.
    """
    hostile = b"\x75\x20" + b"\x96\xff\xff" + b"\x81\x02"
    _expect_error(walk_hid_items, hostile)


def test_hid_truncated_item_data():
    """0x75 δηλώνει 1 byte δεδομένων που δεν υπάρχει."""
    _expect_error(walk_hid_items, b"\x75")


def test_hid_valid_mouse_descriptor_parses():
    """Θετικός έλεγχος με πραγματικό boot-protocol mouse descriptor.

    Αντιστοιχεί στην κατηγορία του PixArt/Lenovo ποντικιού (17ef:608d).
    """
    mouse = bytes([
        0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x09, 0x01,
        0xA1, 0x00, 0x05, 0x09, 0x19, 0x01, 0x29, 0x03,
        0x15, 0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01,
        0x81, 0x02, 0x95, 0x01, 0x75, 0x05, 0x81, 0x03,
        0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x15, 0x81,
        0x25, 0x7F, 0x75, 0x08, 0x95, 0x02, 0x81, 0x06,
        0xC0, 0xC0,
    ])
    items = list(walk_hid_items(mouse))
    # 24 short items των 2 bytes + 2 items του 1 byte (0xC0 End Collection)
    assert len(items) == 26


# --------------------------------------------------------------------------
# safe_parse — fail-closed
# --------------------------------------------------------------------------
def test_safe_parse_converts_error_to_value():
    def boom(_):
        raise DescriptorParsingError("bLength=0")

    result, err = safe_parse(boom, b"")
    assert result is None
    assert "bLength=0" in err


def test_safe_parse_catches_unexpected_bug():
    """Ένα bug στον parser δεν επιτρέπεται να ρίξει τον daemon."""
    def bug(_):
        return [][5]

    result, err = safe_parse(bug, b"")
    assert result is None
    assert "IndexError" in err


def test_safe_parse_passes_through_success():
    result, err = safe_parse(lambda x: x * 2, 21)
    assert result == 42 and err is None


# --------------------------------------------------------------------------
if __name__ == "__main__":
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ok    {name}")
        except Exception as e:                      # noqa: BLE001
            failed += 1
            print(f"  FAIL  {name}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} πέρασαν")
    sys.exit(1 if failed else 0)
