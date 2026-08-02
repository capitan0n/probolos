"""
descriptors_safe.py — Αμυντικό επίπεδο ανάλυσης USB descriptors για τον Cerberus.

Σχεδιαστική αρχή: κάθε σφάλμα ανάλυσης είναι *εύρημα*, όχι κατάρρευση.
Η συσκευή που παράγει σφάλμα μένει σε authorized=0.

Το αρχείο είναι αυτοτελές (μόνο stdlib) και ΔΕΝ αντικαθιστά το descriptors.py.
Το υπάρχον descriptors.py καλεί από εδώ τα primitives (take/walk_descriptors)
αντί για ωμό slicing.

ΓΙΑΤΙ ΧΡΕΙΑΖΕΤΑΙ, παρότι η Python είναι memory-safe:
  1. Το slicing της Python ΔΕΝ πετάει IndexError εκτός ορίων — επιστρέφει
     σιωπηλά κοντύτερο bytes. Συνεχίζεις λοιπόν να δουλεύεις με ελλιπή
     δεδομένα νομίζοντας ότι όλα πήγαν καλά. Αυτό είναι χειρότερο από crash.
  2. bLength == 0 σε TLV αλυσίδα => ο δείκτης δεν προχωρά ποτέ => ατέρμονας
     βρόχος. Αυτός είναι ο πραγματικός DoS, όχι το IndexError.
  3. Δηλωμένα μήκη (wTotalLength) που δεν αντιστοιχούν στο πραγματικό buffer.
"""

from __future__ import annotations

from typing import Iterator, Tuple

# --------------------------------------------------------------------------
# Όρια. Συντηρητικά αλλά πολύ πάνω από κάθε νόμιμη συσκευή.
# --------------------------------------------------------------------------
MAX_DESCRIPTOR_ITEMS = 256      # πλήθος descriptors σε μία configuration
MAX_HID_ITEMS = 4096            # πλήθος items σε HID report descriptor
MAX_HID_PUSH_DEPTH = 16         # βάθος στοίβας PUSH/POP (spec: δεν ορίζει όριο)
MAX_HID_COLLECTION_DEPTH = 32   # βάθος φωλιασμένων Collections
MAX_REPORT_BITS = 64 * 1024     # ReportCount * ReportSize ανά Main item


class DescriptorParsingError(ValueError):
    """Μη έγκυρα δεδομένα από τη συσκευή.

    Κληρονομεί από ValueError ώστε υπάρχοντα except ValueError να το πιάνουν,
    αλλά ξεχωρίζει σημασιολογικά: «η συσκευή είπε ψέματα», όχι «bug στον κώδικα».
    """


# --------------------------------------------------------------------------
# 1. Ασφαλής προσπέλαση bytes
# --------------------------------------------------------------------------
def take(buf: bytes, off: int, length: int, what: str) -> bytes:
    """Slicing που αποτυγχάνει θορυβωδώς αντί σιωπηλά.

    Χρησιμοποίησέ το ΠΑΝΤΟΥ αντί για buf[a:b] όταν τα a,b προέρχονται —
    έστω και έμμεσα — από τη συσκευή.
    """
    if off < 0 or length < 0:
        raise DescriptorParsingError(f"{what}: αρνητικό offset/length")
    end = off + length
    if end > len(buf):
        raise DescriptorParsingError(
            f"{what}: ζητήθηκαν {length}B στο offset {off}, "
            f"διαθέσιμα μόνο {len(buf)}B"
        )
    return buf[off:end]


def u8(buf: bytes, off: int, what: str) -> int:
    return take(buf, off, 1, what)[0]


def u16le(buf: bytes, off: int, what: str) -> int:
    """USB: όλα τα πολυ-byte πεδία είναι little-endian."""
    return int.from_bytes(take(buf, off, 2, what), "little")


# --------------------------------------------------------------------------
# 2. Διάσχιση της standard TLV αλυσίδας
# --------------------------------------------------------------------------
def walk_descriptors(buf: bytes,
                     max_items: int = MAX_DESCRIPTOR_ITEMS
                     ) -> Iterator[Tuple[int, bytes]]:
    """Διατρέχει τη μορφή [bLength][bDescriptorType][payload...].

    Κάνει yield (bDescriptorType, ολόκληρο_το_descriptor_ως_bytes).

    Ο βρόχος τερματίζει ΑΠΟΔΕΔΕΙΓΜΕΝΑ: το off αυξάνεται κατά b_length που
    ελέγχεται >= 2 πριν χρησιμοποιηθεί. Χωρίς αυτόν τον έλεγχο, ένα
    bLength=0 από εχθρική συσκευή παγώνει τον daemon για πάντα.
    """
    off = 0
    seen = 0
    total = len(buf)

    while off < total:
        if seen >= max_items:
            raise DescriptorParsingError(
                f"πάνω από {max_items} descriptors — πιθανή απόπειρα exhaustion"
            )
        if off + 2 > total:
            # Απομένει 1 byte: κολοβή αλυσίδα.
            raise DescriptorParsingError(
                f"κολοβό descriptor header στο offset {off}"
            )

        b_length = buf[off]
        b_type = buf[off + 1]

        if b_length < 2:
            # ΤΟ ΚΡΙΣΙΜΟ ΣΗΜΕΙΟ. Κάθε νόμιμο descriptor έχει τουλάχιστον
            # bLength + bDescriptorType = 2 bytes.
            raise DescriptorParsingError(
                f"bLength={b_length} στο offset {off} — μη έγκυρο (ελάχιστο 2)"
            )
        if off + b_length > total:
            raise DescriptorParsingError(
                f"descriptor τύπου 0x{b_type:02x} στο offset {off} δηλώνει "
                f"{b_length}B αλλά το buffer τελειώνει στα {total}B"
            )

        yield b_type, buf[off:off + b_length]

        off += b_length   # εγγυημένα >= 2
        seen += 1


def effective_total_length(cfg_buf: bytes) -> int:
    """wTotalLength του Configuration Descriptor, περιορισμένο στην πραγματικότητα.

    Μια εχθρική συσκευή δηλώνει wTotalLength=65535 ενώ στέλνει 40 bytes.
    Ο κανόνας: εμπιστεύσου το μέγεθος του buffer, όχι τη δήλωση.
    Η ασυμφωνία δεν είναι από μόνη της κακόβουλη (υπάρχουν buggy συσκευές),
    οπότε την επιστρέφουμε ως πληροφορία αντί να πετάμε exception.
    """
    if len(cfg_buf) < 4:
        raise DescriptorParsingError("Configuration Descriptor < 4 bytes")
    declared = u16le(cfg_buf, 2, "wTotalLength")
    return min(declared, len(cfg_buf))


def wtotallength_mismatch(cfg_buf: bytes) -> int:
    """Επιστρέφει declared - actual. Μη μηδενικό => άξιο καταγραφής finding."""
    declared = u16le(cfg_buf, 2, "wTotalLength")
    return declared - len(cfg_buf)


# --------------------------------------------------------------------------
# 3. HID Report Descriptors
# --------------------------------------------------------------------------
# ΔΙΟΡΘΩΣΗ ΤΗΣ ΚΡΙΤΙΚΗΣ: τα HID report descriptors ΔΕΝ είναι αναδρομικά.
# Είναι επίπεδη ροή items. Δύο ξεχωριστές έννοιες «βάθους» υπάρχουν:
#   α) η στοίβα PUSH/POP (Global items 0xA4 / 0xB4) — αποθηκεύει global state
#   β) το φώλιασμα Collection / End Collection (Main items) — λογική δομή
# Και τα δύο θέλουν όριο, για διαφορετικό λόγο το καθένα.

HID_LONG_ITEM_PREFIX = 0xFE

# bType
_HID_TYPE_MAIN = 0
_HID_TYPE_GLOBAL = 1
_HID_TYPE_LOCAL = 2

# bTag (Main)
_TAG_COLLECTION = 0x0A
_TAG_END_COLLECTION = 0x0C
_MAIN_DATA_TAGS = (0x08, 0x09, 0x0B)      # Input, Output, Feature

# bTag (Global)
_TAG_REPORT_SIZE = 0x07
_TAG_REPORT_COUNT = 0x09
_TAG_PUSH = 0x0A
_TAG_POP = 0x0B


def walk_hid_items(buf: bytes,
                   max_items: int = MAX_HID_ITEMS,
                   max_push_depth: int = MAX_HID_PUSH_DEPTH,
                   max_collection_depth: int = MAX_HID_COLLECTION_DEPTH
                   ) -> Iterator[Tuple[int, int, bytes]]:
    """Διατρέχει HID items. Yield (bType, bTag, data_bytes).

    Μορφή short item: ένα prefix byte
        bits 0-1  bSize  -> 0,1,2,4 bytes δεδομένων (η τιμή 3 σημαίνει 4!)
        bits 2-3  bType
        bits 4-7  bTag
    Μορφή long item: prefix 0xFE, μετά bDataSize, bLongItemTag, data.

    Επιβάλλει ταυτόχρονα:
      - όριο πλήθους items
      - βάθος PUSH/POP
      - βάθος Collection (και ανίχνευση End Collection χωρίς αντίστοιχο άνοιγμα)
      - λογικό όριο στο ReportCount * ReportSize
    """
    off = 0
    seen = 0
    total = len(buf)

    push_depth = 0
    collection_depth = 0
    report_size = 0
    report_count = 0

    while off < total:
        if seen >= max_items:
            raise DescriptorParsingError(
                f"πάνω από {max_items} HID items — πιθανή απόπειρα exhaustion"
            )

        prefix = buf[off]

        if prefix == HID_LONG_ITEM_PREFIX:
            # Long items δεν χρησιμοποιούνται στην πράξη· τα διαβάζουμε
            # σωστά ώστε να μη χαλάσει το alignment της υπόλοιπης ροής.
            if off + 3 > total:
                raise DescriptorParsingError("κολοβό HID long item")
            data_size = buf[off + 1]
            long_tag = buf[off + 2]
            data = take(buf, off + 3, data_size, "HID long item data")
            yield (-1, long_tag, data)
            off += 3 + data_size
            seen += 1
            continue

        b_size_code = prefix & 0x03
        b_size = 4 if b_size_code == 3 else b_size_code   # 3 -> 4 bytes
        b_type = (prefix >> 2) & 0x03
        b_tag = (prefix >> 4) & 0x0F

        data = take(buf, off + 1, b_size, f"HID item tag=0x{b_tag:x}")
        value = int.from_bytes(data, "little") if data else 0

        # --- έλεγχοι κατάστασης ---
        if b_type == _HID_TYPE_GLOBAL:
            if b_tag == _TAG_PUSH:
                push_depth += 1
                if push_depth > max_push_depth:
                    raise DescriptorParsingError(
                        f"HID PUSH βάθος {push_depth} > {max_push_depth}"
                    )
            elif b_tag == _TAG_POP:
                if push_depth == 0:
                    raise DescriptorParsingError("HID POP χωρίς αντίστοιχο PUSH")
                push_depth -= 1
            elif b_tag == _TAG_REPORT_SIZE:
                report_size = value
            elif b_tag == _TAG_REPORT_COUNT:
                report_count = value

        elif b_type == _HID_TYPE_MAIN:
            if b_tag == _TAG_COLLECTION:
                collection_depth += 1
                if collection_depth > max_collection_depth:
                    raise DescriptorParsingError(
                        f"HID Collection βάθος {collection_depth} "
                        f"> {max_collection_depth}"
                    )
            elif b_tag == _TAG_END_COLLECTION:
                if collection_depth == 0:
                    raise DescriptorParsingError(
                        "HID End Collection χωρίς ανοιχτό Collection"
                    )
                collection_depth -= 1
            elif b_tag in _MAIN_DATA_TAGS:
                # ReportCount=65535 * ReportSize=32 => 2 Mbit «report».
                # Καμία νόμιμη συσκευή δεν το κάνει· είναι κλασικό exhaustion.
                bits = report_size * report_count
                if bits > MAX_REPORT_BITS:
                    raise DescriptorParsingError(
                        f"δηλωμένο report {report_count}x{report_size}b "
                        f"= {bits} bits — μη ρεαλιστικό"
                    )

        yield (b_type, b_tag, data)

        off += 1 + b_size   # εγγυημένα >= 1
        seen += 1

    if collection_depth != 0:
        raise DescriptorParsingError(
            f"{collection_depth} Collection χωρίς End Collection"
        )
    if push_depth != 0:
        raise DescriptorParsingError(f"{push_depth} PUSH χωρίς POP")


# --------------------------------------------------------------------------
# 4. Fail-closed wrapper
# --------------------------------------------------------------------------
def safe_parse(fn, *args, **kwargs):
    """Εκτελεί συνάρτηση ανάλυσης και μετατρέπει το σφάλμα σε τιμή.

    Επιστρέφει (result, error_message | None).

    Χρήση στον analyzer:

        parsed, err = safe_parse(parse_configuration, raw)
        if err:
            findings.append(Finding(severity=CRITICAL,
                                    code="DESC_MALFORMED",
                                    detail=err))
            # η συσκευή παραμένει authorized=0

    Πιάνουμε και σκέτο Exception: ένα απρόβλεπτο bug στον parser δεν
    επιτρέπεται να ρίξει τον daemon και να αφήσει την πύλη σε άγνωστη
    κατάσταση. Το CRITICAL finding είναι πάντα η ασφαλής απάντηση.
    """
    try:
        return fn(*args, **kwargs), None
    except DescriptorParsingError as e:
        return None, str(e)
    except Exception as e:  # noqa: BLE001 — σκόπιμα ευρύ, fail-closed
        return None, f"{type(e).__name__} κατά την ανάλυση: {e}"
