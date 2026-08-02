"""
storage_hardening.py — Αμυντικοί έλεγχοι για το stage 4 (storage inspection).

ΤΟ ΠΡΟΒΛΗΜΑ (#3 από τη λίστα κενών)
-----------------------------------
Το storage.py διαβάζει read-only το MBR/GPT μιας εχθρικής συσκευής. Δεν κάνει
mount — σωστά. ΑΛΛΑ ο parser εμπιστεύεται αριθμούς που ελέγχει η συσκευή:

  1. part.start_lba * SECTOR: μια συσκευή δηλώνει start_lba = 0xFFFFFFFF.
     Το offset γίνεται ~2 TB. Το seek()+read() εκεί, σε συσκευή που ΔΕΝ έχει
     τόσο χώρο, μπορεί να κρεμάσει τον driver ή να σφάλει απρόβλεπτα.

  2. end_lba = start_lba + sectors: με start και sectors κοντά στο 2^32, το
     άθροισμα ξεπερνά το μέγεθος. Η σύγκριση "partition past end of device"
     σπάει αν δεν την κάνεις με προσοχή.

  3. Τέσσερα partitions που ΟΛΑ δείχνουν σε τεράστια offsets: τέσσερα seeks
     σε 2 TB = τέσσερις πιθανές κρεμάλες. Το πλήθος είναι φραγμένο (4 στο
     MBR), αλλά το κόστος ανά read δεν είναι.

Η ΛΥΣΗ: επικύρωσε ΚΑΘΕ partition ΠΡΙΝ διαβάσεις οτιδήποτε από αυτό. Ένα
partition που δεν χωράει στο δηλωμένο μέγεθος της συσκευής είναι είτε
κατεστραμμένο είτε εχθρικό — και στις δύο περιπτώσεις, δεν το διαβάζουμε.

Αυτό είναι το ΙΔΙΟ μοτίβο με το descriptors_safe.py: μη εμπιστεύεσαι μήκη
που δηλώνει η συσκευή· διασταύρωσέ τα με την πραγματικότητα (εδώ, το
πραγματικό μέγεθος από sysfs).
"""

from __future__ import annotations

from typing import List, Optional, Tuple

SECTOR = 512

# Ανώτατο εύλογο μέγεθος συσκευής σε sectors (~16 TB). Πάνω από αυτό, η
# δήλωση είναι σχεδόν σίγουρα εχθρική για μια USB συσκευή αποθήκευσης.
MAX_PLAUSIBLE_SECTORS = 32 * 1024 * 1024 * 1024  # 16 TiB / 512

# Ανώτατο offset που θα κάνουμε ποτέ seek. Πέρα από αυτό, δεν διαβάζουμε.
MAX_SEEK_OFFSET = MAX_PLAUSIBLE_SECTORS * SECTOR


class StorageValidationError(ValueError):
    """Μη έγκυρη δομή partition — οδηγεί σε παράλειψη, όχι σε crash/hang."""


def validate_partition(start_lba: int,
                       sectors: int,
                       device_sectors: Optional[int]) -> Tuple[bool, str]:
    """
    Είναι ασφαλές να διαβάσουμε από αυτό το partition;

    Επιστρέφει (ok, reason). Αν ok είναι False, ο caller ΔΕΝ πρέπει να κάνει
    seek/read σε αυτό — απλώς το καταγράφει ως ύποπτο και προχωρά.

    Οι έλεγχοι, με σειρά:
      - μη αρνητικά / μη μηδενικά (ένα partition με sectors=0 είναι κενή θέση)
      - το start δεν ξεπερνά το ανώτατο εύλογο offset
      - end = start + sectors ΔΕΝ κάνει overflow τη λογική (Python ints είναι
        απεριόριστα, οπότε το "overflow" εδώ σημαίνει "ξεπερνά το μέγεθος")
      - αν ξέρουμε το πραγματικό μέγεθος, το partition χωράει μέσα του
    """
    if start_lba < 0 or sectors < 0:
        return False, f"αρνητικό start/sectors ({start_lba}/{sectors})"

    if sectors == 0:
        return False, "κενή θέση (sectors=0)"

    if start_lba > MAX_PLAUSIBLE_SECTORS:
        return False, f"start_lba {start_lba} πέρα από κάθε εύλογο μέγεθος"

    end_lba = start_lba + sectors
    if end_lba > MAX_PLAUSIBLE_SECTORS:
        return False, f"partition τελειώνει στο {end_lba} — μη ρεαλιστικό"

    if device_sectors is not None:
        # Ο ισχυρότερος έλεγχος: το πραγματικό μέγεθος από sysfs. Ένα partition
        # που δηλώνει ότι εκτείνεται πέρα από τον φυσικό δίσκο είναι το κλασικό
        # "partition extends past end of device" — corrupt ή εχθρικό.
        if start_lba >= device_sectors:
            return False, (f"partition ξεκινά στο sector {start_lba} αλλά η "
                           f"συσκευή έχει μόνο {device_sectors}")
        if end_lba > device_sectors:
            return False, (f"partition τελειώνει στο {end_lba} αλλά η συσκευή "
                           f"έχει μόνο {device_sectors} sectors")

    return True, "ok"


def safe_read_offset(start_lba: int, device_sectors: Optional[int]) -> Optional[int]:
    """
    Το byte offset για seek, ΜΟΝΟ αν είναι ασφαλές. Αλλιώς None.

    Χρήση στο storage.inspect, στη θέση του γυμνού `part.start_lba * SECTOR`:

        offset = safe_read_offset(part.start_lba, report.size_sectors)
        if offset is None:
            report.suspicious.append(f"partition {part.index}: unsafe offset")
            continue
        chunk = _read_at(device, offset, SECTOR, open_fn)
    """
    ok, _reason = validate_partition(start_lba, 1, device_sectors)
    if not ok:
        return None
    offset = start_lba * SECTOR
    if offset > MAX_SEEK_OFFSET:
        return None
    return offset


def device_size_sane(device_sectors: Optional[int]) -> Tuple[bool, str]:
    """
    Ελέγχει αν το δηλωμένο μέγεθος της συσκευής είναι το ίδιο εύλογο.

    Μια συσκευή που δηλώνει 100 PB μέσω sysfs προσπαθεί να προκαλέσει
    υπερχείλιση ή τεράστια allocation κάπου παρακάτω. Το πιάνουμε νωρίς.
    """
    if device_sectors is None:
        return True, "άγνωστο μέγεθος (θα βασιστούμε σε per-partition ελέγχους)"
    if device_sectors < 0:
        return False, f"αρνητικό μέγεθος: {device_sectors}"
    if device_sectors > MAX_PLAUSIBLE_SECTORS:
        return False, (f"δηλώνει {device_sectors} sectors "
                       f"(~{device_sectors * SECTOR // (10**12)} TB) — μη ρεαλιστικό")
    return True, "ok"


def filter_safe_partitions(partitions: List,
                           device_sectors: Optional[int]) -> Tuple[List, List[str]]:
    """
    Χωρίζει τα partitions σε (ασφαλή προς ανάγνωση, ύποπτα).

    Επιστρέφει (safe_list, suspicion_messages). Τα ύποπτα ΔΕΝ διαβάζονται
    αλλά ΑΝΑΦΕΡΟΝΤΑΙ — η ίδια η ύπαρξη ενός impossible partition είναι finding.
    """
    safe = []
    suspicious = []
    for part in partitions:
        start = getattr(part, "start_lba", 0)
        sectors = getattr(part, "sectors", 0)
        ok, reason = validate_partition(start, sectors, device_sectors)
        if ok:
            safe.append(part)
        else:
            idx = getattr(part, "index", "?")
            if reason != "κενή θέση (sectors=0)":  # οι κενές θέσεις δεν είναι ύποπτες
                suspicious.append(f"partition {idx}: {reason}")
    return safe, suspicious
