"""
The card-reader media gap: a card inserted into an admitted reader.

A card is a SCSI medium, not a USB device: inserting one produces a block
`change` event and nothing at the USB layer, so the admission gate never sees
it. mediawatch.py is the separate detection layer for that. These tests pin
the pieces AND the wiring -- the project's recurring failure is correct code
that nothing calls, and the watcher is exactly the kind of component that
could be written, tested in isolation, and never reached (under --privsep in
particular, where final admission grants no further read permission).
"""
from __future__ import annotations

import io
import json
import os
import struct
import tempfile
import unittest
import uuid
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from probolos import (daemon as daemon_mod, gate_server, ledger as ledger_mod,
                      mediawatch, protocol, rules, session, storage, sysfs,
                      usbclass)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class FakeReader:
    """Just enough of a UsbDevice for the watcher, the ledger and one_liner."""

    def __init__(self, syspath, kinds=None, safe=True):
        self.syspath = Path(syspath)
        self.name = self.syspath.name
        st = os.stat(syspath)
        self.instance_id = (st.st_dev, st.st_ino)
        self.kinds = kinds or [usbclass.KIND_STORAGE]
        self.inspection_safe = safe
        self.vendor_id, self.product_id = "0bda", "0158"
        self.serial = "READER1"
        self.claims = ["Mass Storage (SCSI)"]
        self.manufacturer, self.product = "Generic", "Card Reader"

    def label(self):
        return "Generic Card Reader"


def mbr(*entries, size_sectors=None):
    """A 512-byte MBR; entries are (type_byte, start, sectors, bootable)."""
    data = bytearray(512)
    for i, (ptype, start, sectors, boot) in enumerate(entries):
        struct.pack_into("<BBBBBBBBII", data, 446 + i * 16,
                         0x80 if boot else 0, 0, 0, 0, ptype, 0, 0, 0,
                         start, sectors)
    struct.pack_into("<H", data, 510, 0xAA55)
    return bytes(data)


def gpt_image(entries, entries_lba=2):
    """Protective MBR + GPT header + entries, as HEADER_READ would see it."""
    data = bytearray(storage.HEADER_READ)
    data[:512] = mbr((0xEE, 1, 100000, False))
    header = bytearray(92)
    header[:8] = b"EFI PART"
    struct.pack_into("<QII", header, 72, entries_lba, 128, 128)
    data[512:512 + 92] = header
    for i, (guid, attrs) in enumerate(entries):
        off = 1024 + i * 128
        data[off:off + 16] = uuid.UUID(guid).bytes_le
        struct.pack_into("<Q", data, off + 48, attrs)
    return bytes(data)


def medium(partitions=(), scheme="mbr", size=62333952, signatures=None,
           gpt_entries=(), error=None):
    return storage.MediumReport(
        device="/dev/sdz", size_sectors=size, scheme=scheme,
        partitions=[storage.Partition(i, b, t, s, n)
                    for i, (t, s, n, b) in enumerate(partitions)],
        signatures=dict(signatures or {}), gpt_entries=list(gpt_entries),
        gpt_entries_parsed=scheme == "gpt", error=error)


FAT_CARD = dict(partitions=[(0x0C, 8192, 62325760, False)],
                signatures={0: "FAT32"})
ESP_CARD = dict(partitions=[(0xEF, 2048, 1048576, False),
                            (0x0C, 1050624, 61283328, False)])


# ---------------------------------------------------------------------------
# 1. GPT entries are read, within the bytes already read
# ---------------------------------------------------------------------------

class GptEntriesAreParsed(unittest.TestCase):

    def test_esp_and_hidden_attribute_are_found(self):
        data = gpt_image([(storage.GPT_ESP_GUID, 0),
                          ("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
                           storage.GPT_ATTR_HIDDEN)])
        entries = storage.parse_gpt_entries(data)
        self.assertEqual([e.type_guid for e in entries],
                         [storage.GPT_ESP_GUID,
                          "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"])
        self.assertTrue(entries[1].attributes & storage.GPT_ATTR_HIDDEN)

    def test_entries_elsewhere_are_not_chased(self):
        """The header chooses where its entries are; we do not read there."""
        data = gpt_image([(storage.GPT_ESP_GUID, 0)], entries_lba=4096)
        self.assertIsNone(storage.parse_gpt_entries(data))

    def test_inspect_records_them(self):
        data = gpt_image([(storage.GPT_ESP_GUID, 0)])
        with tempfile.NamedTemporaryFile() as fh:
            fh.write(data + bytes(storage.PARTITION_SNIFF_READ))
            fh.flush()
            with mock.patch.object(storage, "read_size_sectors",
                                   return_value=200000):
                report = storage.inspect(fh.name)
        self.assertEqual(report.scheme, "gpt")
        self.assertTrue(report.gpt_entries_parsed)
        self.assertEqual(report.gpt_entries[0].type_guid, storage.GPT_ESP_GUID)


# ---------------------------------------------------------------------------
# 2. The media rules
# ---------------------------------------------------------------------------

class MediaRules(unittest.TestCase):

    def ids(self, findings):
        return {f.rule_id: f.severity for f in findings}

    def test_an_ordinary_card_produces_nothing(self):
        self.assertEqual(rules.media_findings(medium(**FAT_CARD)), [])

    def test_mbr_efi_system_partition_is_critical(self):
        found = self.ids(rules.media_findings(medium(**ESP_CARD)))
        self.assertEqual(found["media-efi-system-partition"],
                         rules.Severity.CRITICAL)

    def test_gpt_efi_system_partition_is_critical(self):
        esp = storage.GptEntry(0, storage.GPT_ESP_GUID, 0)
        found = self.ids(rules.media_findings(
            medium(partitions=[(0xEE, 1, 1000, False)], scheme="gpt",
                   gpt_entries=[esp])))
        self.assertIn("media-efi-system-partition", found)

    def test_hidden_partition_is_critical(self):
        found = self.ids(rules.media_findings(
            medium(partitions=[(0x1C, 2048, 1000, False)])))
        self.assertEqual(found["media-hidden-partition"],
                         rules.Severity.CRITICAL)

    def test_new_layout_is_a_warning_and_a_known_one_a_notice(self):
        new = self.ids(rules.media_findings(medium(**FAT_CARD), drift="aa"))
        known = self.ids(rules.media_findings(medium(**FAT_CARD), drift="aa",
                                              drift_known=True))
        self.assertEqual(new["media-layout-drift"], rules.Severity.WARNING)
        self.assertEqual(known["media-layout-drift"], rules.Severity.NOTICE)

    def test_insert_while_locked_is_reported_even_if_unreadable(self):
        found = self.ids(rules.media_findings(
            medium(error="its block device could not be read"), locked=True))
        self.assertEqual(set(found), {"media-inserted-while-locked"})

    def test_severity_is_overridable_like_every_other_rule(self):
        cfg = rules.RuleConfig(severity_overrides={
            "media-efi-system-partition": rules.Severity.NOTICE})
        found = self.ids(rules.media_findings(medium(**ESP_CARD), config=cfg))
        self.assertEqual(found["media-efi-system-partition"],
                         rules.Severity.NOTICE)


# ---------------------------------------------------------------------------
# 3. The drift ledger: reader identity + LUN, first layout is the baseline
# ---------------------------------------------------------------------------

class MediaLedger(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "ledger.json"
        self.dev = mock.Mock(vendor_id="0bda", product_id="0158",
                             serial="READER1")

    def test_first_is_baseline_then_drift_then_known(self):
        led = ledger_mod.Ledger(self.path)
        self.assertEqual(led.record_media(self.dev, "0", "A"), (None, False))
        self.assertEqual(led.record_media(self.dev, "0", "A"), ("A", True))
        self.assertEqual(led.record_media(self.dev, "0", "B"), ("A", False))
        self.assertEqual(led.record_media(self.dev, "0", "B"), ("A", True))

    def test_luns_are_separate_slots(self):
        led = ledger_mod.Ledger(self.path)
        led.record_media(self.dev, "0", "A")
        self.assertEqual(led.record_media(self.dev, "1", "B"), (None, False))

    def test_survives_a_restart(self):
        led = ledger_mod.Ledger(self.path)
        led.record_media(self.dev, "0", "A")
        self.assertIsNone(led.save())
        again = ledger_mod.Ledger(self.path)
        self.assertIsNone(again.load_error)
        self.assertEqual(again.record_media(self.dev, "0", "B"), ("A", False))

    def test_baseline_survives_the_bound(self):
        led = ledger_mod.Ledger(self.path)
        for i in range(ledger_mod.MAX_MEDIA_LAYOUTS * 3):
            led.record_media(self.dev, "0", f"L{i}")
        (layouts,) = led.media.values()
        self.assertEqual(len(layouts), ledger_mod.MAX_MEDIA_LAYOUTS)
        self.assertEqual(layouts[0], "L0")

    def test_malformed_media_section_is_dropped_loudly(self):
        self.path.write_text(json.dumps({
            "schema": ledger_mod.SCHEMA_VERSION,
            "fingerprint_scheme": "normalized-v1",
            "entries": {},
            "media": {"good#lun0": ["A"], "bad#lun0": [1, 2], "x": "y"}}))
        os.chmod(self.path, 0o600)
        led = ledger_mod.Ledger(self.path)
        self.assertEqual(led.media, {"good#lun0": ["A"]})
        self.assertIn("media", led.load_error)


# ---------------------------------------------------------------------------
# 4. The watcher, over a synthetic sysfs tree
# ---------------------------------------------------------------------------

class WatcherTestBase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.host = root / "sys/devices/pci0/usb1/1-2"
        self.lun = self.host / "1-2:1.0/host6/target6:0:0/6:0:0:1"
        self.disk = self.lun / "block/sdz"
        self.disk.mkdir(parents=True)
        os.symlink(self.lun, self.disk / "device")
        (self.disk / "events").write_text("media_change\n")
        (self.disk / "events_poll_msecs").write_text("2000\n")
        self.other = root / "sys/devices/pci0/ata1/host0/block/sdy"
        self.other.mkdir(parents=True)
        self.mounts = root / "mounts"
        self.mounts.write_text("")
        self.logfile = root / "audit.jsonl"

        self.size = 62333952
        self.card = medium(**FAT_CARD)
        self.inspected = []
        self.writes = []
        self.lines = []
        self.deauthorized = []

        def fake_inspect(disk):
            self.inspected.append(disk)
            return self.card

        for target, attr, value in (
                (storage, "read_size_sectors", lambda _d: self.size),
                (mediawatch.MediaWatch, "_inspect",
                 staticmethod(fake_inspect)),
                (mediawatch, "PROC_MOUNTS", str(self.mounts)),
                (sysfs, "set_authorized",
                 lambda p, v: self.writes.append((str(p), v)))):
            p = mock.patch.object(target, attr, value)
            p.start()
            self.addCleanup(p.stop)

        self.reader = FakeReader(self.host)
        self.ledger = ledger_mod.Ledger(root / "ledger.json")

    def watcher(self, policy=mediawatch.POLICY_LOG, locked=False):
        w = mediawatch.MediaWatch(
            policy=policy, ledger=self.ledger, json_log=self.logfile,
            is_locked=lambda: locked, log=self.lines.append,
            on_deauthorized=lambda dev, f: self.deauthorized.append(dev))
        self.assertTrue(w.register(self.reader, "test"))
        return w

    def change(self, w, props=None):
        w.handle("change", str(self.disk),
                 dict({"DEVTYPE": "disk", "DISK_MEDIA_CHANGE": "1"},
                      **(props or {})))

    def output(self):
        return "\n".join(str(l) for l in self.lines)


class WatcherBehaviour(WatcherTestBase):

    def test_a_card_in_a_watched_reader_is_inspected_and_reported(self):
        w = self.watcher()
        self.change(w)
        self.assertEqual(self.inspected, ["sdz"])
        self.assertIn("MEDIUM CHANGE", self.output())
        self.assertIn("LUN 1", self.output())
        entry = json.loads(self.logfile.read_text().splitlines()[-1])
        self.assertEqual(entry["event"], "media-change")
        self.assertEqual(entry["enforcement"], "logged")

    def test_a_disk_that_is_not_a_watched_readers_is_ignored(self):
        w = self.watcher()
        w.handle("change", str(self.other), {"DEVTYPE": "disk"})
        self.assertEqual(self.inspected, [])

    def test_partitions_are_ignored(self):
        w = self.watcher()
        w.handle("change", str(self.disk) + "/sdz1", {"DEVTYPE": "partition"})
        self.assertEqual(self.inspected, [])

    def test_an_empty_slot_is_not_read_and_a_removal_is_logged(self):
        w = self.watcher()
        self.size = 0
        self.change(w)
        self.assertEqual(self.inspected, [])
        self.size = 62333952
        self.change(w)
        self.size = 0
        self.change(w)
        self.assertIn("medium removed", self.output())

    def test_repeated_change_for_the_same_medium_is_reported_once(self):
        w = self.watcher()
        self.change(w)
        w.handle("change", str(self.disk), {"DEVTYPE": "disk"})  # rescan
        self.assertEqual(self.output().count("MEDIUM CHANGE"), 1)

    def test_a_different_card_is_drift_against_the_first(self):
        w = self.watcher()
        self.change(w)
        self.card = medium(partitions=[(0x07, 2048, 1000000, False)],
                           signatures={0: "exFAT"})
        self.change(w)
        self.assertIn("A medium this slot has never seen", self.output())

    def test_the_report_says_when_the_read_was_post_hoc(self):
        w = self.watcher()
        self.mounts.write_text("/dev/sdz1 /run/media/u/CARD vfat rw 0 0\n")
        self.change(w)
        self.assertIn("ALREADY MOUNTED", self.output())

    def test_the_report_says_when_automount_was_inhibited(self):
        w = self.watcher()
        self.change(w, {"UDISKS_AUTO": "0"})
        self.assertIn("inhibited for udisks", self.output())

    def test_the_report_says_when_automount_was_not_inhibited(self):
        w = self.watcher()
        self.change(w)
        self.assertIn("NOT inhibited", self.output())

    def test_a_slot_that_cannot_report_changes_is_flagged(self):
        (self.disk / "events").write_text("\n")
        w = self.watcher()
        self.change(w)
        self.assertIn("does not report media changes", self.output())

    def test_a_recycled_port_is_not_watched(self):
        w = self.watcher()
        w.hosts["1-2"].instance = (0, 0)
        self.change(w)
        self.assertEqual(self.inspected, [])
        self.assertNotIn("1-2", w.hosts)

    def test_a_composite_reader_is_never_registered(self):
        w = mediawatch.MediaWatch(log=self.lines.append)
        for kinds in ([usbclass.KIND_STORAGE, usbclass.KIND_INPUT],
                      [usbclass.KIND_STORAGE, usbclass.KIND_OTHER]):
            self.assertFalse(w.register(FakeReader(self.host, kinds), "t"))
        self.assertFalse(w.register(FakeReader(self.host, safe=False), "t"))

    def test_locked_session_is_a_finding(self):
        w = self.watcher(locked=True)
        self.change(w)
        entry = json.loads(self.logfile.read_text().splitlines()[-1])
        self.assertIn("media-inserted-while-locked",
                      [f["rule"] for f in entry["findings"]])


class WatcherEnforcement(WatcherTestBase):

    def test_log_policy_never_touches_the_reader(self):
        self.card = medium(**ESP_CARD)
        w = self.watcher(policy=mediawatch.POLICY_LOG)
        self.change(w)
        self.assertEqual(self.writes, [])
        self.assertIn("reader stays authorized", self.output())

    def test_deauthorize_policy_drops_the_whole_reader_on_critical(self):
        self.card = medium(**ESP_CARD)
        w = self.watcher(policy=mediawatch.POLICY_DEAUTHORIZE)
        self.change(w)
        self.assertEqual(self.writes, [(str(self.host), 0)])
        self.assertEqual(self.deauthorized, [self.reader])
        self.assertNotIn("1-2", w.hosts)
        entry = json.loads(self.logfile.read_text().splitlines()[-1])
        self.assertEqual(entry["enforcement"], "reader deauthorized")

    def test_deauthorize_policy_ignores_anything_below_critical(self):
        w = self.watcher(policy=mediawatch.POLICY_DEAUTHORIZE)
        self.change(w)
        self.card = medium(partitions=[(0x07, 2048, 1000000, False)])
        self.change(w)                       # drift: WARNING only
        self.assertEqual(self.writes, [])

    def test_a_refused_deauthorization_is_loud(self):
        self.card = medium(**ESP_CARD)
        w = self.watcher(policy=mediawatch.POLICY_DEAUTHORIZE)
        with mock.patch.object(sysfs, "set_authorized",
                               side_effect=OSError("denied")):
            self.change(w)
        self.assertIn("COULD NOT DEAUTHORIZE", self.output())
        self.assertEqual(self.deauthorized, [])

    def test_unknown_policy_is_refused(self):
        with self.assertRaises(ValueError):
            mediawatch.MediaWatch(policy="block-the-card")


# ---------------------------------------------------------------------------
# 5. The privileged gate: without this the watcher is dead under --privsep
# ---------------------------------------------------------------------------

class GateMediaScope(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.devices = root / "sys/devices"
        self.busview = root / "sys/bus/usb/devices"
        self.busview.mkdir(parents=True)
        self.cls = root / "sys/class"
        self.dev = root / "dev"
        self.dev.mkdir()

        self.reader = self._usb("1-2", authorized="1", classes=["08"])
        self.combo = self._usb("1-3", authorized="1", classes=["08", "03"])
        self.later = self._usb("1-4", authorized="0", classes=["08"])
        for node, owner in (("sdz", self.reader), ("sdy", self.combo),
                            ("sdx", self.later)):
            d = self.cls / "block" / node
            d.mkdir(parents=True)
            os.symlink(owner, d / "device")
            (self.dev / node).write_bytes(b"")

        for attr, value in (("USB_REAL_PREFIX", str(self.devices) + "/"),
                            ("USB_LINK_PREFIX", str(self.busview) + "/"),
                            ("SYS_CLASS_PREFIX", str(self.cls) + "/")):
            p = mock.patch.object(gate_server, attr, value)
            p.start()
            self.addCleanup(p.stop)

    def _usb(self, name, authorized, classes):
        path = self.devices / "pci0/usb1" / name
        path.mkdir(parents=True)
        (path / "authorized").write_text(authorized + "\n")
        for i, cls in enumerate(classes):
            intf = path / f"{name}:1.{i}"
            intf.mkdir()
            (intf / "bInterfaceClass").write_text(cls + "\n")
        os.symlink(path, self.busview / name)
        return path

    def gate(self, watch_media=True):
        return gate_server.GateServer(sock=None, log=lambda *_a: None,
                                      watch_media=watch_media)

    def test_off_by_default(self):
        gate = self.gate(watch_media=False)
        self.assertIsNone(gate._media_scope_parent_of(self.dev / "sdz"))
        self.assertIsNone(gate._open_scope_parent_of(self.dev / "sdz"))

    def test_a_reader_present_at_startup_is_in_scope(self):
        gate = self.gate()
        self.assertEqual(gate._media_scope_parent_of(self.dev / "sdz"),
                         self.reader)

    def test_a_composite_is_never_in_scope(self):
        gate = self.gate()
        self.assertIsNone(gate._media_scope_parent_of(self.dev / "sdy"))

    def test_a_reader_admitted_through_the_gate_enters_scope(self):
        gate = self.gate()
        self.assertNotIn(str(self.later), gate._media_hosts)
        st = self.later.stat()
        resp = gate._do_admit(protocol.Request(
            protocol.REQ_ADMIT, path=str(self.later), value=1,
            instance=(st.st_dev, st.st_ino)))
        self.assertTrue(resp.ok, resp.detail)
        self.assertEqual(gate._media_scope_parent_of(self.dev / "sdx"),
                         self.later)

    def test_a_recycled_port_leaves_scope(self):
        gate = self.gate()
        gate._media_hosts[str(self.reader)] = (0, 0)
        self.assertIsNone(gate._media_scope_parent_of(self.dev / "sdz"))

    def test_a_watched_reader_may_be_switched_off_never_on(self):
        gate = self.gate()
        on = gate._do_authorize(protocol.Request(
            protocol.REQ_AUTHORIZE, path=str(self.reader), value=1))
        self.assertFalse(on.ok)
        off = gate._do_authorize(protocol.Request(
            protocol.REQ_AUTHORIZE, path=str(self.reader), value=0))
        self.assertTrue(off.ok, off.detail)
        self.assertEqual((self.reader / "authorized").read_text(), "0")
        self.assertNotIn(str(self.reader), gate._media_hosts)

    def test_an_unwatched_live_device_still_cannot_be_switched_off(self):
        gate = self.gate()
        resp = gate._do_authorize(protocol.Request(
            protocol.REQ_AUTHORIZE, path=str(self.combo), value=0))
        self.assertEqual(resp.status, protocol.DENIED)

    def test_open_block_consults_the_media_scope(self):
        gate = self.gate()
        node = self.dev / "sdz"
        with mock.patch.object(gate_server.GateServer, "_check_block_path",
                               staticmethod(lambda _p: (node, ""))):
            resp, fd = gate._do_open_block(protocol.Request(
                protocol.REQ_OPEN_BLOCK, path=str(node)))
        self.assertTrue(resp.ok, resp.detail)
        os.close(fd)

    def test_run_gate_forwards_the_flag(self):
        seen = {}

        class Recorder:
            def __init__(self, sock, log, watch_media):
                seen["watch_media"] = watch_media

            def serve_forever(self):
                pass

        with mock.patch.object(gate_server, "GateServer", Recorder):
            gate_server.run_gate(None, watch_media=True)
        self.assertTrue(seen["watch_media"])


# ---------------------------------------------------------------------------
# 6. Wiring: daemon and command line
# ---------------------------------------------------------------------------

class DaemonWiring(unittest.TestCase):

    def setUp(self):
        self.watch = mock.Mock(spec=mediawatch.MediaWatch)
        self.engine = daemon_mod.Probolos(monitor=session.AlwaysUnlocked(),
                                          observe=0, inspect_storage=False,
                                          media_watch=self.watch)

    def test_block_events_reach_the_watcher(self):
        event = mock.Mock(subsystem="block", action="change",
                          sys_path="/sys/x/block/sdb",
                          properties={"DISK_MEDIA_CHANGE": "1"})
        self.engine._dispatch(event)
        self.watch.handle.assert_called_once_with(
            "change", "/sys/x/block/sdb", {"DISK_MEDIA_CHANGE": "1"})

    def test_usb_events_still_reach_the_gate(self):
        event = mock.Mock(subsystem="usb", action="add", sys_path="/sys/x/1-2")
        with mock.patch.object(self.engine, "_on_add") as on_add:
            self.engine._dispatch(event)
        on_add.assert_called_once_with("/sys/x/1-2")
        self.watch.handle.assert_not_called()

    def test_an_approved_reader_is_registered(self):
        from tests.test_daemon import make_device
        dev = make_device()
        with mock.patch.object(daemon_mod.sysfs, "admit_device"), \
             mock.patch.object(daemon_mod.sysfs, "set_authorized"), \
             mock.patch.object(self.engine, "_load_with_retry",
                               return_value=dev), \
             mock.patch.object(self.engine, "_ask", return_value=True), \
             mock.patch.object(daemon_mod.report, "one_liner",
                               return_value="x"), \
             mock.patch.object(daemon_mod.report, "render",
                               return_value="x"), \
             redirect_stdout(io.StringIO()):
            self.engine._on_add(str(dev.syspath))
        self.watch.register.assert_called_once_with(dev, "approved")

    def test_a_rejected_reader_is_not_registered(self):
        from tests.test_daemon import make_device
        dev = make_device()
        with mock.patch.object(daemon_mod.sysfs, "set_authorized"), \
             mock.patch.object(self.engine, "_load_with_retry",
                               return_value=dev), \
             mock.patch.object(self.engine, "_ask", return_value=False), \
             mock.patch.object(daemon_mod.report, "one_liner",
                               return_value="x"), \
             mock.patch.object(daemon_mod.report, "render",
                               return_value="x"), \
             redirect_stdout(io.StringIO()):
            self.engine._on_add(str(dev.syspath))
        self.watch.register.assert_not_called()

    def test_baseline_readers_are_registered_at_startup(self):
        from tests.test_daemon import make_device
        dev = make_device("1-7")
        dev.authorized = 1
        dev.is_root_hub = False
        with mock.patch.object(daemon_mod.sysfs, "list_devices",
                               return_value=[dev]), \
             redirect_stdout(io.StringIO()):
            self.engine.snapshot()
        self.watch.register.assert_called_once_with(dev, "present at startup")

    def test_removal_unregisters(self):
        with redirect_stdout(io.StringIO()):
            self.engine._on_remove("/sys/bus/usb/devices/1-2")
        self.watch.unregister.assert_called_once_with("1-2")

    def test_a_policy_deauthorization_puts_the_reader_back_behind_the_gate(self):
        from tests.test_daemon import make_device
        dev = make_device("1-2")
        self.engine.known.add("1-2")
        self.engine._media_policy_deauthorized(dev, [])
        self.assertNotIn("1-2", self.engine.known)


class CommandLineWiring(unittest.TestCase):

    def test_policy_without_watch_is_refused(self):
        from probolos import __main__ as cli
        with redirect_stdout(io.StringIO()), \
             mock.patch("sys.stderr", io.StringIO()), \
             self.assertRaises(SystemExit):
            cli.main(["--media-policy", "deauthorize"])

    def _run(self, argv):
        from probolos import __main__ as cli
        from probolos import privsep
        captured = {}

        def fake_start(analyzer_main, **kwargs):
            captured.update(kwargs)
            return 0

        with mock.patch.object(cli, "require_usb"), \
             mock.patch.object(cli, "require_root"), \
             mock.patch.object(privsep, "start", fake_start), \
             mock.patch.object(cli.daemon, "serve",
                               side_effect=lambda **kw: captured.update(kw)), \
             redirect_stdout(io.StringIO()):
            try:
                cli.main(argv)
            except SystemExit:
                pass
        return captured

    def test_privsep_gate_learns_the_flag_from_the_root_side(self):
        captured = self._run(["--privsep", "--no-trust", "--no-ledger",
                              "--watch-media"])
        self.assertTrue(captured["watch_media"])

    def test_direct_mode_passes_the_flag_and_policy_to_the_daemon(self):
        captured = self._run(["--no-trust", "--no-ledger", "--watch-media",
                              "--media-policy", "deauthorize"])
        self.assertTrue(captured["watch_media"])
        self.assertEqual(captured["media_policy"], "deauthorize")

    def test_off_unless_asked(self):
        captured = self._run(["--no-trust", "--no-ledger"])
        self.assertFalse(captured["watch_media"])


if __name__ == "__main__":
    unittest.main()
