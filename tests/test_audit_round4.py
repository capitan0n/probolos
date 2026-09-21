"""
Regression tests for the round-4 audit.

Every test here fails on the code as it stood before the round-4 fixes. They
are written against the behaviour the fix guarantees, not against its
implementation, so a later refactor that reintroduces the bug still trips them.

Run with:  python -m unittest tests.test_audit_round4 -v
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from probolos import (analyzers, descriptors, gate, ledger as ledger_mod,
                      report, rules, safety, sysfs, textsafe)
from probolos import __main__ as cli


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def descriptor_blob(*interfaces, bcd_device=0x0100, vid=0x0951, pid=0x1666):
    """A device descriptor, one configuration, and N interface descriptors."""
    out = bytes([18, 0x01]) + (0x0200).to_bytes(2, "little")
    out += bytes([0, 0, 0, 64])
    out += vid.to_bytes(2, "little") + pid.to_bytes(2, "little")
    out += bcd_device.to_bytes(2, "little") + bytes([1, 2, 3, 1])
    out += bytes([9, 0x02]) + (9 + 9 * len(interfaces)).to_bytes(2, "little")
    out += bytes([len(interfaces), 1, 0, 0x80, 250])
    for number, (cls, sub, proto) in enumerate(interfaces):
        out += bytes([9, 0x04, number, 0, 1, cls, sub, proto, 0])
    return out


def make_device(raw=None, *, manufacturer="Kingston", product="DataTraveler",
                serial="AABBCCDD", removable="removable",
                syspath="/sys/devices/pci0000:00/usb1/1-4", name="1-4"):
    raw = descriptor_blob((0x08, 0x06, 0x50)) if raw is None else raw
    return sysfs.UsbDevice(
        syspath=Path(syspath), name=name, vendor_id="0951", product_id="1666",
        manufacturer=manufacturer, product=product, serial=serial,
        bus=1, device_num=7, speed="480", authorized=0, device_class=0,
        descriptor_set=descriptors.parse(raw), raw_descriptors=raw,
        removable=removable, instance_id=(1, 1000))


class FakeSysfs:
    """A throwaway tree shaped like the real one: real dirs, bus-view symlinks."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="probolos-test-"))
        self.hub = self.root / "devices/pci0000:00/0000:00:14.0/usb1"
        self.hub.mkdir(parents=True)
        (self.hub / "authorized_default").write_text("1\n")
        (self.hub / "authorized").write_text("1\n")
        (self.hub / "idVendor").write_text("1d6b\n")
        (self.hub / "idProduct").write_text("0002\n")
        self.bus = self.root / "bus/usb/devices"
        self.bus.mkdir(parents=True)
        os.symlink(self.hub, self.bus / "usb1")

    def add_device(self, name, parent=None, removable="removable",
                   authorized="0"):
        directory = (parent or self.hub) / name
        directory.mkdir()
        (directory / "authorized").write_text(f"{authorized}\n")
        (directory / "idVendor").write_text("abcd\n")
        (directory / "idProduct").write_text("1234\n")
        (directory / "removable").write_text(f"{removable}\n")
        link = self.bus / name
        if not link.exists():
            os.symlink(directory, link)
        return directory

    def destroy(self):
        shutil.rmtree(self.root, ignore_errors=True)


# ---------------------------------------------------------------------------
# P1 -- the privileged write must survive the bus view, which is all symlinks
# ---------------------------------------------------------------------------

class BusViewWrites(unittest.TestCase):
    """
    /sys/bus/usb/devices/<name> is a SYMLINK. O_DIRECTORY|O_NOFOLLOW applied to
    the unresolved path fails with ENOTDIR on every one of them, which meant the
    direct backend could not close the gate, could not re-block a device, and
    could not run --release -- while admit(), which lacked the flag, still
    switched devices on.
    """

    def setUp(self):
        self.fake = FakeSysfs()
        self._saved = sysfs.USB_DEVICES
        sysfs.USB_DEVICES = self.fake.bus

    def tearDown(self):
        sysfs.USB_DEVICES = self._saved
        self.fake.destroy()

    def test_set_authorized_default_through_the_bus_view(self):
        hub = sysfs.list_root_hubs()[0]
        self.assertTrue(hub.is_symlink(), "fixture must mirror the real layout")
        sysfs.set_authorized_default(hub, 0)
        self.assertEqual(
            (self.fake.hub / "authorized_default").read_text().strip(), "0")

    def test_set_authorized_through_the_bus_view(self):
        real = self.fake.add_device("1-4")
        device = [d for d in sysfs.list_devices() if d.name == "1-4"][0]
        self.assertTrue(device.syspath.is_symlink())
        sysfs.set_authorized(device.syspath, 1)
        self.assertEqual((real / "authorized").read_text().strip(), "1")

    def test_gate_actually_closes(self):
        with gate.AuthorizationGate(dry_run=False, log=lambda *_a: None):
            self.assertEqual(
                (self.fake.hub / "authorized_default").read_text().strip(), "0",
                "the gate reported success without closing anything")
        self.assertEqual(
            (self.fake.hub / "authorized_default").read_text().strip(), "1")

    def test_symlinked_attribute_is_still_refused(self):
        """The protection that matters is unchanged: O_NOFOLLOW on the file."""
        real = self.fake.add_device("1-5")
        target = self.fake.root / "stolen"
        target.write_text("untouched")
        (real / "authorized").unlink()
        os.symlink(target, real / "authorized")
        with self.assertRaises(OSError):
            sysfs.set_authorized(self.fake.bus / "1-5", 1)
        self.assertEqual(target.read_text(), "untouched")

    def test_admit_and_reblock_agree_about_the_same_path(self):
        """
        The asymmetry was the dangerous part: in a deny-by-default tool, the
        write that switches a device ON must never be the only one that works.
        """
        real = self.fake.add_device("1-6")
        device = [d for d in sysfs.list_devices() if d.name == "1-6"][0]
        sysfs.admit_device(device)
        self.assertEqual((real / "authorized").read_text().strip(), "1")
        sysfs.set_authorized(device.syspath, 0)
        self.assertEqual((real / "authorized").read_text().strip(), "0")


# ---------------------------------------------------------------------------
# P2 -- removable=fixed is only platform testimony on a root-hub port
# ---------------------------------------------------------------------------

class FixedPortExemption(unittest.TestCase):
    """
    A device claiming `fixed` skips analyzers, quarantine and the prompt
    entirely. Behind an external hub that claim comes from the hub's own
    DeviceRemovable bitmap, so one hostile hub disabled the gate for everything
    plugged into it.
    """

    def setUp(self):
        self.fake = FakeSysfs()
        self.policy = safety.SafetyPolicy()

    def tearDown(self):
        self.fake.destroy()

    def _device_at(self, path, removable="fixed"):
        return make_device(
            descriptor_blob((0x08, 0x06, 0x50), (0x03, 0x01, 0x01)),
            removable=removable, syspath=str(path), name=path.name)

    def test_soldered_device_on_a_root_hub_port_is_still_protected(self):
        internal = self.fake.add_device("1-3", removable="fixed")
        self.assertEqual(
            self.policy.is_protected(self._device_at(internal)),
            "device is on a non-removable (internal) port")

    def test_internal_device_behind_an_internal_hub_is_still_protected(self):
        """No regression for laptops whose camera sits behind a soldered hub."""
        hub = self.fake.add_device("1-2", removable="fixed")
        camera = self.fake.add_device("1-2.1", parent=hub, removable="fixed")
        self.assertIsNotNone(self.policy.is_protected(self._device_at(camera)))

    def test_device_behind_a_hostile_hub_is_not_exempt(self):
        rogue = self.fake.add_device("1-4", removable="removable")
        victim = self.fake.add_device("1-4.2", parent=rogue, removable="fixed")
        self.assertIsNone(
            self.policy.is_protected(self._device_at(victim)),
            "a hub's own firmware must not be able to switch the gate off")

    def test_unreadable_ancestor_denies_the_exemption(self):
        hub = self.fake.add_device("1-7", removable="fixed")
        child = self.fake.add_device("1-7.1", parent=hub, removable="fixed")
        (hub / "removable").unlink()
        self.assertIsNone(self.policy.is_protected(self._device_at(child)))

    def test_bus_view_path_still_resolves_to_the_real_chain(self):
        internal = self.fake.add_device("1-8", removable="fixed")
        self.assertIsNotNone(
            self.policy.is_protected(self._device_at(self.fake.bus / "1-8")),
            "the flat bus view must be resolved before the chain is walked")

    def test_operator_allowlist_is_unaffected(self):
        policy = safety.SafetyPolicy(allowed_ports=["1-9"])
        rogue = self.fake.add_device("1-9", removable="removable")
        self.assertIn("allowlist", policy.is_protected(self._device_at(rogue)))


# ---------------------------------------------------------------------------
# P3 -- a decision recorded is not a decision endorsed
# ---------------------------------------------------------------------------

class DescriptorDriftSurvivesRecording(unittest.TestCase):

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix="probolos-ledger-"))
        self.path = self.directory / "ledger.json"
        # Same identity, same single storage interface, different firmware
        # revision: drift is the ONLY signal that separates these two.
        self.genuine = make_device(descriptor_blob((0x08, 0x06, 0x50),
                                                   bcd_device=0x0100))
        self.reflashed = make_device(descriptor_blob((0x08, 0x06, 0x50),
                                                     bcd_device=0x0110))

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def _seed(self):
        led = ledger_mod.Ledger(self.path)
        led.record(self.genuine, "user approved", approved=True)
        led.save()

    def _drift(self, device):
        led = ledger_mod.Ledger(self.path)
        findings = analyzers.run(analyzers.Context(device=device, ledger=led))
        return any(f.rule_id == "descriptor-drift" for f in findings)

    def _record(self, device, reason, approved):
        led = ledger_mod.Ledger(self.path)
        led.record(device, reason, approved=approved)
        led.save()

    def test_genuine_device_never_drifts(self):
        self._seed()
        self.assertFalse(self._drift(self.genuine))

    def test_drift_is_reported_on_first_appearance(self):
        self._seed()
        self.assertTrue(self._drift(self.reflashed))

    def test_drift_survives_a_refusal(self):
        self._seed()
        self.assertTrue(self._drift(self.reflashed))
        self._record(self.reflashed, "user rejected", approved=False)
        self.assertTrue(self._drift(self.reflashed),
                        "refusing a drifted device must not adopt its blob")

    def test_drift_survives_being_held_while_the_screen_was_locked(self):
        """
        The worst case: _hold_until_unlocked() records before anybody has been
        asked anything, so the alarm was erased without a human ever seeing it.
        """
        self._seed()
        self._record(self.reflashed, "held: screen locked", approved=False)
        self.assertTrue(self._drift(self.reflashed))

    def test_approval_is_what_moves_the_baseline(self):
        self._seed()
        self._record(self.reflashed, "user approved", approved=True)
        self.assertFalse(self._drift(self.reflashed),
                         "a firmware update the user accepted must stop nagging")
        self.assertTrue(self._drift(self.genuine),
                        "and the previous revision is now the drifted one")

    def test_old_ledger_carrying_the_new_scheme_marker_is_migrated(self):
        """
        A ledger written by round 4 (raw-blob fingerprint, `baseline_hash`
        already added) carries the entry through `fingerprint_scheme:
        normalized-v1` via Ledger.load(); from_raw is then free to trust the
        stored baseline. The wider migration -- pre-round-4 ledgers with the
        raw-blob baseline -- is covered by
        tests.test_normalized_fingerprint.OldLedgerMigration.
        """
        entry = ledger_mod.Entry.from_raw({
            "identity": "0951:1666:AABBCCDD",
            "descriptor_hash": "bbbb",
            "first_seen": 1.0, "last_seen": 2.0, "times_seen": 2,
            "known_hashes": ["aaaa", "bbbb"],
            "fingerprint_scheme": "normalized-v1",
        })
        self.assertEqual(entry.baseline_hash, "aaaa",
                         "known_hashes[0] is the surviving evidence")

    def test_unreadable_descriptors_never_become_a_baseline(self):
        blind = make_device()
        blind.raw_descriptors = None
        blind.descriptor_set = None
        led = ledger_mod.Ledger(self.path)
        led.record(blind, "user rejected", approved=False)
        self.assertEqual(led.entries[ledger_mod.identity_of(blind)].baseline_hash,
                         "", "a failure to read must not manufacture drift")


# ---------------------------------------------------------------------------
# P4 -- the device does not get to draw on the decision screen
# ---------------------------------------------------------------------------

class ReportBoxHoldsItsShape(unittest.TestCase):

    EXPECTED = report.WIDTH + 2

    def _rows(self, block):
        return [line for line in block.splitlines()
                if line.startswith(("┌", "└", "├", "│"))]

    def _assert_square(self, block, label):
        for line in self._rows(block):
            self.assertEqual(
                textsafe.display_width(line), self.EXPECTED,
                f"{label}: row is {textsafe.display_width(line)} columns, "
                f"box is {self.EXPECTED}: {line[:80]!r}")

    def test_ordinary_device(self):
        device = make_device(manufacturer="PixArt", product="USB Optical Mouse")
        self._assert_square(report.render(device, rules.evaluate(device)),
                            "ordinary")

    def test_long_ascii_name_cannot_push_the_border_off(self):
        device = make_device(product="Logitech USB Receiver " + "A" * 100)
        self._assert_square(report.render(device, rules.evaluate(device)),
                            "long ASCII")

    def test_wide_glyphs_are_measured_in_columns(self):
        device = make_device(manufacturer="羅技",
                             product="無線鍵盤滑鼠組" * 3)
        self._assert_square(report.render(device, rules.evaluate(device)),
                            "CJK")

    def test_device_cannot_forge_a_row_of_the_report(self):
        forged = ("Wireless Mouse" + " " * 44 + "│"
                  + " No inconsistencies found in what it claims"
                  + " " * 18 + "│")
        device = make_device(product=forged)
        block = report.render(device, rules.evaluate(device))
        self._assert_square(block, "forged border")

    def test_a_long_unbroken_token_inside_a_finding_is_split_not_dropped(self):
        name = "Flash" + "Z" * 90          # trips self-contradictory-identity
        device = make_device(
            descriptor_blob((0x03, 0x01, 0x01)), product=name)
        findings = rules.evaluate(device)
        self.assertTrue(any(f.rule_id == "self-contradictory-identity"
                            for f in findings))
        block = report.render(device, findings)
        self._assert_square(block, "device name inside a finding")
        self.assertIn("ZZZ", block, "the evidence must survive the wrapping")

    def test_combining_marks_do_not_shrink_the_box(self):
        device = make_device(product="Kingston" + "́" * 40)
        self._assert_square(report.render(device, rules.evaluate(device)),
                            "stacked marks")

    def test_split_width_loses_nothing(self):
        text = "abc" + "字" * 10 + "def"
        pieces = textsafe.split_width(text, 7)
        self.assertEqual("".join(pieces), text)
        for piece in pieces:
            self.assertLessEqual(textsafe.display_width(piece), 7)


# ---------------------------------------------------------------------------
# P5 -- the optional agent must not be able to stop the gate
# ---------------------------------------------------------------------------

class AgentIdentityIsNotFatal(unittest.TestCase):

    class Args:
        def __init__(self, agent=True, agent_user=None):
            self.agent = agent
            self.agent_user = agent_user

    def setUp(self):
        self._saved = cli._active_session_user
        cli._active_session_user = lambda: None      # as at boot

    def tearDown(self):
        cli._active_session_user = self._saved

    def test_undetectable_desktop_user_does_not_exit(self):
        try:
            self.assertIsNone(cli._resolve_agent_identity(self.Args()))
        except SystemExit as exc:                     # pragma: no cover
            self.fail(f"the gate refused to run over a missing agent: {exc}")

    def test_explicit_but_unknown_agent_user_still_exits(self):
        with self.assertRaises(SystemExit):
            cli._resolve_agent_identity(
                self.Args(agent_user="no-such-user-probolos-test"))

    def test_agent_off_resolves_to_nothing(self):
        self.assertIsNone(cli._resolve_agent_identity(self.Args(agent=False)))


if __name__ == "__main__":
    unittest.main()
