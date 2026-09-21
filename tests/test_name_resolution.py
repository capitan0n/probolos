"""
Regression tests for the third security audit.

Each test below fails against the code as it stood before this round and
passes after it. They are grouped by the property being defended rather than
by the file that happened to contain the defect, because in every case the
defect was the same shape: a protection that existed on one path and not on
the sibling path that needed it just as much.

The eight findings:

  1. analyzers.run() reported a CRASHED rule engine as a NOTICE, so a device
     that broke SemanticAnalyzer read as clean and the trust path admitted it
     without asking.
  2. sysfs._DirectBackend wrote `authorized` by NAME, following symlinks --
     the default (non-privsep) deployment had no equivalent of the pinning
     gate_server.py already does.
  3. ...the same for authorized_default and the bus-wide drivers_autoprobe.
  4. gate_server._do_authorize_interface took intf.parent unvalidated, and
     _usb_device_is_blocked -- the gate's central scope check -- read
     `authorized` by name.
  5. storage.find_block_devices concatenated an unvalidated sysfs directory
     name into "/dev/{name}".
  6. session/__main__ resolved loginctl through $PATH, in a root process.
  7. daemon.pending keyed held devices by PORT, so a recycled port inherited
     another device's question; and an admitted device was never recorded, so
     a duplicate udev 'add' re-gated live hardware.
  8. agentlink.ask() silently discarded an ALWAYS answer when `always` was not
     on offer, turning a made decision into a timeout.
"""

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from probolos import (agentlink, analyzers, daemon as daemon_mod,
                      gate_server, protocol, rules, session, storage, sysfs)


# ---------------------------------------------------------------------------
# 1. A failed decisive analyzer must not read as a clean device
# ---------------------------------------------------------------------------

class CrashedRuleEngineIsNotACleanVerdict(unittest.TestCase):
    """
    The containment in analyzers.run() is correct and must stay; what was
    wrong was the SEVERITY it assigned. SemanticAnalyzer holds every CRITICAL
    identity rule, so its silence cannot be told apart from "this device is
    fine" -- and three separate consumers read the difference:

      * daemon._on_add admits a remembered device when worst() < CRITICAL
      * the terminal prompt drops to [y/N] instead of demanding the word
      * the desktop agent is offered the device as a clickable question

    so a NOTICE there was a device-triggerable fail-open.
    """

    class Exploding(analyzers.SemanticAnalyzer):
        def analyze(self, ctx):
            raise RuntimeError("descriptor walk blew up")

    class ExplodingCosmetic(analyzers.LedgerAnalyzer):
        def analyze(self, ctx):
            raise RuntimeError("history unreadable")

    def test_a_decisive_analyzer_failing_is_itself_critical(self):
        findings = analyzers.run(analyzers.Context(device=object()),
                                 analyzers=[self.Exploding()])
        self.assertEqual(rules.worst(findings), rules.Severity.CRITICAL,
                         "a crashed rule engine must not read as a clean "
                         "device; it is what produces the verdict")

    def test_the_trust_shortcut_no_longer_applies_to_it(self):
        """The precise condition daemon._on_add tests before admitting."""
        findings = analyzers.run(analyzers.Context(device=object()),
                                 analyzers=[self.Exploding()])
        self.assertFalse(rules.worst(findings) < rules.Severity.CRITICAL,
                         "a remembered device must not be waved through on "
                         "the strength of a check that never ran")

    def test_a_cosmetic_analyzer_failing_stays_a_notice(self):
        """
        The other half of the fix. Escalating EVERY failure would make a
        broken history file block a keyboard, which is the lockout the whole
        project is built to avoid.
        """
        findings = analyzers.run(analyzers.Context(device=object()),
                                 analyzers=[self.ExplodingCosmetic()])
        self.assertEqual(rules.worst(findings), rules.Severity.NOTICE)

    def test_the_run_still_continues_past_a_crash(self):
        """Containment intact: the other analyzers still ran."""
        class Quiet(analyzers.Analyzer):
            id = "quiet"
            def analyze(self, ctx):
                return [rules.Finding("saw-it", rules.Severity.INFO, "t", "e")]

        findings = analyzers.run(analyzers.Context(device=object()),
                                 analyzers=[self.Exploding(), Quiet()])
        self.assertIn("saw-it", [f.rule_id for f in findings])

    def test_every_verdict_bearing_analyzer_is_marked_decisive(self):
        """
        Guards the fix against drift. A new analyzer that carries CRITICAL
        rules and forgets `decisive` reintroduces the hole silently, so the
        list is asserted rather than trusted.
        """
        for analyzer in (analyzers.SemanticAnalyzer(),
                         analyzers.BehaviourAnalyzer(),
                         analyzers.PayloadAnalyzer(),
                         analyzers.StorageAnalyzer()):
            self.assertTrue(analyzer.decisive,
                            f"{analyzer.id} produces findings the decision "
                            f"rests on and must be marked decisive")


# ---------------------------------------------------------------------------
# 2 & 3. The direct backend must not write through a symlink
# ---------------------------------------------------------------------------

class DirectBackendNeverFollowsASymlink(unittest.TestCase):
    """
    gate_server.py pins every privileged write to a held directory descriptor
    and explains at length why. _DirectBackend -- used by the DEFAULT
    `sudo python -m probolos`, without --privsep -- did not, so the project
    had two ways to write a privileged sysfs attribute and only the less-used
    one checked what it was writing to.

    A followed symlink here is a root write of "0" or "1" into a file of the
    planter's choosing.
    """

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.victim = self.root / "victim"
        self.victim.write_text("untouched")
        self.devdir = self.root / "device"
        self.devdir.mkdir()

    def _plant(self, attribute):
        (self.devdir / attribute).symlink_to(self.victim)

    def test_authorize_refuses_a_symlinked_attribute(self):
        self._plant("authorized")
        with self.assertRaises(OSError):
            sysfs._DirectBackend().authorize(self.devdir, 1)
        self.assertEqual(self.victim.read_text(), "untouched",
                         "a symlink at <device>/authorized must not become a "
                         "root write to its target")

    def test_authorize_interface_refuses_a_symlinked_attribute(self):
        self._plant("authorized")
        with self.assertRaises(OSError):
            sysfs._DirectBackend().authorize_interface(self.devdir, 0)
        self.assertEqual(self.victim.read_text(), "untouched")

    def test_set_default_refuses_a_symlinked_attribute(self):
        """
        The most powerful attribute the tool writes: 1 here admits every
        device attached from that moment on.
        """
        self._plant("authorized_default")
        with self.assertRaises(OSError):
            sysfs._DirectBackend().set_default(self.devdir, 1)
        self.assertEqual(self.victim.read_text(), "untouched")

    def test_drivers_autoprobe_refuses_a_symlinked_attribute(self):
        """
        Bus-wide, and the one whose failure leaves a machine that binds no
        drivers at all.
        """
        autoprobe = self.devdir / "drivers_autoprobe"
        autoprobe.symlink_to(self.victim)
        with mock.patch.object(sysfs, "DRIVERS_AUTOPROBE", autoprobe):
            with self.assertRaises(OSError):
                sysfs._DirectBackend().set_drivers_autoprobe(0)
        self.assertEqual(self.victim.read_text(), "untouched")

    def test_a_real_attribute_is_still_written_normally(self):
        """The fix must not break the ordinary path it protects."""
        (self.devdir / "authorized").write_text("0")
        sysfs._DirectBackend().authorize(self.devdir, 1)
        self.assertEqual((self.devdir / "authorized").read_text(), "1")

    def test_a_symlinked_parent_directory_is_ACCEPTED(self):
        """
        Inverse of the invariant this test used to assert.

        The round-3 fix opened the parent with O_DIRECTORY|O_NOFOLLOW on the
        path as GIVEN, which refuses any symlink at the final component --
        including /sys/bus/usb/devices/<name>, which IS a symlink into
        /sys/devices/. The whole default (non-privsep) deployment failed with
        ENOTDIR on every write except _DirectBackend.admit(), which had no
        O_NOFOLLOW at all -- so the only privileged write that still worked
        was the one that switches devices ON. In a deny-by-default tool that
        was the worst possible asymmetry.

        Round 4 fixed it by resolving the path first (realpath), then opening
        the resolved directory with O_NOFOLLOW so a symlink planted BETWEEN
        the resolve and the open is still refused. The protection that
        matters -- O_NOFOLLOW on the ATTRIBUTE, plus holding the directory fd
        across the write -- is unchanged, and the four "symlinked attribute
        is refused" tests above still cover it.

        So this test now asserts the CURRENT invariant: a symlinked directory
        alias resolves to its real target and the write lands there, exactly
        as it does when the daemon walks the bus view for real.
        """
        (self.devdir / "authorized").write_text("0")
        alias = self.root / "alias"
        alias.symlink_to(self.devdir)
        sysfs._DirectBackend().authorize(alias, 1)
        self.assertEqual(
            (self.devdir / "authorized").read_text(), "1",
            "the write must land on the real directory the alias points to; "
            "refusing symlinked directories broke the bus view entirely")

    def test_no_descriptor_is_leaked_by_a_refusal(self):
        """
        The refusal path opens the directory and then fails on the attribute.
        A daemon gets one of these per attachment, so a leak here is a slow
        exhaustion of the process that holds the gate.
        """
        self._plant("authorized")
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(50):
            try:
                sysfs._DirectBackend().authorize(self.devdir, 1)
            except OSError:
                pass
        after = len(os.listdir("/proc/self/fd"))
        self.assertLessEqual(after - before, 2,
                             "refusals must not leak descriptors")


# ---------------------------------------------------------------------------
# 4. The gate's own scope check
# ---------------------------------------------------------------------------

class GateScopeCheckIsNotRedirectable(unittest.TestCase):
    """
    _usb_device_is_blocked answers "is this device under quarantine?", and
    that answer is the entire scoping rule for open_input, open_block and
    interface authorization. It read `authorized` by name, so a symlink there
    aimed the gate's central check at a file of the analyzer's choosing -- and
    a "0" read out of that file turns every scope check in the class into a
    yes. The WRITES were pinned and the read that authorizes them was not,
    which is the wrong half to leave open.
    """

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.devdir = self.root / "1-1"
        self.devdir.mkdir()

    def test_a_symlinked_authorized_does_not_read_as_blocked(self):
        decoy = self.root / "decoy"
        decoy.write_text("0")
        (self.devdir / "authorized").symlink_to(decoy)
        self.assertFalse(
            gate_server.GateServer._usb_device_is_blocked(self.devdir),
            "a symlinked `authorized` must not be able to claim quarantine")

    def test_a_real_blocked_device_still_reads_as_blocked(self):
        (self.devdir / "authorized").write_text("0")
        self.assertTrue(
            gate_server.GateServer._usb_device_is_blocked(self.devdir))

    def test_a_real_live_device_still_reads_as_live(self):
        (self.devdir / "authorized").write_text("1")
        self.assertFalse(
            gate_server.GateServer._usb_device_is_blocked(self.devdir))

    def test_a_missing_attribute_fails_closed(self):
        self.assertFalse(
            gate_server.GateServer._usb_device_is_blocked(self.devdir))

    def test_interface_parent_must_pass_safe_usb_path(self):
        """
        `intf.parent` was plain path arithmetic on an analyzer-supplied
        string: the gate trusting the analyzer to describe the very
        relationship the gate exists to verify. A parent that is not a
        genuine, bus-reachable USB device is now refused outright.
        """
        server = gate_server.GateServer(mock.Mock())
        intf = self.root / "1-1:1.0"
        intf.mkdir()
        (intf / "authorized").write_text("0")

        with mock.patch.object(server, "_safe_usb_path",
                               side_effect=lambda p: (
                                   intf if str(p) == str(intf) else None)):
            resp = server._do_authorize_interface(protocol.Request(
                protocol.REQ_AUTHORIZE_INTERFACE, str(intf), 1))

        self.assertEqual(resp.status, protocol.DENIED)
        self.assertIn("parent", resp.detail)


# ---------------------------------------------------------------------------
# 5. Block device names
# ---------------------------------------------------------------------------

class OnlyWholeUsbDisksAreEverOpened(unittest.TestCase):
    """
    The directory entry under `block/` was concatenated straight into
    "/dev/{name}" and handed to os.open() in the direct backend. The
    privileged gate refuses anything but /dev/sdX, so under --privsep this was
    a denied request -- but the direct backend has no such gate, and the two
    halves must agree about what a whole USB disk is rather than one relying
    on the other.
    """

    def _tree(self, *names):
        root = Path(tempfile.mkdtemp())
        block = root / "host0" / "target" / "block"
        block.mkdir(parents=True)
        for name in names:
            (block / name).mkdir()
        return root

    def test_a_traversal_name_is_refused(self):
        """
        ".." cannot be mkdir'd, so the escape is exercised through the filter
        with the names os.walk would hand it. A name containing a separator or
        a dot-dot leaves /dev entirely once concatenated into "/dev/{name}",
        which is what made this a containment failure rather than a tidiness
        one.
        """
        for hostile in ("..", "../../etc/shadow", "sda/../../dev/nvme0n1",
                        ".", "", "sd a"):
            self.assertFalse(storage._WHOLE_DISK_NAME.match(hostile),
                             f"{hostile!r} must never become a /dev path")

    def test_a_plausible_tree_yields_only_the_whole_disk(self):
        root = self._tree("sda", "sda1")
        self.assertEqual(storage.find_block_devices(root), ["/dev/sda"])

    def test_a_partition_node_is_refused(self):
        """
        Probolos inspects the medium it was handed, not a partition of it: a
        partition node would let it reach into a disk it was never asked about.
        """
        root = self._tree("sda", "sda1", "sda2")
        self.assertEqual(storage.find_block_devices(root), ["/dev/sda"])

    def test_an_internal_disk_name_is_refused(self):
        root = self._tree("nvme0n1", "mmcblk0", "sdb")
        self.assertEqual(storage.find_block_devices(root), ["/dev/sdb"])

    def test_mapper_and_loop_names_are_refused(self):
        root = self._tree("dm-0", "loop3", "sdc")
        self.assertEqual(storage.find_block_devices(root), ["/dev/sdc"])

    def test_the_gate_and_the_finder_agree(self):
        """
        Same rule on both sides of the split. If these two regexes ever drift,
        one deployment mode silently inspects something the other refuses.
        """
        for name in ("sda", "sdz", "sdaa"):
            self.assertTrue(storage._WHOLE_DISK_NAME.match(name))
            self.assertTrue(gate_server._BLOCK_NAME.match(name))
        for name in ("sda1", "nvme0n1", "dm-0", "..", "loop0", ""):
            self.assertFalse(storage._WHOLE_DISK_NAME.match(name))
            self.assertFalse(gate_server._BLOCK_NAME.match(name))


# ---------------------------------------------------------------------------
# 6. loginctl
# ---------------------------------------------------------------------------

class LoginctlIsNotResolvedThroughPath(unittest.TestCase):
    """
    shutil.which() walks $PATH, and this runs as root -- once a second from
    the daemon's poll loop, and again for every device. sudo preserves PATH
    under a !secure_path or env_keep configuration and a systemd unit can be
    given any Environment=PATH at all, so a writable directory earlier in PATH
    turned "ask logind whether the screen is locked" into "execute whatever is
    called loginctl", as root.

    In __main__ it is worse than an exec: a fake loginctl that simply PRINTS a
    chosen Name= hands the agent slot -- who may answer questions about
    hardware -- to a uid of its choosing.
    """

    def setUp(self):
        self.fake = Path(tempfile.mkdtemp())
        impostor = self.fake / "loginctl"
        impostor.write_text("#!/bin/sh\necho owned\n")
        impostor.chmod(0o755)
        self._path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{self.fake}:{self._path}"

    def tearDown(self):
        os.environ["PATH"] = self._path

    def test_a_planted_loginctl_on_path_is_never_chosen(self):
        found = session._find_loginctl()
        self.assertNotEqual(found, str(self.fake / "loginctl"))
        if found is not None:
            self.assertIn(found, session._LOGINCTL_CANDIDATES)

    def test_the_monitor_does_not_pick_it_up_either(self):
        monitor = session.LogindMonitor()
        self.assertNotEqual(monitor._binary, str(self.fake / "loginctl"))

    def test_only_absolute_candidates_are_considered(self):
        for candidate in session._LOGINCTL_CANDIDATES:
            self.assertTrue(candidate.startswith("/"),
                            "a relative candidate would reintroduce the hole")

    def test_a_non_executable_candidate_is_skipped(self):
        decoy = self.fake / "loginctl-noexec"
        decoy.write_text("")
        decoy.chmod(0o644)
        with mock.patch.object(session, "_LOGINCTL_CANDIDATES", (str(decoy),)):
            self.assertIsNone(session._find_loginctl())

    def test_a_directory_named_loginctl_is_skipped(self):
        decoy = self.fake / "as-a-dir"
        decoy.mkdir()
        with mock.patch.object(session, "_LOGINCTL_CANDIDATES", (str(decoy),)):
            self.assertIsNone(session._find_loginctl())


# ---------------------------------------------------------------------------
# 7. Port is not device
# ---------------------------------------------------------------------------

def _device(name="3-9", instance=(7, 4242)):
    dev = mock.Mock(spec=sysfs.UsbDevice)
    dev.name = name
    dev.syspath = Path(f"/sys/bus/usb/devices/{name}")
    dev.instance_id = instance
    dev.is_root_hub = False
    dev.kinds = ["storage"]
    dev.claims = []
    dev.vendor_id, dev.product_id, dev.serial = "0951", "1665", "A"
    dev.raw_descriptors = b"\x12\x01"
    dev.removable = "removable"
    dev.interfaces, dev.interface_classes = [], []
    dev.manufacturer, dev.product = "K", "DT"
    dev.parse_error = dev.descriptor_set = None
    dev.string_notes, dev.string_note_fields = [], {}
    dev.speed, dev.inspection_safe = "480", True
    dev.label.return_value = "K DT"
    return dev


class AHeldQuestionBelongsToADeviceNotAPort(unittest.TestCase):
    """
    A sysfs name like "1-4" is a PORT. The held queue stored only that name
    and its path, so an attacker with physical access -- the threat the whole
    lock policy exists for -- could pull the held device while the screen was
    locked and insert their own at the same port. Both are named "1-4", and
    the operator's question, and their expectation of what they were being
    asked about, transferred silently to the substitute.
    """

    def test_a_recycled_port_does_not_inherit_the_question(self):
        engine = daemon_mod.Probolos(observe=0,
                                     monitor=session.FixedState(False))
        engine.pending["3-9"] = (Path("/sys/bus/usb/devices/3-9"), (7, 4242))

        asked = []
        with mock.patch.object(Path, "exists", return_value=True), \
             mock.patch.object(engine, "_still_same_device", return_value=False), \
             mock.patch.object(engine, "_on_add",
                               side_effect=lambda p, was_held=False: asked.append(p)):
            engine._drain_pending()

        self.assertEqual(asked, [], "a different device at the same port must "
                                    "not be asked about under the old entry")
        self.assertEqual(engine.pending, {})

    def test_the_same_device_is_still_asked_about(self):
        engine = daemon_mod.Probolos(observe=0,
                                     monitor=session.FixedState(False))
        engine.pending["3-9"] = (Path("/sys/bus/usb/devices/3-9"), (7, 4242))

        asked = []
        with mock.patch.object(Path, "exists", return_value=True), \
             mock.patch.object(engine, "_still_same_device", return_value=True), \
             mock.patch.object(engine, "_on_add",
                               side_effect=lambda p, was_held=False: asked.append(p)):
            engine._drain_pending()

        self.assertEqual(asked, ["/sys/bus/usb/devices/3-9"])

    def test_still_same_device_compares_the_real_inode(self):
        root = Path(tempfile.mkdtemp())
        devdir = root / "3-9"
        devdir.mkdir()
        st = devdir.stat()
        self.assertTrue(daemon_mod.Probolos._still_same_device(
            devdir, (st.st_dev, st.st_ino)))
        self.assertFalse(daemon_mod.Probolos._still_same_device(
            devdir, (st.st_dev, st.st_ino + 1)))

    def test_a_vanished_path_is_not_the_same_device(self):
        self.assertFalse(daemon_mod.Probolos._still_same_device(
            Path("/nonexistent/3-9"), (1, 2)))

    def test_queueing_records_the_instance(self):
        engine = daemon_mod.Probolos(observe=0,
                                     monitor=session.FixedState(True),
                                     lock_policy=session.POLICY_QUEUE)
        dev = _device()
        with mock.patch.object(daemon_mod.sysfs, "set_authorized"), \
             mock.patch.object(daemon_mod.report, "one_liner", return_value="x"):
            engine._hold_until_unlocked(dev)
        self.assertEqual(engine.pending["3-9"], (dev.syspath, (7, 4242)))


class AnAdmittedDeviceIsNotReGated(unittest.TestCase):
    """
    `known` only ever held the startup baseline: nothing recorded that a
    device had been admitted. udev delivers duplicate 'add' events routinely
    (a `udevadm trigger`, a settle, a subsystem rescan), and each one re-ran
    the whole gate on hardware that was past it -- including _quarantine(),
    which writes authorized=0 and back to 1 on a device the user is USING and
    takes an EVIOCGRAB on input they expect to reach their session.
    """

    def _engine(self):
        return daemon_mod.Probolos(observe=0, inspect_storage=False,
                                   monitor=session.FixedState(False),
                                   lock_policy=session.POLICY_IGNORE)

    def _add(self, engine, dev, approve=True):
        with mock.patch.object(daemon_mod.sysfs, "admit_device"), \
             mock.patch.object(daemon_mod.sysfs, "set_authorized"), \
             mock.patch.object(engine, "_load_with_retry", return_value=dev), \
             mock.patch.object(engine, "_ask", return_value=approve), \
             mock.patch.object(daemon_mod.report, "render", return_value=""), \
             mock.patch.object(daemon_mod.report, "one_liner", return_value="x"):
            engine._on_add(str(dev.syspath))

    def test_an_approved_device_is_recorded_as_known(self):
        engine, dev = self._engine(), _device()
        self._add(engine, dev, approve=True)
        self.assertIn("3-9", engine.known,
                      "a device past the gate must not be gated again")

    def test_a_second_add_for_an_approved_device_is_ignored(self):
        engine, dev = self._engine(), _device()
        self._add(engine, dev, approve=True)

        asked = []
        with mock.patch.object(engine, "_load_with_retry",
                               side_effect=lambda p: asked.append(p)):
            engine._on_add(str(dev.syspath))
        self.assertEqual(asked, [], "a duplicate udev 'add' must not re-run "
                                    "the gate on live hardware")

    def test_a_rejected_device_is_NOT_recorded(self):
        """
        The other direction matters just as much: a device the user refused
        must be asked about again if it comes back, not silently ignored.
        """
        engine, dev = self._engine(), _device()
        self._add(engine, dev, approve=False)
        self.assertNotIn("3-9", engine.known)

    def test_removal_clears_the_record(self):
        engine, dev = self._engine(), _device()
        self._add(engine, dev, approve=True)
        engine._on_remove(str(dev.syspath))
        self.assertNotIn("3-9", engine.known,
                         "the port must be gated again after an unplug")


# ---------------------------------------------------------------------------
# 8. A decision that was made must not evaporate
# ---------------------------------------------------------------------------

class AnUnofferedAlwaysIsDowngradedNotDiscarded(unittest.TestCase):
    """
    `continue` threw the answer away and went back to waiting, so a user who
    clicked a button got a question that then timed out into a denial -- and
    the daemon, seeing None, announced "no answer from the desktop agent" and
    re-asked in a terminal the user may not have been looking at.

    "Always" is "yes" plus "remember it". With remembering not on offer, the
    honest reading is the yes without the remembering, which is strictly LESS
    than the user asked for and so cannot grant anything unintended.
    """

    def _link_answering(self, answer):
        import json
        link = agentlink.AgentLink(Path("/nonexistent/agent.sock"),
                                   log=lambda *a: None)
        conn = mock.Mock()
        link._conn = conn
        sent = {}

        def sendall(payload):
            sent["id"] = json.loads(payload.decode())["id"]

        conn.sendall.side_effect = sendall
        conn.gettimeout.return_value = 1.0

        def recv(*_a, **_k):
            if "id" not in sent:
                raise BlockingIOError
            return (json.dumps({"type": agentlink.MSG_ANSWER,
                                "id": sent["id"],
                                "answer": answer}) + "\n").encode()

        conn.recv.side_effect = recv
        return link

    def test_always_without_the_offer_becomes_yes(self):
        link = self._link_answering(agentlink.ANSWER_ALWAYS)
        self.assertEqual(
            link.ask("t", "b", "none", allow_always=False, timeout=5),
            agentlink.ANSWER_YES,
            "a decision the user made must not be silently dropped")

    def test_always_with_the_offer_stays_always(self):
        link = self._link_answering(agentlink.ANSWER_ALWAYS)
        self.assertEqual(
            link.ask("t", "b", "none", allow_always=True, timeout=5),
            agentlink.ANSWER_ALWAYS)

    def test_no_is_still_no(self):
        link = self._link_answering(agentlink.ANSWER_NO)
        self.assertEqual(
            link.ask("t", "b", "none", allow_always=False, timeout=5),
            agentlink.ANSWER_NO)

    def test_unavailable_is_still_not_a_decision(self):
        """None means "fall back to the terminal", never "the user said no"."""
        link = self._link_answering(agentlink.ANSWER_UNAVAILABLE)
        self.assertIsNone(
            link.ask("t", "b", "none", allow_always=False, timeout=5))


if __name__ == "__main__":
    unittest.main()
