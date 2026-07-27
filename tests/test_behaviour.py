"""
Tests for stage 3 behavioural judgement.

No hardware, no root, no evdev: the analysis takes a plain Observation, so the
timing logic that decides whether a device is an attacker runs in CI on any
machine. That was the reason for splitting observation from judgement.
"""

import unittest

from cerberus import quarantine, rules


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
