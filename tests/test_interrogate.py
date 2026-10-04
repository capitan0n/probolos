"""
The offline half of the interrogation study, with a fake device.

interrogate.py sends control transfers to real hardware for a research study
(CAPABILITIES.md §1.11); it is not on the daemon's path and is left out of
coverage. What it decides without hardware is still worth pinning, because a
mistake there corrupts the study's data silently: which probes run and in what
order, what --gentle leaves out, how a failure is classified, and that every
row the study writes has the columns its CSV header names.

Covers probolos.interrogate.
"""

from __future__ import annotations

import unittest

from probolos import interrogate


class FakeDevice:
    """
    Stands in for a pyusb device: answers ctrl_transfer, records every request.

    `fail` maps a bRequest to the exception that request raises. Answers are
    a buffer of the requested length, as a device would return for IN
    requests; OUT requests return the number of bytes written.
    """

    def __init__(self, fail=None):
        self.fail = fail or {}
        self.requests = []

    def ctrl_transfer(self, bm_request_type, b_request, w_value, w_index,
                      data_or_length, timeout=None):
        self.requests.append((bm_request_type, b_request, w_value))
        if b_request in self.fail:
            raise self.fail[b_request]
        if isinstance(data_or_length, int):
            return bytes(min(data_or_length, 18))
        return len(data_or_length)


INTRUSIVE = {p.name for p in interrogate.PROBES if not p.benign}


def _intrusive_request(request):
    """True for the requests only intrusive probes send."""
    bm_request_type, b_request, w_value = request
    return (b_request == 0x99
            or bm_request_type == interrogate.DIR_OUT_CLASS_INTERFACE
            or (b_request == interrogate.REQ_GET_DESCRIPTOR
                and w_value == (interrogate.DESC_STRING << 8) | 0xEE))


class WhatIsAsked(unittest.TestCase):

    def test_benign_probes_run_first(self):
        """An intrusive probe that wedges the device must not cost the rest."""
        dev = FakeDevice()
        results = interrogate.interrogate(dev)
        order = list(results)
        benign = [n for n in order if n not in INTRUSIVE]
        self.assertEqual(order[:len(benign)], benign)
        first_intrusive = next(i for i, r in enumerate(dev.requests)
                               if _intrusive_request(r))
        self.assertFalse(any(_intrusive_request(r)
                             for r in dev.requests[:first_intrusive]))
        self.assertEqual(set(order), {p.name for p in interrogate.PROBES})

    def test_gentle_sends_no_intrusive_request(self):
        """--gentle is the promise not to provoke the device at all."""
        dev = FakeDevice()
        results = interrogate.interrogate(dev, include_intrusive=False)
        self.assertFalse(INTRUSIVE & set(results))
        self.assertEqual([r for r in dev.requests if _intrusive_request(r)],
                         [])

    def test_each_probe_is_repeated_as_declared(self):
        dev = FakeDevice()
        results = interrogate.interrogate(dev)
        for probe in interrogate.PROBES:
            with self.subTest(probe.name):
                self.assertEqual(len(results[probe.name].latencies_ms),
                                 probe.repeats)
        self.assertEqual(len(dev.requests),
                         sum(p.repeats for p in interrogate.PROBES))


class HowFailuresAreRecorded(unittest.TestCase):

    def run_with(self, exc):
        dev = FakeDevice(fail={0x99: exc})
        result = interrogate.interrogate(dev)["unknown_request"]
        return result, dev

    def test_a_stall_is_a_stall(self):
        result, _ = self.run_with(OSError("[Errno 32] Pipe error"))
        self.assertEqual(result.outcome, interrogate.OUTCOME_STALL)
        self.assertIn("Pipe error", result.detail)

    def test_a_timeout_is_a_timeout(self):
        result, _ = self.run_with(OSError("[Errno 110] Operation timed out"))
        self.assertEqual(result.outcome, interrogate.OUTCOME_TIMEOUT)

    def test_anything_else_is_an_error(self):
        result, _ = self.run_with(OSError("[Errno 19] No such device"))
        self.assertEqual(result.outcome, interrogate.OUTCOME_ERROR)

    def test_a_failing_probe_stops_repeating_and_the_rest_still_run(self):
        result, dev = self.run_with(OSError("Pipe error"))
        self.assertEqual(result.latencies_ms, [])
        self.assertEqual(sum(1 for r in dev.requests if r[1] == 0x99), 1)
        # hid_set_led comes after unknown_request and still ran.
        self.assertTrue(any(r[0] == interrogate.DIR_OUT_CLASS_INTERFACE
                            for r in dev.requests))


class TheStudyRow(unittest.TestCase):

    def test_a_full_battery_fills_exactly_the_header(self):
        row = interrogate.summarize(interrogate.interrogate(FakeDevice()))
        self.assertEqual(set(row), set(interrogate.fieldnames()))

    def test_a_gentle_row_fits_inside_the_header(self):
        """The CSV header is the full battery; a gentle row leaves gaps."""
        row = interrogate.summarize(
            interrogate.interrogate(FakeDevice(), include_intrusive=False))
        self.assertTrue(set(row) < set(interrogate.fieldnames()))

    def test_statistics(self):
        result = interrogate.ProbeResult("p", interrogate.OUTCOME_OK,
                                         latencies_ms=[1.0, 3.0])
        self.assertEqual(result.mean_ms(), 2.0)
        self.assertEqual(result.stdev_ms(), 1.0)
        self.assertIsNone(interrogate.ProbeResult("p", "ok").mean_ms())
        self.assertIsNone(interrogate.ProbeResult(
            "p", "ok", latencies_ms=[1.0]).stdev_ms())
        row = interrogate.summarize({"p": interrogate.ProbeResult(
            "p", interrogate.OUTCOME_STALL)})
        self.assertEqual(row, {"p__outcome": "stall", "p__mean_ms": "",
                               "p__stdev_ms": "", "p__len": ""})


if __name__ == "__main__":
    unittest.main()
