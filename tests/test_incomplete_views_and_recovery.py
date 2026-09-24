"""
Regressions from the September 2026 security and correctness audit.

  * the udev event stream overflowing must not end the gate (fail-open);
  * a descriptor set that could not be examined in full must not be graded
    lower than the worst thing it could contain;
  * the drift baseline must never be the "-" placeholder or an old-scheme
    digest;
  * the agent's confirmation dialog must end before the analyzer stops
    listening for its answer.
"""
from __future__ import annotations

import errno
import json
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from probolos import (analyzers, daemon as daemon_mod, descriptors,
                      ledger as ledger_mod, rules, session, sysfs)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def device_desc(num_configs=1):
    return struct.pack("<BBHBBBBHHHBBBB", 18, 0x01, 0x0200, 0, 0, 0, 64,
                       0x1234, 0x5678, 0x0100, 0, 0, 0, num_configs)


def config_desc(total, n_ifaces=1):
    return struct.pack("<BBHBBBBB", 9, 0x02, total, n_ifaces, 1, 0, 0x80, 50)


def iface_desc(cls=0x08, sub=0x06, proto=0x50, num=0):
    return struct.pack("<BBBBBBBBB", 9, 0x04, num, 0, 1, cls, sub, proto, 0)


def make_device(raw, parse_error=None):
    ds = None
    if parse_error is None:
        ds = descriptors.parse(raw)
    return sysfs.UsbDevice(
        syspath=Path("/sys/devices/pci0000:00/usb1/1-4"), name="1-4",
        vendor_id="1234", product_id="5678", manufacturer="Acme",
        product="Widget", serial="S1", bus=1, device_num=2, speed="480",
        authorized=0, device_class=0, descriptor_set=ds,
        parse_error=parse_error, raw_descriptors=raw,
        removable="removable", instance_id=(1, 2))


STORAGE = device_desc() + config_desc(18) + iface_desc()


# --------------------------------------------------------------------------
# 1. The event stream
# --------------------------------------------------------------------------

class _FakeMonitor:
    """Stands in for pyudev.Monitor: raises `errors` in order, then stops."""

    def __init__(self, errors, stop_event, fd):
        self._errors = list(errors)
        self._stop = stop_event
        self._fd = fd
        self.polls = 0

    def filter_by(self, **_kw):
        pass

    def start(self):
        pass

    def fileno(self):
        return self._fd

    def poll(self, timeout=None):
        self.polls += 1
        if self._errors:
            raise self._errors.pop(0)
        self._stop.set()
        return None


class EventStreamOverflowDoesNotEndTheGate(unittest.TestCase):

    def _run(self, errors):
        stop = threading.Event()
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        monitor = _FakeMonitor(errors, stop, a.fileno())
        fake_pyudev = mock.Mock()
        fake_pyudev.Monitor.from_netlink.return_value = monitor
        engine = daemon_mod.Probolos(monitor=session.AlwaysUnlocked(),
                                     stop_event=stop)
        with mock.patch.object(daemon_mod, "pyudev", fake_pyudev), \
                mock.patch("builtins.print"):
            engine.run()
        return monitor

    def test_enobufs_from_poll_is_survived(self):
        """
        Uncaught, this left run(): the `with AuthorizationGate` block reopened
        every root hub and the daemon exited, from an overflow a busy loop can
        produce.
        """
        monitor = self._run([OSError(errno.ENOBUFS, "No buffer space")] * 3)
        self.assertEqual(monitor.polls, 4, "the loop kept polling afterwards")

    def test_other_stream_errors_still_propagate(self):
        with self.assertRaises(OSError):
            self._run([OSError(errno.EBADF, "Bad file descriptor")])


# --------------------------------------------------------------------------
# 2. Incomplete descriptor views
# --------------------------------------------------------------------------

class IncompleteDescriptorViewsAreCritical(unittest.TestCase):

    def _worst(self, dev, rule_id):
        findings = rules.evaluate(dev)
        self.assertIn(rule_id, {f.rule_id for f in findings})
        return rules.worst(findings)

    def test_unparseable_descriptors_need_the_typed_word(self):
        dev = make_device(STORAGE, parse_error="more than 4096 descriptors")
        self.assertEqual(self._worst(dev, "unreadable-descriptors"),
                         rules.Severity.CRITICAL)

    def test_missing_configurations_need_the_typed_word(self):
        dev = make_device(device_desc(num_configs=2) + config_desc(18)
                          + iface_desc())
        self.assertEqual(self._worst(dev, "configurations-missing"),
                         rules.Severity.CRITICAL)
        self.assertFalse(dev.inspection_safe)

    def test_a_truncated_chain_needs_the_typed_word(self):
        dev = make_device(device_desc() + config_desc(27) + iface_desc()
                          + b"\x09\x04\x00")
        self.assertEqual(self._worst(dev, "descriptor-chain-truncated"),
                         rules.Severity.CRITICAL)

    def test_a_complete_ordinary_device_stays_quiet(self):
        findings = rules.evaluate(make_device(STORAGE))
        ids = {f.rule_id for f in findings}
        self.assertFalse(ids & {"unreadable-descriptors",
                                "configurations-missing",
                                "descriptor-chain-truncated"})
        self.assertLess(rules.worst(findings), rules.Severity.WARNING)


# --------------------------------------------------------------------------
# 3. The drift baseline
# --------------------------------------------------------------------------

class DriftBaselineIsNeverAPlaceholder(unittest.TestCase):

    def setUp(self):
        self.path = Path(tempfile.mkdtemp(prefix="probolos-audit-")) / "l.json"

    def _drift(self, dev):
        led = ledger_mod.Ledger(self.path)
        findings = analyzers.run(analyzers.Context(device=dev, ledger=led))
        return any(f.rule_id == "descriptor-drift" for f in findings)

    def test_unreadable_first_sighting_survives_a_reload(self):
        blind = make_device(STORAGE)
        blind.raw_descriptors = None
        blind.descriptor_set = None
        led = ledger_mod.Ledger(self.path)
        led.record(blind, "user rejected", approved=False)
        self.assertIsNone(led.save())

        reloaded = ledger_mod.Ledger(self.path)
        entry = reloaded.entries[ledger_mod.identity_of(blind)]
        self.assertEqual(entry.baseline_hash, "",
                         "the placeholder must not become a baseline on load")
        self.assertFalse(self._drift(make_device(STORAGE)),
                         "our failure to read is not the device's drift")

    def test_a_persisted_placeholder_baseline_is_discarded(self):
        entry = ledger_mod.Entry.from_raw({
            "identity": "1234:5678:S1", "descriptor_hash": "-",
            "first_seen": 1.0, "last_seen": 2.0, "known_hashes": ["-"],
            "baseline_hash": "-", "fingerprint_scheme": "normalized-v1"})
        self.assertEqual(entry.baseline_hash, "")

    def test_first_sighting_after_the_fingerprint_migration_is_quiet(self):
        dev = make_device(STORAGE)
        ident = ledger_mod.identity_of(dev)
        self.path.write_text(json.dumps({"schema": 1, "entries": {ident: {
            "identity": ident, "descriptor_hash": "old_raw_hash",
            "first_seen": 1.0, "last_seen": 2.0, "times_seen": 2,
            "known_hashes": ["old_raw_hash"],
            "baseline_hash": "old_raw_hash"}}}))
        self.assertFalse(self._drift(dev))

    def test_real_drift_is_still_reported(self):
        led = ledger_mod.Ledger(self.path)
        led.record(make_device(STORAGE), "user approved", approved=True)
        self.assertIsNone(led.save())
        changed = make_device(device_desc() + config_desc(27, n_ifaces=2)
                              + iface_desc()
                              + iface_desc(0x03, 0x01, 0x01, num=1))
        self.assertTrue(self._drift(changed))


# --------------------------------------------------------------------------
# 4. The agent's second dialog
# --------------------------------------------------------------------------

class ConfirmationEndsBeforeTheAnalyzerStopsListening(unittest.TestCase):

    def build(self):
        from probolos import agent as agent_mod
        instance = agent_mod.Agent.__new__(agent_mod.Agent)
        instance.log = lambda *a: None
        instance.notifier = mock.Mock()
        instance.notifier.available.return_value = False
        instance.dialog = mock.Mock()
        instance.sock = None
        return instance, agent_mod

    def test_second_dialog_gets_only_what_is_left(self):
        agent, agent_mod = self.build()
        clock = iter([100.0, 150.0])     # the first dialog took 50 of 60 s
        agent.dialog.confirm.side_effect = [True, True]
        with mock.patch.object(agent_mod.time, "monotonic",
                               side_effect=lambda: next(clock)):
            agent._ask_user({"title": "t", "body": "b"}, 60)
        second_timeout = agent.dialog.confirm.call_args_list[1].kwargs["timeout"]
        self.assertLessEqual(second_timeout, 60 - 50)

    def test_no_budget_left_is_a_refusal_not_a_late_yes(self):
        from probolos.agentlink import ANSWER_NO
        agent, agent_mod = self.build()
        clock = iter([100.0, 170.0])
        agent.dialog.confirm.side_effect = [True, True]
        with mock.patch.object(agent_mod.time, "monotonic",
                               side_effect=lambda: next(clock)):
            answer = agent._ask_user({"title": "t", "body": "b"}, 60)
        self.assertEqual(answer, ANSWER_NO)
        self.assertEqual(agent.dialog.confirm.call_count, 1)


if __name__ == "__main__":
    unittest.main()
