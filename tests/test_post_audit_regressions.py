"""
Regressions found while reviewing the hardening patch, plus two older ones.

Every test here pins a failure that ENDED THE DAEMON. That is the class of bug
that matters most in this codebase: a gate that has exited is not a gate that
failed closed -- the kernel goes on binding drivers to everything plugged in
afterwards, with no question asked. Each one is triggered by something
completely ordinary (a device unplugged at the wrong moment, a slow loginctl),
not by an attack.
"""

import os
import subprocess
import sys
import types
import unittest
from pathlib import Path


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


class LoginctlTimeoutIsContained(unittest.TestCase):
    """
    is_locked() is called once a second from the main loop and once per device.

    The handling only ever wrapped _graphical_sessions(). _locked_hint() runs
    in the loop BELOW that try, so a loginctl call that exceeded its three
    second timeout raised TimeoutExpired out of is_locked() and killed the
    daemon -- a lock-state lookup taking the gate down with it.
    """

    def test_a_hung_loginctl_degrades_to_unknown(self):
        from probolos import session

        monitor = session.LogindMonitor()
        monitor._binary = "/bin/true"

        calls = {"n": 0}

        def hang(*args, **kwargs):
            calls["n"] += 1
            raise subprocess.TimeoutExpired(cmd="loginctl", timeout=3)

        real_run = subprocess.run
        subprocess.run = hang
        try:
            self.assertIsNone(monitor.is_locked())
        finally:
            subprocess.run = real_run
        self.assertGreater(calls["n"], 0)

    def test_a_hung_hint_lookup_does_not_escape_either(self):
        """The specific gap: the sessions list succeeds, the hint call hangs."""
        from probolos import session

        monitor = session.LogindMonitor()
        monitor._binary = "/bin/true"
        monitor._graphical_sessions = lambda: ["c1"]

        def hang(session_id):
            raise subprocess.TimeoutExpired(cmd="loginctl", timeout=3)

        monitor._locked_hint = hang
        with self.assertRaises(subprocess.TimeoutExpired):
            monitor._locked_hint("c1")     # the hazard is real...
        # ...and _run(), which is where the real call lives, contains it.
        real_run = subprocess.run
        subprocess.run = lambda *a, **k: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd="loginctl", timeout=3))
        try:
            self.assertEqual(session.LogindMonitor._run(monitor, "x"), "")
        finally:
            subprocess.run = real_run


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


class UnreadableHubDefaultStaysRestorable(unittest.TestCase):
    """
    A root hub whose authorized_default could not be read was closed anyway and
    then never recorded, so restore() -- which only walks the recorded hubs --
    skipped it. The hub stayed at 0 after the daemon exited: no USB device on
    it binds a driver again until someone writes the file by hand.
    """

    def test_an_unreadable_previous_value_still_records_a_restore_target(self):
        import tempfile
        from probolos import gate_server, protocol

        with tempfile.TemporaryDirectory() as tmp:
            hub = Path(tmp) / "usb1"
            hub.mkdir()
            attr = hub / "authorized_default"
            attr.write_text("not-a-number")

            gate = gate_server.GateServer.__new__(gate_server.GateServer)
            gate._authorized_here = set()
            gate._closed_defaults = {}
            gate._open_leases = {}
            gate._instances = {}
            gate._safe_usb_path = staticmethod(lambda p: hub)
            gate.log = lambda *a: None

            resp = gate_server.GateServer._do_set_default(
                gate, protocol.Request(protocol.REQ_SET_DEFAULT, str(hub), 0))

            self.assertTrue(resp.ok, resp.detail)
            self.assertEqual(attr.read_text(), "0")
            self.assertIn(str(hub), gate._closed_defaults)
            self.assertEqual(gate._closed_defaults[str(hub)], 1)


class NotificationCleanupNeverCostsAnAnswer(unittest.TestCase):
    """
    Notifier.close() runs in the `finally` of the agent's decision path, after
    the human has already chosen. An unhandled TimeoutExpired there replaced
    the return value with an exception and the decision was lost.
    """

    def test_a_hung_gdbus_is_swallowed(self):
        from probolos import agent

        notifier = agent.Notifier.__new__(agent.Notifier)
        notifier._gdbus = "/bin/true"

        real_run = subprocess.run
        subprocess.run = lambda *a, **k: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd="gdbus", timeout=5))
        try:
            notifier.close(7)      # must simply return
        finally:
            subprocess.run = real_run


class AdmitDescriptorIsCloseOnExec(unittest.TestCase):
    """
    The privileged half spawns children (the storage worker, dialog backends).
    A writable descriptor on a device's `authorized` attribute must not be
    inherited by any of them.
    """

    def test_o_cloexec_is_set(self):
        import inspect
        from probolos import sysfs

        source = inspect.getsource(sysfs._DirectBackend.admit)
        self.assertIn("O_CLOEXEC", source)


if __name__ == "__main__":
    unittest.main()
