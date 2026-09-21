"""
Second audit pass over the hardened tree.

Three of these pin failures in the PRIVILEGED half -- the process that holds
the only record of which hubs it closed and which devices it switched on. The
rest pin places where a check exists and does not reach the operation it was
written to protect, which is this codebase's own documented failure pattern.
"""

import os
import socket
import stat
import tempfile
import threading
import unittest
from pathlib import Path


class DeadAnalyzerDoesNotKillTheGate(unittest.TestCase):
    """
    The analyzer exits between sending a request and reading the reply.

    sendmsg() then returns EPIPE. Nothing caught it: the exception left
    _serve_requests, left run_gate, and left privsep.start() -- which never
    reached its os.waitpid(), so the root process died with a traceback and
    the analyzer child was orphaned. Ctrl-C is enough to produce this.
    """

    def test_epipe_ends_the_loop_cleanly(self):
        from probolos import gate_server, protocol

        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        gate = gate_server.GateServer(a, log=lambda *x: None)
        b.sendall(protocol.Request(protocol.REQ_PING).encode())
        b.close()
        gate.serve_forever()      # must simply return
        a.close()

    def test_a_handler_that_raises_does_not_end_the_gate(self):
        """
        Every handler is written to return a Response rather than raise, so
        reaching this path is itself a bug -- which is exactly why the loop
        must survive it instead of trusting it cannot happen.
        """
        from probolos import gate_server, protocol

        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        gate = gate_server.GateServer(a, log=lambda *x: None)

        def boom(_req):
            raise RuntimeError("bug in a handler")

        gate._do_authorize = boom
        b.sendall(protocol.Request(protocol.REQ_AUTHORIZE,
                                   path="/sys/bus/usb/devices/1-1",
                                   value=1).encode())
        b.settimeout(2.0)
        thread = threading.Thread(target=gate.serve_forever, daemon=True)
        thread.start()
        raw = b.recv(protocol.MAX_MESSAGE)
        resp = protocol.Response.decode(raw)
        self.assertEqual(resp.status, protocol.ERROR)
        self.assertIn("internal gate error", resp.detail)
        b.close()
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        a.close()

    def test_a_denial_stays_inside_the_clients_message_limit(self):
        """
        The denial echoes a path the analyzer chose. A reply its own decoder
        refuses as oversized tells it nothing at all.
        """
        from probolos import gate_server, protocol

        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        gate = gate_server.GateServer(a, log=lambda *x: None)
        long_path = "/sys/bus/usb/devices/" + "A" * 7900
        b.sendall(protocol.Request(protocol.REQ_AUTHORIZE_INTERFACE,
                                   path=long_path, value=1).encode())
        b.settimeout(2.0)
        thread = threading.Thread(target=gate.serve_forever, daemon=True)
        thread.start()
        raw = b.recv(protocol.MAX_MESSAGE)
        protocol.Response.decode(raw)      # must not raise "message too large"
        self.assertLessEqual(len(raw), protocol.MAX_MESSAGE)
        b.close()
        thread.join(timeout=3)
        a.close()


class SysfsWritesTruncate(unittest.TestCase):
    """
    O_WRONLY alone overwrites from byte zero and leaves whatever was longer.

    Harmless against a real sysfs attribute, which the kernel handles as a
    store() call -- and wrong everywhere else, including every test fixture
    that stands in for one. Writing "0" over "not-a-number" must not leave
    "0ot-a-number" behind for the next read to parse.
    """

    def test_authorized_default_is_truncated_on_write(self):
        from probolos import gate_server, protocol

        with tempfile.TemporaryDirectory() as tmp:
            hub = Path(tmp) / "usb1"
            hub.mkdir()
            attr = hub / "authorized_default"
            attr.write_text("this is much longer than one digit")

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

    def test_the_direct_backend_truncates_authorized_too(self):
        import inspect
        from probolos import sysfs

        self.assertIn("O_TRUNC", inspect.getsource(sysfs._DirectBackend.admit))


class StackedCombiningMarksAreVisible(unittest.TestCase):
    """
    Combining marks occupy zero terminal columns.

    display_width() and fit() exist to stop a device name from pushing the
    border of the report box off the line, and they measured a run of two
    hundred marks as costing nothing. The terminal stacks them on the
    preceding glyph and they spill over the lines around it -- the same
    outcome, through the one route the width handling does not measure. Worse,
    no note fired, so the rules layer never learned the name was abnormal.
    """

    def test_a_zalgo_name_is_escaped_and_reported(self):
        from probolos import textsafe

        result = textsafe.sanitize("ACME" + "́" * 200)
        self.assertIn(textsafe.NOTE_STACKED_MARKS, result.notes)
        # The escaped form is what makes it visible; ́ must appear as text.
        self.assertIn("\\u0301", result.text)

    def test_real_scripts_are_untouched(self):
        """A rule that fires on ordinary hardware gets turned off."""
        from probolos import textsafe

        for name in ("Logitech USB Keyboard",
                     "Tiế́ng Việt Kềyboard",
                     "ロジクール キーボード",
                     "Kingston DataTraveler"):
            with self.subTest(name=name):
                self.assertNotIn(textsafe.NOTE_STACKED_MARKS,
                                 textsafe.sanitize(name).notes)

    def test_the_note_reaches_the_operator_as_a_finding(self):
        """A note nothing turns into a finding is a note nobody reads."""
        from probolos import rules, textsafe

        class FakeDevice:
            string_notes = [textsafe.NOTE_STACKED_MARKS]
            string_note_fields = {"iProduct": [textsafe.NOTE_STACKED_MARKS]}
            descriptor_set = None
            parse_error = None
            device_class = None
            vendor_id = "dead"
            product_id = "beef"
            manufacturer = product = serial = None
            interfaces = []
            interface_classes = []
            kinds = ["other"]
            claims = []
            name = "1-4"
            removable = None

            def label(self):
                return "test"

        ids = [f.rule_id for f in rules.evaluate(FakeDevice())]
        self.assertIn("stacked-combining-marks", ids)


class ThePromptOffersWhatItAccepts(unittest.TestCase):
    """
    With --timeout set, the countdown prompt replaced the whole prompt string
    with "[y/N]" -- dropping [a]lways from the text while the parser below
    went on accepting it. That is a hidden control on the one prompt in the
    tool that grants something permanent: a user typing `a` for "abort", which
    is what a bare [y/N] invites you to assume it is not, created a trust
    entry that admits that device silently from then on.
    """

    def _prompt_for(self, *, timeout, has_trust):
        import io
        import sys as _sys
        from probolos import daemon as daemon_mod

        engine = daemon_mod.Probolos.__new__(daemon_mod.Probolos)
        engine.timeout = timeout
        engine.trust = object() if has_trust else None
        engine.agent = None
        engine.observe = 0

        captured = io.StringIO()
        real_stdout, real_stdin = _sys.stdout, _sys.stdin
        _sys.stdout = captured
        _sys.stdin = io.StringIO("")      # EOF -> denied, after the prompt
        try:
            daemon_mod.Probolos._ask(engine, dev=None, findings=())
        except Exception:
            pass
        finally:
            _sys.stdout, _sys.stdin = real_stdout, real_stdin
        return captured.getvalue()

    def test_always_is_shown_whenever_always_is_accepted(self):
        text = self._prompt_for(timeout=30.0, has_trust=True)
        self.assertIn("[a]lways", text.lower(),
                      "the countdown prompt accepts 'a' but did not offer it")

    def test_no_always_is_offered_without_a_trust_store(self):
        text = self._prompt_for(timeout=30.0, has_trust=False)
        self.assertNotIn("[a]lways", text.lower())


class GateRestoreIsThreadSafe(unittest.TestCase):
    """
    restore() has three uncoordinated callers: the watchdog thread via
    on_stall, the main thread leaving the `with` block, and atexit. Two can
    run at once -- the watchdog firing during shutdown is the normal way a
    stall ends -- and each rebuilt self._original from what it alone managed
    to restore, so the later assignment discarded the other's result.
    """

    def test_concurrent_restores_do_not_lose_a_hub(self):
        from probolos import gate as gate_mod, sysfs

        hubs = [Path(f"/sys/bus/usb/devices/usb{n}") for n in range(1, 9)]
        written = []
        barrier = threading.Barrier(2)

        def slow_write(hub, value):
            written.append((hub.name, value))

        real = sysfs.set_authorized_default
        sysfs.set_authorized_default = slow_write
        try:
            g = gate_mod.AuthorizationGate(log=lambda *a: None)
            g._original = {h: 1 for h in hubs}
            g._armed = True

            def run():
                barrier.wait()
                g.restore()

            threads = [threading.Thread(target=run) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)
        finally:
            sysfs.set_authorized_default = real

        # Every hub restored exactly once, and nothing left armed.
        self.assertEqual(sorted(n for n, _ in written),
                         sorted(h.name for h in hubs))
        self.assertFalse(g._armed)
        self.assertEqual(g._original, {})


class SocketChownDoesNotFollowALink(unittest.TestCase):
    """
    start() verified /run/probolos with open_directory(secure=True) and then
    closed the descriptor, after which bind(), chmod() and chown() all worked
    by NAME again. os.chown on a name follows symlinks, so the directory that
    was checked and the one written to were the same only by assumption.
    """

    def test_chown_is_relative_to_the_verified_directory(self):
        import inspect
        from probolos import agentlink

        source = inspect.getsource(agentlink.AgentLink._chown_for_owner)
        self.assertIn("dir_fd=directory_fd", source)
        self.assertIn("follow_symlinks=False", source)
        # The old signature took `created_dir` and promised, in its docstring,
        # that the directory was "only chowned if THIS call created it" -- a
        # protection the body never implemented and never even read the flag
        # for. The parameter must now be one the code actually uses.
        signature = inspect.signature(agentlink.AgentLink._chown_for_owner)
        self.assertNotIn("created_dir", signature.parameters)


if __name__ == "__main__":
    unittest.main()
