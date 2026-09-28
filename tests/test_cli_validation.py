"""
Command-line input that used to be accepted and then quietly misread.

  * every duration flag documents 0 as "off" or "wait", and a negative value,
    NaN or infinity fell through the `> 0` tests the daemon makes -- a
    `--watchdog -1` switched a safety layer off without a word;
  * --force-locked and --force-unlocked contradict each other, and the first
    silently won;
  * a missing pyudev was discovered only in run(), after every root hub had
    been closed, and ended in a traceback.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from probolos import __main__ as cli
from probolos import daemon as daemon_mod


class DurationsMustBeFiniteAndNonNegative(unittest.TestCase):

    def _main(self, argv):
        with mock.patch.object(cli, "require_usb"), \
                mock.patch.object(cli.daemon, "serve") as serve, \
                redirect_stdout(io.StringIO()), \
                redirect_stderr(io.StringIO()):
            try:
                cli.main(argv)
            except SystemExit as exc:
                return exc.code, serve
        return None, serve

    def test_bad_values_are_refused_before_anything_runs(self):
        for flag in ("--timeout", "--observe", "--watchdog"):
            for value in ("-1", "nan", "inf", "-inf", "soon"):
                with self.subTest(flag=flag, value=value):
                    code, serve = self._main(["--dry-run", flag, value])
                    self.assertEqual(code, 2)          # argparse usage error
                    serve.assert_not_called()

    def test_zero_and_positive_values_still_parse(self):
        self.assertEqual(cli._seconds("0"), 0.0)
        self.assertEqual(cli._seconds("2.5"), 2.5)
        code, serve = self._main(["--dry-run", "--timeout", "0",
                                  "--observe", "3", "--watchdog", "60"])
        self.assertIsNone(code)
        serve.assert_called_once()


class ForcedLockStateIsOneOrTheOther(unittest.TestCase):

    def test_both_flags_together_are_refused(self):
        with redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit) as caught:
            cli.main(["--force-locked", "--force-unlocked"])
        self.assertEqual(caught.exception.code, 2)


class MissingPyudevIsRefusedBeforeTheGateCloses(unittest.TestCase):

    def test_the_gate_is_never_entered(self):
        with mock.patch.object(daemon_mod, "pyudev", None), \
                mock.patch.object(daemon_mod.gate, "AuthorizationGate") as gate, \
                redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                daemon_mod.serve(dry_run=True)
        self.assertIn("pyudev", str(caught.exception))
        gate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
