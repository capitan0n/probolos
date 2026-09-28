"""
The command line: argument validation and how each flag is wired through.

Covers probolos.__main__.
"""

from __future__ import annotations

import io
import pwd
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from probolos import __main__ as cli
from probolos import privsep


class AgentUserMustNotBeTheAnalyzerAccount(unittest.TestCase):
    """
    probolos.service ships `--privsep --agent --agent-user nobody`, and the
    analyzer drops to `nobody` too. The agent socket then accepted answers
    from every process running as the shared `nobody` account.
    """

    def _run_main(self, agent_user):
        served = {}
        prepared = []

        def fake_start(analyzer_main, **_kw):
            analyzer_main(object())
            return 0

        with mock.patch.object(cli, "require_usb"), \
                mock.patch.object(cli, "require_root"), \
                mock.patch.object(cli.sysfs, "install_backend"), \
                mock.patch.object(cli.daemon, "serve",
                                  side_effect=lambda **kw: served.update(kw)), \
                mock.patch.object(cli.agentlink, "prepare_socket_dir",
                                  side_effect=lambda *a: prepared.append(a)), \
                mock.patch.object(privsep, "start", side_effect=fake_start), \
                mock.patch("builtins.print"):
            with self.assertRaises(SystemExit):
                cli.main(["--privsep", "--agent", "--agent-user", agent_user,
                          "--privsep-user", "nobody", "--no-ledger",
                          "--no-trust", "--timeout", "0"])
        return served, prepared

    def setUp(self):
        try:
            pwd.getpwnam("nobody")
        except KeyError:                                  # pragma: no cover
            self.skipTest("no `nobody` account on this system")

    def test_shipped_placeholder_does_not_enable_the_agent(self):
        served, prepared = self._run_main("nobody")
        self.assertIsNone(served["agent_socket"])
        self.assertIsNone(served["agent_uid"])
        self.assertEqual(prepared, [])

    def test_a_real_desktop_account_still_gets_the_agent(self):
        other = next((e.pw_name for e in pwd.getpwall()
                      if e.pw_uid not in (pwd.getpwnam("nobody").pw_uid,)),
                     None)
        served, prepared = self._run_main(other)
        self.assertIsNotNone(served["agent_socket"])
        self.assertEqual(served["agent_uid"], pwd.getpwnam(other).pw_uid)
        self.assertEqual(len(prepared), 1)


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


class CommandLineWiring(unittest.TestCase):

    def test_policy_without_watch_is_refused(self):
        from probolos import __main__ as cli
        with redirect_stdout(io.StringIO()), \
             mock.patch("sys.stderr", io.StringIO()), \
             self.assertRaises(SystemExit):
            cli.main(["--media-policy", "deauthorize"])

    def _run(self, argv):
        from probolos import __main__ as cli
        from probolos import privsep
        captured = {}

        def fake_start(analyzer_main, **kwargs):
            captured.update(kwargs)
            return 0

        with mock.patch.object(cli, "require_usb"), \
             mock.patch.object(cli, "require_root"), \
             mock.patch.object(privsep, "start", fake_start), \
             mock.patch.object(cli.daemon, "serve",
                               side_effect=lambda **kw: captured.update(kw)), \
             redirect_stdout(io.StringIO()):
            try:
                cli.main(argv)
            except SystemExit:
                pass
        return captured

    def test_privsep_gate_learns_the_flag_from_the_root_side(self):
        captured = self._run(["--privsep", "--no-trust", "--no-ledger",
                              "--watch-media"])
        self.assertTrue(captured["watch_media"])

    def test_direct_mode_passes_the_flag_and_policy_to_the_daemon(self):
        captured = self._run(["--no-trust", "--no-ledger", "--watch-media",
                              "--media-policy", "deauthorize"])
        self.assertTrue(captured["watch_media"])
        self.assertEqual(captured["media_policy"], "deauthorize")

    def test_off_unless_asked(self):
        captured = self._run(["--no-trust", "--no-ledger"])
        self.assertFalse(captured["watch_media"])


# ---------------------------------------------------------------------------
# P5 -- the optional agent must not be able to stop the gate
# ---------------------------------------------------------------------------

class AgentIdentityIsNotFatal(unittest.TestCase):

    class Args:
        def __init__(self, agent=True, agent_user=None):
            self.agent = agent
            self.agent_user = agent_user

    def setUp(self):
        self._saved = cli._active_session_user
        cli._active_session_user = lambda: None      # as at boot

    def tearDown(self):
        cli._active_session_user = self._saved

    def test_undetectable_desktop_user_does_not_exit(self):
        try:
            self.assertIsNone(cli._resolve_agent_identity(self.Args()))
        except SystemExit as exc:                     # pragma: no cover
            self.fail(f"the gate refused to run over a missing agent: {exc}")

    def test_explicit_but_unknown_agent_user_still_exits(self):
        with self.assertRaises(SystemExit):
            cli._resolve_agent_identity(
                self.Args(agent_user="no-such-user-probolos-test"))

    def test_agent_off_resolves_to_nothing(self):
        self.assertIsNone(cli._resolve_agent_identity(self.Args(agent=False)))


class ListIsDispatched(unittest.TestCase):

    def test_list_runs_the_inventory_and_never_closes_the_gate(self):
        from probolos import __main__ as m
        with mock.patch.object(m, "cmd_list") as listing, \
             mock.patch.object(m, "require_root") as root, \
             mock.patch.object(m, "require_usb"):
            m.main(["--list"])
        listing.assert_called_once()
        root.assert_not_called()


# ==========================================================================
# The two version strings that disagreed
# ==========================================================================

class VersionHasOneSource(unittest.TestCase):

    def test_the_package_version_matches_pyproject(self):
        import probolos

        root = Path(__file__).resolve().parent.parent
        pyproject = (root / "pyproject.toml").read_text()
        declared = None
        for line in pyproject.splitlines():
            if line.startswith("version ="):
                declared = line.split("=", 1)[1].strip().strip('"')
                break

        self.assertIsNotNone(declared, "pyproject.toml has no version")
        # Installed: exactly equal. Source checkout: the "+source" fallback,
        # which must still carry the same base number.
        self.assertTrue(
            probolos.__version__ in (declared, declared + "+source"),
            f"{probolos.__version__!r} does not match pyproject {declared!r}")


if __name__ == "__main__":
    unittest.main()
