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
                mock.patch.object(cli, "claim_the_gate"), \
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

    def _run(self, argv, lock=None):
        from probolos import __main__ as cli
        from probolos import privsep
        captured = {}

        def fake_start(analyzer_main, **kwargs):
            captured.update(kwargs)
            return 0

        with mock.patch.object(cli, "require_usb"), \
             mock.patch.object(cli, "require_root"), \
             mock.patch.object(cli, "claim_the_gate", return_value=lock), \
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

    def test_the_analyzer_is_told_to_close_the_gate_lock(self):
        captured = self._run(["--privsep", "--no-trust", "--no-ledger"],
                             lock=7)
        self.assertEqual(captured["close_in_child"], (7,))

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


class OneCommandPerRunAndDryRunChangesNothing(unittest.TestCase):
    """
    `--remove-trusted ""` was falsy, fell through every command and started
    the gate; `--list --release` ran the first and dropped the second; and
    `--dry-run --release` released every device, though --dry-run promises
    to change nothing.
    """

    def _main(self, argv):
        calls = []
        with mock.patch.object(cli, "require_usb"), \
             mock.patch.object(cli, "require_root"), \
             mock.patch.object(cli, "claim_the_gate", return_value=None), \
             mock.patch.object(cli, "cmd_release",
                               side_effect=lambda: calls.append("release")), \
             mock.patch.object(cli, "cmd_list",
                               side_effect=lambda **_k: calls.append("list")), \
             mock.patch.object(cli, "cmd_remove_trusted",
                               side_effect=lambda *_a: calls.append("remove")), \
             mock.patch.object(cli.daemon, "serve",
                               side_effect=lambda **_k: calls.append("serve")), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            try:
                cli.main(argv)
                code = 0
            except SystemExit as exc:
                code = exc.code
        return code, calls

    def test_an_empty_pattern_is_refused_and_starts_nothing(self):
        for value in ("", "   "):
            code, calls = self._main(["--remove-trusted", value])
            self.assertEqual(code, 2)
            self.assertEqual(calls, [], "the gate started")

    def test_two_commands_are_refused(self):
        code, calls = self._main(["--list", "--release"])
        self.assertEqual(code, 2)
        self.assertEqual(calls, [])

    def test_dry_run_refuses_the_commands_that_change_state(self):
        for argv in (["--release"], ["--remove-trusted", "all", "--yes"],
                     ["--remove-all", "--yes"]):
            code, calls = self._main(["--dry-run", *argv])
            self.assertEqual(code, 2, argv)
            self.assertEqual(calls, [], argv)

    def test_one_command_still_runs(self):
        self.assertEqual(self._main(["--remove-trusted", "2"]), (0, ["remove"]))
        self.assertEqual(self._main(["--list", "--dry-run"]), (0, ["list"]))

    def test_dry_run_privsep_hands_nothing_over(self):
        from probolos import privsep
        captured = {}

        def fake_start(_analyzer_main, **kwargs):
            captured.update(kwargs)
            return 0
        with mock.patch.object(cli, "require_usb"), \
             mock.patch.object(privsep, "start", fake_start), \
             mock.patch.object(privsep, "prepare_trust_readable") as readable, \
             redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli.main(["--dry-run", "--privsep", "--ledger",
                          "/var/lib/probolos/state/ledger.json"])
        readable.assert_not_called()
        self.assertEqual(captured["state_paths"], [])


class ReleaseRefusesUnderARunningGate(unittest.TestCase):
    """
    --release authorizes every blocked device and reopens the hubs. Under a
    running gate that admitted what it was holding or had refused, while the
    daemon went on prompting as though the hubs were closed.
    """

    def test_refused_while_a_gate_holds_the_lock(self):
        with mock.patch.object(cli, "require_root"), \
             mock.patch.object(cli.instance, "running", return_value=True), \
             mock.patch.object(cli.gate, "unauthorized_devices") as listed, \
             mock.patch.object(cli.sysfs, "set_authorized") as written:
            with self.assertRaises(SystemExit) as ended:
                cli.cmd_release()
        self.assertIn("running", str(ended.exception.code))
        listed.assert_not_called()
        written.assert_not_called()

    def test_hubs_are_reopened_even_with_no_device_blocked(self):
        """
        It returned at "Nothing stranded" before the hub loop, so a gate left
        closed by a SIGKILL with nothing plugged in stayed closed.
        """
        hub = Path("/sys/bus/usb/devices/usb1")
        with mock.patch.object(cli, "require_root"), \
             mock.patch.object(cli.instance, "running", return_value=False), \
             mock.patch.object(cli.gate, "unauthorized_devices",
                               return_value=[]), \
             mock.patch.object(cli.sysfs, "list_root_hubs", return_value=[hub]), \
             mock.patch.object(cli.sysfs, "get_authorized_default",
                               return_value=0), \
             mock.patch.object(cli.sysfs, "set_authorized_default") as reset, \
             redirect_stdout(io.StringIO()):
            cli.cmd_release()
        reset.assert_called_once_with(hub, 1)

    def test_a_failed_release_is_a_failure_status(self):
        dev = mock.Mock(syspath=Path("/sys/bus/usb/devices/1-1"))
        dev.name = "1-1"
        with mock.patch.object(cli, "require_root"), \
             mock.patch.object(cli.instance, "running", return_value=False), \
             mock.patch.object(cli.gate, "unauthorized_devices",
                               return_value=[dev]), \
             mock.patch.object(cli.sysfs, "set_authorized",
                               side_effect=OSError("EIO")), \
             mock.patch.object(cli.sysfs, "list_root_hubs", return_value=[]), \
             mock.patch.object(cli.report, "one_liner", return_value="x"), \
             redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as ended:
                cli.cmd_release()
        self.assertEqual(ended.exception.code, 1)

if __name__ == "__main__":
    unittest.main()


# ==========================================================================
# --remove-trusted / --remove-all
# ==========================================================================

class RemoveCommands(unittest.TestCase):
    """
    Two stores, two commands. --remove-trusted revokes trust and keeps the
    history; --remove-all clears both, always asks, and refuses while a
    daemon holds the history in memory (it would write it straight back).
    """

    def setUp(self):
        import tempfile
        from probolos import ledger as ledger_mod, trust as trust_mod
        from tests._support import descriptor_blob, make_device
        self.ledger_mod = ledger_mod
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.trust_path = root / "trusted.json"
        self.ledger_path = root / "state" / "ledger.json"

        store = trust_mod.TrustStore(self.trust_path)
        store.trust(make_device())
        self.assertIsNone(store.save())

        # Same identity, then an added keyboard interface: descriptor drift.
        led = ledger_mod.Ledger(self.ledger_path)
        led.record(make_device(), "user approved", approved=True)
        led.record(make_device(raw=descriptor_blob((0x08, 0x06, 0x50),
                                                   (0x03, 0x01, 0x01))),
                   "user rejected")
        self.assertIsNone(led.save())

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *argv, tty=True, answer="y"):
        out = io.StringIO()
        stdin = mock.Mock()
        stdin.isatty.return_value = tty
        with mock.patch.object(cli, "require_usb"), \
             mock.patch.object(cli, "require_root") as root, \
             mock.patch.object(cli.sys, "stdin", stdin), \
             mock.patch("builtins.input", return_value=answer) as asked, \
             redirect_stdout(out):
            cli.main([*argv, "--trust-file", str(self.trust_path),
                      "--ledger", str(self.ledger_path)])
        root.assert_not_called()          # never reaches the gate
        return out.getvalue(), asked

    def _trusted_count(self):
        from probolos import trust as trust_mod
        return len(trust_mod.TrustStore(self.trust_path).devices)

    # ---- --remove-trusted ------------------------------------------------

    def test_one_entry_goes_without_a_question_and_history_stays(self):
        out, asked = self._run("--remove-trusted", "1")
        asked.assert_not_called()
        self.assertEqual(self._trusted_count(), 0)
        self.assertTrue(self.ledger_path.exists())
        self.assertIn("history is kept", out)

    def test_all_asks_and_no_keeps_everything(self):
        out, asked = self._run("--remove-trusted", "all", answer="n")
        asked.assert_called_once()
        self.assertEqual(self._trusted_count(), 1)
        self.assertIn("Nothing removed", out)

    def test_all_with_yes_skips_the_question(self):
        _, asked = self._run("--remove-trusted", "all", "--yes")
        asked.assert_not_called()
        self.assertEqual(self._trusted_count(), 0)

    def test_forget_is_still_accepted(self):
        self._run("--forget", "1")
        self.assertEqual(self._trusted_count(), 0)

    # ---- --remove-all ----------------------------------------------------

    def test_remove_all_clears_both_and_names_the_drift_it_erases(self):
        out, asked = self._run("--remove-all")
        asked.assert_called_once()
        self.assertFalse(self.trust_path.exists())
        self.assertFalse(self.ledger_path.exists())
        self.assertIn("DRIFT", out)
        self.assertIn("0951:1666", out)

    def test_remove_all_declined_removes_nothing(self):
        self._run("--remove-all", answer="")          # Enter = the default, No
        self.assertTrue(self.trust_path.exists())
        self.assertTrue(self.ledger_path.exists())

    def test_remove_all_without_a_terminal_refuses(self):
        with self.assertRaises(SystemExit) as caught:
            self._run("--remove-all", tty=False)
        self.assertIn("--yes", str(caught.exception))
        self.assertTrue(self.ledger_path.exists())

    def test_remove_all_refuses_while_a_daemon_holds_the_history(self):
        import os
        fd = self.ledger_mod.claim(self.ledger_path)
        try:
            with self.assertRaises(SystemExit) as caught:
                self._run("--remove-all", "--yes")
        finally:
            os.close(fd)
        self.assertIn("running", str(caught.exception))
        self.assertTrue(self.trust_path.exists())
        self.assertTrue(self.ledger_path.exists())

    def test_nothing_there_says_so(self):
        self.trust_path.unlink()
        self.ledger_path.unlink()
        out, asked = self._run("--remove-all")
        asked.assert_not_called()
        self.assertIn("Nothing to remove", out)


# ==========================================================================
# One gate per machine
# ==========================================================================

class OneGatePerMachine(unittest.TestCase):
    """
    The service and a copy started by hand ran side by side: both asked about
    every device, and the second copy reopened the gate when it exited.
    """

    def setUp(self):
        import tempfile
        from probolos import instance
        self.instance = instance
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.object(instance, "LOCK_PATH",
                                    Path(tmp.name) / "probolos" / "instance.lock")
        patcher.start()
        self.addCleanup(patcher.stop)

    def _hold(self):
        import os
        fd = self.instance.acquire()
        self.addCleanup(os.close, fd)
        return fd

    def test_a_second_gate_is_refused(self):
        self._hold()
        with self.assertRaises(self.instance.AlreadyRunning):
            self.instance.acquire()

    def test_running_reports_a_held_lock_and_only_a_held_lock(self):
        import os
        self.assertFalse(self.instance.running())       # no file yet
        fd = self.instance.acquire()
        self.assertTrue(self.instance.running())
        os.close(fd)
        self.assertFalse(self.instance.running())

    def test_the_lock_file_is_root_only(self):
        import os
        import stat
        self._hold()
        mode = stat.S_IMODE(os.stat(self.instance.LOCK_PATH).st_mode)
        self.assertEqual(mode & 0o077, 0, f"lock file mode {mode:04o}")

    def test_main_refuses_before_touching_the_gate(self):
        self._hold()
        out = io.StringIO()
        with mock.patch.object(cli, "require_usb"), \
             mock.patch.object(cli, "require_root"), \
             mock.patch.object(cli.daemon, "serve") as serve, \
             redirect_stdout(out):
            with self.assertRaises(SystemExit) as caught:
                cli.main(["--no-trust", "--no-ledger"])
        serve.assert_not_called()
        self.assertIn("already running", str(caught.exception))
        self.assertNotIn("Closing", out.getvalue())

    def test_dry_run_needs_no_lock(self):
        self._hold()
        with mock.patch.object(cli, "require_usb"), \
             mock.patch.object(cli.daemon, "serve") as serve, \
             redirect_stdout(io.StringIO()):
            cli.main(["--dry-run", "--no-trust", "--no-ledger"])
        serve.assert_called_once()

    def test_an_uncreatable_lock_does_not_stop_the_gate(self):
        """Refusing to start would leave the ports open."""
        with mock.patch.object(self.instance, "acquire",
                               side_effect=PermissionError(13, "denied")), \
             redirect_stdout(io.StringIO()) as out:
            self.assertIsNone(cli.claim_the_gate())
        self.assertIn("could not check", out.getvalue())
