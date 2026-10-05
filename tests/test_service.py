"""
The shipped service: the account its analyzer runs as.

Covers systemd/probolos.service, systemd/probolos.sysusers and install.sh,
read as the files that ship, and the command line the unit runs, through
probolos.__main__.
"""

from __future__ import annotations

import os
import pwd
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from probolos import __main__ as cli
from probolos import privsep

ROOT = Path(__file__).resolve().parent.parent
UNIT = ROOT / "systemd" / "probolos.service"
SYSUSERS = ROOT / "systemd" / "probolos.sysusers"
INSTALL = ROOT / "install.sh"


def _unit_lines():
    """The unit's logical lines: comments dropped, continuations joined."""
    lines, current = [], ""
    for raw in UNIT.read_text().splitlines():
        if not current and raw.lstrip().startswith(("#", ";")):
            continue
        if raw.endswith("\\"):
            current += raw[:-1] + " "
            continue
        lines.append(current + raw)
        current = ""
    return lines


def _exec_start():
    """ExecStart's arguments after `python3 -m probolos`."""
    (line,) = [ln for ln in _unit_lines() if ln.startswith("ExecStart=")]
    argv = shlex.split(line[len("ExecStart="):])
    return argv[argv.index("probolos") + 1:]


def _environment():
    env = {}
    for line in _unit_lines():
        if line.startswith("Environment="):
            key, _, value = line[len("Environment="):].partition("=")
            env[key] = value
    return env


def _analyzer_account(argv):
    """--privsep-user's value, or its default when the unit does not pass it."""
    if "--privsep-user" in argv:
        return argv[argv.index("--privsep-user") + 1]
    return "nobody"


class TheServiceAnalyzerHasAnAccountOfItsOwn(unittest.TestCase):
    """
    ROADMAP 1.11. The unit ran `--privsep` with the default --privsep-user,
    the shared `nobody`. Any other process running as `nobody` could kill
    the analyzer; every analyzer exit reopens every hub, and the devices
    attached until the restart became the next run's untouched baseline.
    """

    def test_the_unit_names_an_account_and_it_is_not_nobody(self):
        argv = _exec_start()
        self.assertIn("--privsep", argv)
        self.assertNotEqual(_analyzer_account(argv), "nobody")

    def test_sysusers_declares_that_account(self):
        account = _analyzer_account(_exec_start())
        entries = [line.split() for line in SYSUSERS.read_text().splitlines()
                   if line.strip() and not line.lstrip().startswith("#")]
        self.assertIn(["u", account], [e[:2] for e in entries])

    def test_install_creates_it_before_it_starts_the_service(self):
        script = INSTALL.read_text()
        self.assertIn('"$SRC/systemd/probolos.sysusers"', script)
        created = script.index('systemd-sysusers "$SYSUSERS"')
        started = script.index("systemctl restart probolos.service")
        self.assertLess(created, started)

    def test_the_unconfigured_placeholder_is_the_analyzer_account(self):
        # The gate keeps the agent off when --agent-user is the analyzer's
        # own account. With the analyzer off `nobody`, a placeholder still
        # reading `nobody` would hand the prompt to every `nobody` process.
        self.assertEqual(_environment()["PROBOLOS_AGENT_USER"],
                         _analyzer_account(_exec_start()))


class TheUnitCommandLine(unittest.TestCase):
    """The unit's own ExecStart, run through main() with privsep mocked."""

    def _run_unit_command(self):
        argv = [_environment()["PROBOLOS_AGENT_USER"]
                if arg == "${PROBOLOS_AGENT_USER}" else arg
                for arg in _exec_start()]
        account = _analyzer_account(argv)
        fake = pwd.struct_passwd((account, "x", 61234, 61234, "", "/",
                                  "/usr/bin/nologin"))
        real_getpwnam = pwd.getpwnam
        started, served = {}, {}

        def fake_start(analyzer_main, **kw):
            started.update(kw)
            analyzer_main(object())
            return 0

        with mock.patch.object(cli, "require_usb"), \
                mock.patch.object(cli, "require_root"), \
                mock.patch.object(cli, "claim_the_gate", return_value=None), \
                mock.patch.object(cli.sysfs, "install_backend"), \
                mock.patch.object(cli.daemon, "serve",
                                  side_effect=lambda **kw: served.update(kw)), \
                mock.patch.object(cli.agentlink, "prepare_socket_dir"), \
                mock.patch.object(privsep, "prepare_trust_readable"), \
                mock.patch.object(privsep, "start", side_effect=fake_start), \
                mock.patch("pwd.getpwnam",
                           side_effect=lambda name: fake if name == account
                           else real_getpwnam(name)), \
                mock.patch("builtins.print"):
            with self.assertRaises(SystemExit) as caught:
                cli.main(argv)
        self.assertEqual(caught.exception.code, 0)
        return account, started, served

    def test_the_analyzer_drops_to_the_unit_account(self):
        account, started, _ = self._run_unit_command()
        self.assertEqual(started["drop_to"], account)
        self.assertNotEqual(started["drop_to"], "nobody")

    def test_an_unconfigured_unit_still_runs_without_the_agent(self):
        _, _, served = self._run_unit_command()
        self.assertIsNone(served["agent_socket"])
        self.assertIsNone(served["agent_uid"])


@unittest.skipUnless(os.geteuid() == 0 and shutil.which("systemd-sysusers"),
                     "needs root and systemd-sysusers")
class SysusersMakesALockedSystemAccount(unittest.TestCase):
    """The shipped sysusers file, applied by the real tool to a scratch root."""

    def test_system_uid_no_login_password_locked(self):
        account = _analyzer_account(_exec_start())
        with tempfile.TemporaryDirectory() as root:
            confdir = Path(root, "etc", "sysusers.d")
            confdir.mkdir(parents=True)
            shutil.copy(SYSUSERS, confdir / "probolos.conf")
            subprocess.run(["systemd-sysusers", f"--root={root}"], check=True,
                           capture_output=True)
            passwd = Path(root, "etc", "passwd").read_text().splitlines()
            shadow = Path(root, "etc", "shadow").read_text().splitlines()
        (entry,) = [ln.split(":") for ln in passwd if ln.startswith(account + ":")]
        (secret,) = [ln.split(":") for ln in shadow if ln.startswith(account + ":")]
        self.assertTrue(0 < int(entry[2]) < 1000, entry)
        self.assertRegex(entry[6], re.compile(r"/(nologin|false)$"))
        self.assertTrue(secret[1].startswith("!"), secret)


if __name__ == "__main__":
    unittest.main()
