"""
Regression tests for the security/correctness audit fixes.

Each test fails on the code as it stood before the matching fix.
"""

from __future__ import annotations

import os
import pwd
import shutil
import struct
import tempfile
import types
import unittest
from unittest import mock

from probolos import __main__ as cli
from probolos import agent, privsep, session, storage


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


class LockMonitorIsNotDecidedBeforeLogin(unittest.TestCase):
    """
    detect() fell back to AlwaysUnlocked whenever no graphical session existed
    yet -- which is always the case for a service started at boot -- and the
    lock policy then stayed off for the whole run.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.flag = os.path.join(self.tmp, "logged-in")
        self.loginctl = os.path.join(self.tmp, "loginctl")
        with open(self.loginctl, "w") as fh:
            fh.write(
                "#!/bin/sh\n"
                'if [ "$1" = list-sessions ]; then\n'
                f'  [ -f {self.flag} ] && echo "2 1000 alice seat0 tty2"\n'
                "  exit 0\n"
                "fi\n"
                'case "$*" in *LockedHint*) echo LockedHint=yes ;;\n'
                "  *) echo Type=wayland; echo Remote=no ;; esac\n")
        os.chmod(self.loginctl, 0o755)

    def test_lock_is_seen_after_a_login_that_followed_startup(self):
        with mock.patch.object(session, "_LOGINCTL_CANDIDATES",
                               (self.loginctl,)):
            monitor = session.detect()
            self.assertIsNone(monitor.is_locked())      # nobody logged in yet
            open(self.flag, "w").close()                 # login, then lock
            self.assertTrue(monitor.is_locked())

    def test_no_logind_still_falls_back(self):
        with mock.patch.object(session, "_LOGINCTL_CANDIDATES",
                               (os.path.join(self.tmp, "absent"),)):
            self.assertIsInstance(session.detect(), session.AlwaysUnlocked)


class PartitionSignaturesAreReachable(unittest.TestCase):
    """Per-partition reads were one sector: ext and btrfs magics never fit."""

    def _image(self, magic_offset, magic, part_type):
        path = os.path.join(self.tmp, "disk.img")
        data = bytearray(1024 * 1024)
        struct.pack_into("<BBBBBBBBII", data, 446,
                         0, 0, 0, 0, part_type, 0, 0, 0, 128, 1024)
        data[510:512] = b"\x55\xaa"
        data[128 * 512 + magic_offset:128 * 512 + magic_offset + len(magic)] = magic
        with open(path, "wb") as fh:
            fh.write(data)
        return path, len(data) // 512

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def _inspect(self, path, sectors):
        with mock.patch.object(storage, "read_size_sectors",
                               return_value=sectors):
            return storage.inspect(path)

    def test_ext_inside_a_fat_partition_is_recognised(self):
        report = self._inspect(*self._image(0x438, b"\x53\xef", 0x0C))
        self.assertEqual(report.signatures.get(0), "ext2/3/4")

    def test_btrfs_inside_a_partition_is_recognised(self):
        report = self._inspect(*self._image(0x10040, b"_BHRfS_M", 0x83))
        self.assertEqual(report.signatures.get(0), "btrfs")


class NotificationBodyIsNotMarkup(unittest.TestCase):
    """Device strings reached the notification body as live markup."""

    def test_device_markup_is_escaped(self):
        notifier = agent.Notifier(log=lambda *_a: None)
        notifier._gdbus = "/usr/bin/gdbus"
        with mock.patch("subprocess.run") as run:
            run.return_value = types.SimpleNamespace(
                returncode=0, stdout="(uint32 7,)", stderr="")
            notifier.notify("New USB device",
                            '<a href="https://evil.example/">approve</a>')
        argv = run.call_args[0][0]
        body = argv[argv.index("New USB device") + 1]
        self.assertNotIn("<a", body)
        self.assertIn("&lt;a href=", body)


if __name__ == "__main__":
    unittest.main()
