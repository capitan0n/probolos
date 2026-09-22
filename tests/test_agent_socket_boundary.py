"""
Who can reach, replace or feed the admission socket.

Three separate defects, one boundary:

  1. The socket's directory was mode 2770. Group WRITE on a directory is the
     right to unlink and replace any file inside it, whatever that file's own
     owner and mode -- so every member of the desktop user's group, and every
     process running as the shared `nobody` account that owns it, could put
     its own listener where the admission prompt is expected. connect() never
     needs directory write: traverse on the path and write on the socket inode
     are enough, which is what 2750 plus a 0660 socket gives.

  2. The socket's mode was set with os.chmod on a bare path, as root in the
     no-privsep case, on a path the operator supplies via --agent-socket.
     _chown_for_owner two lines below it was hardened against exactly that and
     carries the reasoning; the chmod was not.

  3. stop() unlinked that same operator-supplied path unconditionally.

Plus the agent half: an unbounded receive buffer and a `timeout` field that
was float()ed straight off the wire.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from probolos import agent as agent_mod
from probolos import agentlink


class SocketDirectoryIsNotGroupWritable(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "probolos"
        patcher = mock.patch.object(agentlink, "DEFAULT_SOCKET",
                                    self.root / "agent.sock")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_group_cannot_replace_the_socket(self):
        agentlink.prepare_socket_dir(self.root / "agent.sock",
                                     os.getuid(), os.getgid())
        mode = stat.S_IMODE(os.stat(self.root).st_mode)
        self.assertFalse(mode & stat.S_IWGRP,
                         f"directory is group-writable (mode {mode:04o}); "
                         f"anyone in that group can unlink the agent socket "
                         f"and bind their own listener in its place")
        self.assertFalse(mode & (stat.S_IRWXO),
                         f"directory is reachable by others (mode {mode:04o})")

    def test_group_can_still_traverse_to_the_socket(self):
        """
        The permission that must survive: without group execute the desktop
        agent cannot reach the socket at all and the prompt disappears.
        """
        agentlink.prepare_socket_dir(self.root / "agent.sock",
                                     os.getuid(), os.getgid())
        mode = stat.S_IMODE(os.stat(self.root).st_mode)
        self.assertTrue(mode & stat.S_IXGRP, "group lost traverse permission")
        self.assertTrue(mode & stat.S_ISGID,
                        "setgid dropped; the socket would not inherit the "
                        "desktop group and the agent could not open it")

    def test_the_directory_must_stay_under_the_runtime_root(self):
        with self.assertRaises(OSError):
            agentlink.prepare_socket_dir(Path("/etc/probolos-agent.sock"),
                                         os.getuid(), os.getgid())


class SocketMetadataIsNotChangedByName(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.sock_path = self.dir / "agent.sock"

    def test_the_socket_is_never_group_readable_by_accident(self):
        link = agentlink.AgentLink(self.sock_path, log=lambda *_a: None,
                                   allowed_uids={os.getuid()})
        self.assertTrue(link.start())
        self.addCleanup(link.stop)
        mode = stat.S_IMODE(os.lstat(self.sock_path).st_mode)
        self.assertEqual(mode, 0o660, f"socket mode is {mode:04o}")

    def test_a_non_socket_at_the_path_is_refused_rather_than_replaced(self):
        self.sock_path.write_text("something else")
        messages = []
        link = agentlink.AgentLink(self.sock_path, log=messages.append,
                                   allowed_uids={os.getuid()})
        self.assertFalse(link.start())
        self.assertTrue(any("could not listen" in m for m in messages),
                        messages)
        self.assertEqual(self.sock_path.read_text(), "something else")

    def test_chmod_refuses_a_path_that_is_no_longer_a_socket(self):
        """
        The guard itself, exercised directly: a symlink swapped in between
        bind() and the chmod must be an error, not a redirection.
        """
        victim = self.dir / "victim"
        victim.write_text("x")
        victim.chmod(0o600)
        os.symlink(victim, self.sock_path)
        link = agentlink.AgentLink(self.sock_path, log=lambda *_a: None)
        directory_fd = os.open(self.dir, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, directory_fd)
        with self.assertRaises(OSError):
            link._chmod_socket(directory_fd, 0o660)
        self.assertEqual(stat.S_IMODE(os.stat(victim).st_mode), 0o600)

    def test_stop_does_not_delete_whatever_sits_at_the_path(self):
        keep = self.dir / "important"
        keep.write_text("do not delete me")
        link = agentlink.AgentLink(keep, log=lambda *_a: None)
        link.stop()
        self.assertTrue(keep.exists(),
                        "stop() unlinked an operator-supplied path that was "
                        "never a socket we created")

    def test_stop_removes_its_own_socket(self):
        link = agentlink.AgentLink(self.sock_path, log=lambda *_a: None,
                                   allowed_uids={os.getuid()})
        self.assertTrue(link.start())
        link.stop()
        self.assertFalse(self.sock_path.exists())


class AgentReceiveIsBounded(unittest.TestCase):

    def test_a_peer_that_never_sends_a_newline_is_dropped(self):
        """
        MAX_MESSAGE bounded each recv() and not their sum. The agent does not
        get to choose what it is talking to -- it connects to a path -- so an
        occupant of that path could grow this without limit.
        """
        listener, peer = socket.socketpair()
        self.addCleanup(listener.close)
        self.addCleanup(peer.close)

        messages = []
        agent = agent_mod.Agent(Path("/nonexistent"), log=messages.append)
        agent.sock = listener
        agent.sock.settimeout(1.0)
        agent.dialog = mock.Mock()
        agent.notifier = mock.Mock(available=lambda: False)

        sent = [0]

        def flood():
            try:
                # Far more than MAX_MESSAGE, and never a newline. Bounded so
                # the test cannot hang if the guard is missing; the assertion
                # below is what distinguishes "dropped" from "still reading".
                for _ in range(64):
                    peer.sendall(b"A" * 4096)
                    sent[0] += 4096
            except OSError:
                pass

        thread = threading.Thread(target=flood)
        thread.start()
        self.addCleanup(thread.join)

        # connect() would replace the socket with a real one; the loop is what
        # is under test, so it is fed the socketpair directly.
        with mock.patch.object(agent, "connect", return_value=True):
            agent.run()

        self.assertTrue(any("oversized" in m for m in messages), messages)
        agent.dialog.confirm.assert_not_called()


class AgentTimeoutIsValidated(unittest.TestCase):
    """
    `float(message.get("timeout", 60))` raised on a string, a list or a null
    and took the agent down -- a way to remove the desktop prompt by sending
    one malformed message.
    """

    def test_unusable_values_fall_back_to_the_default(self):
        for value in ("soon", None, [], {}, True, float("nan"),
                      float("inf"), -5, 0):
            with self.subTest(value=value):
                result = agent_mod._dialog_timeout(value)
                self.assertGreaterEqual(result, agent_mod.MIN_DIALOG_TIMEOUT)
                self.assertLessEqual(result, agent_mod.MAX_DIALOG_TIMEOUT)

    def test_an_absurd_value_is_clamped_rather_than_honoured(self):
        self.assertEqual(agent_mod._dialog_timeout(10 ** 9),
                         agent_mod.MAX_DIALOG_TIMEOUT)

    def test_an_ordinary_value_passes_through(self):
        self.assertEqual(agent_mod._dialog_timeout(45), 45.0)

    def test_non_string_display_fields_do_not_crash_the_agent(self):
        agent = agent_mod.Agent(Path("/nonexistent"), log=lambda *_a: None)
        agent.notifier = mock.Mock(available=lambda: False)
        agent.dialog = mock.Mock()
        agent.dialog.confirm.return_value = False
        agent.sock = None
        agent._handle(json.dumps({
            "type": agent_mod.MSG_DECIDE, "id": 1,
            "title": {"not": "a string"}, "body": ["nor", "this"],
            "timeout": "whenever",
        }).encode())
        agent.dialog.confirm.assert_called_once()
        text = agent.dialog.confirm.call_args.kwargs["text"]
        self.assertIsInstance(text, str)

    def test_a_message_that_is_not_an_object_is_ignored(self):
        agent = agent_mod.Agent(Path("/nonexistent"), log=lambda *_a: None)
        agent.notifier = mock.Mock(available=lambda: False)
        agent.dialog = mock.Mock()
        agent._handle(b'["not", "an", "object"]')
        agent.dialog.confirm.assert_not_called()


if __name__ == "__main__":
    unittest.main()
