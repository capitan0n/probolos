"""
Regression tests for the agent socket, one per way it could be abused.

Named after what was actually done to it rather than after the function under
test: the point of each name is that someone reading a failure knows which
attack came back, not which line changed.

No root, no USB, no desktop session -- the socket and both ends of the
protocol are all that is needed, so these run in the same 4 seconds as the
rest of the suite.
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from cerberus.agentlink import (ANSWER_ALWAYS, ANSWER_NO, ANSWER_YES,
                                AgentLink, MSG_ANSWER, peer_credentials)

SETTLE = 0.15           # let the accept thread run before asserting on it


def _quiet(*_args, **_kwargs):
    pass


class AgentSocketHardening(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.log_lines = []
        self.servers = []
        self.clients = []

    def tearDown(self):
        for client in self.clients:
            try:
                client.close()
            except OSError:
                pass
        for server in self.servers:
            server.stop()
        self._dir.cleanup()

    # ---- helpers ----

    def server(self, allowed_uids=None, quiet=True):
        link = AgentLink(Path(self._dir.name) / f"agent{time.time_ns()}.sock",
                         log=_quiet if quiet else self.log_lines.append,
                         allowed_uids=allowed_uids)
        self.assertTrue(link.start())
        self.servers.append(link)
        return link

    def client(self, link):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(str(link.path))
        self.clients.append(sock)
        time.sleep(SETTLE)
        return sock

    @staticmethod
    def _answer_honestly(sock, answer, box=None, delay=0.0):
        """Behave like the real agent: read the question, echo its id back."""
        buffer = b""
        while b"\n" not in buffer:
            chunk = sock.recv(4096)
            if not chunk:
                return
            buffer += chunk
        question = json.loads(buffer.split(b"\n", 1)[0])
        if box is not None:
            box["id"] = question["id"]
        if delay:
            time.sleep(delay)
        try:
            sock.sendall((json.dumps({
                "type": MSG_ANSWER, "id": question["id"], "answer": answer,
            }) + "\n").encode())
        except OSError:
            pass

    def _agent_thread(self, sock, answer, box=None, delay=0.0):
        thread = threading.Thread(
            target=self._answer_honestly, args=(sock, answer, box, delay),
            daemon=True)
        thread.start()
        return thread

    # ---- F1a: answers sent before the question exists ----

    def test_present_answers_do_not_approve_a_device(self):
        """
        A client that fills the buffer with {"id":1..5,"answer":"always"}
        before any device is attached used to win: ids counted from 1, so the
        first real question was answered instantly from the buffer with no
        dialog shown and no human involved.
        """
        link = self.server()
        client = self.client(link)
        for guess in range(1, 6):
            client.sendall((json.dumps({
                "type": MSG_ANSWER, "id": guess, "answer": ANSWER_ALWAYS,
            }) + "\n").encode())
        time.sleep(SETTLE)

        self.assertIsNone(link.ask("dev", "body", "INFO", True, 0.5))

    def test_request_ids_are_not_sequential(self):
        """Two consecutive questions must not have adjacent, guessable ids."""
        link = self.server()
        client = self.client(link)
        seen = []
        for _ in range(2):
            box = {}
            self._agent_thread(client, ANSWER_NO, box=box)
            link.ask("dev", "body", "INFO", True, 2.0)
            seen.append(box["id"])

        self.assertNotEqual(seen[0], seen[1])
        self.assertGreater(min(seen), 2 ** 40)
        self.assertNotEqual(seen[1] - seen[0], 1)

    # ---- F1b: connection hijacking ----

    def test_second_connection_cannot_evict_the_live_agent(self):
        """
        Accepting each new connection over the old one meant anything that
        could open the socket became the thing answering questions about
        hardware. The running agent must keep the slot.
        """
        link = self.server()
        real = self.client(link)
        intruder = self.client(link)

        try:
            intruder.sendall((json.dumps({
                "type": MSG_ANSWER, "id": 1, "answer": ANSWER_ALWAYS,
            }) + "\n").encode())
        except OSError:
            pass                        # refused connections are closed at once

        box = {}
        self._agent_thread(real, ANSWER_NO, box=box)
        self.assertEqual(link.ask("dev", "body", "INFO", True, 3.0), ANSWER_NO)
        self.assertGreater(box["id"], 2 ** 40)

    def test_dead_agent_is_still_replaced(self):
        """
        The other half of the invariant: refusing every second connection
        would break logout, crash and session change. Only a LIVE agent is
        protected.
        """
        link = self.server()
        first = self.client(link)
        first.close()
        time.sleep(SETTLE)

        second = self.client(link)
        self._agent_thread(second, ANSWER_YES)
        self.assertEqual(link.ask("dev", "body", "INFO", True, 3.0), ANSWER_YES)

    # ---- F1c: peer credentials ----

    def test_connection_from_a_foreign_uid_is_refused(self):
        link = self.server(allowed_uids={os.getuid() + 4242}, quiet=False)
        self.client(link)

        self.assertFalse(link.connected)
        self.assertTrue(any("REFUSED" in line for line in self.log_lines))

    def test_connection_from_the_permitted_uid_is_accepted(self):
        link = self.server(allowed_uids={os.getuid()})
        agent = self.client(link)

        self.assertTrue(link.connected)
        self.assertEqual(link.peer[1], os.getuid())
        self._agent_thread(agent, ANSWER_ALWAYS)
        self.assertEqual(link.ask("dev", "body", "INFO", True, 3.0),
                         ANSWER_ALWAYS)

    def test_peer_credentials_report_this_process(self):
        """SO_PEERCRED must be readable at all, on every supported kernel."""
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            pid, uid, gid = peer_credentials(left)
        finally:
            left.close()
            right.close()
        self.assertEqual((pid, uid, gid), (os.getpid(), os.getuid(), os.getgid()))

    # ---- resource and timing bounds ----

    def test_reply_without_a_newline_cannot_grow_without_limit(self):
        """
        MAX_MESSAGE bounded each recv() but not their sum. A peer sending
        bytes and never a line ending grew the buffer until the timeout.
        """
        link = self.server()
        client = self.client(link)

        def flood():
            try:
                for _ in range(8):
                    client.sendall(b"A" * 4096)
            except OSError:
                pass

        threading.Thread(target=flood, daemon=True).start()
        self.assertIsNone(link.ask("dev", "body", "INFO", True, 10.0))
        self.assertFalse(link.connected)

    def test_answer_arriving_after_the_deadline_is_not_honoured(self):
        """
        The loop checked the deadline only before blocking for a full second,
        so an answer up to a second late was still accepted -- after the user
        had been shown a dialog counting down to that deadline.
        """
        link = self.server()
        client = self.client(link)
        self._agent_thread(client, ANSWER_ALWAYS, delay=1.0)

        started = time.monotonic()
        self.assertIsNone(link.ask("dev", "body", "INFO", True, 0.4))
        self.assertLess(time.monotonic() - started, 0.9)

    def test_a_late_answer_does_not_resolve_the_next_question(self):
        """A reply to question N must not be spent on question N+1."""
        link = self.server()
        client = self.client(link)
        self._agent_thread(client, ANSWER_ALWAYS, delay=0.8)

        self.assertIsNone(link.ask("first", "body", "INFO", True, 0.4))
        self.assertIsNone(link.ask("second", "body", "INFO", True, 0.4))


if __name__ == "__main__":
    unittest.main()
