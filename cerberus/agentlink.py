"""
Talking to a desktop agent, so the answer does not have to come from a terminal.

WHY A THIRD PROCESS
-------------------
The analyzer runs unprivileged and OUTSIDE the user's login session, which is
what makes privilege separation work -- and which also means it cannot reach
that session's D-Bus, cannot show a notification, and should not learn how.
Graphics belong to the session; admission control does not.

So there are three parts, each knowing as little as possible about the others:

    gate      (root)      writes sysfs, opens devices. Knows nothing else.
    analyzer  (nobody)    all the judgement. Knows nothing about graphics.
    agent     (the user)  shows a notification. Knows nothing about USB.

The agent connects inward over a Unix socket and answers questions. If no agent
is connected, the analyzer falls back to the terminal exactly as before -- the
notification path is an interface, not a dependency.

THE PROPERTY THAT MAKES A CLICKABLE PROMPT SAFE
-----------------------------------------------
Approving hardware by clicking looks dangerous: a malicious HID device could
click its own approval. It cannot, and the reason is structural rather than
clever -- when the notification appears the device is still UNAUTHORIZED. It has
no input path into the session, so it cannot move a pointer or press a key. The
question is asked precisely while the thing being asked about is unable to
answer it.

This is the same invariant the terminal prompt relied on, and it is why the
device is put back to blocked the moment the observation window ends. Break that
and the notification becomes unsafe immediately, which is why it is a tested
invariant and not a comment.

WHAT THE AGENT IS NOT TRUSTED WITH
----------------------------------
A CRITICAL finding is never approvable from a notification. Two clicks are too
cheap for a device that matches an attack pattern, and a person clicking through
a popup is not in the same state of attention as one typing the word
"authorize". For those, the agent is told to display a warning and refer the
decision to the terminal.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from pathlib import Path
from typing import Optional

DEFAULT_SOCKET = Path("/run/cerberus/agent.sock")

# Message kinds, analyzer -> agent
MSG_DECIDE = "decide"
MSG_CRITICAL = "critical"       # display only; the answer must come elsewhere
MSG_CANCEL = "cancel"           # device vanished, withdraw the notification

# Message kinds, agent -> analyzer
MSG_ANSWER = "answer"
MSG_HELLO = "hello"

ANSWER_YES = "yes"
ANSWER_ALWAYS = "always"
ANSWER_NO = "no"

MAX_MESSAGE = 16384


def prepare_socket_dir(path: Path, owner_uid: int, group_gid: int) -> None:
    """
    Create the socket directory so that the analyzer and the agent can both
    reach it, and nobody else can.

    Called by the launcher while still root. The directory is owned by the
    analyzer's user, group-owned by the desktop user's group, mode 2770 -- the
    setgid bit matters: it makes the socket the analyzer creates inherit the
    group, which is how a process running as `nobody` ends up with a socket the
    desktop user can open without anyone having to be given broad permissions.

    The alternative -- a world-writable socket -- would let any local account
    answer questions about hardware, which is not a trade worth making for a
    little convenience.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chown(path.parent, owner_uid, group_gid)
    os.chmod(path.parent, 0o2770)


class AgentLink:
    """
    Server side. Accepts one agent at a time and asks it questions.

    Connections are accepted on a background thread so the udev loop is never
    blocked waiting for a desktop process that may never appear. Only the most
    recent connection is kept: an agent that restarts (logout, crash, session
    change) simply replaces the old one.
    """

    def __init__(self, path: Path = DEFAULT_SOCKET, log=print):
        self.path = Path(path)
        self.log = log
        self._listener: Optional[socket.socket] = None
        self._conn: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._next_id = 1

    # ---- lifecycle ----

    def start(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists():
                self.path.unlink()
            self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._listener.bind(str(self.path))
            # Group-accessible only. The group was set on the directory by the
            # launcher and inherited via its setgid bit.
            os.chmod(self.path, 0o660)
            self._listener.listen(1)
            self._listener.settimeout(0.5)
        except OSError as exc:
            self.log(f"[agent] could not listen on {self.path}: {exc}")
            self._listener = None
            return False

        threading.Thread(target=self._accept_loop, daemon=True).start()
        return True

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            for sock in (self._conn, self._listener):
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass
            self._conn = self._listener = None
        try:
            self.path.unlink()
        except OSError:
            pass

    def _accept_loop(self) -> None:
        while not self._stop.is_set() and self._listener:
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.settimeout(1.0)
            with self._lock:
                if self._conn:
                    try:
                        self._conn.close()
                    except OSError:
                        pass
                self._conn = conn
            self.log("[agent] desktop agent connected")

    @property
    def connected(self) -> bool:
        with self._lock:
            return self._conn is not None

    # ---- asking ----

    def ask(self, title: str, body: str, severity: str,
            allow_always: bool, timeout: float) -> Optional[str]:
        """
        Put a question to the agent and wait for an answer.

        Returns "yes", "always", "no", or None when the agent could not answer
        (not connected, disconnected mid-question, or silent past the timeout).
        None means "fall back", not "no" -- the caller decides what a missing
        answer means, and the daemon treats it as a reason to use the terminal
        rather than as a decision nobody made.
        """
        with self._lock:
            conn = self._conn
        if conn is None:
            return None

        request_id = self._next_id
        self._next_id += 1
        message = {
            "type": MSG_DECIDE,
            "id": request_id,
            "title": title,
            "body": body,
            "severity": severity,
            "allow_always": allow_always,
            "timeout": timeout,
        }
        try:
            conn.sendall((json.dumps(message) + "\n").encode())
        except OSError as exc:
            self.log(f"[agent] lost connection while asking: {exc}")
            self._drop(conn)
            return None

        deadline = time.monotonic() + timeout
        buffer = b""
        while time.monotonic() < deadline:
            try:
                chunk = conn.recv(MAX_MESSAGE)
            except socket.timeout:
                continue
            except OSError:
                self._drop(conn)
                return None
            if not chunk:
                self._drop(conn)
                return None
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                answer = self._parse_answer(line, request_id)
                if answer is not None:
                    return answer
        return None

    def notify_critical(self, title: str, body: str) -> None:
        """
        Tell the agent to warn, without offering an answer.

        A CRITICAL device is not approvable by clicking; the notification exists
        so the user knows something is waiting for them, not so they can wave it
        through.
        """
        with self._lock:
            conn = self._conn
        if conn is None:
            return
        try:
            conn.sendall((json.dumps({
                "type": MSG_CRITICAL, "title": title, "body": body,
            }) + "\n").encode())
        except OSError:
            self._drop(conn)

    # ---- internals ----

    def _parse_answer(self, line: bytes, request_id: int) -> Optional[str]:
        try:
            obj = json.loads(line.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if obj.get("type") != MSG_ANSWER:
            return None
        if obj.get("id") != request_id:
            # A late answer to a question that has already been resolved. It is
            # ignored rather than applied, so a stale click can never approve a
            # device the user is not currently looking at.
            return None
        answer = obj.get("answer")
        return answer if answer in (ANSWER_YES, ANSWER_ALWAYS, ANSWER_NO) else None

    def _drop(self, conn) -> None:
        with self._lock:
            if self._conn is conn:
                self._conn = None
        try:
            conn.close()
        except OSError:
            pass
