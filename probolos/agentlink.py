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

WHO IS ALLOWED TO BE THE AGENT
------------------------------
The socket is mode 0660 in a 2770 directory, so only the desktop user's group
can open it at all. That is a real boundary, but it is filesystem permission
alone, and three things have to hold on top of it before a click on a
notification can be treated as a human decision:

    1. The connecting process is who it claims to be. SO_PEERCRED is recorded
       by the kernel at connect() time, cannot be forged by the peer, and is
       the only identity claim here that the client does not simply assert.

    2. A live agent cannot be displaced. Accepting each new connection over
       the old one was written for the case where the agent restarts; it also
       means anything that can open the socket can evict the running agent and
       become the thing that answers questions about hardware.

       The liveness check that enforces this had a race of its own. It runs on
       the accept thread and briefly puts the LIVE connection into non-blocking
       mode; ask() runs on the main thread and is sitting in recv() on that
       same socket. A connection attempt timed to land inside a question would
       make ask()'s recv raise BlockingIOError -- an OSError, not a timeout --
       which ask() reads as "the agent went away" and answers by dropping the
       real agent and returning None. So merely CONNECTING repeatedly was
       enough to cancel every question and evict the agent, which is the thing
       this check exists to prevent. A question in flight is now itself proof
       of life: the probe is skipped entirely while one is open.

    3. An answer cannot precede its question. Request ids counting from 1 let
       a client put replies into the buffer before anything is asked, so the
       first real device question resolves instantly from a value chosen by
       the client rather than by a person. Ids are therefore unguessable, and
       whatever is buffered when a question is asked is discarded unread.

What remains, deliberately: a process running as the desktop user can occupy
the agent slot and never answer. That is not a bypass -- ask() times out and
the daemon falls back to the terminal, which is the safe direction -- and it
cannot be closed here, because a process with that uid can ptrace the real
agent anyway. The trust boundary is the uid, and it is now enforced by the
kernel rather than only by file permissions.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Optional

DEFAULT_SOCKET = Path("/run/probolos/agent.sock")

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
# Not a decision. Sent by the agent when it has no way to show a dialog at all,
# so the analyzer can tell "the user refused" apart from "the user was never
# asked" and fall back to the terminal instead of silently denying everything.
ANSWER_UNAVAILABLE = "unavailable"

MAX_MESSAGE = 16384

# struct ucred { pid_t pid; uid_t uid; gid_t gid; } -- a signed int followed by
# two unsigned ones. Linux-specific, like the rest of this project.
_UCRED = "iII"
_UCRED_SIZE = struct.calcsize(_UCRED)


def peer_credentials(conn) -> tuple:
    """
    Who is on the other end of a connected Unix socket, per the kernel.

    Returns (pid, uid, gid). The kernel fills these in at connect() time from
    the connecting process's real credentials, so they cannot be spoofed by
    the peer and do not change if it later execs something setuid.
    """
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED_SIZE)
    return struct.unpack(_UCRED, raw)


def _still_connected(conn) -> bool:
    """
    True while the peer's end is still open.

    MSG_PEEK looks without consuming, so a real answer already in flight is not
    swallowed by the liveness check. An idle live connection has nothing to
    read and raises BlockingIOError; a peer that has gone away returns b"".
    Data waiting to be read also counts as alive, which is correct: something
    is there, and if it turns out not to be a real agent the question put to it
    simply times out into the terminal fallback.

    The socket is switched to non-blocking explicitly rather than relying on
    MSG_DONTWAIT. On a socket that has a timeout set -- which every accepted
    connection here does -- CPython waits for readability BEFORE calling recv,
    so MSG_DONTWAIT never gets a chance to take effect and the call blocks for
    the full timeout and then raises socket.timeout. socket.timeout is an
    OSError, so a perfectly healthy idle agent would be reported dead, and the
    connection it is holding would be handed to whoever asked next -- turning
    the fix for connection hijacking back into the hijack itself.
    """
    try:
        previous = conn.gettimeout()
        conn.setblocking(False)
    except OSError:
        return False
    try:
        return bool(conn.recv(1, socket.MSG_PEEK))
    except (BlockingIOError, InterruptedError):
        return True
    except OSError:
        return False
    finally:
        try:
            conn.settimeout(previous)
        except OSError:
            pass


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
    from .securefs import open_directory
    directory = os.path.abspath(path.parent)
    root = str(DEFAULT_SOCKET.parent)
    if directory != root and not directory.startswith(root + os.sep):
        raise OSError(f"agent socket directory must be under {root}")
    fd = open_directory(directory, create=True)
    try:
        os.fchown(fd, owner_uid, group_gid)
        os.fchmod(fd, 0o2770)
    finally:
        os.close(fd)


class AgentLink:
    """
    Server side. Accepts one agent at a time and asks it questions.

    Connections are accepted on a background thread so the udev loop is never
    blocked waiting for a desktop process that may never appear. One agent is
    connected at a time: a dead one is replaced, a live one is never displaced.
    An agent that restarts (logout, crash, session change) reconnects into the
    slot its predecessor's closed socket freed.

    `allowed_uids` is the set of uids permitted to be the agent -- normally the
    single uid of the desktop session, which the launcher already knows because
    it passes it to prepare_socket_dir(). When it is None no uid check is made
    and the peer is only logged, which keeps existing callers working but
    leaves the boundary at file permissions alone; pass it in.
    """

    def __init__(self, path: Path = DEFAULT_SOCKET, log=print,
                 allowed_uids=None, owner_uid=None, owner_gid=None):
        self.path = Path(path)
        self.log = log
        self.allowed_uids = None if allowed_uids is None else set(allowed_uids)
        # When set, start() chowns the socket (and the directory it had to
        # create) to this owner. This is the no-privsep case: root binds the
        # socket directly, so without a chown it stays root:root 0660 and the
        # desktop agent -- which runs as the user, not root -- gets EACCES on
        # connect(). Under --privsep the directory is prepared by the launcher
        # instead and these stay None.
        self.owner_uid = owner_uid
        self.owner_gid = owner_gid
        self._listener: Optional[socket.socket] = None
        self._conn: Optional[socket.socket] = None
        self._peer: Optional[tuple] = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        # How many questions are open on the current connection right now.
        # Non-zero means the main thread is inside recv() on that socket, and
        # the accept thread must not touch its blocking mode. See the header.
        self._asking = 0

    # ---- lifecycle ----

    def start(self) -> bool:
        # The directory descriptor is HELD for the rest of this block, not
        # opened and dropped.
        #
        # open_directory(secure=True) verifies every component of the path and
        # then the fd was closed immediately, after which bind(), chmod() and
        # chown() all went back to working by NAME. So the directory that was
        # checked and the directory that was written to were only the same one
        # by assumption -- the exact pattern securefs.py was introduced to
        # remove everywhere else. It is not exploitable as the tree ships,
        # because the verification refuses a group-writable /run/probolos and
        # the root-owned one it accepts cannot be swapped. But `os.chown` on a
        # name follows symlinks, so the day that directory is made writable by
        # the desktop user -- which is exactly what the privsep layout does to
        # it -- this becomes root chowning a file of someone else's choosing.
        directory_fd = None
        try:
            created_dir = not self.path.parent.exists()
            if os.geteuid() == 0:
                from .securefs import open_directory
                directory_fd = open_directory(self.path.parent, create=True,
                                              secure=True)
            else:
                self.path.parent.mkdir(parents=True, exist_ok=True)
            # lexists, not exists: exists() follows symlinks, so a DANGLING
            # symlink left at the socket path -- which anyone in the
            # directory's group can plant -- reads as absent, is never
            # unlinked, and makes bind() fail. The agent path would then be
            # silently unavailable for the whole run.
            if os.path.lexists(self.path):
                import stat
                if not stat.S_ISSOCK(os.lstat(self.path).st_mode):
                    raise OSError("refusing to replace a non-socket agent path")
                self.path.unlink()
            self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._listener.bind(str(self.path))
            # Group-accessible only. Under --privsep the group was set on the
            # directory by the launcher and inherited via its setgid bit; in
            # the no-privsep case we chown below to reach the same end.
            os.chmod(self.path, 0o660)
            self._chown_for_owner(directory_fd)
            self._listener.listen(1)
            self._listener.settimeout(0.5)
        except OSError as exc:
            self.log(f"[agent] could not listen on {self.path}: {exc}")
            self._listener = None
            return False
        finally:
            if directory_fd is not None:
                os.close(directory_fd)

        threading.Thread(target=self._accept_loop, daemon=True).start()
        if self.allowed_uids is None:
            # Visible rather than silent. Without a uid the only thing keeping
            # other accounts off this socket is the 0660/2770 permission pair,
            # and on a distribution whose useradd puts everyone in a shared
            # primary group (`users`, gid 100) that is every interactive
            # account on the machine. The caller is expected to pass a uid;
            # saying so is cheaper than someone discovering it later.
            self.log("[agent] WARNING: no permitted uid configured; any "
                     "process that can open the socket may answer")
        return True

    def _chown_for_owner(self, directory_fd) -> None:
        """
        Hand the socket to the desktop user when we bound it as root.

        Without this the socket is root:root 0660 and the agent -- which runs
        as the user, not root -- cannot connect. It only applies when an owner
        was supplied AND we are actually root; a non-root daemon has nothing to
        grant and silently skips.

        The chown is done relative to the verified directory descriptor and
        with follow_symlinks=False, so it lands on the socket bind() just
        created or on nothing. By name it would follow a symlink planted at
        that path, which is a root chown of an arbitrary file.

        The parameter used to be `created_dir`, whose docstring promised the
        directory was "only chowned if THIS call created it" -- a protection
        that did not exist, because the body never chowned the directory and
        never read the flag. It is replaced by something the code actually
        uses.

        SO_PEERCRED still guards who may answer, so widening filesystem access
        to the socket does not widen who is trusted: an unauthorized uid can
        open it and is then refused in _admit().
        """
        if self.owner_uid is None or os.geteuid() != 0:
            return
        gid = self.owner_gid if self.owner_gid is not None else -1
        try:
            if directory_fd is not None:
                import stat as _stat
                st = os.lstat(self.path.name, dir_fd=directory_fd)
                if not _stat.S_ISSOCK(st.st_mode):
                    raise OSError("agent path is no longer the socket we bound")
                os.chown(self.path.name, self.owner_uid, gid,
                         dir_fd=directory_fd, follow_symlinks=False)
            else:
                os.chown(self.path, self.owner_uid, gid)
        except OSError as exc:
            # Non-fatal: the socket still exists and root can use it. Log it so
            # a failed agent connection has an explanation.
            self.log(f"[agent] could not chown {self.path} to uid "
                     f"{self.owner_uid}: {exc}")

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
            self._peer = None
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
            self._admit(conn)

    def _admit(self, conn) -> None:
        """
        Decide whether a connecting process may become the agent.

        Refusal is silent to the peer and logged here: an attacker learns
        nothing from the socket, and the user has a record that something
        tried. Both refusal paths close the connection rather than leaving it
        open and ignored, so a rejected client cannot hold a descriptor open
        waiting for the real agent to disconnect.
        """
        conn.settimeout(1.0)
        try:
            pid, uid, gid = peer_credentials(conn)
        except OSError as exc:
            self.log(f"[agent] refused: peer credentials unreadable ({exc})")
            self._close(conn)
            return

        if self.allowed_uids is not None and uid not in self.allowed_uids:
            self.log(f"[agent] REFUSED connection from uid={uid} pid={pid}: "
                     f"not a permitted agent user")
            self._close(conn)
            return

        with self._lock:
            # A question in flight is proof of life that costs nothing to
            # check, and checking it this way avoids poking at a socket the
            # other thread is blocked on. Probing anyway is what let a
            # connection attempt cancel a question and evict the agent.
            if self._conn is not None and self._asking > 0:
                self.log(f"[agent] REFUSED second agent from uid={uid} "
                         f"pid={pid}: one is already connected and answering")
                self._close(conn)
                return
            if self._conn is not None and _still_connected(self._conn):
                self.log(f"[agent] REFUSED second agent from uid={uid} "
                         f"pid={pid}: one is already connected")
                self._close(conn)
                return
            if self._conn is not None:
                self._close(self._conn)
            self._conn = conn
            self._peer = (pid, uid, gid)

        self.log(f"[agent] desktop agent connected (pid={pid} uid={uid})")

    @property
    def connected(self) -> bool:
        with self._lock:
            return self._conn is not None

    @property
    def peer(self) -> Optional[tuple]:
        """(pid, uid, gid) of the connected agent, or None."""
        with self._lock:
            return self._peer

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

        # Unguessable rather than sequential, and drawn from the CSPRNG rather
        # than from `random`, whose output is reconstructible from a handful of
        # samples. Unpredictability IS the mechanism here: it is what makes an
        # answer to a question that has not been asked yet impossible to
        # construct. 63 bits keeps it a positive, JSON-safe integer, so the
        # agent -- which only echoes the id back -- needs no change at all.
        #
        # A second bug goes with it: `self._next_id += 1` ran outside the lock,
        # so two devices attached at once could be given the same id and one
        # answer could resolve both questions.
        request_id = secrets.randbits(63)

        # Whatever is already buffered was sent before this question existed
        # and therefore cannot be an answer to it. Discard it unread rather
        # than parse it -- parsing is what let pre-sent replies win the race.
        self._drain(conn)

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
        with self._lock:
            self._asking += 1
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                # Wait for what is LEFT of the budget, not a flat second. The
                # loop used to check the deadline only before blocking for a
                # full second, so an answer arriving up to a second after the
                # deadline had passed was still accepted -- and the user had
                # been shown a dialog counting down to that deadline. A
                # decision must not be honoured after the window it was asked
                # in has closed.
                conn.settimeout(min(1.0, remaining))
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
                if len(buffer) > MAX_MESSAGE:
                    # MAX_MESSAGE bounded each recv() but not their sum, so a
                    # peer sending bytes and never a newline grew this without
                    # limit until the timeout. An agent's answer is a few dozen
                    # bytes; 16 KB with no line ending is not one, and is not
                    # worth holding a connection open for.
                    self.log("[agent] oversized reply, dropping connection")
                    self._drop(conn)
                    return None
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    answer = self._parse_answer(line, request_id)
                    if answer == ANSWER_UNAVAILABLE:
                        return None
                    if answer == ANSWER_ALWAYS and not allow_always:
                        # DOWNGRADE, do not discard. `continue` here threw the
                        # answer away and went back to waiting, so a user who
                        # clicked a button was left with a question that then
                        # timed out into a denial -- and the daemon, seeing
                        # None, printed "no answer from the desktop agent" and
                        # asked again in a terminal the user may not be looking
                        # at. A decision that was made must not evaporate.
                        #
                        # "Always" is "yes" plus "remember it". When remembering
                        # is not on offer (no trust store), the honest reading
                        # of the click is the yes without the remembering --
                        # which is strictly LESS than the user asked for, so it
                        # cannot grant anything they did not intend. The agent
                        # should not have offered the option; that it did is a
                        # mismatch to log, not a reason to drop the answer.
                        self.log("[agent] agent returned 'always' although it "
                                 "was not offered; treating it as 'yes' for "
                                 "this device only, and remembering nothing")
                        answer = ANSWER_YES
                    if answer is not None and time.monotonic() < deadline:
                        return answer
        finally:
            with self._lock:
                self._asking = max(0, self._asking - 1)
            # Leave the socket as the accept path set it up, whatever exit was
            # taken, so the next question does not inherit a shrunken timeout.
            try:
                conn.settimeout(1.0)
            except OSError:
                pass

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
        except (ValueError, UnicodeDecodeError, RecursionError):
            return None
        if not isinstance(obj, dict):
            return None
        if obj.get("type") != MSG_ANSWER:
            return None
        if obj.get("id") != request_id:
            # A late answer to a question that has already been resolved. It is
            # ignored rather than applied, so a stale click can never approve a
            # device the user is not currently looking at.
            return None
        answer = obj.get("answer")
        return answer if answer in (ANSWER_YES, ANSWER_ALWAYS, ANSWER_NO,
                                    ANSWER_UNAVAILABLE) else None

    def _drain(self, conn) -> int:
        """
        Discard everything already buffered. Returns the number of bytes thrown
        away, which is non-zero only when someone was speaking out of turn.
        """
        discarded = 0
        try:
            previous = conn.gettimeout()
            conn.setblocking(False)
        except OSError:
            return 0
        try:
            while discarded < MAX_MESSAGE * 4:
                try:
                    chunk = conn.recv(MAX_MESSAGE)
                except (BlockingIOError, InterruptedError):
                    break            # nothing left waiting: buffer is clear
                except OSError:
                    break
                if not chunk:
                    break            # peer closed; ask() will notice shortly
                discarded += len(chunk)
        finally:
            # Restore what was there rather than assuming: leaving the socket
            # non-blocking would turn ask()'s recv loop into a busy spin.
            try:
                conn.settimeout(previous)
            except OSError:
                pass
        if discarded >= MAX_MESSAGE * 4:
            self._drop(conn)
        if discarded:
            self.log(f"[agent] discarded {discarded} unsolicited bytes before "
                     f"asking -- an agent should only speak when asked")
        return discarded

    @staticmethod
    def _close(conn) -> None:
        """Close without touching shared state, so it is safe under the lock."""
        try:
            conn.close()
        except OSError:
            pass

    def _drop(self, conn) -> None:
        with self._lock:
            if self._conn is conn:
                self._conn = None
                self._peer = None
        self._close(conn)
