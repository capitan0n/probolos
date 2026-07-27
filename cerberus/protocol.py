"""
The protocol between the privileged gate and the unprivileged analyzer.

This module is the CONTRACT, and nothing else. It defines the messages the two
halves exchange and how they are framed on the wire. It performs no privileged
operation, opens no device, and makes no policy decision -- so it can be read,
in full, to understand exactly what the root half is ever asked to do.

That auditability is the whole point of the split. The privileged surface is
only as trustworthy as it is small, and the first measure of its size is how
short the list of things it will do is. That list is here:

    AUTHORIZE      set authorized=1/0 on one device path
    SET_DEFAULT    set authorized_default on one root hub
    OPEN_INPUT     open an input node read-only and pass back the fd
    PING           liveness check

Nothing else. The gate refuses anything not on this list. In particular it
never runs a rule, never reads keystrokes, never touches the ledger -- those
live entirely on the unprivileged side.

FRAMING
-------
Messages are JSON objects, one per SEQPACKET datagram. SEQPACKET preserves
message boundaries, so there is no need for a length prefix or a parser that
could disagree with the sender about where a message ends -- a class of bug
that has no place in a privileged process. A file descriptor, when one is
returned, rides alongside its datagram as ancillary data (SCM_RIGHTS).

PATH DISCIPLINE
---------------
Every device path the analyzer sends is validated by the gate against a fixed
prefix before use (see gate_server). The protocol carries paths as plain
strings; it is the gate's job, not this module's, to refuse anything outside
/sys/bus/usb/devices or /dev/input. The rule lives with the privilege, not
with the message format.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

# Request kinds
REQ_AUTHORIZE = "authorize"
REQ_SET_DEFAULT = "set_default"
REQ_OPEN_INPUT = "open_input"
REQ_PING = "ping"

# Response status
OK = "ok"
ERROR = "error"
DENIED = "denied"          # request was well-formed but refused by policy

MAX_MESSAGE = 8192         # one datagram; requests are tiny, this is generous


@dataclass
class Request:
    kind: str
    path: str = ""             # device or node path the request concerns
    value: Optional[int] = None  # for authorize / set_default

    def encode(self) -> bytes:
        obj = {"kind": self.kind, "path": self.path}
        if self.value is not None:
            obj["value"] = self.value
        return json.dumps(obj).encode()

    @staticmethod
    def decode(data: bytes) -> "Request":
        obj = _load(data)
        kind = obj.get("kind")
        if kind not in (REQ_AUTHORIZE, REQ_SET_DEFAULT, REQ_OPEN_INPUT, REQ_PING):
            raise ValueError(f"unknown request kind: {kind!r}")
        value = obj.get("value")
        if value is not None and not isinstance(value, int):
            raise ValueError("value must be an integer")
        path = obj.get("path", "")
        if not isinstance(path, str):
            raise ValueError("path must be a string")
        return Request(kind=kind, path=path, value=value)


@dataclass
class Response:
    status: str
    detail: str = ""
    has_fd: bool = False       # true when an fd rides alongside this response

    def encode(self) -> bytes:
        return json.dumps({
            "status": self.status,
            "detail": self.detail,
            "has_fd": self.has_fd,
        }).encode()

    @staticmethod
    def decode(data: bytes) -> "Response":
        obj = _load(data)
        status = obj.get("status")
        if status not in (OK, ERROR, DENIED):
            raise ValueError(f"unknown response status: {status!r}")
        return Response(status=status,
                        detail=str(obj.get("detail", "")),
                        has_fd=bool(obj.get("has_fd", False)))

    @property
    def ok(self) -> bool:
        return self.status == OK


def _load(data: bytes) -> dict:
    if len(data) > MAX_MESSAGE:
        raise ValueError(f"message too large: {len(data)} bytes")
    try:
        obj = json.loads(data.decode())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"malformed message: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError("message is not an object")
    return obj
