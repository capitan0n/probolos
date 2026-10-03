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
    OPEN_BLOCK     open a block device read-only and pass back the fd
    TRUST          add one entry to the trust store: only for a device this
                   gate admitted moments ago on this connection, and only
                   under the fingerprint the gate itself measured before it
                   first switched that device on
    PING           liveness check

Nothing else. The gate refuses anything not on this list. In particular it
never runs a rule, never reads keystrokes, never touches the ledger -- those
live entirely on the unprivileged side. TRUST is the one write to persistent
state, and the analyzer supplies none of what it pins: the key must equal the
gate's own measurement, and the label is display text only.

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
REQ_ADMIT = "admit"
REQ_SET_DEFAULT = "set_default"
REQ_OPEN_INPUT = "open_input"
REQ_OPEN_BLOCK = "open_block"
# Interface-level authorization: bind/unbind a driver for ONE interface of a
# device rather than the whole device. Used by the deferred-bind path.
REQ_AUTHORIZE_INTERFACE = "authorize_interface"
# Remember one admitted device in the root-owned trust store. Exists because
# the analyzer, running as `nobody`, cannot write that file by design, and
# "always" was otherwise impossible under --privsep.
REQ_TRUST = "trust"
REQ_PING = "ping"

# Response status
OK = "ok"
ERROR = "error"
DENIED = "denied"          # request was well-formed but refused by policy

MAX_MESSAGE = 8192         # one datagram; requests are tiny, this is generous

# Bounds on the two TRUST strings, in characters. An honest key is
# vendor:product:serial (the serial already capped by textsafe) plus '#' and
# 64 hex digits, far under 512. The label is display text; two maximum-length
# device strings joined can just exceed 256, so GateClient.trust trims it
# rather than lose "always" for that device. Even with every character escaped
# by json.dumps (up to 12 bytes each), an honest request stays inside
# MAX_MESSAGE; one that does not is refused by _load like any other.
MAX_KEY = 512
MAX_LABEL = 256


@dataclass
class Request:
    kind: str
    path: str = ""             # device or node path the request concerns
    value: Optional[int] = None  # for authorize / set_default
    instance: Optional[tuple] = None
    key: Optional[str] = None    # TRUST only: the analyzer's trust key
    label: Optional[str] = None  # TRUST only: display name for --trusted

    def encode(self) -> bytes:
        obj = {"kind": self.kind, "path": self.path}
        if self.value is not None:
            obj["value"] = self.value
        if self.instance is not None:
            obj["instance"] = self.instance
        if self.key is not None:
            obj["key"] = self.key
        if self.label is not None:
            obj["label"] = self.label
        return json.dumps(obj).encode()

    @staticmethod
    def decode(data: bytes) -> "Request":
        obj = _load(data)
        kind = obj.get("kind")
        if kind not in (REQ_AUTHORIZE, REQ_ADMIT, REQ_SET_DEFAULT, REQ_OPEN_INPUT,
                        REQ_OPEN_BLOCK, REQ_AUTHORIZE_INTERFACE, REQ_TRUST,
                        REQ_PING):
            raise ValueError(f"unknown request kind: {kind!r}")
        value = obj.get("value")
        if value is not None and type(value) is not int:
            raise ValueError("value must be an integer")
        path = obj.get("path", "")
        if not isinstance(path, str) or "\x00" in path:
            raise ValueError("path must be a string")
        instance = obj.get("instance")
        if instance is not None:
            if (not isinstance(instance, list) or len(instance) != 2
                    or any(type(n) is not int or n < 0 for n in instance)):
                raise ValueError("invalid device instance")
            instance = tuple(instance)
        # Shape only, here: the gate decides whether the key is the right one
        # and whether the label is clean enough to store. What is refused at
        # this layer is anything that is not even a bounded string -- a
        # number, a list, an embedded NUL -- so the handler never has to ask.
        texts = {}
        for name, limit in (("key", MAX_KEY), ("label", MAX_LABEL)):
            text = obj.get(name)
            if text is not None:
                if not isinstance(text, str) or "\x00" in text:
                    raise ValueError(f"{name} must be a string")
                if len(text) > limit:
                    raise ValueError(f"{name} is longer than {limit} characters")
            texts[name] = text
        if kind == REQ_TRUST and (not path or instance is None
                                  or texts["key"] is None
                                  or texts["label"] is None):
            raise ValueError("trust needs a path, a device instance, a key "
                             "and a label")
        return Request(kind=kind, path=path, value=value, instance=instance,
                       key=texts["key"], label=texts["label"])


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
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise ValueError(f"malformed message: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError("message is not an object")
    return obj
