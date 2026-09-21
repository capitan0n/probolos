"""
The guarantees that come before every feature.

A USB admission tool has one failure mode that disqualifies it from being
installed anywhere: leaving somebody without a keyboard. Everything else in
this project is a security feature; this file is a safety feature, and safety
outranks security when the two disagree.

Four independent layers, because one is a single point of failure:

  1. PROTECTED DEVICES  — devices on non-removable ports are never gated
  2. PORT ALLOWLIST     — an operator-declared port that always works
  3. WATCHDOG           — opens the gate if the daemon stops making progress
  4. PANIC FILE         — an escape hatch usable from another terminal or SSH

Layers 1-2 prevent the lockout. Layers 3-4 end one that happened anyway. The
existing restore paths in gate.py cover a daemon that DIES; the watchdog here
covers a daemon that is alive but STUCK, which nothing else catches.

Each of these is stated as an invariant and tested as one. A guarantee that is
not tested is a wish.

WHY THE PANIC FILE MUST BE PLACED BY ROOT
-----------------------------------------
Creating the panic file disables the tool. That is its whole purpose, and it
is why it has to cost exactly what `systemctl stop probolos` costs. At
/tmp/probolos-panic it cost nothing: any local account could open the gate for
every device on the machine, or -- worse, because it looks like a malfunction
rather than an attack -- leave one behind so the daemon refuses to start at
all. A world-writable off switch on a security tool is not an escape hatch.

Nothing is lost by requiring root. The lockout scenario this exists for
assumes you can still type: the built-in keyboard sits on the i8042 PS/2
controller and is never gated, and a machine where you can run `touch` is a
machine where you can run `sudo touch`.
"""

from __future__ import annotations

import os
import re
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

# Root hubs -- usb1, usb2, ... -- are the controllers themselves. Reaching one
# while walking up from a device means the chain ended at the machine, which is
# the only place `removable` carries platform authority. Defined here rather
# than imported from sysfs so this module, which is the safety layer, keeps no
# dependency on the layer it is protecting people from.
_ROOT_HUB_RE = re.compile(r"^usb\d+$")

# USB permits 7 tiers; 8 is past anything real and bounds the walk regardless of
# what the tree looks like.
_MAX_TIERS = 8

# /run rather than /tmp, and BESIDE the runtime directory rather than inside
# it. /run/probolos looks like the obvious home, but agentlink.prepare_socket_dir
# chowns it to the analyzer's uid and chmods it 2770 so the desktop agent can
# reach the socket -- which would put the panic file back within reach of both
# `nobody` and the desktop user's group. /run itself is root:root 0755.
#
# A second benefit falls out of tmpfs: a forgotten panic file no longer
# survives a reboot, so the "it would fire the watchdog instantly" startup
# refusal in daemon.py can only ever be triggered within one boot.
DEFAULT_PANIC_FILE = Path("/run/probolos.panic")


def panic_file_is_valid(path: Path, required_uid: int = 0,
                        log=print) -> bool:
    """
    True only if this really is a panic file placed there by an operator.

    Existence is not enough, and neither is ownership on its own:

      * Path.exists() FOLLOWS SYMLINKS. A symlink at the panic path would let
        whoever created it point at any file that happens to exist, and the
        gate would open itself.

      * A FIFO, socket or device node is not a signal from an operator, so the
        path must be a regular file.

      * The file must be owned by root. Creating it disables the tool.

      * The DIRECTORY must be root-owned and not writable by anyone else. This
        is the check that is easy to leave out and expensive to omit: the path
        is operator-supplied via --panic-file, and in a directory an attacker
        can write to, `ln /etc/hostname /run/probolos.panic` produces a file
        that is regular, root-owned, and entirely under their control as to
        WHEN it appears. Ownership of the file says nothing about who put it
        there if anyone can hardlink one in.

      * st_nlink must be 1. Belt and braces against the same trick: a
        legitimate panic file, freshly created by touch, has exactly one link.

    An invalid file is reported and IGNORED, never treated as a panic. This is
    the same direction the rest of the project fails in: when the tool cannot
    tell what it is looking at, it does not open.
    """
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        log(f"[safety] cannot check panic file {path}: {exc}")
        return False

    def refuse(reason: str) -> bool:
        log(f"[safety] IGNORING {path}: {reason}. A panic file must be placed "
            f"by an operator:  sudo touch {path}")
        return False

    if stat.S_ISLNK(info.st_mode):
        return refuse("it is a symlink")
    if not stat.S_ISREG(info.st_mode):
        return refuse(f"not a regular file (mode {stat.filemode(info.st_mode)})")
    if info.st_uid != required_uid:
        return refuse(f"owned by uid {info.st_uid}, not {required_uid}")
    if info.st_nlink != 1:
        return refuse(f"it has {info.st_nlink} hard links")

    try:
        parent = path.parent.lstat()
    except OSError as exc:
        log(f"[safety] cannot check {path.parent}: {exc}")
        return False
    if parent.st_uid != required_uid:
        return refuse(f"its directory is owned by uid {parent.st_uid}, "
                      f"not {required_uid}")
    if parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return refuse(f"its directory {path.parent} is writable by others "
                      f"(mode {stat.filemode(parent.st_mode)}), so the file "
                      f"could have been hardlinked in")
    return True


def _fixed_all_the_way_to_a_root_hub(syspath) -> bool:
    """
    True only if `removable=fixed` was decided by the PLATFORM, not by a device.

    THE BUG THIS CLOSES
    -------------------
    `removable=fixed` skips everything. daemon._on_add() calls is_protected(),
    admits the device and RETURNS -- before analyzers.run(), before the
    behavioural quarantine, before any prompt. So whatever sets that attribute
    decides whether Probolos runs at all, and the assumption was that it means
    "soldered to the board".

    That is true for a device on a ROOT HUB port, where the kernel takes the
    value from ACPI (_PLD/_UPC) -- firmware the machine's own manufacturer
    wrote. It is NOT true one tier further out. The kernel's own ABI
    documentation says the value is inferred "from a combination of hub
    descriptor bits and platform-specific data such as ACPI", and the hub
    descriptor bits are the DeviceRemovable bitmap, which for an EXTERNAL hub
    is supplied by that hub's firmware. An attacker's hub declares its
    downstream ports hard-wired and every device behind it reads `fixed` --
    so plugging in one hub disables the gate for everything plugged into it.

    THE RULE
    --------
    Walk up from the device. Every USB ancestor between it and the controller
    must ITSELF be `fixed`, and the walk must actually reach a root hub. The
    chain is then only as trustworthy as its weakest link, and it terminates at
    the one link the platform vouches for:

        usb1/1-2  (internal hub, ACPI: fixed) / 1-2.1 (camera: fixed)  -> True
        usb1/1-4  (attacker's hub, ACPI: removable) / 1-4.2 (anything) -> False

    An unreadable ancestor, a walk that runs off the tree, or one that never
    reaches a root hub all answer False: the exemption is granted only on
    positive evidence, never on the absence of it. Refusing costs a prompt;
    granting it wrongly costs the whole tool.

    The path is resolved first because the bus view (/sys/bus/usb/devices/1-4)
    is a flat directory of symlinks -- its parent is `devices`, not the hub, so
    walking it unresolved would refuse every genuinely internal device.
    """
    if syspath is None:
        return False
    try:
        current = Path(os.path.realpath(str(syspath)))
    except (OSError, ValueError):
        return False

    for _tier in range(_MAX_TIERS):
        parent = current.parent
        if parent == current:
            return False                    # ran off the top of the tree
        name = parent.name
        if _ROOT_HUB_RE.match(name):
            return True                     # the controller: ACPI decided this
        if ":" in name:
            return False                    # an interface node; not a device chain
        try:
            value = (parent / "removable").read_text().strip()
        except OSError:
            return False                    # cannot prove it, so do not claim it
        if value != "fixed":
            return False                    # this ancestor is itself pluggable
        current = parent
    return False


@dataclass
class SafetyPolicy:
    """What must never be blocked, however suspicious it looks."""

    # Ports whose devices are always authorized, given as sysfs names such as
    # "1-4". Intended for the port an operator keeps a rescue keyboard in.
    allowed_ports: List[str] = field(default_factory=list)

    # Devices soldered to the board -- the built-in keyboard and touchpad on a
    # laptop -- report removable="fixed". Gating them is how a user ends up
    # locked out of their own machine with no way to answer the prompt.
    protect_fixed_ports: bool = True

    panic_file: Path = DEFAULT_PANIC_FILE

    # Whose panic file counts. Root in every real deployment; overridable so
    # the invariant can be tested without the suite needing root, and so a
    # rootless --dry-run run can still exercise the hatch.
    panic_file_uid: int = 0

    def is_protected(self, dev) -> Optional[str]:
        """
        Return the reason this device must not be gated, or None.

        Returning the REASON rather than a boolean is deliberate: the decision
        gets printed, so a user who wonders why a device sailed through can
        find out without reading the source.
        """
        if getattr(dev, "is_root_hub", False):
            return "root hub"
        if dev.name in self.allowed_ports:
            return f"port {dev.name} is on the operator allowlist"
        if (self.protect_fixed_ports
                and getattr(dev, "removable", None) == "fixed"
                and _fixed_all_the_way_to_a_root_hub(getattr(dev, "syspath", None))):
            return "device is on a non-removable (internal) port"
        return None

    def panic_requested(self, log=print) -> bool:
        """Is there a valid panic file right now?"""
        return panic_file_is_valid(self.panic_file, self.panic_file_uid, log)


class Watchdog:
    """
    Opens the gate if the main loop stops making progress.

    The distinction from gate.py's restore paths matters: those fire when the
    process ENDS. A process that is alive but wedged -- a deadlock, a blocking
    read that never returns, a driver stuck in D state -- ends nothing and
    triggers none of them, while every USB device attached meanwhile stays
    dead. That is the gap this fills.

    Waiting for a human is not a stall, so the prompt runs inside `paused()`.
    """

    def __init__(self, timeout: float, on_stall: Callable[[str], None],
                 policy: Optional[SafetyPolicy] = None,
                 interval: float = 0.5, log=print):
        self.timeout = timeout
        self.on_stall = on_stall
        self.policy = policy or SafetyPolicy()
        self.interval = interval
        self.log = log
        self._last_beat = time.monotonic()
        self._paused = False
        self._fired = False
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._reported_invalid_panic = False

    def beat(self) -> None:
        with self._lock:
            self._last_beat = time.monotonic()

    @contextmanager
    def paused(self):
        """Suspend the timer while legitimately blocked on a human."""
        with self._lock:
            self._paused = True
        try:
            yield
        finally:
            with self._lock:
                self._paused = False
                self._last_beat = time.monotonic()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)

    @property
    def fired(self) -> bool:
        return self._fired

    def _panic_present(self) -> bool:
        """
        Check the hatch, complaining about a bad file only once.

        check_once() runs every `interval`, so an invalid file left in place
        would otherwise print the same refusal twice a second until someone
        removed it -- burying the findings the user actually needs to read,
        which is the same reason Ledger.save() reports a repeated failure once.
        """
        # lexists, not exists: a dangling symlink is present-but-invalid and
        # must be reported, not silently treated as an empty path.
        if not os.path.lexists(self.policy.panic_file):
            self._reported_invalid_panic = False   # gone: complain again if it returns
            return False

        quiet = self._reported_invalid_panic
        if panic_file_is_valid(self.policy.panic_file,
                               self.policy.panic_file_uid,
                               log=(lambda *_a: None) if quiet else self.log):
            return True
        self._reported_invalid_panic = True
        return False

    def check_once(self) -> Optional[str]:
        """
        One evaluation. Split out from the loop so the logic is testable
        without threads or sleeping.
        """
        if self._fired:
            return None
        # Checked before _paused on purpose: an escape hatch that stops working
        # while the daemon waits for a human is no escape hatch, and waiting for
        # a human is exactly when someone reaches for it.
        if self._panic_present():
            self._fired = True
            return f"panic file {self.policy.panic_file} appeared"
        with self._lock:
            if self._paused:
                return None
            idle = time.monotonic() - self._last_beat
        if idle > self.timeout:
            self._fired = True
            return f"no progress for {idle:.1f}s"
        return None

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            reason = self.check_once()
            if reason:
                self.on_stall(reason)
                return
