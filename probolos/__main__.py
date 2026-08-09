"""
Command line entry point.

    sudo python -m probolos                 # run the gate
    sudo python -m probolos --dry-run       # observe only, gate stays open
    python -m probolos --list               # what is attached right now
    sudo python -m probolos --release       # free devices stranded by a crash
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

from . import (agentlink, daemon, gate, ledger as ledger_mod, report, rules,
               safety, session as session_mod, sysfs, trust as trust_mod,
               usbclass)

BANNER = r"""
   ___         _
  / __|___ _ _| |__  ___ _ _ _  _ ___
 | (__/ -_) '_| '_ \/ -_) '_| || (_-<
  \___\___|_| |_.__/\___|_|  \_,_/__/   identity · consistency · behaviour
"""


def require_root() -> None:
    if os.geteuid() != 0:
        sys.exit("This needs root: writing to /sys/bus/usb/.../authorized "
                 "is a privileged operation.\nTry: sudo python -m probolos")


def require_usb() -> None:
    if not sysfs.usb_subsystem_available():
        sys.exit(f"{sysfs.USB_DEVICES} does not exist — no USB subsystem here "
                 "(container? kernel without USB support?)")


def cmd_list(verbose: bool = False) -> None:
    """Inventory of attached devices. Read-only, no privileges needed."""
    require_usb()
    devices = [d for d in sysfs.list_devices() if not d.is_root_hub]
    if not devices:
        print("No USB devices attached.")
        return
    print(f"{len(devices)} USB device(s) attached:\n")
    for dev in devices:
        state = {1: "authorized", 0: "BLOCKED"}.get(dev.authorized, "unknown")
        findings = rules.evaluate(dev)
        print(f"  [{state:>10}] {report.one_liner(dev, findings)}")
        if not verbose:
            continue
        # The per-interface breakdown is the raw material for stage 2 rules.
        # Rules invented without looking at real hardware produce false
        # positives on ordinary devices, which trains users to ignore alarms.
        print(f"               manufacturer : {dev.manufacturer or '-'}")
        print(f"               product      : {dev.product or '-'}")
        print(f"               serial       : {dev.serial or '-'}")
        print(f"               speed        : {dev.speed or '?'} Mbps")
        print(f"               kinds        : {', '.join(dev.kinds)}")
        ds = dev.descriptor_set
        if ds and ds.configs:
            c = ds.configs[0]
            src = "self-powered" if c.self_powered else "bus-powered"
            print(f"               declares     : {c.max_power_ma} mA "
                  f"({src}, raw {c.max_power_raw} × {c.power_unit_ma} mA)")
        if dev.parse_error:
            print(f"               PARSE ERROR  : {dev.parse_error}")
        for iface in dev.interfaces:
            desc = usbclass.describe_interface(iface.interface_class,
                                               iface.interface_subclass,
                                               iface.interface_protocol)
            print(f"               iface {iface.number}      : "
                  f"class 0x{iface.interface_class:02x} "
                  f"sub 0x{iface.interface_subclass:02x} "
                  f"proto 0x{iface.interface_protocol:02x}  → {desc}")
        for f in findings:
            print(f"               {f.severity.label:<8} : {f.title}")
        print()


def cmd_release() -> None:
    """
    Recovery path. If Probolos was SIGKILLed while the gate was closed, devices
    plugged in afterwards are sitting dead. This authorizes them in one go.

    It exists because a security tool that can brick your peripherals owes you
    an obvious way out.
    """
    require_root()
    stranded = gate.unauthorized_devices()
    if not stranded:
        print("Nothing stranded — no blocked devices found.")
        return
    for dev in stranded:
        try:
            sysfs.set_authorized(dev.syspath, 1)
            print(f"  released: {report.one_liner(dev)}")
        except OSError as exc:
            print(f"  failed {dev.name}: {exc}")

    for hub in sysfs.list_root_hubs():
        current = sysfs.get_authorized_default(hub)
        if current == 0:
            sysfs.set_authorized_default(hub, 1)
            print(f"  {hub.name}: authorized_default reset to 1")


def _active_session_user() -> Optional[str]:
    """
    Work out whose desktop session this is, so the agent socket can be made
    reachable by exactly that user and nobody else.

    Uses logind, which already provides the lock state, rather than guessing
    from SUDO_USER -- although that is used as a fallback, since running under
    sudo is the normal case here and it is a strong hint.
    """
    import os
    import shutil
    import subprocess

    loginctl = shutil.which("loginctl")
    if loginctl:
        try:
            out = subprocess.run([loginctl, "list-sessions", "--no-legend"],
                                 capture_output=True, text=True, timeout=3)
            for line in out.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    info = subprocess.run(
                        [loginctl, "show-session", parts[0], "-p", "Type",
                         "-p", "Name"],
                        capture_output=True, text=True, timeout=3)
                    values = dict(l.split("=", 1)
                                  for l in info.stdout.splitlines() if "=" in l)
                    if values.get("Type") in ("x11", "wayland", "mir"):
                        return values.get("Name")
        except (OSError, subprocess.SubprocessError):
            pass
    return os.environ.get("SUDO_USER")


def _resolve_agent_identity(args):
    """
    Who is allowed to answer questions about hardware: (uid, gid, name).

    Resolved once, before the privsep branch, because both halves need it from
    different angles: prepare_socket_dir needs the GID, to make the socket
    reachable from the session; AgentLink needs the UID, to check SO_PEERCRED
    against. Deriving them separately invites them to disagree, and the failure
    that produces is quiet -- an agent that connects, shows a dialog, and has
    its answer silently refused.

    Failing here rather than later is deliberate: --agent with an unresolvable
    user is a configuration error, and it should not be discovered only after
    the gate has already closed on every USB port.
    """
    if not getattr(args, "agent", False):
        return None

    import pwd

    name = args.agent_user or _active_session_user()
    if name is None:
        sys.exit("--agent needs --agent-user USER (could not detect the "
                 "desktop user automatically)")
    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        sys.exit(f"--agent-user {name}: no such user")
    return entry.pw_uid, entry.pw_gid, name


def cmd_trusted(path) -> None:
    """Show what this machine currently lets in without asking, numbered."""
    store = trust_mod.TrustStore(path)
    if store.load_error:
        sys.exit(f"trust store unreadable: {store.load_error}")
    entries = store.ordered()
    if not entries:
        print("No remembered devices. Every device will be asked about.")
        return
    import datetime
    print(f"Remembered devices ({len(entries)}) — admitted without asking:\n")
    for i, entry in enumerate(entries, start=1):
        when = datetime.datetime.fromtimestamp(entry.trusted_at)
        print(f"[{i}] {entry.label}")
        print(f"      identity    : {entry.identity}")
        print(f"      descriptors : {entry.descriptor_hash[:16]}…")
        print(f"      trusted     : {when:%Y-%m-%d %H:%M}, admitted "
              f"{entry.times_admitted} time(s)")
        print(f"      ports       : {', '.join(entry.ports) or '-'}")
        print()
    print("Remove one with:  sudo python -m probolos --forget N   "
          "(N is the number in brackets)")


def cmd_forget(path, pattern: str) -> None:
    store = trust_mod.TrustStore(path)
    if pattern.lower() == "all":
        count = store.clear()
        print(f"Forgot all {count} device(s).")
    elif pattern.isdigit():
        # A bare number refers to the position shown by --trusted, like
        # `ufw delete N`. This is the common case: look, then delete by number.
        identity = store.forget_index(int(pattern))
        if identity is None:
            sys.exit(f"No remembered device numbered {pattern}. "
                     f"Run --trusted to see the list.")
        print(f"Forgot [{pattern}] {identity}")
    else:
        removed = store.forget(pattern)
        if not removed:
            print(f"Nothing matched {pattern!r}. Run --trusted to see the list.")
            return
        for identity in removed:
            print(f"  forgot {identity}")
    error = store.save()
    if error:
        sys.exit(f"could not write trust store: {error}")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        prog="probolos",
        description="Hold new USB devices unauthorized until a human decides.")
    parser.add_argument("--list", action="store_true",
                        help="show attached devices and exit")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="with --list: full per-interface breakdown")
    parser.add_argument("--release", action="store_true",
                        help="authorize all blocked devices and reopen the gate")
    parser.add_argument("--dry-run", action="store_true",
                        help="report devices without ever blocking or authorizing")
    parser.add_argument("--timeout", type=float, default=0.0, metavar="SEC",
                        help="auto-deny after SEC seconds of no answer (0 = wait)")
    parser.add_argument("--log", type=Path, metavar="FILE",
                        help="append decisions as JSON lines to FILE")
    parser.add_argument("--rules", type=Path, metavar="FILE",
                        help="YAML file tuning rule severities (optional)")
    parser.add_argument("--observe", type=float, default=3.0, metavar="SEC",
                        help="seconds of behavioural quarantine for input "
                             "devices (0 disables stage 3)")
    parser.add_argument("--capture-payload", action="store_true",
                        help="reconstruct what a quarantined device typed. "
                             "OFF by default: this records key content, and "
                             "only ever from devices never authorized")
    parser.add_argument("--ledger", type=Path, metavar="FILE",
                        default=None,
                        help="device history file for drift detection "
                             "(default: XDG state dir, or /var/lib/probolos "
                             "as root)")
    parser.add_argument("--no-ledger", action="store_true",
                        help="keep no history between runs")
    parser.add_argument("--allow-port", action="append", default=[],
                        metavar="PORT",
                        help="port that is never gated, e.g. 1-4 (repeatable). "
                             "Keep a rescue keyboard in one")
    parser.add_argument("--gate-fixed-ports", action="store_true",
                        help="also gate internal, non-removable ports. "
                             "This can lock you out of a laptop keyboard")
    parser.add_argument("--watchdog", type=float, default=60.0, metavar="SEC",
                        help="reopen the gate if the daemon stops making "
                             "progress for SEC seconds (0 disables)")
    parser.add_argument("--panic-file", type=Path,
                        default=safety.DEFAULT_PANIC_FILE,
                        help="create this file from another terminal to force "
                             "the gate open")
    parser.add_argument("--trusted", action="store_true",
                        help="list remembered devices and exit")
    parser.add_argument("--forget", metavar="PATTERN",
                        help="remove a remembered device: a number from "
                             "--trusted, a name/id substring, or 'all'")
    parser.add_argument("--history", action="store_true",
                        help="show the recorded history of every USB device seen, and exit")
    parser.add_argument("--no-trust", action="store_true",
                        help="ask about every device, ignore what is remembered")
    parser.add_argument("--trust-file", type=Path, metavar="FILE",
                        help="where remembered devices are stored")
    parser.add_argument("--no-storage-scan", action="store_true",
                        help="skip reading the partition table of storage "
                             "devices (stage 4)")
    parser.add_argument("--lock-policy", default=session_mod.POLICY_QUEUE,
                        choices=[session_mod.POLICY_QUEUE,
                                 session_mod.POLICY_DENY,
                                 session_mod.POLICY_IGNORE],
                        help="what to do when a device arrives while the "
                             "screen is locked: hold it and ask on unlock "
                             "(default), deny outright, or take no notice")
    parser.add_argument("--force-locked", action="store_true",
                        help="pretend the screen is locked (to test the policy)")
    parser.add_argument("--force-unlocked", action="store_true",
                        help="pretend the screen is unlocked")
    parser.add_argument("--agent", action="store_true",
                        help="accept decisions from a desktop notification "
                             "agent (start it with: python -m probolos.agent)")
    parser.add_argument("--agent-socket", type=Path,
                        default=agentlink.DEFAULT_SOCKET, metavar="PATH",
                        help="where the desktop agent connects")
    parser.add_argument("--agent-user", metavar="USER",
                        help="the desktop user allowed to answer through the "
                             "agent (default: the owner of the active session)")
    parser.add_argument("--privsep", action="store_true",
                        help="run with privilege separation: a small root gate "
                             "and an unprivileged analyzer. Recommended")
    parser.add_argument("--privsep-user", default="nobody", metavar="USER",
                        help="user the analyzer drops to under --privsep")
    args = parser.parse_args(argv)

    require_usb()

    trust_path = args.trust_file or trust_mod.default_path()

    if args.list:
        # Dispatched here with the other read-only commands. Without this the
        # flag parsed but fell through to require_root() and CLOSED THE GATE --
        # a documented inventory command that instead disabled every USB port.
        cmd_list(verbose=args.verbose)
        return
    if args.trusted:
        cmd_trusted(trust_path)
        return
    if args.history:
        from . import history
        print(history.show_history(verbose=args.verbose,
                                   path=args.ledger if args.ledger else None))
        return
    if args.forget:
        cmd_forget(trust_path, args.forget)
        return
    if args.release:
        cmd_release()
        return

    print(BANNER)
    if not args.dry_run:
        require_root()
        print("[!] The gate will close: NEW USB devices will not work until")
        print("[!] you approve them here. Keep a second way in (SSH, or your")
        print("[!] built-in keyboard) while testing.\n")

    forced_lock = None
    if args.force_locked:
        forced_lock = True
    elif args.force_unlocked:
        forced_lock = False

    rule_config = None
    if args.rules:
        try:
            rule_config = rules.load_config(args.rules)
        except (RuntimeError, ValueError, OSError) as exc:
            sys.exit(f"rule config: {exc}")

    policy = safety.SafetyPolicy(
        allowed_ports=args.allow_port,
        protect_fixed_ports=not args.gate_fixed_ports,
        panic_file=args.panic_file,
    )
    if args.gate_fixed_ports:
        print("[!] --gate-fixed-ports: internal devices WILL be blocked.")
        print("[!] If this machine's keyboard is internal USB, make sure you")
        print("[!] have SSH access before continuing.\n")

    ledger_path = (None if args.no_ledger
                   else (args.ledger or ledger_mod.default_path()))

    # Resolved once here, before the privsep branch, so the socket's group
    # (set by prepare_socket_dir) and the uid AgentLink checks against can
    # never drift apart. None when --agent is off.
    agent_identity = _resolve_agent_identity(args)
    agent_uid = agent_identity[0] if agent_identity else None
    agent_gid = agent_identity[1] if agent_identity else None

    def _serve():
        daemon.serve(dry_run=args.dry_run, timeout=args.timeout,
                     json_log=args.log, rule_config=rule_config,
                     observe=args.observe,
                     policy=policy,
                     ledger_path=ledger_path,
                     capture_payload=args.capture_payload,
                     watchdog_timeout=args.watchdog,
                     trust_path=None if args.no_trust else trust_path,
                     inspect_storage=not args.no_storage_scan,
                     lock_policy=args.lock_policy,
                     force_locked=forced_lock,
                     agent_socket=args.agent_socket if args.agent else None,
                     agent_uid=agent_uid,
                     agent_gid=agent_gid)

    if args.privsep:
        from . import privsep
        from .gate_client import GateBackend

        def analyzer_main(gate_client):
            # Runs in the UNPRIVILEGED child. Every privileged sysfs write from
            # here on is routed to the root gate over the socket.
            sysfs.install_backend(GateBackend(gate_client))
            _serve()
            return 0

        if args.agent:
            # The analyzer will run as `nobody` and the agent as the desktop
            # user; neither can grant the other access afterwards, so the
            # directory is set up here, while still root. The identity was
            # already resolved above -- reused here so the socket's group and
            # the uid AgentLink enforces cannot disagree.
            try:
                import pwd as _pwd
                uid, gid, agent_user = agent_identity
                analyzer_uid = _pwd.getpwnam(args.privsep_user).pw_uid
                agentlink.prepare_socket_dir(args.agent_socket,
                                             analyzer_uid, gid)
                print(f"[agent] {args.agent_socket.parent} prepared for "
                      f"{agent_user} (uid {uid})")
            except (KeyError, OSError) as exc:
                sys.exit(f"could not prepare the agent socket directory: {exc}")

        try:
            # ONLY the ledger directory is handed to the analyzer. The trust
            # store is deliberately excluded: whoever can write a directory can
            # replace any file in it, so handing over the trust store's
            # directory would let a hostile process running as the same shared
            # `nobody` account forge an entry that admits its own device with
            # no prompt. The analyzer reads trust and cannot rewrite it; the
            # cost is that "always" cannot be persisted from the unprivileged
            # half, which serve() reports plainly when it happens.
            # Trust is read-only to the analyzer: readable file, root-owned
            # directory. Done before the drop, while we still can.
            if not args.no_trust and trust_path:
                privsep.prepare_trust_readable(trust_path)
            rc = privsep.start(analyzer_main, drop_to=args.privsep_user,
                               state_paths=[p for p in (ledger_path,) if p])
        except privsep.PrivsepError as exc:
            sys.exit(f"privsep: {exc}")
        sys.exit(rc)
    else:
        _serve()


if __name__ == "__main__":
    main()
