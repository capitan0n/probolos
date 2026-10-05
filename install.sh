#!/usr/bin/env bash
# Run Probolos as a background service, in one command.
#
#   sudo ./install.sh               install (or update) and start
#   sudo ./install.sh --uninstall   stop and remove (history and trust are kept)
#   sudo ./install.sh --user NAME   name the desktop account that answers
#                                   (default: the account that ran sudo)
#
# Re-run it after pulling new code: it copies the new version and restarts.
#
# What it sets up:
#   /opt/probolos                      the code, root-owned (it runs as root)
#   /usr/local/bin/probolos            so `sudo probolos --history` works anywhere
#   probolos.service                   the gate (system service, --privsep)
#   probolos-agent.service             the KDE/GNOME prompt (user service)
set -euo pipefail

PREFIX=/opt/probolos
BIN=/usr/local/bin/probolos
PY=/usr/bin/python3
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Out of whatever directory sudo was run in: python as root must not import
# a module that happens to sit there (and every path below is absolute).
cd /
UNIT=/etc/systemd/system/probolos.service
DROPIN_DIR=/etc/systemd/system/probolos.service.d
AGENT_UNIT=/etc/systemd/user/probolos-agent.service
AGENT_DROPIN_DIR=/etc/systemd/user/probolos-agent.service.d
MARKER="# installed by probolos install.sh"

die() { echo "error: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0 $*"

user="${SUDO_USER:-}"
action=install
while [ $# -gt 0 ]; do
    case "$1" in
        --uninstall) action=uninstall ;;
        --user) [ $# -ge 2 ] || die "--user needs a NAME"; shift; user="$1" ;;
        -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
    shift
done

# systemctl --user for the desktop account. Best effort: it only works while
# that account is logged in, and the agent starts at its next login anyway.
user_systemctl() {
    [ -n "$user" ] && systemctl --user -M "$user@" "$@" >/dev/null 2>&1
}

install_all() {
    [ -n "$user" ] || die "no desktop account: run with sudo from your own account, or pass --user NAME"
    # Looked up, and replaced by the name the system knows: `id` also takes a
    # number, so `--user 0` passed a test for the NAME root, and the daemon
    # then failed to look the account up and restarted forever.
    local entry
    entry="$(getent passwd -- "$user")" || die "no such user: $user"
    user="${entry%%:*}"
    [ "$(printf '%s' "$entry" | cut -d: -f3)" -ne 0 ] \
        || die "the desktop account must not be root (pass --user NAME)"
    [ -f "$SRC/probolos/__main__.py" ] || die "run this from the probolos source tree"
    [ -x "$PY" ] || die "$PY not found"
    "$PY" -I -c 'import pyudev' 2>/dev/null || die "pyudev is missing. Install it:
    Arch/Manjaro:   sudo pacman -S python-pyudev
    Debian/Ubuntu:  sudo apt install python3-pyudev
    Fedora:         sudo dnf install python3-pyudev"

    # Two gates fighting over the same ports helps nobody. A probolos started
    # by hand holds the gate lock; the service's own instance is expected.
    # The source path goes in as an argument, not into the program text: a
    # checkout path with a quote in it made the program a syntax error, which
    # read as "not running" and skipped this check.
    if ! systemctl is-active --quiet probolos.service 2>/dev/null \
        && "$PY" -I -c 'import sys; sys.path.insert(0, sys.argv[1])
from probolos import instance
sys.exit(0 if instance.running() else 1)' "$SRC" 2>/dev/null; then
        die "probolos is already running (in a terminal?). Stop it with Ctrl-C first."
    fi

    # The code. Root-owned and writable by nobody else: whoever can write the
    # code a root service runs has root.
    rm -rf "$PREFIX.new" "$PREFIX.old"
    mkdir -p "$PREFIX.new"
    cp -r "$SRC/probolos" "$PREFIX.new/"
    # Regular files and directories only, checked in the root-owned copy so
    # nothing can change between the check and the use. cp -r copies a
    # symlink as a symlink, and chown/chmod -R leave its target alone: one in
    # the checkout (or the package directory itself being one) left the root
    # service running code its owner could still edit.
    if [ -n "$(find "$PREFIX.new" ! -type f ! -type d -print -quit)" ]; then
        rm -rf "$PREFIX.new"
        die "$SRC/probolos holds a symlink or special file; copy the tree without it"
    fi
    find "$PREFIX.new" -name __pycache__ -prune -exec rm -rf {} +
    chown -R root:root "$PREFIX.new"
    chmod -R u=rwX,go=rX "$PREFIX.new"
    # Swapped by two renames rather than delete-then-move, so the running
    # service is without its code for as short a time as possible.
    if [ -e "$PREFIX" ]; then mv "$PREFIX" "$PREFIX.old"; fi
    mv "$PREFIX.new" "$PREFIX"
    rm -rf "$PREFIX.old"
    "$PY" -I -m compileall -q "$PREFIX" >/dev/null || true
    # Again for the bytecode just written, whatever root's umask made it.
    chown -R root:root "$PREFIX"
    chmod -R u=rwX,go=rX "$PREFIX"

    # The command. -I ignores PYTHON* variables, user site-packages and the
    # current directory: `sudo probolos` run inside a folder that happens to
    # contain a probolos/ package must not execute that package as root.
    cat > "$BIN" <<EOF
#!/bin/sh
$MARKER
exec $PY -I -c '
import runpy, sys
sys.path.insert(0, "$PREFIX")
runpy.run_module("probolos", run_name="__main__", alter_sys=True)
' "\$@"
EOF
    chmod 755 "$BIN"

    # The units: shipped files unchanged, local settings in drop-ins.
    install -m 644 "$SRC/systemd/probolos.service" "$UNIT"
    mkdir -p "$DROPIN_DIR"
    cat > "$DROPIN_DIR/install.conf" <<EOF
$MARKER
[Service]
Environment=PYTHONPATH=$PREFIX
Environment=PROBOLOS_AGENT_USER=$user
EOF

    install -m 644 "$SRC/systemd/probolos-agent.service" "$AGENT_UNIT"
    mkdir -p "$AGENT_DROPIN_DIR"
    cat > "$AGENT_DROPIN_DIR/install.conf" <<EOF
$MARKER
# Only the account that may answer runs the agent.
[Unit]
ConditionUser=$user

[Service]
Environment=PYTHONPATH=$PREFIX
WorkingDirectory=/
EOF

    systemctl daemon-reload
    systemctl enable --quiet probolos.service
    systemctl restart probolos.service          # starts it, or loads new code
    systemctl --global enable --quiet probolos-agent.service

    local agent="running"
    if ! { user_systemctl daemon-reload && user_systemctl restart probolos-agent.service; }; then
        agent="starts at $user's next login"
    fi

    cat <<EOF

Probolos is running in the background.
  gate    : $(systemctl is-active probolos.service 2>/dev/null || echo unknown)
  prompt  : $agent (asks $user)

  status  : systemctl status probolos
  logs    : journalctl -u probolos -f
  history : sudo probolos --history
  stop    : sudo systemctl stop probolos     (reopens the gate)
  remove  : sudo ./install.sh --uninstall

Devices already plugged in were left alone; only new ones are asked about.
EOF
}

uninstall_all() {
    # Stopping first: every exit path of the gate reopens it.
    systemctl disable --now --quiet probolos.service 2>/dev/null || true
    systemctl --global disable --quiet probolos-agent.service 2>/dev/null || true
    user_systemctl stop probolos-agent.service || true

    rm -f "$UNIT" "$AGENT_UNIT"
    # Only our own drop-in: an override.conf from `systemctl edit` is the
    # administrator's, and goes only if it is the last thing there.
    rm -f "$DROPIN_DIR/install.conf" "$AGENT_DROPIN_DIR/install.conf"
    rmdir "$DROPIN_DIR" "$AGENT_DROPIN_DIR" 2>/dev/null || true
    rm -rf "$PREFIX" "$PREFIX.new" "$PREFIX.old"
    # Only our own wrapper, never someone else's file at that path.
    if [ -f "$BIN" ] && grep -qF "$MARKER" "$BIN"; then
        rm -f "$BIN"
    fi
    systemctl daemon-reload 2>/dev/null || true
    user_systemctl daemon-reload || true

    cat <<EOF
Probolos is stopped and removed; the gate is open.
History and remembered devices are kept in /var/lib/probolos
(delete that folder to erase them too).
EOF
}

"${action}_all"
