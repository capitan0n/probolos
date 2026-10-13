# Running Probolos as a service

Two units, because the two halves live in different places: the gate is a
**system** service (it needs root and udev), and the desktop prompt (the
agent) is a **user** service (a dialog can only appear in your graphical
session).

## Test in the foreground first

Before you rely on it at boot, run it by hand until you are satisfied (stop
the service first if it is already installed: `sudo systemctl stop probolos`;
only one gate can run at a time):

```bash
sudo python3 -m probolos --privsep --agent --agent-user "$USER"
python3 -m probolos.agent           # in your desktop session
```

## Install

```bash
sudo ./install.sh                # install and start; re-run after `git pull` to update
sudo ./install.sh --user NAME    # the account whose desktop answers (default: who ran sudo)
sudo ./install.sh --uninstall    # stop and remove; /var/lib/probolos is kept
```

It installs:

- the code, root-owned, in `/opt/probolos` (a root service must not run code a
  user can edit);
- a `probolos` command in `/usr/local/bin` (`sudo probolos --history`);
- the `probolos` system account the analyzer runs as;
- both units, with your local settings in drop-ins, and starts them.

It refuses while a Probolos started by hand is still running. Uninstalling
keeps the `probolos` account, which owns the kept history.

Check that both run:

```bash
systemctl status probolos.service
systemctl --user status probolos-agent.service
sudo journalctl -u probolos -f
```

How the service asks:

- With no desktop session (login screen, logout), new devices are **held**
  and asked about once you are back. Remembered devices still get in.
- The service runs with `--timeout 0`, but a desktop dialog still closes after
  60 s. The device then stays blocked, recorded as "no answer" (not as a
  refusal), and a notice tells you to replug it to be asked again.

## By hand

Put the source at `/opt/probolos`, owned by root (there is no distribution
package yet; ROADMAP 1.8). Then:

```bash
# the analyzer's account: the unit runs --privsep-user probolos
sudo install -D -m 644 systemd/probolos.sysusers /etc/sysusers.d/probolos.conf
sudo systemd-sysusers /etc/sysusers.d/probolos.conf
# the gate, as root
sudo cp systemd/probolos.service /etc/systemd/system/
sudo systemctl edit probolos.service
```

```ini
[Service]
Environment=PYTHONPATH=/opt/probolos
# Whose desktop answers. The shipped placeholder, `probolos`, turns the
# prompt off: with no terminal either, every new device is then refused as
# "no answer" (after the stage 3 and 4 checks), with nobody asked.
Environment=PROBOLOS_AGENT_USER=yourname
```

```bash
# the agent, as you
mkdir -p ~/.config/systemd/user
cp systemd/probolos-agent.service ~/.config/systemd/user/
systemctl --user edit probolos-agent.service
```

```ini
[Service]
Environment=PYTHONPATH=/opt/probolos
# Not your home directory: a `probolos/` folder there would be imported
# instead of the installed one.
WorkingDirectory=/
```

`systemctl edit` reloads the units when you save. Start both:

```bash
sudo systemctl enable --now probolos.service
systemctl --user enable --now probolos-agent.service
```

(`install.sh` also adds `ConditionUser=` to the agent, because it installs it
for every account; a unit in your own `~/.config/systemd/user` does not need
it.)

## What the sandboxing does

The gate needs root, so its unit limits what root can still reach:

| Setting | Effect |
|---|---|
| `ProtectSystem=strict` | the filesystem is read-only, except the state and runtime directories |
| `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, `IPAddressDeny=any` | no IP traffic; `PrivateNetwork` stays off because udev events arrive over host netlink |
| `DevicePolicy=closed` | input devices, and block devices read-only; nothing else |
| `MemoryDenyWriteExecute=yes` | no writable and executable memory |
| `SystemCallFilter` | no module loading, raw I/O, mounting, rebooting, ... |
| `CapabilityBoundingSet` | only the five capabilities the privilege drop and directory setup need |

`ProtectKernelTunables` is deliberately **off**: writing
`/sys/bus/usb/devices/*/authorized` is the whole mechanism. That is the one
broad permission the design cannot avoid, and the reason the privileged half
is kept apart from the analyzer, with its own tests and a coverage floor.

## Removing it

```bash
sudo ./install.sh --uninstall
# or, for a manual install:
sudo systemctl disable --now probolos.service
systemctl --user disable --now probolos-agent.service
```

Stopping the service reopens the gate, as every exit does. If devices stay
blocked:

```bash
sudo probolos --release    # from a checkout: sudo python3 -m probolos --release
```
