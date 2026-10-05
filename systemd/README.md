# Running Probolos as a service

Two units, because the two halves live in different places: the gate is a
**system** service (it needs root and udev), and the agent is a **user** service
(it needs your graphical session, which is the only place a dialog can appear).

## Install

**The easy way**, from the source tree:

```bash
sudo ./install.sh                # install and start; re-run after pulling to update
sudo ./install.sh --uninstall    # stop and remove; /var/lib/probolos is kept
```

It does what the manual steps below do, and more: code to `/opt/probolos`
(root-owned, since a root service must not run code its user can edit), a
`probolos` command in `/usr/local/bin`, both units with local settings in
drop-ins (`PROBOLOS_AGENT_USER` = the account that ran `sudo`), and it starts
both. It refuses while a probolos started by hand is still running.

**By hand.** Put the source at `/opt/probolos`, owned by root. (No
distribution package exists yet; ROADMAP 1.8.) Then install the units and give each the settings `install.sh`
puts in its drop-ins. (`install.sh` also adds `ConditionUser=` to the agent,
because it installs the agent for every account; a unit in your own
`~/.config/systemd/user` runs only for you and does not need it.)

```bash
# the gate, as root
sudo cp systemd/probolos.service /etc/systemd/system/
sudo systemctl edit probolos.service
```

```ini
[Service]
Environment=PYTHONPATH=/opt/probolos
# The account whose desktop answers. The unit ships the placeholder `nobody`,
# the analyzer's own account, so the gate turns the agent off: every new
# device is then held blocked, with nobody asked.
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

`systemctl edit` reloads the units when you save.

## Start

```bash
sudo systemctl enable --now probolos.service
systemctl --user enable --now probolos-agent.service
```

Check both:

```bash
systemctl status probolos.service
systemctl --user status probolos-agent.service
sudo journalctl -u probolos -f
```

## Before enabling it at boot

**Test it in the foreground first.** A service that closes the USB gate at boot
and then fails to start its agent will leave you approving devices from a
terminal you have to find. Run it by hand until you are satisfied:

```bash
sudo python -m probolos --privsep --agent
python -m probolos.agent
```

Note the gate is started with `--timeout 0`, meaning a question waits
indefinitely rather than expiring into a refusal. That is right for a background
service: a device you plugged in and walked away from should still be waiting
when you come back, not silently rejected. Set a timeout if you prefer the
opposite.

## What the sandboxing does

The gate needs root, so the units restrict what root can still reach:

| Setting | Effect |
|---|---|
| `ProtectSystem=strict` | the whole filesystem read-only except the state and runtime directories |
| `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, `IPAddressDeny=any` | no IP sockets or traffic; `PrivateNetwork` stays `no` because udev events arrive over host netlink |
| `DevicePolicy=closed` | only input nodes and block devices; no sound, video, tty or GPU |
| `MemoryDenyWriteExecute=yes` | no writable-executable memory |
| `SystemCallFilter` | denies module loading, raw I/O, mounting, reboot, and the rest |
| `CapabilityBoundingSet` | only the five capabilities the privilege drop and directory setup need |

`ProtectKernelTunables` is deliberately **not** enabled: writing
`/sys/bus/usb/devices/*/authorized` is the entire mechanism. That is the one
broad permission the design cannot do without, and it is the reason the
privileged half (`gate_server.py` and the protocol it serves) is kept separate
from the analyzer, with its own tests and a coverage floor.

## Removing it

```bash
sudo systemctl disable --now probolos.service
systemctl --user disable --now probolos-agent.service
```

Stopping the service reopens the gate, as every exit path does. If something has
gone wrong and devices are left blocked:

```bash
sudo probolos --release    # after install.sh; from a checkout: sudo python3 -m probolos --release
```
