# Running Probolos as a service

Two units, because the two halves live in different places: the gate is a
**system** service (it needs root and udev), and the agent is a **user** service
(it needs your graphical session, which is the only place a dialog can appear).

## Install

```bash
# the gate, as root
sudo cp systemd/probolos.service /etc/systemd/system/
sudo systemctl daemon-reload

# the agent, as you
mkdir -p ~/.config/systemd/user
cp systemd/probolos-agent.service ~/.config/systemd/user/
systemctl --user daemon-reload
```

Probolos must be importable by the system Python, either installed as a package
or with the source directory on `PYTHONPATH`. For a source checkout, add to the
system unit:

```ini
Environment=PYTHONPATH=/opt/probolos
```

and put the source at `/opt/probolos`.

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
| `PrivateNetwork=yes` | no sockets at all — a compromised analyzer cannot send anything anywhere |
| `DevicePolicy=closed` | only input nodes and block devices; no sound, video, tty or GPU |
| `MemoryDenyWriteExecute=yes` | no writable-executable memory |
| `SystemCallFilter` | denies module loading, raw I/O, mounting, reboot, and the rest |
| `CapabilityBoundingSet` | only the five capabilities the privilege drop and directory setup need |

`ProtectKernelTunables` is deliberately **not** enabled: writing
`/sys/bus/usb/devices/*/authorized` is the entire mechanism. That is the one
broad permission the design cannot do without, and it is the reason the
privileged half is kept to about 150 auditable lines.

## Removing it

```bash
sudo systemctl disable --now probolos.service
systemctl --user disable --now probolos-agent.service
```

Stopping the service reopens the gate, as every exit path does. If something has
gone wrong and devices are left blocked:

```bash
sudo python -m probolos --release
```
