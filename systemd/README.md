# Running Cerberus as a service

Two units, because the two halves live in different places: the gate is a
**system** service (it needs root and udev), and the agent is a **user** service
(it needs your graphical session, which is the only place a dialog can appear).

## Install

```bash
# the gate, as root
sudo cp systemd/cerberus.service /etc/systemd/system/
sudo systemctl daemon-reload

# the agent, as you
mkdir -p ~/.config/systemd/user
cp systemd/cerberus-agent.service ~/.config/systemd/user/
systemctl --user daemon-reload
```

Cerberus must be importable by the system Python, either installed as a package
or with the source directory on `PYTHONPATH`. For a source checkout, add to the
system unit:

```ini
Environment=PYTHONPATH=/opt/cerberus
```

and put the source at `/opt/cerberus`.

## Start

```bash
sudo systemctl enable --now cerberus.service
systemctl --user enable --now cerberus-agent.service
```

Check both:

```bash
systemctl status cerberus.service
systemctl --user status cerberus-agent.service
sudo journalctl -u cerberus -f
```

## Before enabling it at boot

**Test it in the foreground first.** A service that closes the USB gate at boot
and then fails to start its agent will leave you approving devices from a
terminal you have to find. Run it by hand until you are satisfied:

```bash
sudo python -m cerberus --privsep --agent
python -m cerberus.agent
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
sudo systemctl disable --now cerberus.service
systemctl --user disable --now cerberus-agent.service
```

Stopping the service reopens the gate, as every exit path does. If something has
gone wrong and devices are left blocked:

```bash
sudo python -m cerberus --release
```
