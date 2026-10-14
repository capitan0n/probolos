# Security

## Reporting a vulnerability

Report it privately through GitHub:
<https://github.com/capitan0n/probolos/security/advisories/new>. Please do not
open a public issue for it; anything already public can go in a normal issue.

Please include the distribution and kernel, the Probolos version (the release,
or `git describe --tags --always` in your checkout), whether `--privsep` was
on, and the device or input that triggered it. Fixes go through a private
advisory and are published with the release that carries them.

## What Probolos defends against

Someone with brief physical access leaves a USB device behind, or talks you
into plugging one in, and the device is not what it claims to be. The classic
case is a keystroke-injection device inside a USB-stick case.

It assumes that:

- the machine and its kernel are trustworthy when Probolos starts;
- you answer prompts with a keyboard (or an SSH session) that was already there;
- root is not already compromised.

## What it does not stop

| Threat | Why not |
|---|---|
| Bugs in the kernel's USB code | the kernel reads the device's descriptors before Probolos sees it; only a separate machine (`usbip`) avoids that |
| Malicious filesystems | a crafted FAT/exFAT/NTFS attacks the kernel when it is mounted; Probolos reads partition tables, not filesystems |
| A patient device | one that behaves for days and attacks later passes every check; the history only catches changed *descriptors* |
| A perfect copy | an O.MG cable declares exactly what a real cable does; only stage 3 can catch it, and only if it types while being checked |
| Thunderbolt / PCIe DMA | another subsystem: use the IOMMU and `boltctl` |
| Bluetooth and other wireless | a radio adapter passes the checks, then accepts a keyboard over the air |
| Anything after you allow a device | Probolos stops watching it (cards: see `--watch-media`) |
| Malicious hubs or controller chips | the bus itself is trusted |

## Known weaknesses

Open, and listed on purpose. ROADMAP item numbers are in brackets.

1. **The rescue port is open while the screen is locked.** Internal ports
   and `--allow-port` are not gated behind a locked screen either, so a rescue
   keyboard can type the password. Anyone else at the machine can use an
   `--allow-port` port just as well: give one only if your keyboard is USB.
2. **Keystrokes can slip through during stage 3.** The device is switched on
   before its input can be captured (`EVIOCGRAB`), and keys sent in that gap
   reach your session. `--close-race-window` does not fix this. Stages 3 and 4
   also switch on the device's other functions for a moment. To avoid both,
   use `--observe 0 --no-storage-scan`.
3. **Desktop automount can win the race.** While stage 4 reads a stick, or when
   a card goes into an allowed reader, the desktop may mount it. The udev rule
   in the README stops udisks-based automount only.
4. **Cards are not gated.** A card in an allowed reader is a medium, not a
   device. `--watch-media` detects it and, at most, switches the whole reader
   off.
5. **A `--privsep` run started by hand uses the shared `nobody` account** by
   default. Any other process running as `nobody` can kill the analyzer, which
   reopens the gate. The service runs the analyzer as its own `probolos`
   account and is not affected; by hand, pass `--privsep-user probolos` once
   that account exists [1.11].
6. **The analyzer makes the decisions.** Privilege separation limits what a
   compromised analyzer can make root do, but it can still allow or block
   devices, or exit, which reopens the gate.
7. **Typing rhythm can be faked.** A device can imitate human timing
   (Malboard, 2019), so `machine-generated-keystrokes` should be assumed
   beatable. The rule that matters is `unprompted-typing`: nobody should be
   typing on a device in quarantine at all, however human it looks.
8. **Stage 4 is a hint, not a gate.** It knows a fixed set of filesystems, and
   a device can delay its storage until the check gives up. Decisions rest on
   stages 1 and 2.
9. **Root hubs added after start are not gated** (a new USB controller, for
   example in a dock).
10. **`--close-race-window` is experimental.** It turns off automatic driver
    binding for the whole system and may leave it off after a `SIGKILL`; it
    cannot be combined with `--privsep`.

## Privilege separation: what it bounds

With `--privsep` (always on in the service), a small root **gate** does the
privileged work and an unprivileged **analyzer** does everything else:

- The gate acts only on devices the kernel shows as blocked, or that it
  switched on itself for inspection, and only on that exact device. It never
  opens your existing keyboards, and never your disks unless `--watch-media`
  is on (below).
- When the analyzer goes away, the gate switches off what it had switched on
  for inspection, puts back interfaces it turned off, and reopens the root
  hubs. Devices you allowed stay on.
- "Always allow" is written by the gate itself, only for a device it has just
  allowed, and only with a fingerprint it measured itself.
- With `--watch-media`, the analyzer may also read every USB storage device
  that is watched (all storage-only devices present at start or allowed later:
  card readers, sticks and USB disks) and switch it off, never on.

The details are in [docs/TECHNICAL-REFERENCE.md](docs/TECHNICAL-REFERENCE.md).

## Keystroke privacy

Probolos can record what a quarantined device typed (`--capture-payload`).
That is limited by design, not just by settings:

- devices attached before Probolos started, such as your own keyboard, are
  never inspected;
- quarantine runs only *before* you decide: an allowed device is never
  recorded;
- without `--capture-payload`, only the timing of keys is kept, never which
  keys.

Tests pin all three (`tests/test_quarantine.py`). A setup in which Probolos
records a device somebody approved and is using is a security bug: please
report it. In the EU, recording input on a work machine may still involve GDPR
obligations, so turn `--capture-payload` on deliberately.

## Not locking yourself out

| Safety layer | What it covers |
|---|---|
| Internal ports | `removable=fixed` ports are not gated (unless `--gate-fixed-ports`), even while the screen is locked |
| `--allow-port` | a rescue port that is never gated, even while the screen is locked: anyone at the machine can use it too |
| Watchdog | reopens the gate if Probolos stops making progress (`--watchdog`, default 60 s) |
| Panic file | `sudo touch /run/probolos.panic` from another terminal or SSH; the watchdog checks for it |
| Exit handling | the gate reopens on exit, crash and signals; `--release` afterwards |

The panic file must be owned by root, or any user could turn Probolos off with
it; it lives in `/run`, so it is gone after a reboot. If even the root gate
dies, recover by hand ("If something goes wrong" in the README).

The kernel's documentation of USB authorization:
<https://docs.kernel.org/usb/authorization.html>
