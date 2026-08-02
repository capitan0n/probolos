"""
Stage 2: semantic consistency checking.

THE DESIGN CONSTRAINT, LEARNED FROM REAL HARDWARE
-------------------------------------------------
The first three devices inventoried on a real laptop were a Microsoft-branded
mouse whose manufacturer string says "PixArt", a Realtek Bluetooth radio with
two interfaces, and a Chicony webcam with two interfaces. Every one of them
would have tripped an obvious-looking rule:

  "manufacturer string must match the VID owner"  -> flags the mouse
  "more than one interface is suspicious"         -> flags 2 of 3 devices

A tool that raises an alarm about your own mouse teaches you to ignore its
alarms, which is worse than having no tool. So the rules here are built on a
different principle:

  Judge FUNCTIONAL COHERENCE, not string similarity.

"SanDisk declaring a keyboard" is suspicious not because the strings disagree
with a database, but because a storage device has no functional reason to send
keystrokes. That reasoning survives contact with real hardware; string matching
does not.

Severity is deliberately graded. A tool with one alarm level forces every
finding to be either an emergency or invisible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Sequence, Set

from . import usbclass

# Class codes referenced by the rules
CLS_AUDIO = 0x01
CLS_CDC = 0x02
CLS_HID = 0x03
CLS_MASS_STORAGE = 0x08
CLS_HUB = 0x09
CLS_CDC_DATA = 0x0A
CLS_VIDEO = 0x0E
CLS_WIRELESS = 0xE0
CLS_MISC = 0xEF
CLS_VENDOR = 0xFF


class Severity(IntEnum):
    INFO = 0
    NOTICE = 1
    WARNING = 2
    CRITICAL = 3

    @property
    def label(self) -> str:
        return {
            Severity.INFO: "INFO",
            Severity.NOTICE: "NOTICE",
            Severity.WARNING: "WARNING",
            Severity.CRITICAL: "CRITICAL",
        }[self]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    explanation: str


# ---------------------------------------------------------------------------
# Benign patterns
#
# These are sets of interface classes that legitimately coexist. They suppress
# ONLY the generic "this device has several different functions" notice. They
# can never suppress a specific rule -- a malicious device must not be able to
# hide by also looking like something ordinary.
# ---------------------------------------------------------------------------

BENIGN_CLASS_GROUPS: List[Set[int]] = [
    {CLS_VIDEO},                        # webcam: UVC control + streaming
    {CLS_VIDEO, CLS_AUDIO},             # webcam with built-in microphone
    {CLS_WIRELESS},                     # Bluetooth radio: HCI + isochronous
    {CLS_AUDIO},                        # sound card / DAC
    {CLS_AUDIO, CLS_HID},               # headset whose volume buttons are HID
    {CLS_HID},                          # keyboard, mouse, gamepad
    {CLS_HID, CLS_VENDOR},              # peripheral with a config channel
    {CLS_MASS_STORAGE},                 # flash drive, external disk
    {CLS_HUB},
    {CLS_CDC, CLS_CDC_DATA},            # network adapter: control + data pair
    {CLS_VENDOR},
    {CLS_MISC},
]

# Words in a device's own strings that suggest it is storage. Used only for
# self-contradiction checks -- never for matching against an external database.
STORAGE_WORDS = ("flash", "drive", "disk", "storage", "stick", "cruzer",
                 "datatraveler", "memory", "sd card", "card reader", "ssd")


@dataclass
class RuleConfig:
    """Which rules run, and how loudly. Overridable from YAML."""
    disabled: Set[str] = field(default_factory=set)
    severity_overrides: Dict[str, Severity] = field(default_factory=dict)
    extra_benign_groups: List[Set[int]] = field(default_factory=list)

    def severity(self, rule_id: str, default: Severity) -> Severity:
        return self.severity_overrides.get(rule_id, default)

    def enabled(self, rule_id: str) -> bool:
        return rule_id not in self.disabled


DEFAULT_CONFIG = RuleConfig()


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------

def evaluate(dev, config: Optional[RuleConfig] = None) -> List[Finding]:
    """
    Run every rule against one device and return findings, worst first.

    `dev` is a sysfs.UsbDevice. It is not imported for typing here to keep this
    module free of circular imports and trivially unit-testable with stubs.
    """
    cfg = config or DEFAULT_CONFIG
    findings: List[Finding] = []

    ifaces = dev.interfaces
    classes: Set[int] = set(dev.interface_classes)
    has_keyboard = any(
        usbclass.is_keyboard(i.interface_class, i.interface_subclass,
                             i.interface_protocol) for i in ifaces)

    def add(rule_id: str, default_sev: Severity, title: str, explanation: str):
        if not cfg.enabled(rule_id):
            return
        findings.append(Finding(rule_id, cfg.severity(rule_id, default_sev),
                                title, explanation))

    # -- 1. The BadUSB signature ------------------------------------------
    if has_keyboard and CLS_MASS_STORAGE in classes:
        add("storage-with-keyboard", Severity.CRITICAL,
            "Storage device that can also type",
            "This device presents itself as both a disk and a keyboard. The "
            "storage half provides the alibi while the keyboard half can enter "
            "commands on your behalf. Legitimate flash drives never need a "
            "keyboard interface. This is the classic BadUSB layout.")

    # -- 2. Keystroke injection plus a network path ------------------------
    if has_keyboard and (classes & {CLS_CDC, CLS_CDC_DATA, CLS_WIRELESS}):
        add("network-with-keyboard", Severity.CRITICAL,
            "Device that can both type and reach the network",
            "A device combining keystroke injection with its own network "
            "interface can run commands and carry the results out over a link "
            "you do not control. Very few legitimate products do this.")

    # -- 3. A keyboard hiding beside some other function -------------------
    unrelated = classes - {CLS_HID, CLS_HUB, CLS_VENDOR}
    if has_keyboard and unrelated and CLS_MASS_STORAGE not in classes:
        names = ", ".join(usbclass.class_name(c) for c in sorted(unrelated))
        add("keyboard-with-unrelated-function", Severity.WARNING,
            "Keyboard bundled with an unrelated function",
            f"Alongside the keyboard this device also declares: {names}. That "
            "combination is unusual and worth a moment's thought about whether "
            "the device you plugged in really does both jobs.")

    # -- 4. The device contradicts its own description ---------------------
    label = f"{dev.manufacturer or ''} {dev.product or ''}".lower()
    if has_keyboard and any(word in label for word in STORAGE_WORDS):
        add("self-contradictory-identity", Severity.WARNING,
            "Calls itself storage, behaves as a keyboard",
            f"The device names itself '{dev.label()}', which describes a "
            "storage product, yet it declares a keyboard interface. Note this "
            "compares the device against ITSELF -- no external vendor database "
            "is involved, because cross-branded hardware is normal.")

    # -- 5. Several unrelated functions in one device ----------------------
    if len(classes) > 1 and not _is_benign_group(classes, cfg):
        names = ", ".join(usbclass.class_name(c) for c in sorted(classes))
        add("multiple-distinct-functions", Severity.NOTICE,
            "Device combines several different functions",
            f"Declared functions: {names}. This is not suspicious by itself -- "
            "many ordinary devices are composite -- but this particular "
            "combination is not one of the patterns known to be routine.")

    # -- 6. Structural anomalies in the descriptors ------------------------
    if dev.parse_error:
        add("unreadable-descriptors", Severity.WARNING,
            "Device descriptors could not be read",
            f"{dev.parse_error}. A device whose own descriptors do not parse "
            "is either broken or deliberately malformed. Either way its claims "
            "cannot be checked, so it cannot be assessed.")

    if dev.descriptor_set and dev.descriptor_set.declared_interface_mismatch():
        add("interface-count-mismatch", Severity.WARNING,
            "Device disagrees with itself about its own structure",
            "A configuration declares a different number of interfaces than it "
            "actually contains. Honest hardware is internally consistent.")

    if dev.descriptor_set and not ifaces:
        add("no-interfaces", Severity.NOTICE,
            "Device declares no interfaces",
            "Nothing can be said about what this device does, because it "
            "describes no functions at all.")

    # -- 7. Weak signal, stated as weak ------------------------------------
    if has_keyboard and _speed_mbps(dev) and _speed_mbps(dev) >= 480:
        add("keyboard-at-high-speed", Severity.NOTICE,
            "Keyboard on a high-speed connection",
            "Keyboards need almost no bandwidth and are usually low- or "
            "full-speed. High-speed is typical of devices built on flash-drive "
            "hardware. This signal is weak on its own: keyboards with built-in "
            "hubs or USB passthrough are legitimately high-speed.")

    # -- 8. What the device says about its own power draw ------------------
    findings.extend(_power_findings(dev, cfg))

    findings.sort(key=lambda f: f.severity, reverse=True)
    return findings


def _power_findings(dev, cfg: RuleConfig) -> List[Finding]:
    """
    Consistency checks on the device's declared power consumption.

    These are DECLARATIONS, not measurements. A computer cannot measure what a
    USB device actually draws -- there is no current sensor on the port, and
    the battery gauge is swamped by CPU frequency changes. So this is one more
    reading of the device's own testimony, and it catches only the careless:
    anyone who clones a descriptor set clones bMaxPower along with it.

    They are cheap and occasionally decisive, so they are here -- at low
    severity, honestly labelled, because overstating a weak signal is how a
    tool loses the user's attention for the strong ones.
    """
    from . import descriptors as desc_mod

    out: List[Finding] = []
    ds = getattr(dev, "descriptor_set", None)
    if ds is None or not ds.configs:
        return out

    def add(rule_id, severity, title, explanation):
        if cfg.enabled(rule_id):
            out.append(Finding(rule_id, cfg.severity(rule_id, severity),
                               title, explanation))

    bcd = ds.device.usb_version
    limit = desc_mod.bus_power_limit_ma(bcd)
    first = ds.configs[0]
    declared = first.max_power_ma
    classes = set(dev.interface_classes)

    # (a) Objective: the device asks for more than the bus may legally supply.
    # No threshold guessing here -- the number comes from the specification.
    if declared > limit:
        add("power-exceeds-bus-limit", Severity.WARNING,
            "Device asks for more power than the bus can legally supply",
            f"It declares {declared} mA, while USB {bcd >> 8}.{(bcd >> 4) & 0xF} "
            f"permits at most {limit} mA for one device. Real products are "
            "tested against this limit; a descriptor that violates it was "
            "probably written by hand rather than by a vendor toolchain.")

    # (b) Storage that costs nothing to run has no flash in it. Programming
    # NAND takes real current, and this is the one power check that touches
    # physics rather than paperwork -- though only the paperwork is visible.
    if CLS_MASS_STORAGE in classes and not first.self_powered and declared <= 50:
        add("storage-declares-negligible-power", Severity.NOTICE,
            "Storage device that claims to need almost no power",
            f"It declares {declared} mA. Writing to NAND flash costs real "
            "current, and ordinary drives declare far more than this. A device "
            "that expects to spend nothing may have nothing to spend it on.")

    # (c) REMOVED: "self-powered yet demanding bus power".
    #
    # This rule existed briefly and was deleted after it fired on an internal
    # Realtek Bluetooth radio (0bda:4853) that declares self-powered and
    # bMaxPower=250. On re-reading the specification the premise was simply
    # wrong: bMaxPower states the maximum a device MAY draw, a self-powered
    # device is not forbidden from drawing bus power, and countless products
    # declare the maximum regardless. There was no contradiction to detect.
    #
    # Left as a comment rather than deleted silently, so that the next person
    # who thinks of it -- including a later version of its author -- finds the
    # reason it does not work before writing it again.

    # (d) Weakest of the four, and marked as such. Multiple configurations may
    # legitimately have different power needs, so only a wide gap is mentioned.
    span = ds.power_span()
    if len(ds.configs) > 1 and span and span[0] > 0 and span[1] >= span[0] * 4:
        add("power-varies-across-configurations", Severity.NOTICE,
            "Configurations disagree widely about power",
            f"Declared draw ranges from {span[0]} mA to {span[1]} mA across "
            "configurations. This can be perfectly legitimate; it is mentioned "
            "only because it is unusual.")

    return out


def _is_benign_group(classes: Set[int], cfg: RuleConfig) -> bool:
    """
    True if this exact combination is a recognised ordinary pattern.

    Subset rather than equality: a webcam that omits its audio interface is
    still a webcam, and should not become noisy for being simpler than the
    reference pattern.
    """
    for group in list(BENIGN_CLASS_GROUPS) + cfg.extra_benign_groups:
        if classes <= group:
            return True
    return False


def _speed_mbps(dev) -> Optional[float]:
    try:
        return float(dev.speed)
    except (TypeError, ValueError):
        return None


def worst(findings: Sequence[Finding]) -> Severity:
    """Highest severity present, or INFO when the device looks ordinary."""
    return max((f.severity for f in findings), default=Severity.INFO)


# ---------------------------------------------------------------------------
# Optional YAML configuration
# ---------------------------------------------------------------------------

def load_config(path) -> RuleConfig:
    """
    Load rule configuration from YAML, if PyYAML is available.

    The configurable surface is deliberately narrow: enable/disable rules,
    change severities, and add benign patterns. There is no expression language
    for writing new rules from YAML. That restraint is the point -- a rule DSL
    is where this kind of project drowns, and a rule that needs real logic
    belongs in Python where it can be tested.

    Expected shape:

        disabled:
          - keyboard-at-high-speed
        severity:
          multiple-distinct-functions: warning
        benign_groups:
          - [0x03, 0xff]
    """
    try:
        import yaml
    except ImportError:
        raise RuntimeError(
            "PyYAML is not installed (Manjaro: sudo pacman -S python-yaml). "
            "Cerberus runs fine without it using the built-in rules.")

    with open(path) as fh:
        data = yaml.safe_load(fh) or {}

    by_name = {s.name.lower(): s for s in Severity}
    overrides = {}
    for rule_id, name in (data.get("severity") or {}).items():
        key = str(name).lower()
        if key not in by_name:
            raise ValueError(f"unknown severity '{name}' for rule '{rule_id}'")
        overrides[rule_id] = by_name[key]

    return RuleConfig(
        disabled=set(data.get("disabled") or []),
        severity_overrides=overrides,
        extra_benign_groups=[set(g) for g in (data.get("benign_groups") or [])],
    )


# ---------------------------------------------------------------------------
# Stage 3: judging observed behaviour
#
# Kept here, next to the identity rules, so that every judgement Cerberus makes
# lives in one auditable place. quarantine.py only observes; it never decides.
# This module deliberately does not import evdev -- it takes a plain data object
# and can therefore be tested on any machine, with no hardware and no root.
# ---------------------------------------------------------------------------

# An operator asked not to touch a device produces no keystrokes. So the
# baseline expectation during quarantine is silence, and the question is only
# how to read the exceptions.
_ACCIDENT_THRESHOLD = 5      # a lean on the keyboard, not a payload
_MACHINE_INTERVAL = 0.050    # 50 ms between keys: faster than sustained human
_MACHINE_REGULARITY = 0.20   # coefficient of variation below this is inhuman


def behaviour_findings(obs, config: Optional[RuleConfig] = None) -> List[Finding]:
    """
    Turn a quarantine Observation into findings.

    The strongest signal here is not speed. It is that the device typed AT ALL
    while its owner was told to keep their hands off it. Timing statistics only
    serve to separate an accidental brush against the keys from an automated
    payload.
    """
    cfg = config or DEFAULT_CONFIG
    findings: List[Finding] = []

    def add(rule_id: str, default_sev: Severity, title: str, explanation: str):
        if not cfg.enabled(rule_id):
            return
        findings.append(Finding(rule_id, cfg.severity(rule_id, default_sev),
                                title, explanation))

    # -- could we observe at all? -----------------------------------------
    if obs.error:
        add("quarantine-unavailable", Severity.NOTICE,
            "Behaviour could not be observed",
            f"{obs.error}. The device was judged on its claims alone, which is "
            "exactly the situation a well-made malicious device is built for.")
        return findings

    ungrabbed = [n for n in obs.nodes if n not in obs.grabbed]
    if obs.grab_failures or ungrabbed:
        detail = "; ".join(obs.grab_failures) or ", ".join(ungrabbed)
        add("incomplete-isolation", Severity.WARNING,
            "Device was not fully isolated",
            f"Some input channels stayed outside the quarantine ({detail}). "
            "Anything sent through them reached the session normally, so the "
            "observation below is incomplete.")

    keys = obs.key_presses
    if not keys:
        return findings

    # -- it typed, unprompted ---------------------------------------------
    intervals = obs.intervals()
    mean_gap = _mean(intervals)
    cv = _coefficient_of_variation(intervals)
    first = obs.time_to_first_key()

    machine_like = (
        len(keys) >= 3
        and mean_gap is not None and mean_gap < _MACHINE_INTERVAL
        and cv is not None and cv < _MACHINE_REGULARITY
    )

    if machine_like:
        add("machine-generated-keystrokes", Severity.CRITICAL,
            "Keystrokes were generated by a machine, not a person",
            f"{len(keys)} keystrokes arrived while nobody was touching the "
            f"device, averaging {mean_gap * 1000:.0f} ms apart with a timing "
            f"variation of {cv:.2f}. Human typing is slower and markedly more "
            "irregular; this rhythm is automated. The keystrokes were captured "
            "by Cerberus and did not reach your session.")
    elif len(keys) >= _ACCIDENT_THRESHOLD:
        add("unprompted-typing", Severity.CRITICAL,
            "Device typed on its own",
            f"{len(keys)} keystrokes arrived during quarantine although the "
            "device was not being touched. Whatever the timing, a device that "
            "types unprompted is doing something it was not asked to do.")
    else:
        add("unexpected-keystrokes", Severity.WARNING,
            "A few unexplained keystrokes",
            f"{len(keys)} keystroke(s) arrived during quarantine. This is as "
            "consistent with brushing against the keys as with an attack, so "
            "it is reported rather than judged.")

    if first is not None and first < 0.5 and len(keys) >= 3:
        add("immediate-activity", Severity.WARNING,
            "Typing began the instant the device came alive",
            f"The first keystroke arrived {first * 1000:.0f} ms after "
            "authorization. Legitimate input devices wait for a person.")

    return findings


def race_window_note(obs) -> Optional[str]:
    """
    Plain statement of the exposure gap, for the report.

    Printed always, not only when it is large. The gap between authorizing a
    device and capturing its input is inherent to the approach, and a tool that
    mentions its own weak point only when convenient is not trustworthy.
    """
    if not obs.observed:
        return None
    enum_ms = obs.race_window * 1000
    exp_ms = obs.exposure_window * 1000
    # Two distinct numbers, because conflating them hides the mechanism:
    #   enumeration = authorize -> grab (kernel work; ~constant)
    #   exposure    = live node existed -> grab (the real risk window)
    if obs.first_node_at > 0.0 and exp_ms < enum_ms:
        return (f"enumeration {enum_ms:.0f} ms; actual exposure {exp_ms:.0f} ms "
                f"(a live input node existed for {exp_ms:.0f} ms before capture)")
    # Fallback path (no deferred bind, or node timing unavailable): the
    # old honest statement, where enumeration and exposure coincide.
    return (f"isolated {enum_ms:.0f} ms after authorization; "
            f"anything sent in that window reached the session")


def _mean(values) -> Optional[float]:
    return sum(values) / len(values) if values else None


def _coefficient_of_variation(values) -> Optional[float]:
    """
    Standard deviation divided by the mean: regularity, independent of speed.

    This is the discriminating statistic. Raw speed catches only crude
    payloads, and a fast typist can outrun a slow one; but no human sustains a
    near-constant interval between keys, while a script does so by default.
    """
    if len(values) < 2:
        return None
    mean = sum(values) / len(values)
    if mean <= 0:
        return None
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return (variance ** 0.5) / mean


# ---------------------------------------------------------------------------
# Stage 4: judging what a storage medium says about itself
# ---------------------------------------------------------------------------

# A gap before the first partition is normal -- 1 MiB alignment (2048 sectors)
# has been standard for over a decade, and some tools use 8 MiB. Only a gap far
# beyond any alignment convention suggests space deliberately set aside.
_ALIGNMENT_TOLERANCE_SECTORS = 32768        # 16 MiB


def storage_findings(report, config: Optional[RuleConfig] = None) -> List[Finding]:
    """
    Turn a raw-medium report into findings.

    Everything here is a structural contradiction: the medium disagreeing with
    itself. Nothing depends on reading files, and nothing depends on the medium
    being honest, because every number is checked against another number rather
    than believed.
    """
    cfg = config or DEFAULT_CONFIG
    out: List[Finding] = []

    def add(rule_id, severity, title, explanation):
        if cfg.enabled(rule_id):
            out.append(Finding(rule_id, cfg.severity(rule_id, severity),
                               title, explanation))

    if report is None:
        return out

    if report.error:
        add("storage-unreadable", Severity.NOTICE,
            "The medium could not be read",
            f"{report.error}. Its contents were not examined, so this device "
            "was judged on its declared identity alone.")
        return out

    from . import storage as storage_mod

    partitions = [p for p in report.partitions
                  if p.type_byte != storage_mod.PROTECTIVE_MBR_TYPE]
    size = report.size_sectors

    # -- 1. A partition that does not fit on the disk it claims to be on -----
    if size:
        for part in partitions:
            if part.end_lba > size:
                over = part.end_lba - size
                add("partition-beyond-end-of-device", Severity.WARNING,
                    "A partition claims space past the end of the device",
                    f"Partition {part.index + 1} ends at sector "
                    f"{part.end_lba} on a device of {size} sectors, "
                    f"{over} sectors too far. This cannot happen on honestly "
                    "written media; it is how a device lies about its own "
                    "capacity, and reading it will not return what was "
                    "written.")
                break

    # -- 2. Partitions that overlap each other -------------------------------
    ordered = sorted(partitions, key=lambda p: p.start_lba)
    for earlier, later in zip(ordered, ordered[1:]):
        if later.start_lba < earlier.end_lba:
            add("overlapping-partitions", Severity.WARNING,
                "Two partitions claim the same sectors",
                f"Partition {earlier.index + 1} runs to sector "
                f"{earlier.end_lba} while partition {later.index + 1} starts "
                f"at {later.start_lba}. Overlapping partitions are impossible "
                "to produce by ordinary formatting and mean the two views of "
                "the medium disagree about what is stored where.")
            break

    # -- 3. Declared type versus what is actually written --------------------
    for part in partitions:
        seen = report.signatures.get(part.index)
        expected = storage_mod.expected_filesystems(part.type_byte)
        if seen and expected and seen not in expected:
            add("filesystem-type-mismatch", Severity.NOTICE,
                "A partition contains something other than it declares",
                f"Partition {part.index + 1} is declared as "
                f"{storage_mod.type_name(part.type_byte)} but contains a "
                f"{seen} signature. Usually this is a medium that was "
                "reformatted without the partition type being updated, which "
                "is harmless; it is reported because the two statements do "
                "not agree.")
            break

    # -- 4. Unallocated space before the first partition ---------------------
    if partitions:
        first = min(partitions, key=lambda p: p.start_lba)
        if first.start_lba > _ALIGNMENT_TOLERANCE_SECTORS:
            mib = first.start_lba * storage_mod.SECTOR / (1024 * 1024)
            add("large-unallocated-gap", Severity.NOTICE,
                "A large unused area sits before the first partition",
                f"The first partition begins {mib:.1f} MiB into the device. "
                "Alignment normally accounts for 1 to 8 MiB. A much larger "
                "gap is space no filesystem describes, which is where data "
                "would go if it were meant not to be found by ordinary tools.")

    # -- 5. A GPT that contradicts its own protective MBR --------------------
    if report.scheme == "gpt":
        protective = [p for p in report.partitions
                      if p.type_byte == storage_mod.PROTECTIVE_MBR_TYPE]
        if not protective:
            add("gpt-without-protective-mbr", Severity.NOTICE,
                "GPT header present without a protective MBR",
                "A GPT-partitioned medium normally carries a protective MBR "
                "so that older tools do not treat it as unpartitioned. Its "
                "absence is unusual, though some tools produce it.")

    return out
