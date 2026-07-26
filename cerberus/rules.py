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

    findings.sort(key=lambda f: f.severity, reverse=True)
    return findings


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
