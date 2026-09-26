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
from .textsafe import (NOTE_BIDI, NOTE_CONTROL, NOTE_INVISIBLE,
                       NOTE_STACKED_MARKS)

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
# USB descriptor string fields, mapped to a phrase an operator can read.
# The keys are the names descriptors.py attaches to string_note_fields.
_STRING_FIELD_PHRASES = {
    "iManufacturer": "manufacturer name",
    "iProduct": "product name",
    "iSerialNumber": "serial number",
    "manufacturer": "manufacturer name",
    "product": "product name",
    "serial": "serial number",
}


def _crafted_field_phrases(per_field: Dict[str, Sequence[str]],
                           wanted: Set[str]) -> List[str]:
    """
    Names of the fields whose sanitiser notes intersect `wanted`.

    per_field maps a descriptor field name to the list of textsafe notes it
    triggered. We return the human phrase for each field that carries at least
    one of the notes we care about, in a stable order so the message and the
    tests are deterministic.
    """
    out: List[str] = []
    for field_name, field_notes in per_field.items():
        if set(field_notes) & wanted:
            phrase = _STRING_FIELD_PHRASES.get(field_name, field_name)
            if phrase not in out:
                out.append(phrase)
    return out


def _join_phrases(phrases: Sequence[str]) -> str:
    """Join phrases for prose: 'a', 'a and b', 'a, b and c'."""
    items = list(phrases)
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]


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
    # A HID interface that declares no boot protocol has not said whether it is
    # a keyboard, and the descriptors cannot tell us -- the report descriptor,
    # which holds the answer, is not in the sysfs blob (see
    # usbclass.is_undeclared_hid). Every rule below that asked has_keyboard was
    # therefore evadable by declaring subclass 0x00 / protocol 0x00: legal,
    # ordinary, and a fully working keyboard under Linux.
    #
    # The response is NOT to widen has_keyboard, which would fire on the many
    # honest peripherals that use subclass 0. It is to keep the two apart and
    # let each rule state which question it is asking -- "this device says it
    # can type" or "this device might be able to type and will not say".
    has_undeclared_hid = any(
        usbclass.is_undeclared_hid(i.interface_class, i.interface_subclass,
                                   i.interface_protocol) for i in ifaces)
    # A declared boot mouse also "might type": the sysfs blob does not contain
    # the report descriptor, so a device that says `subclass=1, protocol=2`
    # (mouse) can still map its HID reports to Usage Page 0x01 / Usage 0x06
    # (keyboard). Alone, this is a completely normal mouse and must not raise
    # anything -- see test_ordinary_mouse_alone_never_alerts. In combination
    # with mass storage, it is the same BadUSB layout as the undeclared case,
    # and the property test found the gap in the pair rules below.
    has_declared_mouse = any(
        usbclass.is_mouse(i.interface_class, i.interface_subclass,
                          i.interface_protocol) for i in ifaces)
    input_of_unknown_shape = has_undeclared_hid or has_declared_mouse
    may_type = has_keyboard or has_undeclared_hid

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

    # -- 2b. The same two shapes, with the HID half saying nothing ---------
    # Combination rules only. An undeclared HID interface ON ITS OWN is
    # unremarkable -- countless mice, headset buttons and vendor config
    # channels look exactly like this -- so flagging it alone would be the
    # false-positive machine this whole module was written to avoid. Paired
    # with mass storage or a network interface it is a different statement:
    # there is no mainstream product that is a flash drive plus an input
    # device of undisclosed kind, and that is precisely the BadUSB layout.
    if input_of_unknown_shape and not has_keyboard:
        if CLS_MASS_STORAGE in classes:
            add("storage-with-undeclared-hid", Severity.CRITICAL,
                "Storage device with an input interface that may be able "
                "to type",
                "This device presents itself as a disk AND as a human "
                "interface device whose actual behaviour is not visible from "
                "the descriptors -- either it declined to say (subclass 0) "
                "or it declared itself a mouse, but the answer lives in the "
                "HID report descriptor, which is not readable without "
                "talking to the device. Either way, the report descriptor "
                "can map keys. Treat it as the BadUSB layout: the storage "
                "half is the alibi, and the input half may be able to type. "
                "Legitimate flash drives do not carry an input interface at "
                "all.")
        if classes & {CLS_CDC, CLS_CDC_DATA, CLS_WIRELESS}:
            add("network-with-undeclared-hid", Severity.WARNING,
                "Network device with an input interface of unclear shape",
                "Alongside its own network path this device declares a human "
                "interface device whose actual behaviour is not visible from "
                "the descriptors (either subclass 0, or a declared mouse "
                "whose report descriptor was not read). If that interface "
                "can type, the pair can run commands and carry the results "
                "out over a link you do not control. This is a WARNING "
                "rather than a CRITICAL because the combination has "
                "legitimate instances -- some radios expose a vendor HID "
                "channel -- and because what the interface actually does "
                "cannot be read from the descriptors.")

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
    if may_type and any(word in label for word in STORAGE_WORDS):
        what = ("a keyboard interface" if has_keyboard
                else "a human interface device that will not say what kind "
                     "it is")
        add("self-contradictory-identity", Severity.WARNING,
            "Calls itself storage, presents an input interface",
            f"The device names itself '{dev.label()}', which describes a "
            f"storage product, yet it declares {what}. Note this "
            "compares the device against ITSELF -- no external vendor database "
            "is involved, because cross-branded hardware is normal. A disguised "
            "keystroke injector that omits the boot protocol used to slip past "
            "this rule; it no longer does.")

    # -- 5. Several unrelated functions in one device ----------------------
    if len(classes) > 1 and not _is_benign_group(classes, cfg):
        names = ", ".join(usbclass.class_name(c) for c in sorted(classes))
        add("multiple-distinct-functions", Severity.NOTICE,
            "Device combines several different functions",
            f"Declared functions: {names}. This is not suspicious by itself -- "
            "many ordinary devices are composite -- but this particular "
            "combination is not one of the patterns known to be routine.")

    # -- 6. Structural anomalies in the descriptors ------------------------
    # These attributes are read with getattr so the rule engine stays
    # trivially unit-testable with lightweight stubs that only carry the
    # fields a given rule needs. A real sysfs.UsbDevice always defines them.
    #
    # The three findings below all mean the same thing: part of what the
    # device declared was never examined, so every rule above ran on a partial
    # list of its functions. They are CRITICAL for the reason analyzers.run()
    # gives for a crashed rule engine -- an unexamined function list is not a
    # clean result. As WARNINGs they made an incomplete view CHEAPER to
    # approve than a complete one: a storage+keyboard device whose descriptors
    # could not be read in full dropped from "type the word authorize" to a
    # clickable [y/N], and a remembered one was admitted without a question.
    #
    # The kernel reads every descriptor itself and trims malformed tails before
    # exposing them (drivers/usb/core/config.c adjusts wTotalLength), so on
    # real hardware these arise from Probolos's own limits -- the descriptor
    # count bound, or the 18 + 65535 byte cap on the sysfs `descriptors`
    # attribute -- not from ordinary buggy devices.
    parse_error = getattr(dev, "parse_error", None)
    if parse_error:
        add("unreadable-descriptors", Severity.CRITICAL,
            "Device descriptors could not be read",
            f"{parse_error}. A device whose own descriptors do not parse "
            "is either broken or deliberately malformed. Either way its claims "
            "cannot be checked, so it cannot be assessed -- and whatever it "
            "declared in the part that was not read, the kernel will still "
            "configure.")

    descriptor_set = getattr(dev, "descriptor_set", None)
    if descriptor_set and descriptor_set.declared_interface_mismatch():
        add("interface-count-mismatch", Severity.WARNING,
            "Device disagrees with itself about its own structure",
            "A configuration declares a different number of interfaces than it "
            "actually contains. Honest hardware is internally consistent.")

    if descriptor_set and not ifaces:
        add("no-interfaces", Severity.NOTICE,
            "Device declares no interfaces",
            "Nothing can be said about what this device does, because it "
            "describes no functions at all.")

    # These two only became observable once descriptors.parse() was routed
    # through descriptors_safe; the loop it replaced discarded a truncated tail
    # without recording that it had done so.
    truncated = getattr(descriptor_set, "truncated", None)
    if truncated:
        add("descriptor-chain-truncated", Severity.CRITICAL,
            "The descriptor chain stops before it should",
            f"{truncated}. What was parsed is still shown, but the device did "
            "not deliver everything it promised, so any function described in "
            "the missing part is invisible to every check below.")

    configs = getattr(descriptor_set, "configs", None)
    declared_configs = getattr(getattr(descriptor_set, "device", None),
                               "num_configurations", None)
    if (isinstance(configs, list) and isinstance(declared_configs, int)
            and len(configs) < declared_configs):
        add("configurations-missing", Severity.CRITICAL,
            "Some of the device's configurations were never examined",
            f"The device declares {declared_configs} configuration(s) but "
            f"only {len(configs)} could be read. The kernel may select one "
            "that was not examined, and nothing it declares there has been "
            "checked.")

    overstated = getattr(descriptor_set, "length_overstated", 0)
    if overstated > 0:
        add("descriptor-length-overstated", Severity.NOTICE,
            "Device claims more descriptor data than it sent",
            f"wTotalLength overstates the delivered configuration data by "
            f"{overstated} bytes. Vendor toolchains compute this field; a "
            "mismatch is the fingerprint of a descriptor set edited by hand.")

    # -- 7. Weak signal, stated as weak ------------------------------------
    if has_keyboard and _speed_mbps(dev) and _speed_mbps(dev) >= 480:
        add("keyboard-at-high-speed", Severity.NOTICE,
            "Keyboard on a high-speed connection",
            "Keyboards need almost no bandwidth and are usually low- or "
            "full-speed. High-speed is typical of devices built on flash-drive "
            "hardware. This signal is weak on its own: keyboards with built-in "
            "hubs or USB passthrough are legitimately high-speed.")

    # -- 7b. The device's own strings were crafted, not just messy ---------
    # textsafe.py sanitises every USB string and records WHY it had to. Those
    # notes surface here as findings. The split matters: control characters and
    # bidi overrides are active deception (they rewrite what the operator reads
    # in the prompt), while zero-width/invisible characters are a weaker signal
    # that is often just sloppy Unicode. So the first two escalate together and
    # the third is only ever a NOTICE.
    notes = set(getattr(dev, "string_notes", ()) or ())
    per_field = getattr(dev, "string_note_fields", {}) or {}

    deceptive = notes & {NOTE_CONTROL, NOTE_BIDI}
    if deceptive:
        fields = _crafted_field_phrases(per_field, {NOTE_CONTROL, NOTE_BIDI})
        where = _join_phrases(fields)
        detail = (f" The {where} contains characters that do not print as "
                  "themselves." if where else "")
        add("crafted-strings", Severity.WARNING,
            "Device strings contain characters designed to mislead",
            "One of this device's text fields carries control characters or a "
            "right-to-left override. Those do not describe anything -- their "
            "only effect is to change what this prompt shows you versus what "
            "the device really is." + detail)

        # Escalation: a device that can TYPE and also lies about its own name
        # is expressing intent, not manufacturing sloppiness. Treated like the
        # other BadUSB signatures.
        if may_type:
            add("crafted-strings-hid", Severity.CRITICAL,
                "A device that can type also disguised its own name",
                "This device declares an input interface AND hides deceptive "
                "characters in its identity strings." + detail + " A real "
                "keyboard has no reason to obfuscate its name; combined with "
                "the ability to inject keystrokes this matches a BadUSB that is "
                "trying not to be recognised.")

    if NOTE_INVISIBLE in notes:
        fields = _crafted_field_phrases(per_field, {NOTE_INVISIBLE})
        where = _join_phrases(fields)
        detail = (f" Seen in the {where}." if where else "")
        add("invisible-string-characters", Severity.NOTICE,
            "Device strings contain invisible characters",
            "One or more zero-width or otherwise invisible characters appear in "
            "this device's text. This is often just careless Unicode rather "
            "than an attack, so it is flagged only for awareness." + detail)

    if NOTE_STACKED_MARKS in notes:
        fields = _crafted_field_phrases(per_field, {NOTE_STACKED_MARKS})
        where = _join_phrases(fields)
        detail = (f" Seen in the {where}." if where else "")
        add("stacked-combining-marks", Severity.WARNING,
            "Device strings pile combining marks on one character",
            "More combining marks are stacked on a single character than any "
            "writing system uses. They take up no terminal columns, so a long "
            "run of them renders over the lines around it and can disfigure "
            "this report while measuring as a short string." + detail +
            " No manufacturer does this by accident, so it is a strong sign "
            "the descriptor was written rather than generated.")

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
    # AttributeError is caught alongside the value errors so a device (or a
    # test stub) that simply does not carry a speed reads as "unknown speed"
    # rather than crashing the whole evaluation.
    try:
        return float(dev.speed)
    except (AttributeError, TypeError, ValueError):
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
            "Probolos runs fine without it using the built-in rules.")

    with open(path) as fh:
        data = yaml.safe_load(fh) or {}

    # Every access below assumed a mapping of the expected shape, so a file
    # that was merely the wrong shape -- a list, a bare string, a `severity:`
    # that is not a mapping, a `benign_groups:` whose entries are not lists --
    # raised AttributeError or TypeError. __main__ catches only RuntimeError,
    # ValueError and OSError around this call, so the result was a traceback
    # instead of the one-line "rule config: ..." the operator was meant to get,
    # and the gate never closed. A config file that cannot be read must fail
    # like a config error, not like a crash.
    if not isinstance(data, dict):
        raise ValueError("the rule file must be a mapping of settings at its "
                         "top level")

    def _mapping(key):
        value = data.get(key) or {}
        if not isinstance(value, dict):
            raise ValueError(f"'{key}' must be a mapping, not "
                             f"{type(value).__name__}")
        return value

    def _sequence(key):
        value = data.get(key) or []
        if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
            raise ValueError(f"'{key}' must be a list, not "
                             f"{type(value).__name__}")
        return value

    by_name = {s.name.lower(): s for s in Severity}
    overrides = {}
    for rule_id, name in _mapping("severity").items():
        key = str(name).lower()
        if key not in by_name:
            raise ValueError(f"unknown severity '{name}' for rule '{rule_id}'")
        overrides[str(rule_id)] = by_name[key]

    groups = []
    for group in _sequence("benign_groups"):
        if isinstance(group, (str, bytes)) or not isinstance(group, (list, tuple)):
            raise ValueError("each entry of 'benign_groups' must be a list of "
                             "interface class codes, e.g. [0x03, 0xff]")
        for code in group:
            if isinstance(code, bool) or not isinstance(code, int):
                raise ValueError(f"benign_groups: {code!r} is not a class code")
        groups.append(set(group))

    return RuleConfig(
        disabled={str(r) for r in _sequence("disabled")},
        severity_overrides=overrides,
        extra_benign_groups=groups,
    )


# ---------------------------------------------------------------------------
# Stage 3: judging observed behaviour
#
# Kept here, next to the identity rules, so that every judgement Probolos makes
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

    # -- did the device actually go back to blocked? -----------------------
    # CRITICAL, not a notice. Every other finding here is read on the
    # assumption that the device is off again and cannot act while the human
    # reads. If the re-block failed, that assumption is false: the device is
    # live, ungrabbed, and the prompt about to be shown would be misleading in
    # the one direction that matters.
    if getattr(obs, "reblock_error", None):
        add("quarantine-not-restored", Severity.CRITICAL,
            "The device is STILL SWITCHED ON after observation",
            f"Probolos could not set authorized=0 again ({obs.reblock_error}). "
            "If the device is still plugged in it is live and no longer "
            "captured, so anything it sends now reaches your session. Unplug "
            "it before answering.")

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
            "by Probolos and did not reach your session.")
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
    return (f"first input captured {enum_ms:.0f} ms after authorization; "
            "input may have escaped before capture. Node-discovery time "
            "does not measure the true exposure window.")


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

    # -- 0. Structures the hardening layer refused to read -------------------
    # MediumReport.suspicious was being written by the inspection code and read
    # by nothing at all: the checks ran, rejected impossible geometry, and then
    # the reasons went nowhere. A refusal that never reaches the operator is
    # indistinguishable from a check that was never performed.
    if report.suspicious:
        detail = "; ".join(report.suspicious[:4])
        if len(report.suspicious) > 4:
            detail += f"; and {len(report.suspicious) - 4} more"
        add("impossible-partition-geometry", Severity.WARNING,
            "The medium describes structures that cannot exist",
            f"{detail}. These were not read, deliberately: seeking to an "
            "offset a device invented is how a partition table becomes an "
            "instruction rather than a description. Honest media do not "
            "produce this.")

    # -- 0b. A filesystem signature with nothing behind it ------------------
    # The signature is not reported as a filesystem (storage.identify_
    # filesystem refuses it), but silently dropping it would repeat the
    # mistake above: a check that ran and told nobody. Bytes that name a
    # filesystem which is not there are the medium disagreeing with itself.
    hollow = getattr(report, "hollow_signatures", None)
    if hollow:
        add("filesystem-signature-without-structure", Severity.NOTICE,
            "A filesystem signature is present without the filesystem",
            f"{'; '.join(hollow[:4])}. The identifying bytes are there but "
            "the volume structure they introduce is not, so the medium is not "
            "reported as that filesystem. Ordinary formatting does not produce "
            "this. Corruption can, and so can bytes planted to make the medium "
            "look like something it is not.")

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


# ---------------------------------------------------------------------------
# Media changes in an already-admitted storage host (mediawatch.py)
# ---------------------------------------------------------------------------

# MBR type bytes that exist to be skipped by ordinary tools: the "hidden"
# variants of FAT and NTFS (the 0x10 bit set on the visible type), plus 0x27,
# the hidden NTFS recovery partition.
_HIDDEN_MBR_TYPES = {0x11, 0x14, 0x16, 0x17, 0x1B, 0x1C, 0x1E, 0x27}
_MBR_ESP_TYPE = 0xEF


def media_findings(medium, *, drift: Optional[str] = None,
                   drift_known: bool = False, locked: bool = False,
                   config: Optional[RuleConfig] = None) -> List[Finding]:
    """
    Findings about a medium inserted into a reader that was already admitted.

    These are ADDED to storage_findings, never instead of them. They exist
    only on the media-change path: a card has no admission step, so nothing
    here decides whether it is let in. They decide what the operator is told
    and, under --media-policy deauthorize, whether the READER is switched off.

    `drift` is the baseline layout this medium differs from (None when it
    matches or is the first seen); `drift_known` says the new layout has been
    seen in this slot before.
    """
    cfg = config or DEFAULT_CONFIG
    out: List[Finding] = []

    def add(rule_id, severity, title, explanation):
        if cfg.enabled(rule_id):
            out.append(Finding(rule_id, cfg.severity(rule_id, severity),
                               title, explanation))

    if locked:
        add("media-inserted-while-locked", Severity.WARNING,
            "A medium was inserted while the session was locked",
            "Nobody was at the machine to insert it. A card slot in a reader "
            "that was already trusted has no admission step of its own, so "
            "this is the moment it would be used by someone with brief "
            "physical access.")

    if medium is None or medium.error:
        return out

    from . import storage as storage_mod

    esp = [f"partition {p.index + 1}" for p in medium.partitions
           if p.type_byte == _MBR_ESP_TYPE]
    esp += [f"GPT entry {e.index + 1}" for e in medium.gpt_entries
            if e.type_guid == storage_mod.GPT_ESP_GUID]
    if esp:
        add("media-efi-system-partition", Severity.CRITICAL,
            "The inserted medium carries an EFI system partition",
            f"{', '.join(esp[:4])}. An EFI system partition holds boot "
            "loaders: it is what makes a card a boot payload rather than "
            "storage. Firmware can be set to boot from it, and nothing about "
            "photos or documents needs one.")

    hidden = [f"partition {p.index + 1} "
              f"({storage_mod.type_name(p.type_byte)})"
              for p in medium.partitions if p.type_byte in _HIDDEN_MBR_TYPES]
    hidden += [f"GPT entry {e.index + 1}" for e in medium.gpt_entries
               if e.attributes & storage_mod.GPT_ATTR_HIDDEN]
    if hidden:
        add("media-hidden-partition", Severity.CRITICAL,
            "The inserted medium carries a hidden partition",
            f"{', '.join(hidden[:4])}. The type or attribute exists so that "
            "file managers and operating systems skip the partition. Data "
            "on a card that is meant not to be seen by the person using it "
            "is the case this rule is for.")

    if drift is not None:
        if drift_known:
            add("media-layout-drift", Severity.NOTICE,
                "This slot has seen a different medium before",
                "The layout differs from the first medium recorded in this "
                "slot of this reader, but matches one seen here since. "
                "Usually several cards in rotation.")
        else:
            add("media-layout-drift", Severity.WARNING,
                "A medium this slot has never seen",
                "The layout (partition table, sizes, filesystem signatures) "
                "differs from every medium recorded in this slot of this "
                "reader. A new card is often just a new card; it is reported "
                "because the reader was trusted on the strength of a "
                "different one.")
    return out
