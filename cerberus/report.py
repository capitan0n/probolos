"""
Turning a device into a question a human can answer.

Design rule for this file: never show a number the user cannot act on. VID/PID
appear once, at the bottom, as a forensic reference -- not as the basis of the
decision. The decision line is always in plain language.

Stages 1-2 report IDENTITY and SEMANTIC CONSISTENCY. Stages 3-4 will add
behavioural and content findings below the same claim block.
"""

from __future__ import annotations

from typing import List, Optional, Sequence

from . import rules, sysfs, usbclass

# Severity is shown as a word, not a colour or a number. A user under time
# pressure reads one word.
_SEVERITY_MARK = {
    rules.Severity.CRITICAL: "!!",
    rules.Severity.WARNING: " !",
    rules.Severity.NOTICE: " ~",
    rules.Severity.INFO: "  ",
}

_VERDICT = {
    rules.Severity.CRITICAL: "CRITICAL — this matches a known attack pattern",
    rules.Severity.WARNING: "WARNING — something here does not add up",
    rules.Severity.NOTICE: "NOTICE — minor oddity, probably harmless",
    rules.Severity.INFO: "No inconsistencies found in what it claims",
}

WIDTH = 62


def _line(text: str = "") -> str:
    # Border(1) + space(1) + padded text(WIDTH-1) + border(1) == WIDTH + 2,
    # which is exactly the width of the ─ rules above and below.
    return f"│ {text:<{WIDTH - 1}}│"


def _rule(left="├", right="┤", fill="─") -> str:
    return left + fill * WIDTH + right


def _wrap(text: str, width: int) -> List[str]:
    """Naive word wrap. Explanations are prose and must not run off the box."""
    words, lines, current = text.split(), [], ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines


def _finding_lines(finding: rules.Finding) -> List[str]:
    """
    Render one finding, wrapping BOTH the title and the body.

    Titles are written for humans and some are long; letting them overflow the
    box was a real bug. Wrapping here means every future rule is safe by
    construction rather than by remembering to keep titles short.
    """
    mark = _SEVERITY_MARK[finding.severity]
    head = f"{mark} {finding.severity.label}: {finding.title}"
    lines = []
    for i, chunk in enumerate(_wrap(head, WIDTH - 3)):
        lines.append(_line(chunk if i == 0 else f"     {chunk}"))
    for chunk in _wrap(finding.explanation, WIDTH - 8):
        lines.append(_line(f"     {chunk}"))
    return lines


def render(dev: sysfs.UsbDevice,
           findings: Optional[Sequence[rules.Finding]] = None) -> str:
    """Build the full report block for one blocked device."""
    findings = list(findings or [])
    verdict = rules.worst(findings)
    out: List[str] = []
    out.append("┌" + "─" * WIDTH + "┐")
    out.append(_line("NEW USB DEVICE — BLOCKED, AWAITING DECISION"))
    out.append(_rule())

    # --- what it claims to be -------------------------------------------
    claims = dev.claims
    if claims:
        out.append(_line("Claims to be:"))
        for claim in claims:
            out.append(_line(f"    • {claim}"))
    elif dev.parse_error:
        out.append(_line("Claims to be:  UNKNOWN — descriptors unreadable"))
        out.append(_line(f"    ({dev.parse_error})"))
    else:
        cls = dev.device_class if dev.device_class is not None else 0
        out.append(_line(f"Claims to be:  {usbclass.class_name(cls)}"))

    out.append(_line())

    # --- who it says it is (device-supplied strings, never trusted) ------
    out.append(_line(f"Manufacturer:  {dev.manufacturer or '(none reported)'}"))
    out.append(_line(f"Product:       {dev.product or '(none reported)'}"))
    out.append(_line(f"Serial:        {dev.serial or '(none reported)'}"))

    out.append(_rule())

    # --- raw facts, for the record --------------------------------------
    port = f"bus {dev.bus} port {dev.name}" if dev.bus else dev.name
    out.append(_line(f"ID {dev.vendor_id}:{dev.product_id}   {port}   "
                     f"{dev.speed or '?'} Mbps"))

    if dev.descriptor_set:
        d = dev.descriptor_set.device
        n_ifaces = len(dev.interfaces)
        out.append(_line(f"{n_ifaces} interface(s), {d.num_configurations} "
                         f"configuration(s)"))
        cfgs = dev.descriptor_set.configs
        if cfgs:
            cfg0 = cfgs[0]
            source = "self-powered" if cfg0.self_powered else "bus-powered"
            # The raw byte is shown alongside the milliamps because the two
            # differ by the USB generation, and that discrepancy was a real bug.
            out.append(_line(f"declares {cfg0.max_power_ma} mA  ({source}, "
                             f"bMaxPower={cfg0.max_power_raw} × "
                             f"{cfg0.power_unit_ma} mA)"))

    # --- what the rules concluded ---------------------------------------
    out.append(_rule())
    out.append(_line(_VERDICT[verdict]))

    for finding in findings:
        out.append(_line())
        out.extend(_finding_lines(finding))

    out.append("└" + "─" * WIDTH + "┘")

    # --- honesty about what has NOT been checked ------------------------
    out.append("")
    out.append("  Checked: identity and internal consistency of what the")
    out.append("  device CLAIMS. Not checked: how it actually behaves once")
    out.append("  live, and what it contains. Those are stages 3 and 4.")

    return "\n".join(out)


def one_liner(dev: sysfs.UsbDevice,
              findings: Optional[Sequence[rules.Finding]] = None) -> str:
    """Compact form for logs."""
    claims = ", ".join(dev.claims) or "unknown"
    text = (f"{dev.vendor_id}:{dev.product_id} [{claims}] "
            f"'{dev.label()}' at {dev.name}")
    if findings:
        text += f"  <{rules.worst(findings).label}: {len(findings)} finding(s)>"
    return text


def render_behaviour(obs, findings: Sequence[rules.Finding]) -> str:
    """
    Second report block, printed after the device has been watched in isolation.

    Deliberately a SEPARATE block rather than an update of the first one: the
    user should see that two independent kinds of evidence were gathered, and
    that a device passing the identity check can still fail here.
    """
    out: List[str] = []
    out.append("┌" + "─" * WIDTH + "┐")
    out.append(_line("BEHAVIOUR UNDER QUARANTINE"))
    out.append(_rule())

    if obs.error:
        out.append(_line(f"Not observed: {obs.error}"))
    else:
        nodes = len(obs.grabbed)
        out.append(_line(f"Isolated {nodes} input channel(s) for "
                         f"{obs.duration:.0f}s"))
        out.append(_line(f"Keystrokes captured : {len(obs.key_presses)}"))
        if obs.button_presses:
            out.append(_line(f"Button presses      : {obs.button_presses} "
                             f"(normal for a mouse)"))
        if obs.motion_events:
            out.append(_line(f"Motion events       : {obs.motion_events} "
                             f"(normal for a mouse)"))

        note = rules.race_window_note(obs)
        if note:
            out.append(_line())
            for line in _wrap(f"Exposure gap: {note}.", WIDTH - 3):
                out.append(_line(line))

    if findings:
        out.append(_rule())
        for finding in findings:
            out.extend(_finding_lines(finding))
            if finding is not findings[-1]:
                out.append(_line())

    out.append("└" + "─" * WIDTH + "┘")
    return "\n".join(out)
