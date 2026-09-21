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

from . import rules, sysfs, textsafe, usbclass

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
    """
    One row of the box, exactly WIDTH + 2 terminal columns wide.

    THE BUG THIS FIXES
    ------------------
    This was `f"│ {text:<{WIDTH - 1}}│"`. Python's field width counts
    CHARACTERS, and textsafe.pad/fit/display_width -- written precisely so a
    device could not push the border off the line, and carrying that reasoning
    in their own docstrings -- had no callers anywhere in the project. The
    entire column-width defence was dead code, which is this codebase's
    recurring failure: a protection written, documented, and never wired to
    the path that needs it.

    Three consequences, all reachable from the device side, because
    iManufacturer/iProduct/iSerialNumber are chosen by the device and the
    identity rows below are not wrapped:

      * a 122-character ASCII product name -- inside sanitize()'s 126-character
        budget -- produced a 140-column row in a 64-column box;
      * a CJK name is legitimate and costs two columns per glyph, so an honest
        Chinese product name broke the box as effectively as an attack;
      * box-drawing characters are neither Cc nor Cf, so sanitize() passes them
        through untouched. A product string of spaces, "│", and the text
        "No inconsistencies found in what it claims" renders as a convincing
        extra row -- on the one screen where the admission decision is made,
        and once the terminal wraps the over-long line the device controls
        whole visual rows of it.

    pad() fits first and then pads to an exact column count, so the row is the
    right width whatever the device sent.
    """
    return f"│ {textsafe.pad(text, WIDTH - 1)}│"


def _rule(left="├", right="┤", fill="─") -> str:
    return left + fill * WIDTH + right


def _wrap(text: str, width: int) -> List[str]:
    """
    Naive word wrap. Explanations are prose and must not run off the box.

    Measured in terminal COLUMNS, not characters -- see _line. A single token
    wider than the line is split rather than emitted whole: device-supplied
    strings are reproduced inside finding explanations (dev.label() appears in
    self-contradictory-identity), they routinely contain no spaces at all, and
    `len(candidate) > width and current` let exactly those through untouched.
    """
    words, lines, current = text.split(), [], ""
    for word in words:
        for piece in textsafe.split_width(word, width):
            candidate = f"{current} {piece}".strip()
            if textsafe.display_width(candidate) > width and current:
                lines.append(current)
                current = piece
            else:
                current = candidate
    if current:
        lines.append(current)
    return lines


# Width of the "Manufacturer:  " style labels below, so the wrapped
# continuation of a long device string lines up under the value rather than
# under the label.
_LABEL_WIDTH = 15


def _field(label: str, value: Optional[str]) -> List[str]:
    """
    One "Label: value" row carrying a DEVICE-SUPPLIED string.

    The identity rows were the only ones in the report that went through no
    wrapping at all, which is what made them the device's way into the layout.

    Only the value is wrapped, never the label with it: _wrap() splits on
    whitespace, so wrapping the two together collapsed the padding that lines
    the columns up.

    The value is QUOTED, and that is a security property rather than a style
    choice. Wrapping stops the device from breaking the box; it does not stop
    it from writing a plausible sentence inside one. sanitize() passes "│"
    through untouched -- correctly, since it is a printable character and no
    list of forbidden glyphs stays complete -- so a product string can still
    read as a row of the report, and the sentence a device would pick is the
    verdict. Quotation marks answer that without guessing at characters: they
    say whose words these are, so anything between them is plainly the
    device's testimony and not Probolos's conclusion.
    """
    if value:
        rows = _wrap(f'"{value}"', WIDTH - 3 - _LABEL_WIDTH) or ['""']
    else:
        rows = ["(none reported)"]
    head = f"{label + ':':<{_LABEL_WIDTH}}"
    return ([_line(head + rows[0])]
            + [_line(" " * _LABEL_WIDTH + row) for row in rows[1:]])


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
    # Through _field, so a long or wide name wraps inside the box instead of
    # drawing outside it. These three values are the most directly
    # device-controlled text in the whole report.
    out.extend(_field("Manufacturer", dev.manufacturer))
    out.extend(_field("Product", dev.product))
    out.extend(_field("Serial", dev.serial))

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


def render_medium(medium, findings: Sequence[rules.Finding]) -> str:
    """
    Report block for stage 4: what is physically on the medium.

    Presented separately from the identity block for the same reason as the
    behaviour block -- it is independent evidence, gathered a different way,
    and a device that passes the first can fail this one.
    """
    from . import storage as storage_mod

    out: List[str] = []
    out.append("┌" + "─" * WIDTH + "┐")
    out.append(_line("WHAT IS ON THE MEDIUM (read-only, never mounted)"))
    out.append(_rule())

    if medium.error:
        out.append(_line(f"Not inspected: {medium.error}"))
    else:
        size = medium.size_sectors
        if size:
            gib = size * storage_mod.SECTOR / (1024 ** 3)
            out.append(_line(f"Capacity     : {gib:.1f} GiB ({size} sectors)"))
        out.append(_line(f"Layout       : {medium.scheme.upper()}"))

        real = [p for p in medium.partitions
                if p.type_byte != storage_mod.PROTECTIVE_MBR_TYPE]
        if not real and medium.scheme == "none":
            fs = medium.signatures.get(-1)
            out.append(_line(f"No partition table; contains {fs or 'no known'} "
                             f"filesystem"))
        for part in real:
            seen = medium.signatures.get(part.index)
            boot = " [bootable]" if part.bootable else ""
            out.append(_line(
                f"Partition {part.index + 1}  : "
                f"{storage_mod.type_name(part.type_byte)}{boot}"))
            out.append(_line(
                f"               starts at sector {part.start_lba}, "
                f"{part.sectors} sectors"))
            if seen:
                out.append(_line(f"               contains {seen}"))

    if findings:
        out.append(_rule())
        for finding in findings:
            out.extend(_finding_lines(finding))
            if finding is not findings[-1]:
                out.append(_line())

    out.append("└" + "─" * WIDTH + "┘")
    out.append("")
    out.append("  Only the partition table and filesystem signatures were")
    out.append("  read. No files were opened and nothing was mounted, so the")
    out.append("  kernel's filesystem drivers never saw this medium.")
    return "\n".join(out)
