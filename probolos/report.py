"""
Minimal renderer -- no boxes, indent-based hierarchy, color for severity.

Same public API as report.py: render(), render_behaviour(), render_medium(),
one_liner(). Callers replace `from . import report` with `from . import report1
as report` to try it. Every rule, every finding, every severity, and the whole
data flow are the ones report.py already builds -- only the DISPLAY changes.

Design rules for this variant:
  * no ASCII borders. Section breaks are one blank line and one header line.
  * one label, one value, one line where possible. Wrapping still happens on
    long device strings and on finding explanations.
  * device-supplied text is quoted so a name that reads like a verdict is
    plainly the device's testimony, not Probolos's.
  * severity is color + one word + one symbol, not a sentence.
  * VID/PID/serial appear once, at the bottom of identity, as reference.
"""

from __future__ import annotations

import os
import sys
from typing import List, Optional, Sequence

from . import rules, sysfs, textsafe, usbclass

# --------------------------------------------------------------------------
# Color -- ANSI, only when stdout is a TTY and NO_COLOR is not set.
#
# Piping the report into a file or a pager should not fill it with escape
# codes; a machine that ignores NO_COLOR is a machine whose users learn to
# turn colour off with `| cat`. Detection is done ONCE at import time and
# cached, because writing findings to a log later must not depend on whatever
# stream the caller is currently on.
# --------------------------------------------------------------------------
def _colour_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


_USE_COLOUR = _colour_enabled()


def _c(code: str, text: str) -> str:
    if not _USE_COLOUR:
        return text
    return f"\033[{code}m{text}\033[0m"


def _bold(text): return _c("1", text)
def _dim(text): return _c("2", text)
def _red(text): return _c("1;31", text)
def _yellow(text): return _c("33", text)
def _cyan(text): return _c("36", text)
def _green(text): return _c("32", text)


# One symbol + one colour per severity. Severity words come from rules.py
# unchanged, so a log parser reading "CRITICAL" still finds it.
_SEVERITY_STYLE = {
    rules.Severity.CRITICAL: ("✖", _red),
    rules.Severity.WARNING:  ("⚠", _yellow),
    rules.Severity.NOTICE:   ("•", _cyan),
    rules.Severity.INFO:     ("✓", _green),
}

# Width of the terminal we target for wrapping. 62 keeps parity with
# report.py's box interior, so a fresh eye can compare the two directly.
WIDTH = 62
INDENT = "  "


def _wrap(text: str, width: int, indent: str = "") -> List[str]:
    """Column-aware word wrap. See report.py for the same helper's rationale."""
    words, lines, current = text.split(), [], ""
    for word in words:
        for piece in textsafe.split_width(word, width):
            candidate = f"{current} {piece}".strip()
            if textsafe.display_width(candidate) > width and current:
                lines.append(indent + current)
                current = piece
            else:
                current = candidate
    if current:
        lines.append(indent + current)
    return lines


def _quote(value: Optional[str]) -> str:
    """Device-supplied text in quotes so it reads as testimony, not verdict."""
    return f'"{value}"' if value else "—"


def render(dev: sysfs.UsbDevice,
           findings: Optional[Sequence[rules.Finding]] = None) -> str:
    findings = list(findings or [])
    verdict = rules.worst(findings)
    out: List[str] = []

    # --- header: two words, then a rule of dashes as a soft separator ------
    out.append("")
    out.append(_bold("NEW USB DEVICE") + _dim(" · blocked, awaiting decision"))
    out.append(_dim("─" * WIDTH))

    # --- what it claims to be, top-level identity, and reference number ---
    claims = dev.claims
    if claims:
        # First claim on the same visual level as the header, further claims
        # indented, so a composite device (BadUSB) reads at a glance.
        out.append(INDENT + _bold(claims[0]))
        for claim in claims[1:]:
            out.append(INDENT + "+ " + _bold(claim))
    elif dev.parse_error:
        out.append(INDENT + _bold("UNKNOWN") + _dim(f" — {dev.parse_error}"))
    else:
        cls = dev.device_class if dev.device_class is not None else 0
        out.append(INDENT + _bold(usbclass.class_name(cls)))

    # Manufacturer/product on ONE line -- the two are read together. Serial
    # gets its own line because it is long and forensic rather than
    # descriptive.
    mp = f"{_quote(dev.manufacturer)}  {_quote(dev.product)}"
    for row in _wrap(mp, WIDTH - len(INDENT)):
        out.append(INDENT + row)
    if dev.serial:
        out.append(INDENT + _dim("serial ") + _quote(dev.serial))

    # Facts on one dim line -- VID/PID, port, speed, power -- so the eye
    # jumps over them unless it wants them.
    port = f"port {dev.name}" if dev.bus is None else f"bus {dev.bus} port {dev.name}"
    parts = [f"{dev.vendor_id}:{dev.product_id}", port,
             f"{dev.speed or '?'} Mbps"]
    if dev.descriptor_set and dev.descriptor_set.configs:
        cfg0 = dev.descriptor_set.configs[0]
        source = "self-powered" if cfg0.self_powered else "bus-powered"
        parts.append(f"{cfg0.max_power_ma} mA {source}")
    out.append(INDENT + _dim(" · ".join(parts)))

    # --- findings, most severe first (the caller already sorted them) ------
    if not findings:
        out.append("")
        out.append(INDENT + _green("✓ no inconsistencies in what it claims"))
    else:
        for finding in findings:
            out.append("")
            symbol, colour = _SEVERITY_STYLE[finding.severity]
            head = f"{symbol} {finding.severity.label} · {finding.title}"
            for i, chunk in enumerate(_wrap(head, WIDTH - len(INDENT))):
                out.append(INDENT + (colour(chunk) if i == 0 else chunk))
            for chunk in _wrap(finding.explanation,
                               WIDTH - len(INDENT) - 4):
                out.append(INDENT + "    " + _dim(chunk))

    out.append(_dim("─" * WIDTH))
    out.append(_dim(INDENT + "checked: identity + consistency. "
                    "Stages 3 & 4 follow."))
    return "\n".join(out)


def one_liner(dev: sysfs.UsbDevice,
              findings: Optional[Sequence[rules.Finding]] = None) -> str:
    claims = ", ".join(dev.claims) or "unknown"
    text = (f"{dev.vendor_id}:{dev.product_id} [{claims}] "
            f"'{dev.label()}' at {dev.name}")
    if findings:
        text += f"  <{rules.worst(findings).label}: {len(findings)} finding(s)>"
    return text


def render_behaviour(obs, findings: Sequence[rules.Finding]) -> str:
    out: List[str] = []
    out.append("")
    out.append(_bold("BEHAVIOUR UNDER QUARANTINE"))
    out.append(_dim("─" * WIDTH))

    if obs.error:
        out.append(INDENT + _dim(f"not observed: {obs.error}"))
    else:
        nodes = len(obs.grabbed)
        out.append(INDENT +
                   f"isolated {_bold(str(nodes))} input channel(s) for "
                   f"{obs.duration:.0f}s")
        out.append(INDENT +
                   f"keystrokes captured: {_bold(str(len(obs.key_presses)))}")
        if obs.button_presses:
            out.append(INDENT + _dim(
                f"button presses: {obs.button_presses} (normal for a mouse)"))
        if obs.motion_events:
            out.append(INDENT + _dim(
                f"motion events: {obs.motion_events} (normal for a mouse)"))
        note = rules.race_window_note(obs)
        if note:
            for line in _wrap(f"exposure gap: {note}",
                              WIDTH - len(INDENT)):
                out.append(INDENT + _dim(line))

    for finding in findings:
        out.append("")
        symbol, colour = _SEVERITY_STYLE[finding.severity]
        head = f"{symbol} {finding.severity.label} · {finding.title}"
        for i, chunk in enumerate(_wrap(head, WIDTH - len(INDENT))):
            out.append(INDENT + (colour(chunk) if i == 0 else chunk))
        for chunk in _wrap(finding.explanation, WIDTH - len(INDENT) - 4):
            out.append(INDENT + "    " + _dim(chunk))

    out.append(_dim("─" * WIDTH))
    return "\n".join(out)


def render_medium(medium, findings: Sequence[rules.Finding]) -> str:
    from . import storage as storage_mod

    out: List[str] = []
    out.append("")
    out.append(_bold("MEDIUM") + _dim(" · read-only, never mounted"))
    out.append(_dim("─" * WIDTH))

    if medium.error:
        out.append(INDENT + _dim(f"not inspected: {medium.error}"))
    else:
        size = medium.size_sectors
        if size:
            gib = size * storage_mod.SECTOR / (1024 ** 3)
            out.append(INDENT + f"capacity: {_bold(f'{gib:.1f} GiB')} "
                       + _dim(f"({size} sectors)"))
        out.append(INDENT + f"layout:   {_bold(medium.scheme.upper())}")

        real = [p for p in medium.partitions
                if p.type_byte != storage_mod.PROTECTIVE_MBR_TYPE]
        if not real and medium.scheme == "none":
            fs = medium.signatures.get(-1)
            if fs:
                out.append(INDENT + _dim(f"whole-device {fs} filesystem "
                                         f"(no partition table)"))
            else:
                out.append(INDENT + _dim("no partition table; "
                                         "contains no known filesystem"))
        for part in real:
            seen = medium.signatures.get(part.index)
            boot = " · bootable" if part.bootable else ""
            type_desc = (f"{storage_mod.type_name(part.type_byte)} "
                         f"(0x{part.type_byte:02X})")
            out.append("")
            out.append(INDENT + _bold(f"partition {part.index + 1}") +
                       f"  {type_desc}" + _dim(boot))
            out.append(INDENT + _dim(
                f"    start sector {part.start_lba} · {part.sectors} sectors"))
            if seen:
                out.append(INDENT + _dim(f"    contains: {seen}"))

    for finding in findings:
        out.append("")
        symbol, colour = _SEVERITY_STYLE[finding.severity]
        head = f"{symbol} {finding.severity.label} · {finding.title}"
        for i, chunk in enumerate(_wrap(head, WIDTH - len(INDENT))):
            out.append(INDENT + (colour(chunk) if i == 0 else chunk))
        for chunk in _wrap(finding.explanation, WIDTH - len(INDENT) - 4):
            out.append(INDENT + "    " + _dim(chunk))

    out.append(_dim("─" * WIDTH))
    return "\n".join(out)
