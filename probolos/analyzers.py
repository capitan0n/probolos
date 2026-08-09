"""
The analyzer plugin layer.

Every check Probolos performs is an object with one method:

    analyze(ctx) -> List[Finding]

That contract already existed by accident -- `rules.evaluate` and
`rules.behaviour_findings` both took a device-ish thing and returned findings --
so formalising it cost almost nothing and buys the thing the project most needs:
a place to add the next nine ideas without turning the daemon into a switchboard.

Two properties are enforced here rather than trusted to each analyzer:

  * an analyzer that raises does not take the daemon down. A crash in a
    speculative heuristic must never prevent a user from admitting their
    keyboard, so exceptions become a NOTICE finding and the run continues.
  * analyzers declare what they need. One that requires a behavioural
    observation is skipped, visibly, when there is none -- rather than
    silently returning nothing, which would look like a clean result.
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass, field
from typing import Any, List, Optional, Sequence

from . import payload as payload_mod
from . import rules


@dataclass
class Context:
    """Everything an analyzer may look at."""
    device: Any
    observation: Any = None
    ledger: Any = None
    config: Optional[rules.RuleConfig] = None
    extra: dict = field(default_factory=dict)


class Analyzer:
    id = "base"
    title = "base analyzer"
    requires_observation = False

    def analyze(self, ctx: Context) -> List[rules.Finding]:
        raise NotImplementedError


class SemanticAnalyzer(Analyzer):
    """Stages 1-2: what the device claims, and whether it is coherent."""
    id = "semantic"
    title = "identity and internal consistency"

    def analyze(self, ctx):
        return rules.evaluate(ctx.device, ctx.config)


class BehaviourAnalyzer(Analyzer):
    """Stage 3: what it did while isolated."""
    id = "behaviour"
    title = "behaviour under quarantine"
    requires_observation = True

    def analyze(self, ctx):
        return rules.behaviour_findings(ctx.observation, ctx.config)


class LedgerAnalyzer(Analyzer):
    """
    Identity across time.

    A first sighting is never a finding. Devices are unknown before they are
    known, and treating novelty as suspicion would fire on every single device
    the first time the tool is ever run.
    """
    id = "ledger"
    title = "history and descriptor drift"

    def analyze(self, ctx):
        from . import ledger as ledger_mod

        if ctx.ledger is None:
            return []
        findings = []

        if ctx.ledger.load_error:
            findings.append(rules.Finding(
                "ledger-unavailable", rules.Severity.NOTICE,
                "Device history could not be read",
                f"{ctx.ledger.load_error}. This device was judged without any "
                "knowledge of how it has behaved before."))
            return findings

        entry = ctx.ledger.lookup(ctx.device)
        if entry is None:
            return []

        digest = ledger_mod.descriptor_fingerprint(ctx.device)
        if digest and digest != entry.descriptor_hash:
            findings.append(rules.Finding(
                "descriptor-drift", rules.Severity.CRITICAL,
                "This device has changed what it says it is",
                "The same claimed identity was seen before with a different "
                "descriptor set. Real hardware does not rewrite its own "
                "descriptors between plug-ins; a device that does has either "
                "been reflashed or is impersonating one that was here before. "
                f"Previously seen {entry.times_seen} time(s), first on "
                f"{_stamp(entry.first_seen)}."))

        if "user rejected" in entry.decisions:
            findings.append(rules.Finding(
                "previously-rejected", rules.Severity.WARNING,
                "You have refused this device before",
                f"This identity was rejected on a previous occasion "
                f"(seen {entry.times_seen} time(s), ports: "
                f"{', '.join(entry.ports)})."))

        return findings


class PayloadAnalyzer(Analyzer):
    """
    Stage 3b: reconstruct what the device was trying to type.

    Silent unless payload capture was explicitly enabled, and structurally
    incapable of running on a device that has ever been authorized.
    """
    id = "payload"
    title = "attempted payload"
    requires_observation = True

    def analyze(self, ctx):
        recovered = payload_mod.reconstruct_observation(ctx.observation)
        if recovered is None or not recovered.keystrokes:
            return []

        tokens = recovered.suspicious_tokens()
        detail = (f"Reconstructed {recovered.keystrokes} keystroke(s). "
                  f"Nothing reached your session.")
        if tokens:
            detail += f" Contains: {', '.join(tokens[:6])}."

        return [rules.Finding(
            "payload-captured", rules.Severity.CRITICAL,
            "The device's payload was captured in full",
            detail)]


class StorageAnalyzer(Analyzer):
    """
    Stage 4: structural inspection of the raw medium.

    Requires a MediumReport in the context, which the daemon produces only for
    storage devices and only inside the same briefly-authorized window used for
    behavioural quarantine.
    """
    id = "storage"
    title = "what the medium contains"

    def analyze(self, ctx):
        medium = ctx.extra.get("medium")
        if medium is None:
            return []
        return rules.storage_findings(medium, ctx.config)


DEFAULT_ANALYZERS: List[Analyzer] = [
    SemanticAnalyzer(),
    LedgerAnalyzer(),
    BehaviourAnalyzer(),
    PayloadAnalyzer(),
    StorageAnalyzer(),
]


def run(ctx: Context,
        analyzers: Optional[Sequence[Analyzer]] = None
        ) -> List[rules.Finding]:
    """Run every applicable analyzer, worst finding first."""
    findings: List[rules.Finding] = []

    for analyzer in (analyzers if analyzers is not None else DEFAULT_ANALYZERS):
        if analyzer.requires_observation and ctx.observation is None:
            continue
        try:
            findings.extend(analyzer.analyze(ctx))
        except Exception as exc:  # noqa: BLE001 - deliberate containment
            # A broken heuristic must never stop somebody admitting a keyboard.
            findings.append(rules.Finding(
                f"analyzer-failed:{analyzer.id}", rules.Severity.NOTICE,
                f"The '{analyzer.id}' check could not run",
                f"{type(exc).__name__}: {exc}. That check contributed nothing "
                "to the verdict below."))
            ctx.extra.setdefault("tracebacks", []).append(
                traceback.format_exc())

    findings.sort(key=lambda f: f.severity, reverse=True)
    return findings


def _stamp(epoch: float) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M")
