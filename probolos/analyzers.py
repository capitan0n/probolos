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

    # Whether this analyzer's silence can be mistaken for a clean verdict.
    #
    # `run()` turns a crashing analyzer into a finding so that one broken
    # heuristic cannot stop somebody admitting their keyboard. That is right
    # for a speculative check and WRONG for the checks the admission decision
    # actually rests on: see the note on run() below. An analyzer that carries
    # verdict-bearing rules sets this, and its failure is reported at the
    # severity its absence deserves rather than as a footnote.
    decisive = False

    def analyze(self, ctx: Context) -> List[rules.Finding]:
        raise NotImplementedError


class SemanticAnalyzer(Analyzer):
    """Stages 1-2: what the device claims, and whether it is coherent."""
    id = "semantic"
    title = "identity and internal consistency"
    # Every CRITICAL identity rule lives here: the BadUSB signatures, the
    # crafted-string escalation, the self-contradiction check. If this does not
    # run, nothing else produces them.
    decisive = True

    def analyze(self, ctx):
        return rules.evaluate(ctx.device, ctx.config)


class BehaviourAnalyzer(Analyzer):
    """Stage 3: what it did while isolated."""
    id = "behaviour"
    title = "behaviour under quarantine"
    requires_observation = True
    # Holds machine-generated-keystrokes, unprompted-typing and -- the one that
    # matters most -- quarantine-not-restored, which is the only thing that
    # tells the operator the device is still live while they read the prompt.
    decisive = True

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
        # Compared against the BASELINE -- the set first seen under this
        # identity, and thereafter only one a human approved -- not against
        # `descriptor_hash`, which Ledger.record() overwrites on every decision
        # including a refusal and including the bare act of queueing a device
        # while the screen was locked. Measuring against a field the attacker's
        # own appearance had just rewritten meant the alarm fired exactly once
        # and never again, no matter how the first appearance was answered.
        #
        # The digest itself is normalized: it drops fields that vary with the
        # bus controller (bcdUSB, bMaxPower, endpoint packet sizes, SuperSpeed
        # companion descriptors), so moving the same physical stick between a
        # USB 2 and a USB 3 port is not drift. What survives is what the
        # device says it IS: VID/PID, firmware revision, interface counts,
        # and each interface's class/subclass/protocol -- the fields a BadUSB
        # reflash actually has to change to add new functionality. See
        # ledger.descriptor_fingerprint for the full field list and rationale.
        #
        # getattr with a fallback: an Entry rebuilt from a ledger written
        # before the field existed is migrated in from_raw, but a test stub or
        # a hand-built Entry may not carry it, and losing the check silently is
        # the failure mode this whole finding is about.
        baseline = getattr(entry, "baseline_hash", "") or entry.descriptor_hash
        if digest and baseline and digest != baseline:
            findings.append(rules.Finding(
                "descriptor-drift", rules.Severity.CRITICAL,
                "This device has changed what it says it is",
                "This identity has been seen before presenting a different "
                "descriptor set to the one in front of you now. Real hardware "
                "does not rewrite its own descriptors between plug-ins; a "
                "device that does has either been reflashed or is "
                "impersonating one that was here before. The comparison is "
                "against the set you last approved for this identity and is "
                "measured on what the device declares itself to be, not on "
                "how the bus enumerated it, so a mere USB 2 vs. USB 3 port "
                "change does not trip this. Refusing it -- or leaving it "
                "queued while you were away -- does not clear it either. "
                f"Previously seen {entry.times_seen} time(s), first on "
                f"{_stamp(entry.first_seen)}; "
                f"{len(entry.known_hashes) or 1} distinct identity "
                f"fingerprint(s) recorded under it."))

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
    decisive = True

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
    # impossible-partition-geometry and the overlap/past-the-end rules are the
    # only evidence about the medium the operator ever sees.
    decisive = True

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
    """
    Run every applicable analyzer, worst finding first.

    CONTAINMENT MUST NOT BECOME A FAIL-OPEN (the bug fixed here)
    ------------------------------------------------------------
    Catching an analyzer's exception and continuing is right: a crash in a
    speculative heuristic must never prevent a user from admitting their
    keyboard. But the failure was recorded as a NOTICE for EVERY analyzer,
    including SemanticAnalyzer -- which is where all of the CRITICAL identity
    rules live. So a device that crashed the rule engine produced, in full:

        NOTICE  The 'semantic' check could not run

    and nothing else. Every consumer of that verdict then read it as a clean
    device:

      * daemon._on_add admits a remembered device without asking whenever
        `rules.worst(findings) < CRITICAL`, which a NOTICE satisfies;
      * the terminal prompt drops from "type the word authorize" to a bare
        [y/N], because `critical` is False;
      * the desktop agent is offered the device as an ordinary clickable
        question, which a CRITICAL device is never supposed to be.

    That is a fail-open reachable from the device side: the descriptor blob is
    attacker-controlled and rules.evaluate() walks it. The rule engine is
    hardened and the parser is fuzzed, so this is a second line rather than a
    live hole -- but "the analyzer cannot crash" is precisely the assumption a
    security tool should not be resting a fail-open on, and the project's own
    recurring bug is protections that were written and never wired to the path
    that needs them.

    So the severity of a failure now follows what the failure COSTS. A decisive
    analyzer is one whose findings the decision rests on; its silence cannot be
    distinguished from a clean result, so its failure is itself CRITICAL and
    the operator is made to type the word. A non-decisive one (history, say)
    stays a NOTICE, because losing it degrades the report rather than the
    verdict. Either way the run continues and the keyboard can still be
    admitted -- deliberately, by a human who was told what was not checked.
    """
    findings: List[rules.Finding] = []

    for analyzer in (analyzers if analyzers is not None else DEFAULT_ANALYZERS):
        if analyzer.requires_observation and ctx.observation is None:
            continue
        try:
            findings.extend(analyzer.analyze(ctx))
        except Exception as exc:  # noqa: BLE001 - deliberate containment
            # A broken heuristic must never stop somebody admitting a keyboard,
            # so this is still a finding rather than a raise. What changed is
            # the severity: see the docstring.
            decisive = getattr(analyzer, "decisive", False)
            if decisive:
                severity = rules.Severity.CRITICAL
                explanation = (
                    f"{type(exc).__name__}: {exc}. This check is what produces "
                    f"the verdict for this stage, so its absence is NOT a clean "
                    f"result -- nothing examined this device at all here. It is "
                    f"reported as CRITICAL so that it cannot be admitted "
                    f"without a deliberate decision, and so a remembered device "
                    f"is not waved through on the strength of a check that "
                    f"never ran.")
            else:
                severity = rules.Severity.NOTICE
                explanation = (
                    f"{type(exc).__name__}: {exc}. That check contributed "
                    f"nothing to the verdict below.")
            findings.append(rules.Finding(
                f"analyzer-failed:{analyzer.id}", severity,
                f"The '{analyzer.id}' check could not run", explanation))
            ctx.extra.setdefault("tracebacks", []).append(
                traceback.format_exc())

    findings.sort(key=lambda f: f.severity, reverse=True)
    return findings


def _stamp(epoch: float) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M")
