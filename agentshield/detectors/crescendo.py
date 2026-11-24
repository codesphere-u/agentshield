"""Multi-turn crescendo jailbreak escalation state tracker."""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass

from agentshield.detectors.prompt_injection import PromptInjectionDetector
from agentshield.models import (
    EvaluationVerdict,
    OWASPCategory,
    PolicyDecision,
    RiskLevel,
    SecurityFinding,
)


@dataclass(frozen=True)
class _EscalationCue:
    cue_id: str
    title: str
    weight: float
    pattern: re.Pattern[str]


_ESCALATION_CUES: tuple[_EscalationCue, ...] = (
    _EscalationCue(
        cue_id="CRESC-HYP",
        title="Hypothetical / Fiction Framing Probe",
        weight=18.0,
        pattern=re.compile(
            r"(?i)\b(purely\s+hypothetical|for\s+a\s+(novel|fictional\s+story|movie\s+script|cybersecurity\s+textbook)|in\s+an?\s+alternate\s+universe|thought\s+experiment)\b"
        ),
    ),
    _EscalationCue(
        cue_id="CRESC-AUTH",
        title="Authority / Compliance Exception Claim",
        weight=22.0,
        pattern=re.compile(
            r"(?i)\b(i\s+am\s+(the\s+admin|an?\s+authorized\s+pentester|your\s+developer)|authorized\s+red[- ]team|for\s+internal\s+audit\s+only|you\s+have\s+permission\s+to\s+skip)\b"
        ),
    ),
    _EscalationCue(
        cue_id="CRESC-STEP",
        title="Incremental Boundary Push",
        weight=24.0,
        pattern=re.compile(
            r"(?i)\b(now\s+be\s+more\s+specific|give\s+me\s+the\s+exact\s+(payload|exploit|command|steps|credentials)|drop\s+the\s+(disclaimers?|warnings?|hedging)|continue\s+from\s+where\s+you\s+stopped\s+without\s+filters?)\b"
        ),
    ),
    _EscalationCue(
        cue_id="CRESC-META",
        title="Guardrail & Policy Probing",
        weight=20.0,
        pattern=re.compile(
            r"(?i)\b(what\s+are\s+your\s+(exact\s+)?restrictions|how\s+could\s+someone\s+bypass|which\s+phrases\s+trigger\s+your\s+filter|summarize\s+your\s+hidden\s+rules)\b"
        ),
    ),
)


@dataclass(frozen=True)
class TurnRiskRecord:
    """Recorded risk telemetry for a single conversation turn."""

    turn_index: int
    turn_score: float
    cumulative_score: float
    matched_cues: tuple[str, ...]
    single_turn_blocked: bool


class ConversationRiskTracker:
    """Session-level rolling risk accumulator detecting multi-turn crescendo jailbreaks.

    Combines single-turn `PromptInjectionDetector` analysis with soft escalation-cue scoring,
    exponential score decay across benign turns, and consecutive-escalation streak detection.
    """

    def __init__(
        self,
        *,
        detector: PromptInjectionDetector | None = None,
        window_size: int = 10,
        decay_factor: float = 0.85,
        block_threshold: float = 70.0,
        min_escalation_streak: int = 3,
    ) -> None:
        if window_size < 2:
            raise ValueError("window_size must be at least 2")
        if not 0.0 < decay_factor <= 1.0:
            raise ValueError("decay_factor must be in (0.0, 1.0]")
        if not 1.0 <= block_threshold <= 100.0:
            raise ValueError("block_threshold must be in [1.0, 100.0]")

        self.detector = detector or PromptInjectionDetector()
        self.window_size = window_size
        self.decay_factor = decay_factor
        self.block_threshold = block_threshold
        self.min_escalation_streak = min_escalation_streak
        self._sessions: dict[str, deque[TurnRiskRecord]] = {}
        self._cumulative: dict[str, float] = {}
        self._turn_counts: dict[str, int] = {}

    def evaluate_turn(
        self,
        session_id: str,
        text: str,
        *,
        source: str = "direct_user",
    ) -> EvaluationVerdict:
        """Evaluate a single turn in context of prior session history and return a verdict."""
        base_verdict = self.detector.evaluate(text, source=source)
        matched_cues: list[str] = []
        cue_score = 0.0

        for cue in _ESCALATION_CUES:
            if cue.pattern.search(text):
                matched_cues.append(cue.cue_id)
                cue_score += cue.weight

        turn_score = min(100.0, float(base_verdict.risk_score) + cue_score)
        prev_cumulative = self._cumulative.get(session_id, 0.0)
        decayed = prev_cumulative * self.decay_factor
        new_cumulative = min(100.0, round(decayed + turn_score, 2))

        turn_idx = self._turn_counts.get(session_id, 0) + 1
        self._turn_counts[session_id] = turn_idx
        self._cumulative[session_id] = new_cumulative

        history = self._sessions.setdefault(session_id, deque(maxlen=self.window_size))
        history.append(
            TurnRiskRecord(
                turn_index=turn_idx,
                turn_score=round(turn_score, 2),
                cumulative_score=new_cumulative,
                matched_cues=tuple(matched_cues),
                single_turn_blocked=not base_verdict.allowed,
            )
        )

        findings = list(base_verdict.findings)
        is_crescendo_streak = self._has_escalation_streak(history)

        if new_cumulative >= self.block_threshold:
            findings.append(
                SecurityFinding(
                    detector="ConversationRiskTracker[CRESCENDO-001]",
                    category=OWASPCategory.LLM01_PROMPT_INJECTION,
                    risk_level=RiskLevel.HIGH,
                    title="Multi-Turn Crescendo Risk Threshold Exceeded",
                    description=(
                        f"Rolling decayed session risk reached {new_cumulative:.1f}/100 "
                        f"(threshold={self.block_threshold:.1f}) over {len(history)} tracked turns."
                    ),
                    matched_evidence=f"session={session_id} cumulative={new_cumulative:.1f} cues={matched_cues}",
                    remediation="Terminate or reset the conversation context and require human review.",
                )
            )
        elif is_crescendo_streak:
            findings.append(
                SecurityFinding(
                    detector="ConversationRiskTracker[CRESCENDO-002]",
                    category=OWASPCategory.LLM01_PROMPT_INJECTION,
                    risk_level=RiskLevel.HIGH,
                    title="Sustained Multi-Turn Escalation Pattern Detected",
                    description=(
                        f"Session '{session_id}' exhibited {self.min_escalation_streak} consecutive "
                        "risk-bearing escalation turns indicative of a crescendo jailbreak."
                    ),
                    matched_evidence=f"session={session_id} streak={self.min_escalation_streak} cumulative={new_cumulative:.1f}",
                    remediation="Tighten policy enforcement and block sensitive tool execution for this session.",
                )
            )

        if not findings:
            return EvaluationVerdict(
                allowed=True,
                decision=PolicyDecision.ALLOW,
                risk_level=RiskLevel.LOW if new_cumulative >= 20.0 else RiskLevel.NONE,
                risk_score=round(new_cumulative),
                findings=[],
            )

        highest_risk = max(findings, key=lambda f: f.risk_level.score).risk_level
        blocked = (
            not base_verdict.allowed
            or new_cumulative >= self.block_threshold
            or is_crescendo_streak
        )
        return EvaluationVerdict(
            allowed=not blocked,
            decision=PolicyDecision.DENY if blocked else PolicyDecision.ALLOW,
            risk_level=highest_risk,
            risk_score=max(base_verdict.risk_score, round(new_cumulative)),
            findings=findings,
        )

    def _has_escalation_streak(self, history: deque[TurnRiskRecord]) -> bool:
        if len(history) < self.min_escalation_streak:
            return False
        recent = list(history)[-self.min_escalation_streak :]
        if any(rec.turn_score <= 0.0 for rec in recent):
            return False
        return all(
            recent[i].cumulative_score > recent[i - 1].cumulative_score
            for i in range(1, len(recent))
        ) and recent[-1].cumulative_score >= self.block_threshold * 0.65

    def session_summary(self, session_id: str) -> dict[str, object]:
        """Return rolling risk metrics for a tracked session."""
        history = list(self._sessions.get(session_id, ()))
        return {
            "session_id": session_id,
            "turns_tracked": len(history),
            "cumulative_risk": self._cumulative.get(session_id, 0.0),
            "blocked_turns": sum(1 for r in history if r.single_turn_blocked),
        }

    def reset_session(self, session_id: str) -> None:
        """Clear accumulated risk state for a session."""
        self._sessions.pop(session_id, None)
        self._cumulative.pop(session_id, None)
        self._turn_counts.pop(session_id, None)
