"""Multi-layer Prompt Injection & Untrusted Context Poisoning Detector."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from agentshield.models import (
    EvaluationVerdict,
    OWASPCategory,
    PolicyDecision,
    RiskLevel,
    SecurityFinding,
)


@dataclass(frozen=True)
class _InjectionSignature:
    rule_id: str
    title: str
    category: OWASPCategory
    risk_level: RiskLevel
    pattern: re.Pattern[str]
    description: str
    remediation: str


_SIGNATURES: tuple[_InjectionSignature, ...] = (
    _InjectionSignature(
        rule_id="PI-001",
        title="Direct System Instruction Override",
        category=OWASPCategory.LLM01_PROMPT_INJECTION,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(
            r"(?i)\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(previous|prior|above|all|system|developer|original|safety)\b.{0,30}\b(instructions?|prompts?|rules?|directives?|guardrails?|constraints?)\b"
        ),
        description="Input attempts to nullify or override prior system/developer instructions.",
        remediation="Reject prompt override directives and enforce strict system/user role separation.",
    ),
    _InjectionSignature(
        rule_id="PI-002",
        title="System Prompt Exfiltration Attempt",
        category=OWASPCategory.LLM07_SYSTEM_PROMPT_LEAKAGE,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(
            r"(?i)\b(reveal|print|output|repeat|show|dump|display|verbatim)\b.{0,45}\b(system\s+prompt|developer\s+message|hidden\s+instructions?|initial\s+instructions?|system\s+instructions?|exact\s+instructions?)\b"
        ),
        description="Input probes for verbatim disclosure of confidential system instructions or tool schemas.",
        remediation="Block system prompt introspection requests and strip internal prompt headers from output.",
    ),
    _InjectionSignature(
        rule_id="PI-003",
        title="Adversarial Roleplay / Jailbreak Framing",
        category=OWASPCategory.LLM01_PROMPT_INJECTION,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(
            r"(?i)(\b(you\s+are\s+now\s+in\s+(developer|god|unrestricted|dan|jailbreak|sudo)\s+mode)\b|\b(act\s+as\s+an?\s+unrestricted|do\s+anything\s+now|without\s+any\s+(safety|ethical|policy)\s+(restrictions?|filters?|limits?))\b)"
        ),
        description="Input uses persona adoption, DAN framing, or unrestricted mode commands to bypass guardrails.",
        remediation="Enforce immutable agent identity and reject privilege mode toggles in user input.",
    ),
    _InjectionSignature(
        rule_id="PI-004",
        title="Synthetic Role / Delimiter Spoofing",
        category=OWASPCategory.LLM01_PROMPT_INJECTION,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(
            r"(?i)(<\|im_start\|>\s*system|<\|system\|>|\[SYSTEM\s*INSTRUCTION\]|###\s*(SYSTEM|INSTRUCTION)\s*OVERRIDE|</?(system_prompt|developer_instruction)>)"
        ),
        description="Input injects special chat-template control tokens or pseudo-system XML/Markdown delimiters.",
        remediation="Sanitize chat template control tokens before model tokenization.",
    ),
    _InjectionSignature(
        rule_id="PI-005",
        title="Indirect Context / Retrieved Document Poisoning",
        category=OWASPCategory.LLM08_CONTEXT_POISONING,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(
            r"(?i)(<!--[\s\S]{0,300}?(ignore|execute|call\s+tool|send\s+to|exfiltrate|system)[\s\S]{0,300}?-->|\[HIDDEN\s+AI\s+INSTRUCTION\]|IMPORTANT\s+NOTE\s+TO\s+(AI|ASSISTANT|AGENT)\s*:|AI\s+ASSISTANT\s+MUST\s+IMMEDIATELY)"
        ),
        description="Untrusted document or HTML comment embeds covert instructions targeting the autonomous agent.",
        remediation="Isolate untrusted retrieved data in non-executable data envelopes and block tool calls triggered by external context.",
    ),
    _InjectionSignature(
        rule_id="PI-006",
        title="Covert Tool Invocation / Data Exfiltration Directive",
        category=OWASPCategory.ASI02_TOOL_MISUSE,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(
            r"(?i)\b(silently|secretly|without\s+telling\s+the\s+user|automatically\s+invoke|call\s+the\s+tool)\b.{0,80}\b(webhook|http|curl|fetch|send_email|bash|exec|exfiltrate|attacker|external\s+server)\b"
        ),
        description="Input instructs the agent to invoke external tools or transmit data without user awareness.",
        remediation="Require explicit human-in-the-loop approval for external network or state-mutating tool calls.",
    ),
    _InjectionSignature(
        rule_id="PI-007",
        title="Resource Exhaustion / Token Bomb Directive",
        category=OWASPCategory.LLM10_UNBOUNDED_CONSUMPTION,
        risk_level=RiskLevel.MEDIUM,
        pattern=re.compile(
            r"(?i)\b(repeat\s+the\s+(word|phrase|character)\s+.{1,30}\s+(forever|infinitely|10000\s+times|million\s+times)|recursive(ly)?\s+call\s+yourself\s+in\s+an?\s+infinite\s+loop)\b"
        ),
        description="Input attempts to trigger unbounded token generation or recursive agent loops.",
        remediation="Apply strict output token budgets and maximum agent iteration limits.",
    ),
)

_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")
_BASE64_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_CANDIDATE_RE = re.compile(r"\b(?:[0-9a-fA-F]{32,})\b")


class PromptInjectionDetector:
    """Multi-layer heuristic and structural detector for direct and indirect prompt injections."""

    def __init__(self, max_input_length: int = 32_000) -> None:
        self.max_input_length = max_input_length

    def evaluate(
        self,
        text: str,
        *,
        source: str = "direct_user",
    ) -> EvaluationVerdict:
        """Analyze input text for prompt injection, context poisoning, and obfuscated payloads."""
        findings: list[SecurityFinding] = []

        if len(text) > self.max_input_length:
            findings.append(
                SecurityFinding(
                    detector="PromptInjectionDetector",
                    category=OWASPCategory.LLM10_UNBOUNDED_CONSUMPTION,
                    risk_level=RiskLevel.HIGH,
                    title="Input Exceeds Maximum Context Budget",
                    description=(
                        f"Input length ({len(text)} chars) exceeds configured maximum "
                        f"({self.max_input_length} chars)."
                    ),
                    matched_evidence=f"length={len(text)}",
                    remediation="Truncate or reject oversized payloads before LLM ingestion.",
                )
            )

        # 1. Detect zero-width character steganography / obfuscation
        zw_matches = _ZERO_WIDTH_RE.findall(text)
        normalized_text = _ZERO_WIDTH_RE.sub("", text)
        if len(zw_matches) >= 3:
            findings.append(
                SecurityFinding(
                    detector="PromptInjectionDetector",
                    category=OWASPCategory.LLM01_PROMPT_INJECTION,
                    risk_level=RiskLevel.HIGH,
                    title="Zero-Width Character Obfuscation Detected",
                    description=(
                        f"Input contains {len(zw_matches)} invisible zero-width Unicode characters "
                        "commonly used to bypass keyword filters."
                    ),
                    matched_evidence=f"zero_width_count={len(zw_matches)}",
                    remediation="Strip invisible Unicode format characters before evaluation and inference.",
                )
            )

        # 2. Scan both original and de-obfuscated text against signatures
        for sig in _SIGNATURES:
            match = sig.pattern.search(normalized_text)
            if match:
                category = sig.category
                if source != "direct_user" and sig.category == OWASPCategory.LLM01_PROMPT_INJECTION:
                    category = OWASPCategory.LLM08_CONTEXT_POISONING
                findings.append(
                    SecurityFinding(
                        detector=f"PromptInjectionDetector[{sig.rule_id}]",
                        category=category,
                        risk_level=sig.risk_level,
                        title=sig.title,
                        description=sig.description,
                        matched_evidence=match.group(0)[:120],
                        remediation=sig.remediation,
                    )
                )

        # 3. Inspect Base64 and Hex encoded segments for hidden instructions
        for decoded_source, decoded_text in self._extract_decoded_payloads(normalized_text):
            for sig in _SIGNATURES:
                match = sig.pattern.search(decoded_text)
                if match:
                    findings.append(
                        SecurityFinding(
                            detector=f"PromptInjectionDetector[{sig.rule_id}:Encoded]",
                            category=OWASPCategory.LLM01_PROMPT_INJECTION,
                            risk_level=RiskLevel.CRITICAL,
                            title=f"Encoded Payload Injection ({decoded_source})",
                            description=(
                                f"Decoded {decoded_source} payload contains a hidden prompt injection "
                                f"matching '{sig.title}'."
                            ),
                            matched_evidence=match.group(0)[:120],
                            remediation="Decode and inspect Base64/Hex blobs prior to passing input to the model.",
                        )
                    )

        if not findings:
            return EvaluationVerdict(
                allowed=True,
                decision=PolicyDecision.ALLOW,
                risk_level=RiskLevel.NONE,
                risk_score=0,
                findings=[],
                sanitized_content=normalized_text,
            )

        highest_risk = max(findings, key=lambda f: f.risk_level.score).risk_level
        risk_score = min(100, max(f.risk_level.score for f in findings) + (len(findings) - 1) * 10)
        decision = (
            PolicyDecision.DENY
            if highest_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL, RiskLevel.MEDIUM)
            else PolicyDecision.ALLOW
        )

        return EvaluationVerdict(
            allowed=(decision == PolicyDecision.ALLOW),
            decision=decision,
            risk_level=highest_risk,
            risk_score=risk_score,
            findings=findings,
            sanitized_content=normalized_text if decision == PolicyDecision.ALLOW else None,
        )

    @staticmethod
    def _extract_decoded_payloads(text: str) -> list[tuple[str, str]]:
        decoded_list: list[tuple[str, str]] = []
        for candidate in _BASE64_CANDIDATE_RE.findall(text):
            try:
                raw = base64.b64decode(candidate, validate=True)
                decoded = raw.decode("utf-8")
                if decoded.isprintable():
                    decoded_list.append(("Base64", decoded))
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue

        for candidate in _HEX_CANDIDATE_RE.findall(text):
            if len(candidate) % 2 != 0:
                continue
            try:
                raw = bytes.fromhex(candidate)
                decoded = raw.decode("utf-8")
                if decoded.isprintable():
                    decoded_list.append(("Hex", decoded))
            except (ValueError, UnicodeDecodeError):
                continue

        return decoded_list
