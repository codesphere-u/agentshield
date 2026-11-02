"""Egress & Output Firewall for Sensitive Information Disclosure and Improper Output Handling."""

from __future__ import annotations

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
class _LeakageRule:
    rule_id: str
    title: str
    category: OWASPCategory
    risk_level: RiskLevel
    pattern: re.Pattern[str]
    replacement: str
    description: str


_LEAKAGE_RULES: tuple[_LeakageRule, ...] = (
    _LeakageRule(
        rule_id="DL-001",
        title="OpenAI / Anthropic / Live API Secret Key",
        category=OWASPCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"\b(?:sk-(?:proj-|ant-|live-)?[A-Za-z0-9_\-]{20,})\b"),
        replacement="[REDACTED_API_KEY]",
        description="Detected an API secret key with 'sk-' prefix in agent output.",
    ),
    _LeakageRule(
        rule_id="DL-002",
        title="GitHub Personal Access or OAuth Token",
        category=OWASPCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{28,}\b|github_pat_[A-Za-z0-9_]{30,}\b"),
        replacement="[REDACTED_GITHUB_TOKEN]",
        description="Detected a GitHub access token in agent output.",
    ),
    _LeakageRule(
        rule_id="DL-003",
        title="AWS Access Key ID",
        category=OWASPCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        replacement="[REDACTED_AWS_KEY]",
        description="Detected an AWS IAM access key identifier.",
    ),
    _LeakageRule(
        rule_id="DL-004",
        title="Google Cloud API Key",
        category=OWASPCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        replacement="[REDACTED_GCP_API_KEY]",
        description="Detected a Google Cloud API key.",
    ),
    _LeakageRule(
        rule_id="DL-005",
        title="Cryptographic Private Key Block",
        category=OWASPCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(
            r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"
        ),
        replacement="[REDACTED_PRIVATE_KEY]",
        description="Detected a PEM/OpenSSH private key block in output.",
    ),
    _LeakageRule(
        rule_id="DL-006",
        title="JSON Web Token (JWT) Bearer Credential",
        category=OWASPCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        replacement="[REDACTED_JWT]",
        description="Detected a signed JSON Web Token in output.",
    ),
    _LeakageRule(
        rule_id="DL-007",
        title="Database Connection URI with Embedded Credentials",
        category=OWASPCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
        risk_level=RiskLevel.CRITICAL,
        pattern=re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^:\s/]+:[^@\s/]+@[^\s\"']+"
        ),
        replacement="[REDACTED_DB_URI]",
        description="Detected a database connection string containing inline credentials.",
    ),
    _LeakageRule(
        rule_id="DL-008",
        title="US Social Security Number (SSN)",
        category=OWASPCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        replacement="[REDACTED_SSN]",
        description="Detected a formatted US Social Security Number.",
    ),
    _LeakageRule(
        rule_id="DL-009",
        title="Unsafe Executable HTML / XSS Payload in Output",
        category=OWASPCategory.LLM05_IMPROPER_OUTPUT_HANDLING,
        risk_level=RiskLevel.HIGH,
        pattern=re.compile(
            r"(?i)(<\s*script\b[^>]*>[\s\S]*?<\s*/\s*script\s*>|javascript\s*:\s*[a-zA-Z0-9_]+\s*\(|<\s*img\b[^>]*\bonerror\s*=)"
        ),
        replacement="[REDACTED_UNSAFE_MARKUP]",
        description="Agent output contains executable script markup or inline event handlers.",
    ),
)

_CREDIT_CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def _passes_luhn(digits: str) -> bool:
    if len(digits) < 13 or len(digits) > 19 or len(set(digits)) == 1:
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = ord(ch) - 48
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


class DataLeakageDetector:
    """Scans and redacts secrets, PII, canary tokens, and unsafe markup in agent outputs."""

    def __init__(self, canary_tokens: list[str] | None = None) -> None:
        self.canary_tokens = [t for t in (canary_tokens or []) if t]

    def scan(self, text: str, *, redact_on_match: bool = True) -> EvaluationVerdict:
        """Scan text for sensitive credentials, PII, canary tokens, and unsafe output."""
        findings: list[SecurityFinding] = []
        sanitized = text

        for rule in _LEAKAGE_RULES:
            matches = list(rule.pattern.finditer(sanitized))
            if matches:
                sample = matches[0].group(0)
                masked_sample = (
                    sample[:6] + "..." + sample[-4:] if len(sample) > 12 else "[MATCHED]"
                )
                findings.append(
                    SecurityFinding(
                        detector=f"DataLeakageDetector[{rule.rule_id}]",
                        category=rule.category,
                        risk_level=rule.risk_level,
                        title=rule.title,
                        description=rule.description,
                        matched_evidence=masked_sample,
                        remediation="Redact sensitive credentials and prevent raw secret injection into agent context.",
                    )
                )
                if redact_on_match:
                    sanitized = rule.pattern.sub(rule.replacement, sanitized)

        # Credit card check with Luhn validation
        for match in list(_CREDIT_CARD_CANDIDATE_RE.finditer(sanitized)):
            raw_cc = match.group(0)
            digits_only = re.sub(r"\D", "", raw_cc)
            if _passes_luhn(digits_only):
                findings.append(
                    SecurityFinding(
                        detector="DataLeakageDetector[DL-010]",
                        category=OWASPCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
                        risk_level=RiskLevel.HIGH,
                        title="Payment Card Number (Luhn Validated)",
                        description="Detected a payment card number passing Luhn checksum validation.",
                        matched_evidence=f"****-****-****-{digits_only[-4:]}",
                        remediation="Mask PAN data before returning responses to downstream clients.",
                    )
                )
                if redact_on_match:
                    sanitized = sanitized.replace(raw_cc, "[REDACTED_CREDIT_CARD]")

        # Canary token detection (System Prompt / Context Leakage detection)
        for token in self.canary_tokens:
            if token in sanitized:
                findings.append(
                    SecurityFinding(
                        detector="DataLeakageDetector[DL-CANARY]",
                        category=OWASPCategory.LLM07_SYSTEM_PROMPT_LEAKAGE,
                        risk_level=RiskLevel.CRITICAL,
                        title="System Canary Token Exfiltration",
                        description="Output contains a protected canary token from the system prompt or confidential store.",
                        matched_evidence=f"canary:{token[:6]}***",
                        remediation="Terminate session and rotate exposed system instructions.",
                    )
                )
                if redact_on_match:
                    sanitized = sanitized.replace(token, "[REDACTED_CANARY_TOKEN]")

        if not findings:
            return EvaluationVerdict(
                allowed=True,
                decision=PolicyDecision.ALLOW,
                risk_level=RiskLevel.NONE,
                risk_score=0,
                findings=[],
                sanitized_content=text,
            )

        highest_risk = max(findings, key=lambda f: f.risk_level.score).risk_level
        risk_score = min(100, max(f.risk_level.score for f in findings) + (len(findings) - 1) * 10)
        decision = PolicyDecision.REDACT if redact_on_match else PolicyDecision.DENY

        return EvaluationVerdict(
            allowed=False,
            decision=decision,
            risk_level=highest_risk,
            risk_score=risk_score,
            findings=findings,
            sanitized_content=sanitized,
        )
