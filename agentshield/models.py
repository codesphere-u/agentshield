"""Strongly typed Pydantic v2 models for AgentShield security evaluations, policies, and audit trails."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class RiskLevel(str, Enum):
    """Severity classification for security findings and actions."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> int:
        mapping = {
            RiskLevel.NONE: 0,
            RiskLevel.LOW: 25,
            RiskLevel.MEDIUM: 50,
            RiskLevel.HIGH: 75,
            RiskLevel.CRITICAL: 100,
        }
        return mapping[self]


class PolicyDecision(str, Enum):
    """Enforcement decision returned by AgentShield detectors and policy rules."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    REDACT = "redact"


class OWASPCategory(str, Enum):
    """OWASP 2026 Top 10 for LLM & Agentic Applications categories."""

    LLM01_PROMPT_INJECTION = "LLM01:2026 Prompt Injection"
    LLM02_SENSITIVE_INFO_DISCLOSURE = "LLM02:2026 Sensitive Information Disclosure"
    LLM05_IMPROPER_OUTPUT_HANDLING = "LLM05:2026 Improper Output Handling"
    LLM06_EXCESSIVE_AGENCY = "LLM06:2026 Excessive Agency"
    LLM07_SYSTEM_PROMPT_LEAKAGE = "LLM07:2026 System Prompt Leakage"
    LLM08_CONTEXT_POISONING = "LLM08:2026 Untrusted Context & Vector Poisoning"
    LLM10_UNBOUNDED_CONSUMPTION = "LLM10:2026 Unbounded Consumption"
    ASI02_TOOL_MISUSE = "ASI02:2026 Agentic Tool Misuse"


class ToolCall(BaseModel):
    """Represents a proposed tool invocation by an autonomous agent."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str = Field(..., min_length=1, description="Canonical name of the invoked tool")
    arguments: dict[str, Any] = Field(
        default_factory=dict, description="Structured tool call arguments"
    )
    caller_id: str = Field(default="default-agent", description="Agent or session identifier")
    call_id: str = Field(default_factory=lambda: f"call_{uuid4().hex[:12]}")
    context_source: str = Field(
        default="direct_user",
        description="Origin of the context triggering the call (e.g., direct_user, retrieved_doc, webhook)",
    )


class AgentAction(BaseModel):
    """Envelope representing an agent prompt, tool invocation, or output emission."""

    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(default_factory=lambda: f"act_{uuid4().hex[:12]}")
    agent_id: str = Field(default="default-agent")
    action_type: str = Field(
        ..., description="Type of action: prompt_input, context_ingest, tool_call, output_emission"
    )
    content: str | None = Field(default=None, description="Text content for prompts or outputs")
    tool_call: ToolCall | None = Field(default=None, description="Associated tool invocation")
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PolicyRule(BaseModel):
    """Declarative capability rule governing tool permissions and parameter constraints."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(..., description="Unique identifier for the policy rule")
    tool_pattern: str = Field(
        ..., description="Tool name or glob pattern (e.g., 'shell_*', 'http_request', '*')"
    )
    decision: PolicyDecision = Field(..., description="Action to take when rule matches")
    description: str = Field(default="", description="Human-readable rationale for the rule")
    risk_level: RiskLevel = Field(default=RiskLevel.MEDIUM)
    allowed_domains: list[str] = Field(
        default_factory=list, description="Optional allowlist of hostnames for network tools"
    )
    blocked_arg_patterns: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Mapping of argument name to regex patterns that trigger this rule",
    )
    max_string_length: int | None = Field(
        default=None, description="Maximum allowed string length for any argument"
    )


class SecurityFinding(BaseModel):
    """Single detection event emitted by a detector or policy inspector."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(default_factory=lambda: f"find_{uuid4().hex[:10]}")
    detector: str = Field(..., description="Name of the detector or policy module")
    category: OWASPCategory = Field(..., description="Mapped OWASP 2026 category")
    risk_level: RiskLevel = Field(..., description="Severity of the finding")
    title: str = Field(..., description="Short summary of the threat")
    description: str = Field(..., description="Detailed explanation of why the input matched")
    matched_evidence: str = Field(
        default="", description="Sanitized snippet or indicator that triggered the finding"
    )
    remediation: str = Field(
        default="", description="Recommended mitigation or policy adjustment"
    )


class EvaluationVerdict(BaseModel):
    """Consolidated security verdict for a prompt, tool call, or agent output."""

    model_config = ConfigDict(extra="forbid")

    verdict_id: str = Field(default_factory=lambda: f"vrd_{uuid4().hex[:12]}")
    allowed: bool = Field(..., description="True if execution is permitted to proceed")
    decision: PolicyDecision = Field(..., description="Overall policy enforcement decision")
    risk_level: RiskLevel = Field(..., description="Highest risk level across all findings")
    risk_score: int = Field(..., ge=0, le=100, description="Numeric risk score (0-100)")
    findings: list[SecurityFinding] = Field(default_factory=list)
    sanitized_content: str | None = Field(
        default=None, description="Redacted or sanitized output when applicable"
    )
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuditEntry(BaseModel):
    """Tamper-evident hash-chained audit record."""

    model_config = ConfigDict(extra="forbid")

    sequence_id: int = Field(..., ge=1, description="Monotonically increasing ledger index")
    entry_id: str = Field(default_factory=lambda: f"aud_{uuid4().hex[:12]}")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    event_type: str = Field(
        ..., description="Event classification (prompt_check, tool_eval, output_scan, approval)"
    )
    actor: str = Field(default="default-agent")
    subject: str = Field(..., description="Target tool name, prompt source, or output channel")
    decision: PolicyDecision
    risk_level: RiskLevel
    finding_count: int = Field(default=0, ge=0)
    summary: str = Field(default="")
    previous_hash: str = Field(..., min_length=64, max_length=64)
    entry_hash: str = Field(..., min_length=64, max_length=64)


class ScenarioResult(BaseModel):
    """Outcome of a single benchmark scenario in the evaluation suite."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    title: str
    category: OWASPCategory
    attack_vector: str
    is_attack: bool
    expected_decision: PolicyDecision
    actual_decision: PolicyDecision
    passed: bool
    risk_level: RiskLevel
    finding_titles: list[str] = Field(default_factory=list)
    latency_ms: float = Field(default=0.0)


class SecurityReport(BaseModel):
    """Aggregate report produced by the AgentShield evaluation benchmark runner."""

    model_config = ConfigDict(extra="forbid")

    report_id: str = Field(default_factory=lambda: f"rep_{uuid4().hex[:12]}")
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    framework_version: str = Field(default="1.0.0")
    total_scenarios: int
    total_attacks: int
    total_benign: int
    true_positives: int
    false_negatives: int
    true_negatives: int
    false_positives: int
    detection_recall: float = Field(..., ge=0.0, le=1.0)
    false_positive_rate: float = Field(..., ge=0.0, le=1.0)
    policy_accuracy: float = Field(..., ge=0.0, le=1.0)
    category_breakdown: dict[str, dict[str, int | float]] = Field(default_factory=dict)
    results: list[ScenarioResult] = Field(default_factory=list)
