"""AgentShield: AI Agent Security & Governance Framework."""

from agentshield.adapters.runtime import ShieldedAgentRuntime, ToolExecutionBlockedError, guard_tool
from agentshield.audit.ledger import AuditLedger
from agentshield.detectors.data_leakage import DataLeakageDetector
from agentshield.detectors.prompt_injection import PromptInjectionDetector
from agentshield.evaluation.suite import BenchmarkSuite
from agentshield.models import (
    AgentAction,
    AuditEntry,
    EvaluationVerdict,
    OWASPCategory,
    PolicyDecision,
    PolicyRule,
    RiskLevel,
    SecurityFinding,
    SecurityReport,
    ToolCall,
)
from agentshield.policy.engine import AgentShieldPolicy

__version__ = "1.0.0"

__all__ = [
    "AgentAction",
    "AgentShieldPolicy",
    "AuditEntry",
    "AuditLedger",
    "BenchmarkSuite",
    "DataLeakageDetector",
    "EvaluationVerdict",
    "OWASPCategory",
    "PolicyDecision",
    "PolicyRule",
    "PromptInjectionDetector",
    "RiskLevel",
    "SecurityFinding",
    "SecurityReport",
    "ShieldedAgentRuntime",
    "ToolCall",
    "ToolExecutionBlockedError",
    "guard_tool",
]
