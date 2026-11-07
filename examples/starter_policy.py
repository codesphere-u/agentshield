"""Create a local, low-noise example of an AgentShield starter policy bundle."""

from __future__ import annotations

from pathlib import Path

from agentshield import AgentShieldPolicy, PolicyDecision, PolicyRule, RiskLevel
from agentshield.policy.config import build_policy_from_config


EXAMPLE_CONFIG = {
    "sandbox_root": "/workspace",
    "allowed_domains": ["api.github.com", "api.openai.com"],
    "block_untrusted_context_high_risk": True,
    "rules": [
        {
            "rule_id": "POL-EX-001",
            "tool_pattern": "transfer_funds",
            "decision": PolicyDecision.REQUIRE_APPROVAL.value,
            "description": "Payments require explicit human approval.",
            "risk_level": RiskLevel.HIGH.value,
        },
        {
            "rule_id": "POL-EX-002",
            "tool_pattern": "send_email",
            "decision": PolicyDecision.REQUIRE_APPROVAL.value,
            "description": "Outbound email requires human review.",
            "risk_level": RiskLevel.MEDIUM.value,
        },
    ],
}


def example_policy() -> AgentShieldPolicy:
    """Return a simple starter policy suitable for repository-level safe defaults."""
    return build_policy_from_config(EXAMPLE_CONFIG)


if __name__ == "__main__":
    path = Path(__file__).resolve().parent.parent / "examples" / "agent_policy.json"
    print(f"Starter policy built from {path}")
