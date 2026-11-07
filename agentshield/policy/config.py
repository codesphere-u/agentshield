"""Policy configuration helpers for AgentShield starter kits and CI validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentshield.models import PolicyDecision, PolicyRule, RiskLevel
from agentshield.policy.engine import AgentShieldPolicy


def _coerce_rule(rule_data: dict[str, Any]) -> PolicyRule:
    """Normalize an incoming rule dictionary into a PolicyRule instance."""
    if not isinstance(rule_data, dict):
        raise TypeError("Each rule must be a JSON object.")

    decision = rule_data.get("decision", PolicyDecision.DENY.value)
    risk = rule_data.get("risk_level", RiskLevel.MEDIUM.value)

    blocked_patterns = rule_data.get("blocked_arg_patterns", {}) or {}
    normalized_blocked = {
        str(key): [str(pattern) for pattern in value]
        for key, value in blocked_patterns.items()
    }

    return PolicyRule(
        rule_id=str(rule_data.get("rule_id", "CUSTOM-RULE")),
        tool_pattern=str(rule_data["tool_pattern"]),
        decision=PolicyDecision(decision),
        description=str(rule_data.get("description", "")),
        risk_level=RiskLevel(risk),
        allowed_domains=[str(domain) for domain in rule_data.get("allowed_domains", [])],
        blocked_arg_patterns=normalized_blocked,
        max_string_length=rule_data.get("max_string_length"),
    )


def load_policy_config(path: str | Path) -> AgentShieldPolicy:
    """Load a JSON policy bundle from disk and convert it into an AgentShieldPolicy."""
    config_path = Path(path)
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    return build_policy_from_config(payload)


def build_policy_from_config(data: dict[str, Any]) -> AgentShieldPolicy:
    """Turn a dictionary config into an AgentShieldPolicy instance."""
    if not isinstance(data, dict):
        raise TypeError("Policy config must decode to a JSON object.")

    rules_payload = data.get("rules", [])
    if not isinstance(rules_payload, list):
        raise TypeError("Policy config 'rules' must be a JSON array.")

    rules = [_coerce_rule(rule) for rule in rules_payload]
    allowed_domains = [str(domain) for domain in data.get("allowed_domains", [])]

    return AgentShieldPolicy(
        rules=rules,
        sandbox_root=str(data.get("sandbox_root", "/workspace")),
        allowed_domains=allowed_domains,
        block_untrusted_context_high_risk=bool(
            data.get("block_untrusted_context_high_risk", True)
        ),
    )


def summarize_policy(policy: AgentShieldPolicy) -> dict[str, Any]:
    """Return a compact JSON-safe summary for CLI output and CI checks."""
    return {
        "sandbox_root": policy.sandbox_root,
        "allowed_domains": policy.allowed_domains,
        "block_untrusted_context_high_risk": policy.block_untrusted_context_high_risk,
        "rules_loaded": len(policy.rules),
        "rule_ids": [rule.rule_id for rule in policy.rules],
    }
