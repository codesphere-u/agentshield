# ADR 001: Deterministic Policy Firewall vs. Probabilistic LLM Guardrails

- **Status**: Accepted
- **Date**: 2026-11-02

## Context

Many first-generation AI guardrail frameworks rely on a secondary LLM call ("LLM-as-a-Judge") to inspect incoming prompts and proposed tool calls. In production agentic deployments, this pattern exhibits three critical failure modes:
1. **Non-Determinism & Second-Order Prompt Injection**: An attacker who crafts an adversarial payload can jailbreak both the primary agent and the guardrail model simultaneously.
2. **Latency & Cost Amplification**: Invoking an external LLM before every tool call adds 300–1,200 ms per step and doubles token expenditure.
3. **Lack of Cryptographic Auditability**: Probabilistic confidence scores cannot enforce hard capability invariants such as "never connect to RFC1918 private subnets" or "never traverse outside `/workspace`".

## Decision

We designed **AgentShield** around **deterministic, zero-external-API security invariants**:
- Tool capability enforcement is implemented as a declarative rule engine (`AgentShieldPolicy`) paired with domain-specific structural parsers (`ipaddress`, `urllib.parse`, `posixpath`, Luhn checksums, and compiled regular expressions).
- All evaluations complete in **< 0.2 ms** in-process with zero external network dependencies.
- Every verdict is recorded in a tamper-evident SHA-256 hash chain (`AuditLedger`).

## Consequences

- **Positive**: 100% reproducible verdicts in CI/CD, sub-millisecond runtime overhead, immune to probabilistic judge manipulation, and zero API key requirement.
- **Negative / Trade-off**: Purely semantic social-engineering phrasing that uses no known structural override patterns or restricted tool arguments may bypass regex/heuristic prompt checks—which is why AgentShield enforces **strict capability and context-isolation policies at the tool execution boundary** even if a prompt bypasses stage 1.
