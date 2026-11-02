# Changelog

All notable changes to **AgentShield** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-02

### Added
- **Core Pydantic v2 Models (`agentshield.models`)**: `AgentAction`, `ToolCall`, `PolicyRule`, `SecurityFinding`, `RiskLevel`, `EvaluationVerdict`, `AuditEntry`, and `SecurityReport`.
- **Multi-Layer Prompt Injection Detector (`agentshield.detectors.prompt_injection`)**: Direct override, system prompt exfiltration, DAN/jailbreak framing, ChatML delimiter spoofing, indirect HTML/RAG context poisoning, Base64/Hex decoded payload inspection, and zero-width Unicode steganography detection.
- **Declarative Capability & Tool Policy Engine (`agentshield.policy.engine`)**: `allow`, `deny`, and `require_approval` rules plus built-in deep argument inspectors for Shell command chaining/destruction, Filesystem sandbox & secret file protection, Cloud Metadata/RFC1918 SSRF prevention, and Destructive/Stacked SQL query blocking.
- **Egress & Output DLP Firewall (`agentshield.detectors.data_leakage`)**: Automatic detection and redaction for API keys (`sk-`, `ghp_`, `AKIA`, `AIza`), PEM private keys, JWTs, database URIs, SSNs, Luhn-validated credit cards, XSS `<script>` payloads, and system canary tokens.
- **Tamper-Evident Audit Ledger (`agentshield.audit.ledger`)**: Append-only SHA-256 hash-chained `AuditLedger` with `verify_integrity()`.
- **OWASP 2026 Benchmark Suite (`agentshield.evaluation.suite`)**: 25-scenario deterministic benchmark achieving 100% recall and 0% FPR.
- **Runtime Adapters (`agentshield.adapters`)**: `ShieldedAgentRuntime` and `@guard_tool` decorator supporting Python callables, OpenAI tool calls, and Anthropic/MCP schemas.
- **CLI & FastAPI Security Lab (`agentshield.cli`, `agentshield.server.app`)**: Interactive dark-mode Security Lab UI and REST API endpoints.
