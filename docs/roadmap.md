# AgentShield Roadmap

## v1.0 (Current Release)
- [x] Strongly typed Pydantic v2 security models mapped to OWASP 2026 LLM & Agentic Top 10
- [x] Multi-layer `PromptInjectionDetector` with Base64/Hex decoding and zero-width steganography detection
- [x] Declarative `AgentShieldPolicy` with built-in Shell, Filesystem, SSRF, and SQL inspectors
- [x] `DataLeakageDetector` egress firewall with Luhn validation and canary token support
- [x] SHA-256 hash-chained `AuditLedger` with tamper verification
- [x] 25-scenario reproducible OWASP 2026 benchmark suite (`agentshield evaluate`)
- [x] Interactive dark-mode FastAPI Security Lab (`agentshield serve`)

## v1.1 (Planned)
- [ ] Native Model Context Protocol (MCP) stdio/SSE proxy server mode (`agentshield mcp-proxy`)
- [ ] Ed25519 asymmetric cryptographic signing for exported `AuditLedger` bundles
- [ ] OpenTelemetry (OTel) trace and metric exporter for SIEM integration
- [ ] YAML/TOML policy file hot-reloading
