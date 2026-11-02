# Testing & Verification Guide

AgentShield ships with **42 automated tests** and a **25-scenario OWASP 2026 benchmark suite**.

## Running the Test Suite

```bash
uv run --with pytest --with fastapi --with httpx --with pydantic --with uvicorn pytest -v
```

### Test Categories Covered in `tests/test_agentshield.py`

1. **Prompt Injection & Context Poisoning (10 tests)**:
   - Direct system instruction overrides (`PI-001`)
   - System prompt verbatim exfiltration (`PI-002`)
   - DAN / Developer Mode jailbreak framing (`PI-003`)
   - ChatML `<|im_start|>system` delimiter spoofing (`PI-004`)
   - Indirect RAG HTML comment poisoning (`PI-005`)
   - Base64 and Hex encoded injection payloads
   - Zero-width Unicode character steganography
   - Unbounded token bomb / input length exhaustion
   - Benign developer prompt negative control

2. **Capability & Tool Policy Engine (15 tests)**:
   - Shell command chaining (`;`, `|`) and destructive commands (`rm -rf`)
   - Filesystem path traversal (`..`), outside-sandbox paths, and `.env` secret access
   - Cloud metadata SSRF (`169.254.169.254`), RFC1918 private IPs (`192.168.1.50`), and `file://` scheme blocking
   - Outbound domain allowlist enforcement
   - Destructive SQL (`DROP TABLE`) and stacked query injection (`; DELETE`)
   - Human-in-the-loop `require_approval` gating (`transfer_funds`)
   - Untrusted context privilege isolation (`retrieved_email` invoking `bash`)

3. **Egress DLP & Secret Redaction (7 tests)**:
   - OpenAI (`sk-proj-`), AWS (`AKIA`), GitHub (`ghp_`), JWT, PEM private key, PostgreSQL URI, SSN, and Luhn-validated Visa card redaction
   - XSS `<script>` sanitization and system canary token detection

4. **SHA-256 Audit Ledger Tamper Detection (3 tests)**:
   - End-to-end JSONL persistence and reload verification
   - Detection of in-place summary tampering and record deletion

5. **Adapters, Benchmark Suite, CLI & FastAPI Endpoints (7 tests)**:
   - `@guard_tool` decorator, OpenAI/MCP tool call normalization, CLI exit codes, and FastAPI REST API + Security Lab HTML rendering.
