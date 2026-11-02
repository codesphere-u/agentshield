# Known Limitations & Threat Boundaries

Transparency about security boundaries is essential for production deployment:

1. **Novel Semantic Prompt Injections**:
   - `PromptInjectionDetector` uses deterministic structural signatures, Base64/Hex decoding, and zero-width character normalization. Novel paraphrased social engineering that avoids known override patterns may pass stage-1 prompt inspection.
   - **Mitigation**: Always pair `PromptInjectionDetector` with `AgentShieldPolicy` (stage 2) and `context_source` tagging so that even if a prompt is not flagged, any resulting privileged tool call from untrusted context or outside sandbox constraints is deterministically blocked.

2. **DNS Rebinding & Redirect SSRF**:
   - `AgentShieldPolicy` inspects literal IP addresses and hostnames statically before the HTTP request is sent. It does not perform live DNS resolution or follow HTTP `302` redirects at evaluation time.
   - **Mitigation**: Configure `allowed_domains` on `AgentShieldPolicy` and disable automatic redirects in the underlying HTTP client when executing network tools.

3. **Process-Level OS Sandboxing**:
   - AgentShield is an in-process Python policy firewall and wrapper. If an agent is permitted to execute arbitrary Python code inside the same interpreter process, it could inspect memory directly.
   - **Mitigation**: Run untrusted code execution tools inside isolated containers, microVMs (gVisor/Firecracker), or separate OS processes gated by AgentShield.
