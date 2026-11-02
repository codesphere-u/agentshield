# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `1.0.x` | Yes |
| `< 1.0.0` | No |

## Reporting a Vulnerability

We take the security of **AgentShield** seriously. If you discover a bypass in our prompt injection signatures, tool capability inspectors (Shell, Filesystem, SSRF, SQLi), egress secret redaction rules, or SHA-256 audit ledger verification:

1. **Do NOT open a public GitHub issue** containing a live zero-day exploit payload.
2. Submit a private security advisory via [GitHub Security Advisories](https://github.com/codesphere-u/agentshield/security/advisories/new).
3. Include a minimal reproducible scenario (`BenchmarkScenario` or `ToolCall` payload) demonstrating the bypass.

We acknowledge vulnerability reports within **48 hours** and aim to publish a patched release and regression test within **7 days**.
