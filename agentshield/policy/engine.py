"""Declarative Capability & Tool Permission Policy Engine with built-in high-risk inspectors."""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import posixpath
import re
from urllib.parse import urlparse

from agentshield.models import (
    EvaluationVerdict,
    OWASPCategory,
    PolicyDecision,
    PolicyRule,
    RiskLevel,
    SecurityFinding,
    ToolCall,
)

_SHELL_TOOLS = {"bash", "sh", "shell", "run_command", "execute_command", "terminal", "exec_shell"}
_FILE_TOOLS = {
    "read_file",
    "write_file",
    "delete_file",
    "list_dir",
    "open_file",
    "filesystem_read",
    "filesystem_write",
}
_NETWORK_TOOLS = {
    "http_request",
    "fetch_url",
    "curl",
    "webhook_post",
    "browse_url",
    "http_get",
    "http_post",
}
_DB_TOOLS = {"sql_query", "execute_sql", "db_query", "postgres_query", "run_sql"}

_SHELL_CHAIN_RE = re.compile(
    r"(?:;|&&|\|\||\|(?!\s*$)|`[^`]+`|\$\([^)]+\)|>\s*/etc/|curl\b.*\|\s*(?:ba)?sh|wget\b.*\|\s*(?:ba)?sh)"
)
_SHELL_DESTRUCTIVE_RE = re.compile(
    r"(?i)\b(?:rm\s+-[a-zA-Z]*r[a-zA-Z]*f|mkfs(?:\.[a-z0-9]+)?|dd\s+if=|chmod\s+777\s+/|chown\s+-R\s+root|sudo\s+|su\s+root|nc\s+-e|/dev/tcp/)"
)

_SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:\.env(?:\.[a-z0-9_]+)?|\.ssh(?:/|$)|id_rsa|id_ed25519|\.aws(?:/|$)|credentials\.json|etc/passwd|etc/shadow|\.git/config|\.kube/config)"
)

_DESTRUCTIVE_SQL_RE = re.compile(
    r"(?i)\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE|ALTER\s+SYSTEM|GRANT\s+ALL|INTO\s+OUTFILE|LOAD_FILE\s*\(|DELETE\s+FROM\s+[a-zA-Z0-9_.]+\s*(?:;|$|\s+WHERE\s+1\s*=\s*1))"
)
_STACKED_SQL_RE = re.compile(r";\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\b", re.IGNORECASE)

_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.internal",
    "100.100.100.200",
    "localhost",
    "0.0.0.0",
}


class AgentShieldPolicy:
    """Evaluates proposed agent tool calls against declarative capability rules and deep argument inspectors."""

    def __init__(
        self,
        rules: list[PolicyRule] | None = None,
        *,
        sandbox_root: str = "/workspace",
        allowed_domains: list[str] | None = None,
        block_untrusted_context_high_risk: bool = True,
    ) -> None:
        self.sandbox_root = posixpath.normpath(sandbox_root)
        self.allowed_domains = [d.lower() for d in (allowed_domains or [])]
        self.block_untrusted_context_high_risk = block_untrusted_context_high_risk
        self.rules: list[PolicyRule] = rules if rules is not None else self.default_rules()

    @staticmethod
    def default_rules() -> list[PolicyRule]:
        """Standard production security policy rules."""
        return [
            PolicyRule(
                rule_id="POL-001",
                tool_pattern="admin_*",
                decision=PolicyDecision.DENY,
                description="Administrative tools are strictly prohibited for autonomous agents.",
                risk_level=RiskLevel.CRITICAL,
            ),
            PolicyRule(
                rule_id="POL-002",
                tool_pattern="transfer_funds",
                decision=PolicyDecision.REQUIRE_APPROVAL,
                description="Financial transactions require explicit human-in-the-loop approval.",
                risk_level=RiskLevel.HIGH,
            ),
            PolicyRule(
                rule_id="POL-003",
                tool_pattern="send_email",
                decision=PolicyDecision.REQUIRE_APPROVAL,
                description="External email transmission requires human approval to prevent data exfiltration.",
                risk_level=RiskLevel.MEDIUM,
            ),
            PolicyRule(
                rule_id="POL-004",
                tool_pattern="delete_*",
                decision=PolicyDecision.REQUIRE_APPROVAL,
                description="Destructive deletion tools require human confirmation.",
                risk_level=RiskLevel.HIGH,
            ),
        ]

    def evaluate_tool_call(self, tool_call: ToolCall) -> EvaluationVerdict:
        """Evaluate a ToolCall against custom rules and built-in shell, file, network, and SQL inspectors."""
        findings: list[SecurityFinding] = []
        explicit_decisions: list[PolicyDecision] = []

        tool_lower = tool_call.tool_name.lower()
        serialized_args = json.dumps(tool_call.arguments, sort_keys=True)

        # 1. Check declarative PolicyRules
        for rule in self.rules:
            if fnmatch.fnmatch(tool_lower, rule.tool_pattern.lower()):
                if rule.max_string_length is not None and len(serialized_args) > rule.max_string_length:
                    findings.append(
                        SecurityFinding(
                            detector=f"AgentShieldPolicy[{rule.rule_id}]",
                            category=OWASPCategory.LLM10_UNBOUNDED_CONSUMPTION,
                            risk_level=rule.risk_level,
                            title=f"Tool Argument Exceeds Length Policy ({rule.rule_id})",
                            description=f"Arguments length {len(serialized_args)} exceeds limit {rule.max_string_length}.",
                            matched_evidence=f"len={len(serialized_args)}",
                            remediation="Constrain tool argument size.",
                        )
                    )
                    explicit_decisions.append(PolicyDecision.DENY)

                if rule.blocked_arg_patterns:
                    for arg_name, patterns in rule.blocked_arg_patterns.items():
                        val = str(tool_call.arguments.get(arg_name, ""))
                        for pat in patterns:
                            if re.search(pat, val, re.IGNORECASE):
                                findings.append(
                                    SecurityFinding(
                                        detector=f"AgentShieldPolicy[{rule.rule_id}]",
                                        category=OWASPCategory.ASI02_TOOL_MISUSE,
                                        risk_level=rule.risk_level,
                                        title=f"Blocked Argument Pattern ({rule.rule_id})",
                                        description=rule.description or f"Argument '{arg_name}' matched restricted pattern.",
                                        matched_evidence=val[:80],
                                        remediation="Remove restricted parameter values.",
                                    )
                                )
                                explicit_decisions.append(rule.decision)
                elif rule.decision in (PolicyDecision.DENY, PolicyDecision.REQUIRE_APPROVAL):
                    findings.append(
                        SecurityFinding(
                            detector=f"AgentShieldPolicy[{rule.rule_id}]",
                            category=OWASPCategory.LLM06_EXCESSIVE_AGENCY,
                            risk_level=rule.risk_level,
                            title=f"Policy Rule Match: {rule.rule_id}",
                            description=rule.description
                            or f"Tool '{tool_call.tool_name}' matched policy rule '{rule.rule_id}'.",
                            matched_evidence=f"tool={tool_call.tool_name}",
                            remediation=(
                                "Request human approval before execution."
                                if rule.decision == PolicyDecision.REQUIRE_APPROVAL
                                else "Use an approved least-privilege tool."
                            ),
                        )
                    )
                    explicit_decisions.append(rule.decision)

        # 2. Untrusted Context Privilege Escalation Check
        is_high_risk_tool = (
            tool_lower in _SHELL_TOOLS
            or tool_lower in _DB_TOOLS
            or tool_lower.startswith(("write_", "delete_", "exec_", "send_"))
        )
        if (
            self.block_untrusted_context_high_risk
            and tool_call.context_source != "direct_user"
            and is_high_risk_tool
        ):
            findings.append(
                SecurityFinding(
                    detector="AgentShieldPolicy[CTX-ISOLATION]",
                    category=OWASPCategory.LLM08_CONTEXT_POISONING,
                    risk_level=RiskLevel.CRITICAL,
                    title="Privileged Tool Invoked from Untrusted Context",
                    description=(
                        f"High-risk tool '{tool_call.tool_name}' was triggered while processing "
                        f"untrusted context source '{tool_call.context_source}'."
                    ),
                    matched_evidence=f"source={tool_call.context_source}, tool={tool_call.tool_name}",
                    remediation="Block state-mutating or command-execution tools when processing untrusted external documents.",
                )
            )
            explicit_decisions.append(PolicyDecision.DENY)

        # 3. Built-in Shell / Command Inspector
        if tool_lower in _SHELL_TOOLS or "command" in tool_call.arguments or "cmd" in tool_call.arguments:
            cmd_str = str(
                tool_call.arguments.get("command")
                or tool_call.arguments.get("cmd")
                or ""
            )
            findings.extend(self._inspect_shell_command(cmd_str))

        # 4. Built-in Filesystem Inspector
        if tool_lower in _FILE_TOOLS or "path" in tool_call.arguments or "file_path" in tool_call.arguments:
            path_str = str(
                tool_call.arguments.get("path")
                or tool_call.arguments.get("file_path")
                or tool_call.arguments.get("filename")
                or ""
            )
            if path_str:
                findings.extend(self._inspect_file_path(path_str))

        # 5. Built-in Network / SSRF Inspector
        if tool_lower in _NETWORK_TOOLS or "url" in tool_call.arguments or "endpoint" in tool_call.arguments:
            url_str = str(
                tool_call.arguments.get("url")
                or tool_call.arguments.get("endpoint")
                or tool_call.arguments.get("uri")
                or ""
            )
            if url_str:
                findings.extend(self._inspect_network_url(url_str))

        # 6. Built-in Database / SQL Inspector
        if tool_lower in _DB_TOOLS or "query" in tool_call.arguments or "sql" in tool_call.arguments:
            sql_str = str(
                tool_call.arguments.get("query")
                or tool_call.arguments.get("sql")
                or ""
            )
            if sql_str:
                findings.extend(self._inspect_sql_query(sql_str))

        if not findings:
            return EvaluationVerdict(
                allowed=True,
                decision=PolicyDecision.ALLOW,
                risk_level=RiskLevel.NONE,
                risk_score=0,
                findings=[],
            )

        highest_risk = max(findings, key=lambda f: f.risk_level.score).risk_level
        risk_score = min(100, max(f.risk_level.score for f in findings) + (len(findings) - 1) * 10)

        # Any inspector finding or DENY rule results in DENY; otherwise REQUIRE_APPROVAL if only approval rules matched
        inspector_findings = [
            f for f in findings if not f.detector.startswith("AgentShieldPolicy[POL-")
        ]
        if inspector_findings or PolicyDecision.DENY in explicit_decisions:
            decision = PolicyDecision.DENY
        elif PolicyDecision.REQUIRE_APPROVAL in explicit_decisions:
            decision = PolicyDecision.REQUIRE_APPROVAL
        else:
            decision = PolicyDecision.DENY

        return EvaluationVerdict(
            allowed=(decision == PolicyDecision.ALLOW),
            decision=decision,
            risk_level=highest_risk,
            risk_score=risk_score,
            findings=findings,
        )

    def _inspect_shell_command(self, cmd: str) -> list[SecurityFinding]:
        results: list[SecurityFinding] = []
        if not cmd:
            return results

        chain_match = _SHELL_CHAIN_RE.search(cmd)
        if chain_match:
            results.append(
                SecurityFinding(
                    detector="ShellInspector[SH-001]",
                    category=OWASPCategory.ASI02_TOOL_MISUSE,
                    risk_level=RiskLevel.CRITICAL,
                    title="Shell Command Chaining / Subshell Injection",
                    description="Command contains shell chaining operators, subshells, or remote pipe execution.",
                    matched_evidence=chain_match.group(0)[:80],
                    remediation="Pass arguments as a parameterized array without shell interpolation.",
                )
            )

        dest_match = _SHELL_DESTRUCTIVE_RE.search(cmd)
        if dest_match:
            results.append(
                SecurityFinding(
                    detector="ShellInspector[SH-002]",
                    category=OWASPCategory.LLM06_EXCESSIVE_AGENCY,
                    risk_level=RiskLevel.CRITICAL,
                    title="Destructive or Privilege-Escalation Shell Command",
                    description="Command invokes destructive filesystem wipe, raw disk write, or privilege escalation.",
                    matched_evidence=dest_match.group(0)[:80],
                    remediation="Block destructive commands and run agent processes under unprivileged sandboxes.",
                )
            )
        return results

    def _inspect_file_path(self, raw_path: str) -> list[SecurityFinding]:
        results: list[SecurityFinding] = []
        # Check traversal segments
        parts = re.split(r"[/\\]", raw_path)
        if ".." in parts:
            results.append(
                SecurityFinding(
                    detector="FilesystemInspector[FS-001]",
                    category=OWASPCategory.ASI02_TOOL_MISUSE,
                    risk_level=RiskLevel.CRITICAL,
                    title="Directory Path Traversal Attempt",
                    description=f"Path '{raw_path}' contains parent directory traversal ('..') segments.",
                    matched_evidence=raw_path[:100],
                    remediation="Canonicalize paths and enforce strict prefix containment within the sandbox root.",
                )
            )

        # Check sandbox containment if absolute path is given
        normalized = posixpath.normpath(raw_path.replace("\\", "/"))
        if normalized.startswith("/") and not (
            normalized == self.sandbox_root or normalized.startswith(self.sandbox_root + "/")
        ):
            results.append(
                SecurityFinding(
                    detector="FilesystemInspector[FS-002]",
                    category=OWASPCategory.LLM06_EXCESSIVE_AGENCY,
                    risk_level=RiskLevel.HIGH,
                    title="Filesystem Access Outside Sandbox Root",
                    description=f"Resolved path '{normalized}' is outside allowed sandbox root '{self.sandbox_root}'.",
                    matched_evidence=normalized[:100],
                    remediation=f"Restrict all agent file operations to '{self.sandbox_root}'.",
                )
            )

        # Check sensitive secret files
        sec_match = _SENSITIVE_PATH_RE.search(normalized)
        if sec_match:
            results.append(
                SecurityFinding(
                    detector="FilesystemInspector[FS-003]",
                    category=OWASPCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
                    risk_level=RiskLevel.CRITICAL,
                    title="Sensitive Credential or System File Access",
                    description=f"Attempted access to protected secret or system path '{sec_match.group(0)}'.",
                    matched_evidence=raw_path[:100],
                    remediation="Mount secrets via isolated vault bindings rather than readable workspace files.",
                )
            )

        return results

    def _inspect_network_url(self, raw_url: str) -> list[SecurityFinding]:
        results: list[SecurityFinding] = []
        parsed = urlparse(raw_url)
        scheme = (parsed.scheme or "").lower()
        hostname = (parsed.hostname or "").lower()

        if scheme not in ("http", "https"):
            results.append(
                SecurityFinding(
                    detector="NetworkInspector[NET-001]",
                    category=OWASPCategory.ASI02_TOOL_MISUSE,
                    risk_level=RiskLevel.HIGH,
                    title="Disallowed URI Scheme",
                    description=f"URI scheme '{scheme or 'empty'}' is prohibited (only http/https permitted).",
                    matched_evidence=raw_url[:100],
                    remediation="Permit only HTTPS requests to verified external endpoints.",
                )
            )
            return results

        if not hostname:
            results.append(
                SecurityFinding(
                    detector="NetworkInspector[NET-002]",
                    category=OWASPCategory.ASI02_TOOL_MISUSE,
                    risk_level=RiskLevel.HIGH,
                    title="Malformed Network URL",
                    description="URL is missing a valid hostname.",
                    matched_evidence=raw_url[:100],
                    remediation="Validate URL syntax before execution.",
                )
            )
            return results

        if hostname in _METADATA_HOSTS or hostname.endswith((".internal", ".local")):
            results.append(
                SecurityFinding(
                    detector="NetworkInspector[NET-003]",
                    category=OWASPCategory.ASI02_TOOL_MISUSE,
                    risk_level=RiskLevel.CRITICAL,
                    title="SSRF Target: Cloud Metadata or Loopback Host",
                    description=f"Target host '{hostname}' points to cloud instance metadata or internal loopback.",
                    matched_evidence=raw_url[:100],
                    remediation="Block IMDSv1/v2 metadata IP 169.254.169.254 and loopback interfaces in agent HTTP clients.",
                )
            )
            return results

        # Check IP address literals for private/loopback/link-local ranges
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                results.append(
                    SecurityFinding(
                        detector="NetworkInspector[NET-004]",
                        category=OWASPCategory.ASI02_TOOL_MISUSE,
                        risk_level=RiskLevel.CRITICAL,
                        title="SSRF Target: Private or Reserved IP Subnet",
                        description=f"Target IP '{ip}' belongs to a non-routable private, loopback, or link-local subnet.",
                        matched_evidence=raw_url[:100],
                        remediation="Enforce egress firewall rules blocking RFC1918, loopback, and link-local IP ranges.",
                    )
                )
        except ValueError:
            pass

        if self.allowed_domains and not any(
            hostname == d or hostname.endswith("." + d) for d in self.allowed_domains
        ):
            results.append(
                SecurityFinding(
                    detector="NetworkInspector[NET-005]",
                    category=OWASPCategory.LLM06_EXCESSIVE_AGENCY,
                    risk_level=RiskLevel.HIGH,
                    title="Outbound Request to Unapproved Domain",
                    description=f"Host '{hostname}' is not in the configured domain allowlist.",
                    matched_evidence=hostname,
                    remediation="Add trusted API domains explicitly to the policy allowlist.",
                )
            )

        return results

    def _inspect_sql_query(self, sql: str) -> list[SecurityFinding]:
        results: list[SecurityFinding] = []
        dest_match = _DESTRUCTIVE_SQL_RE.search(sql)
        if dest_match:
            results.append(
                SecurityFinding(
                    detector="DatabaseInspector[DB-001]",
                    category=OWASPCategory.LLM06_EXCESSIVE_AGENCY,
                    risk_level=RiskLevel.CRITICAL,
                    title="Destructive or Unconstrained SQL Statement",
                    description="Query contains destructive DDL/DML (DROP, TRUNCATE, or unconstrained DELETE).",
                    matched_evidence=dest_match.group(0)[:100],
                    remediation="Connect agents to read-only database replicas with parameterized query views.",
                )
            )

        stacked_match = _STACKED_SQL_RE.search(sql)
        if stacked_match:
            results.append(
                SecurityFinding(
                    detector="DatabaseInspector[DB-002]",
                    category=OWASPCategory.ASI02_TOOL_MISUSE,
                    risk_level=RiskLevel.CRITICAL,
                    title="Stacked SQL Query Injection",
                    description="Query attempts to chain multiple SQL statements via semicolon separator.",
                    matched_evidence=stacked_match.group(0)[:100],
                    remediation="Disallow multi-statement SQL execution in database drivers.",
                )
            )
        return results
