"""Runtime wrappers (`guard_tool`, `ShieldedAgentRuntime`) for Python functions, MCP tools, and LLM tool calls."""

from __future__ import annotations

import functools
import inspect
import json
from collections.abc import Callable
from typing import Any, ParamSpec, TypeVar

from agentshield.audit.ledger import AuditLedger
from agentshield.detectors.data_leakage import DataLeakageDetector
from agentshield.detectors.prompt_injection import PromptInjectionDetector
from agentshield.models import EvaluationVerdict, PolicyDecision, ToolCall
from agentshield.policy.engine import AgentShieldPolicy

P = ParamSpec("P")
R = TypeVar("R")


class ToolExecutionBlockedError(PermissionError):
    """Raised when AgentShield blocks or pauses a tool invocation."""

    def __init__(self, tool_name: str, verdict: EvaluationVerdict) -> None:
        self.tool_name = tool_name
        self.verdict = verdict
        titles = ", ".join(f.title for f in verdict.findings) or verdict.decision.value
        super().__init__(
            f"AgentShield blocked tool '{tool_name}' [decision={verdict.decision.value}, "
            f"risk={verdict.risk_level.value}]: {titles}"
        )


class ShieldedAgentRuntime:
    """Unified firewall runtime combining Prompt Injection, Tool Policy, Egress DLP, and Audit Ledger."""

    def __init__(
        self,
        *,
        policy: AgentShieldPolicy | None = None,
        prompt_detector: PromptInjectionDetector | None = None,
        leakage_detector: DataLeakageDetector | None = None,
        audit_ledger: AuditLedger | None = None,
        agent_id: str = "shielded-agent",
        approval_callback: Callable[[ToolCall, EvaluationVerdict], bool] | None = None,
    ) -> None:
        self.policy = policy or AgentShieldPolicy()
        self.prompt_detector = prompt_detector or PromptInjectionDetector()
        self.leakage_detector = leakage_detector or DataLeakageDetector()
        self.audit_ledger = audit_ledger or AuditLedger()
        self.agent_id = agent_id
        self.approval_callback = approval_callback

    def check_prompt(self, text: str, *, source: str = "direct_user") -> EvaluationVerdict:
        """Inspect incoming user prompt or retrieved context and log to audit ledger."""
        verdict = self.prompt_detector.evaluate(text, source=source)
        self.audit_ledger.record(
            event_type="prompt_check",
            subject=f"prompt:{source}",
            verdict=verdict,
            actor=self.agent_id,
        )
        return verdict

    def evaluate_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        context_source: str = "direct_user",
    ) -> EvaluationVerdict:
        """Evaluate a proposed tool call against the policy engine and record in the audit ledger."""
        call = ToolCall(
            tool_name=tool_name,
            arguments=arguments or {},
            caller_id=self.agent_id,
            context_source=context_source,
        )
        verdict = self.policy.evaluate_tool_call(call)
        self.audit_ledger.record(
            event_type="tool_eval",
            subject=tool_name,
            verdict=verdict,
            actor=self.agent_id,
        )
        return verdict

    def scan_output(self, text: str, *, redact: bool = True) -> EvaluationVerdict:
        """Scan outgoing agent response or tool output for leaked credentials and PII."""
        verdict = self.leakage_detector.scan(text, redact_on_match=redact)
        self.audit_ledger.record(
            event_type="output_scan",
            subject="agent_output",
            verdict=verdict,
            actor=self.agent_id,
        )
        return verdict

    def execute_tool(
        self,
        func: Callable[..., R],
        *,
        tool_name: str | None = None,
        arguments: dict[str, Any] | None = None,
        context_source: str = "direct_user",
        redact_output: bool = True,
    ) -> R | str:
        """Evaluate tool permissions, execute the callable if permitted, and scan output for secrets."""
        resolved_name = tool_name or getattr(func, "__name__", "unknown_tool")
        args = arguments or {}
        call = ToolCall(
            tool_name=resolved_name,
            arguments=args,
            caller_id=self.agent_id,
            context_source=context_source,
        )
        verdict = self.policy.evaluate_tool_call(call)
        self.audit_ledger.record(
            event_type="tool_eval",
            subject=resolved_name,
            verdict=verdict,
            actor=self.agent_id,
        )

        if verdict.decision == PolicyDecision.REQUIRE_APPROVAL:
            if self.approval_callback and self.approval_callback(call, verdict):
                pass
            else:
                raise ToolExecutionBlockedError(resolved_name, verdict)
        elif not verdict.allowed:
            raise ToolExecutionBlockedError(resolved_name, verdict)

        result = func(**args)
        if redact_output and isinstance(result, str):
            egress_verdict = self.scan_output(result, redact=True)
            if egress_verdict.sanitized_content is not None:
                return egress_verdict.sanitized_content
        return result

    def evaluate_provider_tool_call(
        self, payload: dict[str, Any], *, context_source: str = "direct_user"
    ) -> EvaluationVerdict:
        """Normalize and evaluate an OpenAI, Anthropic, or MCP formatted tool-call payload."""
        # OpenAI format: {"type": "function", "function": {"name": "...", "arguments": "{...}"}}
        if "function" in payload and isinstance(payload["function"], dict):
            fn = payload["function"]
            name = str(fn.get("name", "unknown"))
            raw_args = fn.get("arguments", {})
            args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
            return self.evaluate_tool(name, args, context_source=context_source)

        # Anthropic / MCP format: {"name": "...", "input": {...}} or {"params": {"name": "...", "arguments": {...}}}
        if "params" in payload and isinstance(payload["params"], dict):
            params = payload["params"]
            name = str(params.get("name", "unknown"))
            args = dict(params.get("arguments", {}))
            return self.evaluate_tool(name, args, context_source=context_source)

        name = str(payload.get("name") or payload.get("tool_name") or "unknown")
        args = dict(payload.get("input") or payload.get("arguments") or {})
        return self.evaluate_tool(name, args, context_source=context_source)


def guard_tool(
    runtime: ShieldedAgentRuntime | None = None,
    *,
    tool_name: str | None = None,
    context_source: str = "direct_user",
    redact_output: bool = True,
) -> Callable[[Callable[P, R]], Callable[P, R | str]]:
    """Decorator that wraps any Python function with AgentShield policy enforcement and egress DLP."""
    active_runtime = runtime or ShieldedAgentRuntime()

    def decorator(func: Callable[P, R]) -> Callable[P, R | str]:
        sig = inspect.signature(func)
        resolved_name = tool_name or func.__name__

        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R | str:
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            arg_dict = dict(bound.arguments)
            return active_runtime.execute_tool(
                func,
                tool_name=resolved_name,
                arguments=arg_dict,
                context_source=context_source,
                redact_output=redact_output,
            )

        return wrapper

    return decorator
