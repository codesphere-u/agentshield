# LangGraph Node Middleware Wrapper with AgentShield

This guide demonstrates how to wrap LangGraph tool execution nodes and message-intake nodes using `AgentShieldPolicy`, `AuditLedger`, `ConversationRiskTracker`, and `ShieldedAgentRuntime` without modifying your tool business logic.

## Why Wrap LangGraph Nodes?

In LangGraph workflows, an LLM node emits `tool_calls` into graph state and routes them to a tool-execution node. Wrapping that node with AgentShield enforces:

1. **Multi-turn prompt & crescendo screening** before agent reasoning (`ConversationRiskTracker`).
2. **Pre-execution tool policy enforcement** against SSRF, command injection, path traversal, and destructive SQL (`AgentShieldPolicy`).
3. **Egress DLP redaction** on tool outputs before they re-enter graph state (`DataLeakageDetector`).
4. **Tamper-evident hash-chained auditing** across every node transition (`AuditLedger`).

## Reusable LangGraph Middleware Wrapper

```python
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentshield import (
    AgentShieldPolicy,
    AuditLedger,
    ConversationRiskTracker,
    PolicyDecision,
    ShieldedAgentRuntime,
    ToolCall,
    ToolExecutionBlockedError,
)


def make_shielded_langgraph_tool_node(
    tools_by_name: dict[str, Callable[..., Any]],
    *,
    policy: AgentShieldPolicy | None = None,
    ledger: AuditLedger | None = None,
    agent_id: str = "langgraph-agent",
) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """Return a LangGraph-compatible node function that guards every tool call."""
    runtime = ShieldedAgentRuntime(
        policy=policy or AgentShieldPolicy(),
        audit_ledger=ledger or AuditLedger(),
        agent_id=agent_id,
    )

    def shielded_tool_node(state: dict[str, Any]) -> dict[str, Any]:
        messages = list(state.get("messages", []))
        last_msg = messages[-1] if messages else {}
        tool_calls = (
            last_msg.get("tool_calls", [])
            if isinstance(last_msg, dict)
            else getattr(last_msg, "tool_calls", [])
        )
        context_source = str(state.get("context_source", "direct_user"))
        tool_outputs: list[dict[str, Any]] = []

        for tc in tool_calls:
            name = tc["name"] if isinstance(tc, dict) else tc.name
            args = tc.get("args", {}) if isinstance(tc, dict) else tc.args
            call_id = tc.get("id", "call") if isinstance(tc, dict) else tc.id

            fn = tools_by_name.get(name)
            if fn is None:
                tool_outputs.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": name,
                        "content": f"[BLOCKED] Unknown tool: {name}",
                    }
                )
                continue

            try:
                result = runtime.execute_tool(
                    fn,
                    tool_name=name,
                    arguments=dict(args),
                    context_source=context_source,
                    redact_output=True,
                )
                tool_outputs.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": name,
                        "content": str(result),
                    }
                )
            except ToolExecutionBlockedError as exc:
                tool_outputs.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": name,
                        "content": f"[AGENTSHIELD {exc.verdict.decision.value.upper()}] {exc}",
                    }
                )

        return {"messages": messages + tool_outputs}

    return shielded_tool_node
```

## Wiring Into `StateGraph`

```python
from langgraph.graph import END, StateGraph
from agentshield import AgentShieldPolicy, AuditLedger, ConversationRiskTracker

ledger = AuditLedger()
policy = AgentShieldPolicy(allowed_domains=["api.github.com"])
crescendo = ConversationRiskTracker()

def input_guard_node(state: dict[str, Any]) -> dict[str, Any]:
    session_id = state.get("session_id", "default")
    user_text = state["messages"][-1]["content"]
    verdict = crescendo.evaluate_turn(session_id, user_text)
    ledger.record(
        event_type="prompt_check",
        subject=f"langgraph:{session_id}",
        verdict=verdict,
        actor="langgraph-input-guard",
    )
    if not verdict.allowed:
        return {"blocked": True, "block_reason": verdict.findings[0].title}
    return {"blocked": False}

def read_notes(path: str) -> str:
    return f"Loaded notes from {path}"

tool_node = make_shielded_langgraph_tool_node(
    {"read_file": read_notes},
    policy=policy,
    ledger=ledger,
)

graph = StateGraph(dict)
graph.add_node("input_guard", input_guard_node)
graph.add_node("tools", tool_node)
graph.set_entry_point("input_guard")
graph.add_conditional_edges(
    "input_guard",
    lambda s: END if s.get("blocked") else "tools",
)
graph.add_edge("tools", END)
app = graph.compile()
```

## Verifying Ledger Integrity After a Graph Run

```python
is_valid, message = ledger.verify_integrity()
assert is_valid, f"Audit trail tampered: {message}"
```
