"""Command-line interface for AgentShield (`python -m agentshield.cli` / `agentshield`)."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

import uvicorn

from agentshield.adapters.runtime import ShieldedAgentRuntime
from agentshield.evaluation.suite import BenchmarkSuite


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentshield",
        description="AgentShield v1.0 — OWASP 2026 AI Agent Security & Governance Framework",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # evaluate
    eval_parser = subparsers.add_parser(
        "evaluate",
        help="Run the 25-scenario OWASP 2026 Agentic security benchmark suite",
    )
    eval_parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional file path to write the Markdown or JSON report",
    )
    eval_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the benchmark report as formatted JSON",
    )

    # check-prompt
    prompt_parser = subparsers.add_parser(
        "check-prompt",
        help="Inspect untrusted user input or retrieved context for prompt injection",
    )
    prompt_parser.add_argument("text", type=str, help="Prompt or document text to evaluate")
    prompt_parser.add_argument(
        "--source",
        type=str,
        default="direct_user",
        help="Origin of input (e.g., direct_user, retrieved_webpage)",
    )

    # check-tool
    tool_parser = subparsers.add_parser(
        "check-tool",
        help="Evaluate a proposed tool call against the AgentShield security policy",
    )
    tool_parser.add_argument("--tool", required=True, type=str, help="Tool name")
    tool_parser.add_argument(
        "--args",
        default="{}",
        type=str,
        help="JSON-encoded dictionary of tool arguments",
    )
    tool_parser.add_argument(
        "--source",
        default="direct_user",
        type=str,
        help="Context origin (e.g., direct_user, retrieved_email)",
    )

    # scan-output
    scan_parser = subparsers.add_parser(
        "scan-output",
        help="Scan outgoing agent response for leaked API keys, PII, and unsafe markup",
    )
    scan_parser.add_argument("text", type=str, help="Agent response text to scan and redact")

    # serve
    serve_parser = subparsers.add_parser(
        "serve",
        help="Start the FastAPI AgentShield Security Lab server",
    )
    serve_parser.add_argument("--host", type=str, default="127.0.0.1", help="Bind host")
    serve_parser.add_argument("--port", type=int, default=8090, help="Bind port")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    runtime = ShieldedAgentRuntime()

    if args.command == "evaluate":
        suite = BenchmarkSuite()
        report = suite.run()
        if args.json:
            rendered = report.model_dump_json(indent=2)
        else:
            rendered = suite.format_markdown(report)

        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(rendered, encoding="utf-8")

        print(rendered)
        return 0 if report.policy_accuracy == 1.0 else 1

    if args.command == "check-prompt":
        verdict = runtime.check_prompt(args.text, source=args.source)
        print(verdict.model_dump_json(indent=2))
        return 0 if verdict.allowed else 2

    if args.command == "check-tool":
        try:
            parsed_args = json.loads(args.args)
            if not isinstance(parsed_args, dict):
                raise TypeError("--args must decode to a JSON object")
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            print(json.dumps({"error": f"Invalid JSON for --args: {exc}"}), file=sys.stderr)
            return 1
        verdict = runtime.evaluate_tool(args.tool, parsed_args, context_source=args.source)
        print(verdict.model_dump_json(indent=2))
        return 0 if verdict.allowed else 2

    if args.command == "scan-output":
        verdict = runtime.scan_output(args.text, redact=True)
        print(verdict.model_dump_json(indent=2))
        return 0 if verdict.allowed else 2

    if args.command == "serve":
        uvicorn.run("agentshield.server.app:app", host=args.host, port=args.port)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
