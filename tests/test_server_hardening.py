"""Production hardening, observability, and HTTP security tests for AgentShield server."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from agentshield import cli as agentshield_cli
from agentshield.adapters.runtime import ShieldedAgentRuntime
from agentshield.server.app import create_app


def test_health_healthz_readyz_get_and_head() -> None:
    app = create_app()
    with TestClient(app) as client:
        for path in ("/health", "/healthz", "/readyz"):
            get_resp = client.get(path)
            assert get_resp.status_code == 200
            body = get_resp.json()
            assert body["service"] == "agentshield"
            assert get_resp.headers["cache-control"] == "no-store"
            assert get_resp.headers["x-content-type-options"] == "nosniff"
            assert get_resp.headers["x-frame-options"] == "SAMEORIGIN"
            assert get_resp.headers["referrer-policy"] == "strict-origin-when-cross-origin"

            head_resp = client.head(path)
            assert head_resp.status_code == 200
            assert head_resp.content == b""
            assert head_resp.headers["cache-control"] == "no-store"
            assert head_resp.headers["x-content-type-options"] == "nosniff"


def test_readyz_returns_503_when_audit_chain_tampered() -> None:
    runtime = ShieldedAgentRuntime()
    runtime.check_prompt("Hello")
    runtime.audit_ledger._entries[0].summary = "tampered"
    client = TestClient(create_app(runtime=runtime))

    resp = client.get("/readyz")
    assert resp.status_code == 503
    assert resp.json()["status"] == "not_ready"
    assert resp.json()["audit_integrity"] is False


def test_metrics_prometheus_and_json_formats() -> None:
    runtime = ShieldedAgentRuntime()
    runtime.check_prompt("Test prompt")
    client = TestClient(create_app(runtime=runtime))

    client.get("/health")
    client.post("/api/v1/evaluate-prompt", json={})  # triggers 422

    prom_resp = client.get("/metrics")
    assert prom_resp.status_code == 200
    assert prom_resp.headers["content-type"].startswith("text/plain; version=0.0.4")
    text = prom_resp.text
    assert 'http_requests_total{service="agentshield"} 2' in text
    assert 'http_requests_by_status_total{service="agentshield",status="200"} 1' in text
    assert 'http_requests_by_status_total{service="agentshield",status="422"} 1' in text
    assert 'http_request_errors_total{service="agentshield",class="4xx"} 1' in text
    assert 'agentshield_audit_entries{service="agentshield"} 1' in text
    assert "process_uptime_seconds" in text

    json_resp = client.get("/metrics", headers={"Accept": "application/json"})
    assert json_resp.status_code == 200
    data = json_resp.json()
    assert data["service"] == "agentshield"
    assert data["total_requests"] == 3
    assert data["error_counts"]["client_errors_4xx"] == 1
    assert data["status_code_counts"]["200"] == 2
    assert data["status_code_counts"]["422"] == 1
    assert data["gauges"]["audit_entries"] == 1
    assert data["gauges"]["audit_integrity_valid"] == 1
    assert data["uptime_seconds"] >= 0.0


def test_request_id_validation_and_security_headers() -> None:
    client = TestClient(create_app())

    ok_resp = client.get("/api/v1/audit-log", headers={"X-Request-ID": "req-abc_123.xy"})
    assert ok_resp.status_code == 200
    assert ok_resp.headers["x-request-id"] == "req-abc_123.xy"
    assert ok_resp.headers["cache-control"] == "no-store"

    for bad_id in ("bad id with spaces", "bad\nid", "<script>alert(1)</script>", "x" * 200):
        resp = client.get("/health", headers={"X-Request-ID": bad_id})
        assert resp.status_code == 200
        echoed = resp.headers["x-request-id"]
        assert echoed != bad_id
        assert len(echoed) == 32

    ui_resp = client.get("/")
    assert ui_resp.status_code == 200
    assert ui_resp.headers["x-content-type-options"] == "nosniff"
    assert "cache-control" not in ui_resp.headers


def test_body_size_limit_returns_413_with_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTSHIELD_MAX_BODY_BYTES", "64")
    client = TestClient(create_app())

    too_big = client.post(
        "/api/v1/evaluate-prompt",
        json={"text": "A" * 200, "source": "direct_user"},
        headers={"X-Request-ID": "req-large-1"},
    )
    assert too_big.status_code == 413
    assert too_big.json()["error"] == "Payload too large"
    assert too_big.json()["request_id"] == "req-large-1"
    assert too_big.headers["x-request-id"] == "req-large-1"
    assert too_big.headers["x-content-type-options"] == "nosniff"
    assert too_big.headers["cache-control"] == "no-store"

    def chunked_body() -> Iterator[bytes]:
        yield b'{"text":"'
        yield b"B" * 100
        yield b'"}'

    chunked_resp = client.post(
        "/api/v1/evaluate-prompt",
        content=chunked_body(),
        headers={"Content-Type": "application/json"},
    )
    assert chunked_resp.status_code == 413
    assert chunked_resp.json()["error"] == "Payload too large"


def test_global_exception_handler_sanitizes_500_and_preserves_http_errors() -> None:
    app = create_app()

    @app.get("/api/v1/test-boom")
    def trigger_boom() -> dict[str, str]:
        raise RuntimeError("sensitive internal secret path /var/secrets")

    @app.get("/api/v1/test-http")
    def trigger_http() -> dict[str, str]:
        raise HTTPException(status_code=404, detail="Policy item not found")

    client = TestClient(app, raise_server_exceptions=False)

    boom_resp = client.get("/api/v1/test-boom", headers={"X-Request-ID": "req-err-500"})
    assert boom_resp.status_code == 500
    assert boom_resp.json() == {"error": "Internal server error", "request_id": "req-err-500"}
    assert "sensitive internal secret" not in boom_resp.text
    assert boom_resp.headers["x-request-id"] == "req-err-500"
    assert boom_resp.headers["x-content-type-options"] == "nosniff"
    assert boom_resp.headers["cache-control"] == "no-store"

    http_resp = client.get("/api/v1/test-http")
    assert http_resp.status_code == 404
    assert http_resp.json()["detail"] == "Policy item not found"

    val_resp = client.post("/api/v1/evaluate-prompt", json={"text": ""})
    assert val_resp.status_code == 422


def test_cli_serve_invokes_uvicorn(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict[str, object] = {}

    def fake_run(target: object, host: str, port: int) -> None:
        called["target"] = target
        called["host"] = host
        called["port"] = port

    monkeypatch.setattr(agentshield_cli.uvicorn, "run", fake_run)
    rc = agentshield_cli.main(["serve", "--host", "0.0.0.0", "--port", "8090"])
    assert rc == 0
    assert called == {"target": "agentshield.server.app:app", "host": "0.0.0.0", "port": 8090}
