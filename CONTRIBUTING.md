# Contributing to AgentShield

Thank you for contributing to **AgentShield**! We welcome new OWASP 2026 benchmark scenarios, detector signatures, tool capability inspectors, and framework adapters.

## Development Workflow

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/codesphere-u/agentshield.git
   cd agentshield
   ```
2. Run the full test suite and benchmark runner:
   ```bash
   uv run --with pytest --with fastapi --with httpx --with pydantic pytest -v
   uv run python -m agentshield.cli evaluate
   ```
3. Run Ruff linting:
   ```bash
   uv run --with ruff ruff check .
   ```

## Adding New Detection Rules or Benchmark Scenarios

- Every new detector signature in `agentshield/detectors/` or tool inspector in `agentshield/policy/engine.py` **must** include:
  - At least one adversarial positive test in `tests/test_agentshield.py`.
  - At least one benign negative control test to verify zero false positives.
  - Mapping to a canonical `OWASPCategory` enum value in `agentshield/models.py`.
