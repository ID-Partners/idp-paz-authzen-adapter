"""Coverage gate for the concierge's Grant Management client.

Enforces 100% line coverage on the functions that talk to the authorization server —
`_gm_call` and the token-claim readers. A missed line there is a response shape nobody
tested, and the failure mode is the one we already hit in production: a non-dict answer
crashing the agent turn, or an error rendering as a policy decision.

Deliberately scoped to those functions rather than the whole module: `agent_events` drives
Anthropic and the A2A task agents, so covering it here would mean mocking the world and
would test the mocks. It is covered by the deployed E2E instead.

Run: pytest --cov=agent_core --cov-report=json:.coverage.json && pytest test_coverage_gate.py
(the gate reads the report the main run produced; it skips if there is none).
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

GATED = {"_gm_call", "_token_claim", "_token_sub"}
HERE = Path(__file__).parent


def _report():
    for name in (".coverage.json", "/tmp/cov.json"):
        p = Path(name) if name.startswith("/") else HERE / name
        if p.exists():
            return json.loads(p.read_text())
    return None


@pytest.mark.parametrize("func", sorted(GATED))
def test_gated_function_is_fully_covered(func):
    report = _report()
    if report is None:
        pytest.skip("no coverage report; run pytest --cov=agent_core --cov-report=json first")

    files = report.get("files", {})
    entry = next((v for k, v in files.items() if k.endswith("agent_core.py")), None)
    assert entry is not None, "agent_core.py absent from the coverage report"

    missing = set(entry["missing_lines"])
    tree = ast.parse((HERE / "agent_core.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func:
            gaps = sorted(l for l in range(node.lineno, node.end_lineno + 1) if l in missing)
            assert not gaps, f"{func} has uncovered lines {gaps} — every response shape must be tested"
            return
    pytest.fail(f"{func} not found in agent_core.py")
