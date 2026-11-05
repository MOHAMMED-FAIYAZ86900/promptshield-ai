from fastapi.testclient import TestClient

from app.main import app
from app import main, tools


client = TestClient(app)


def setup_function():
    tools.reset_sandbox()


def test_integrity_intent_failure_prevents_execution(monkeypatch):
    def fail_integrity(**kwargs):
        raise OSError("Synthetic integrity storage failure")

    monkeypatch.setattr(main, "append_integrity_event", fail_integrity)

    before = tools.TOOL_EXECUTION_COUNTS["summarize_document"]

    response = client.post(
        "/agent/run",
        json={
            "action": "summarize_document",
            "arguments": {"document": "Integrity failure test."},
        },
    )

    result = response.json()

    assert response.status_code == 200
    assert result["status"] == "blocked"
    assert result["execution_status"] == "blocked"

    after = tools.TOOL_EXECUTION_COUNTS["summarize_document"]
    assert after == before


def test_integrity_outcome_failure_does_not_claim_blocked(monkeypatch):
    original_append = main.append_integrity_event
    calls = {"count": 0}

    def fail_outcome(**kwargs):
        calls["count"] += 1

        if calls["count"] == 2:
            raise OSError("Synthetic integrity outcome failure")

        return original_append(**kwargs)

    monkeypatch.setattr(main, "append_integrity_event", fail_outcome)

    before = tools.TOOL_EXECUTION_COUNTS["summarize_document"]

    response = client.post(
        "/agent/run",
        json={
            "action": "summarize_document",
            "arguments": {"document": "Integrity outcome test."},
        },
    )

    result = response.json()

    assert response.status_code == 200
    assert result["status"] == "success"
    assert result["execution_status"] == "executed"
    assert result["audit_warning"]

    after = tools.TOOL_EXECUTION_COUNTS["summarize_document"]
    assert after == before + 1
