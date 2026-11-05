
from fastapi.testclient import TestClient

from app.main import app
from app import main, tools


client = TestClient(app)


def setup_function():
    tools.reset_sandbox()


def test_intent_audit_failure_prevents_tool_execution(monkeypatch):
    def fail_audit(**kwargs):
        raise OSError("Synthetic audit storage failure")

    monkeypatch.setattr(main, "write_audit_event", fail_audit)

    before = tools.TOOL_EXECUTION_COUNTS["summarize_document"]

    response = client.post(
        "/agent/run",
        json={
            "action": "summarize_document",
            "arguments": {"document": "Synthetic test document."},
        },
    )

    result = response.json()

    assert response.status_code == 200
    assert result["status"] == "blocked"
    assert result["execution_status"] == "blocked"
    assert result["policy_id"] == "PS-FAIL-CLOSED-AUDIT-INTENT"

    after = tools.TOOL_EXECUTION_COUNTS["summarize_document"]
    assert after == before


def test_outcome_audit_failure_does_not_claim_execution_was_blocked(
    monkeypatch,
):
    original_write = main.write_audit_event
    calls = {"count": 0}

    def fail_second_audit(**kwargs):
        calls["count"] += 1

        # First write is execution intent; second is execution outcome.
        if calls["count"] == 2:
            raise OSError("Synthetic outcome audit failure")

        return original_write(**kwargs)

    monkeypatch.setattr(main, "write_audit_event", fail_second_audit)

    before = tools.TOOL_EXECUTION_COUNTS["summarize_document"]

    response = client.post(
        "/agent/run",
        json={
            "action": "summarize_document",
            "arguments": {"document": "Synthetic test document."},
        },
    )

    result = response.json()

    assert response.status_code == 200
    assert result["status"] == "success"
    assert result["execution_status"] == "executed"
    assert result["audit_warning"]
    assert "executed" in result["audit_warning"].lower()

    after = tools.TOOL_EXECUTION_COUNTS["summarize_document"]
    assert after == before + 1


def test_invalid_arguments_do_not_execute_tool():
    before = tools.TOOL_EXECUTION_COUNTS["summarize_document"]

    response = client.post(
        "/agent/run",
        json={
            "action": "summarize_document",
            "arguments": {},
        },
    )

    result = response.json()

    assert result["status"] == "invalid_arguments"
    assert result["execution_status"] == "validation_failed"

    after = tools.TOOL_EXECUTION_COUNTS["summarize_document"]
    assert after == before


def test_registered_tool_execution_failure_is_reported(monkeypatch):
    def fail_tool(document):
        raise RuntimeError("Synthetic tool failure")

    monkeypatch.setitem(
        main.prepare_registered_tool.__globals__["EXECUTORS"],
        "summarize_document",
        (
            main.prepare_registered_tool.__globals__["EXECUTORS"][
                "summarize_document"
            ][0],
            fail_tool,
        ),
    )

    response = client.post(
        "/agent/run",
        json={
            "action": "summarize_document",
            "arguments": {"document": "Synthetic test document."},
        },
    )

    result = response.json()

    assert result["status"] == "execution_failed"
    assert result["execution_status"] == "execution_failed"
