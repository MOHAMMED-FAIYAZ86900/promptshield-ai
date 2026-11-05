from fastapi.testclient import TestClient

from app.main import app
from app.tools import TOOL_EXECUTION_COUNTS, reset_sandbox

client = TestClient(app)

def setup_function():
    reset_sandbox()

def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_legitimate_document_summary_executes():
    response = client.post("/agent/run",
    json={
        "action": "summarize_document",
        "arguments": {
        "document": "This is a synthetic support document."
            },
        },
    )

    assert response.status_code == 200

    result = response.json()

    assert result["status"] == "success"
    assert result["decision"] == "allow"
    assert TOOL_EXECUTION_COUNTS["summarize_document"] == 1

def test_restricted_customer_record_never_executes():
    response = client.post("/agent/run",
    json={
"action": "read_customer_record",
"arguments": {"customer_id": "CUST-1001"},
},
)

    assert response.status_code == 200

    result = response.json()

    assert result["status"] == "blocked"
    assert result["decision"] == "deny"
    assert TOOL_EXECUTION_COUNTS["read_customer_record"] == 0

def test_unknown_action_is_blocked():
    response = client.post(
"/agent/run",
    json={
"action": "delete_everything",
"arguments": {},
},
)


    assert response.status_code == 200
    assert response.json()["status"] == "blocked"

def test_support_ticket_creation_executes():
    response = client.post(
"/agent/run",
    json={
"action": "create_support_ticket",
"arguments": {
"subject": "Synthetic login issue",
"description": "The user cannot sign in.",
},
},
)

    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert TOOL_EXECUTION_COUNTS["create_support_ticket"] == 1
