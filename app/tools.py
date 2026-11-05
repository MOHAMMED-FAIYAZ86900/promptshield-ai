from typing import Any

#Synthetic data only. Never place real customer information here.

SYNTHETIC_CUSTOMERS = {
"CUST-1001": {
"name": "Synthetic Customer A",
"email": "customer-a@example.test",
"account_status": "active",
},
"CUST-1002": {
"name": "Synthetic Customer B",
"email": "customer-b@example.test",
"account_status": "pending",
},
}

SUPPORT_TICKETS: list[dict[str, Any]] = []

#Helps prove that a denied tool was never executed.

TOOL_EXECUTION_COUNTS = {
"summarize_document": 0,
"create_support_ticket": 0,
"read_customer_record": 0,
"export_customer_data": 0,
}

def reset_sandbox() -> None:
    """Reset mutable state for repeatable tests."""
SUPPORT_TICKETS.clear()

for tool_name in TOOL_EXECUTION_COUNTS:
    TOOL_EXECUTION_COUNTS[tool_name] = 0

def summarize_document(document: str) -> dict[str, Any]:
    """Simulate a permitted document-summarization operation."""
    TOOL_EXECUTION_COUNTS["summarize_document"] += 1

    return {
        "status": "success",
    "summary": document[:500],
}

def create_support_ticket(
    subject: str,
    description: str,
    ) -> dict[str, Any]:
    """Create a synthetic support ticket."""
    TOOL_EXECUTION_COUNTS["create_support_ticket"] += 1

    ticket = {
        "ticket_id": f"TICKET-{len(SUPPORT_TICKETS) + 1:04d}",
        "subject": subject,
        "description": description,
}

    SUPPORT_TICKETS.append(ticket)

    return {
    "status": "success",
    "ticket": ticket,
}

def read_customer_record(customer_id: str) -> dict[str, Any]:
    """Restricted operation; must never run through the gateway."""
    TOOL_EXECUTION_COUNTS["read_customer_record"] += 1

    customer = SYNTHETIC_CUSTOMERS.get(customer_id)

    if customer is None:
        return {
            "status": "not_found",
            "customer_id": customer_id,
        }

    return {
        "status": "success",
        "customer_id": customer_id,
        "record": customer,
    }

def export_customer_data() -> dict[str, Any]:
    """Restricted operation; must never run through the gateway."""
    TOOL_EXECUTION_COUNTS["export_customer_data"] += 1

    return {
        "status": "success",
        "records": list(SYNTHETIC_CUSTOMERS.values()),
    }