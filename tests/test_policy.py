from app.policy_engine import authorize_action, Decision

def test_document_summary_is_allowed():
    result = authorize_action("summarize_document")
    assert result.decision == Decision.ALLOW

def test_support_ticket_is_allowed():
    result = authorize_action("create_support_ticket")
    assert result.decision == Decision.ALLOW

def test_customer_record_access_is_denied():
    result = authorize_action("read_customer_record")
    assert result.decision == Decision.DENY

def test_customer_data_export_is_denied():
    result = authorize_action("export_customer_data")
    assert result.decision == Decision.DENY

def test_unknown_action_is_denied():
    result = authorize_action("delete_everything")
    assert result.decision == Decision.DENY
    assert result.policy_id == "PS-DENY-DEFAULT"
