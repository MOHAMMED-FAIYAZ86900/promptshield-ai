from copy import deepcopy

import pytest

from app.audit_integrity import (
    AuditIntegrityError,
    build_hash_chain,
    verify_hash_chain,
)


@pytest.fixture
def sample_events():
    return [
        {"action": "summarize_document", "decision": "allow"},
        {"action": "read_customer_record", "decision": "deny"},
        {"action": "create_support_ticket", "decision": "allow"},
    ]


def test_valid_chain_passes(sample_events):
    chain = build_hash_chain(sample_events)
    result = verify_hash_chain(chain)

    assert result["valid"] is True
    assert result["events_checked"] == 3
    assert result["errors"] == []


def test_modified_event_is_detected(sample_events):
    chain = build_hash_chain(sample_events)
    chain[1]["event"]["decision"] = "allow"

    result = verify_hash_chain(chain)

    assert result["valid"] is False
    assert result["errors"]


def test_deleted_event_is_detected(sample_events):
    chain = build_hash_chain(sample_events)
    del chain[1]

    result = verify_hash_chain(chain)

    assert result["valid"] is False
    assert result["errors"]


def test_reordered_events_are_detected(sample_events):
    chain = build_hash_chain(sample_events)
    chain[0], chain[1] = chain[1], chain[0]

    result = verify_hash_chain(chain)

    assert result["valid"] is False
    assert result["errors"]


def test_duplicated_event_is_detected(sample_events):
    chain = build_hash_chain(sample_events)
    chain.append(deepcopy(chain[-1]))

    result = verify_hash_chain(chain)

    assert result["valid"] is False
    assert result["errors"]


def test_non_dictionary_event_is_rejected():
    with pytest.raises(AuditIntegrityError):
        build_hash_chain([
            {"action": "summarize_document"},
            "invalid-event",
        ])


def test_empty_chain_is_valid():
    result = verify_hash_chain([])

    assert result["valid"] is True
    assert result["events_checked"] == 0
