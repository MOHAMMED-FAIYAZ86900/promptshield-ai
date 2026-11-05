import json

import pytest

from app.audit_integrity import (
    AuditIntegrityError,
    append_integrity_event,
    verify_integrity_storage,
)


def test_persistent_append_and_checkpoint(tmp_path):
    log = tmp_path / "audit.jsonl"
    checkpoint = tmp_path / "checkpoint.json"

    append_integrity_event(
        {"action": "summarize_document", "decision": "allow"},
        log,
        checkpoint,
    )

    append_integrity_event(
        {"action": "read_customer_record", "decision": "deny"},
        log,
        checkpoint,
    )

    result = verify_integrity_storage(log, checkpoint)

    assert result["valid"] is True
    assert result["events_checked"] == 2
    assert result["checkpoint_present"] is True


def test_modified_persistent_event_is_detected(tmp_path):
    log = tmp_path / "audit.jsonl"
    checkpoint = tmp_path / "checkpoint.json"

    append_integrity_event(
        {"action": "summarize_document"},
        log,
        checkpoint,
    )

    entries = [
        json.loads(line)
        for line in log.read_text(encoding="utf-8").splitlines()
    ]
    entries[0]["event"]["action"] = "export_customer_data"
    log.write_text(
        "".join(json.dumps(item) + "\n" for item in entries),
        encoding="utf-8",
    )

    result = verify_integrity_storage(log, checkpoint)
    assert result["valid"] is False


def test_checkpoint_tampering_is_detected(tmp_path):
    log = tmp_path / "audit.jsonl"
    checkpoint = tmp_path / "checkpoint.json"

    append_integrity_event(
        {"action": "summarize_document"},
        log,
        checkpoint,
    )

    data = json.loads(checkpoint.read_text(encoding="utf-8"))
    data["event_count"] = 999
    checkpoint.write_text(json.dumps(data), encoding="utf-8")

    result = verify_integrity_storage(log, checkpoint)
    assert result["valid"] is False


def test_missing_checkpoint_is_detected(tmp_path):
    log = tmp_path / "audit.jsonl"
    checkpoint = tmp_path / "checkpoint.json"

    append_integrity_event(
        {"action": "summarize_document"},
        log,
        checkpoint,
    )

    checkpoint.unlink()

    result = verify_integrity_storage(log, checkpoint)
    assert result["valid"] is False


def test_append_refuses_corrupted_chain(tmp_path):
    log = tmp_path / "audit.jsonl"
    checkpoint = tmp_path / "checkpoint.json"

    append_integrity_event(
        {"action": "summarize_document"},
        log,
        checkpoint,
    )

    entries = [
        json.loads(line)
        for line in log.read_text(encoding="utf-8").splitlines()
    ]
    entries[0]["event"]["action"] = "tampered"
    log.write_text(
        "".join(json.dumps(item) + "\n" for item in entries),
        encoding="utf-8",
    )

    with pytest.raises(AuditIntegrityError):
        append_integrity_event(
            {"action": "create_support_ticket"},
            log,
            checkpoint,
        )
