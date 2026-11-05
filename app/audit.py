
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any
from uuid import uuid4


PROJECT_ROOT = Path(__file__).resolve().parent.parent

AUDIT_LOG_PATH = Path(
    os.environ.get(
        "PROMPTSHIELD_AUDIT_LOG",
        str(PROJECT_ROOT / "logs" / "audit.jsonl"),
    )
)

_LOCK = Lock()


def write_audit_event(
    *,
    action: str,
    decision: str,
    reason: str,
    policy_id: str,
    execution_status: str,
    request_id: str | None = None,
    detection_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Write a structured security audit event.

    Events are stored as JSON Lines: one JSON object per line.

    A request_id correlates events belonging to the same request.
    If one is not provided, a unique ID is generated for the event.

    This local prototype provides append-only application logging,
    but does not provide tamper-proof or cryptographically signed logs.
    """

    if request_id is None:
        request_id = str(uuid4())

    event = {
        "event_id": str(uuid4()),
        "request_id": request_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "decision": decision,
        "reason": reason,
        "policy_id": policy_id,
        "execution_status": execution_status,
        "detection_evidence": detection_evidence or {},
    }

    AUDIT_LOG_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    serialized_event = json.dumps(
        event,
        ensure_ascii=False,
    )

    with _LOCK:
        with AUDIT_LOG_PATH.open(
            "a",
            encoding="utf-8",
        ) as log_file:
            log_file.write(serialized_event + "\n")

    return event
