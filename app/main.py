
from uuid import uuid4
from typing import Any
import os
import json
import secrets
from pathlib import Path

from fastapi import (
    FastAPI,
    Depends,
    Header,
    HTTPException,
    Query,
)

from app import tools
from app.audit import write_audit_event, AUDIT_LOG_PATH
from app.audit_integrity import append_integrity_event
from app.detector import detect_prompt_injection
from app.executor import (
    ToolExecutionError,
    ToolValidationError,
    execute_prepared_tool,
    prepare_registered_tool,
)
from app.policy_engine import Decision, authorize_action
from app.schemas import DocumentAnalysisRequest, ToolRequest


app = FastAPI(
    title="PromptShield AI",
    description=(
        "Runtime security gateway for AI agents. "
        "Deterministic authorization, prompt-injection detection, "
        "and security audit logging."
    ),
    version="0.1.0",
)


# ============================================================
# API AUTHENTICATION
# ============================================================

def verify_api_key(
    x_api_key: str | None = Header(default=None),
):
    """
    Require an API key when PROMPTSHIELD_API_KEY is configured.

    Local development remains compatible when the variable
    is not configured.
    """

    expected_key = os.getenv("PROMPTSHIELD_API_KEY")

    if not expected_key:
        return

    if not x_api_key or not secrets.compare_digest(
        x_api_key,
        expected_key,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
        )


# ============================================================
# BASIC ENDPOINTS
# ============================================================

@app.get("/")
def root():
    return {
        "project": "PromptShield AI",
        "stage": 10,
        "status": "running",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


# ============================================================
# AUDIT EVENT PERSISTENCE
# ============================================================

def _audit_event(
    *,
    request_id: str,
    action: str,
    decision: str,
    reason: str,
    policy_id: str,
    execution_status: str,
    detection_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist one audit event or propagate the persistence error."""

    event = write_audit_event(
        request_id=request_id,
        action=action,
        decision=decision,
        reason=reason,
        policy_id=policy_id,
        execution_status=execution_status,
        detection_evidence=detection_evidence,
    )

    project_root = Path(__file__).resolve().parent.parent

    integrity_log = Path(
        os.environ.get(
            "PROMPTSHIELD_INTEGRITY_LOG",
            str(project_root / "logs" / "integrity_audit.jsonl"),
        )
    )

    integrity_checkpoint = Path(
        os.environ.get(
            "PROMPTSHIELD_INTEGRITY_CHECKPOINT",
            str(project_root / "logs" / "integrity_checkpoint.json"),
        )
    )

    append_integrity_event(
        event=event,
        log_path=integrity_log,
        checkpoint_path=integrity_checkpoint,
    )

    return event


# ============================================================
# BLOCKED RESPONSE
# ============================================================

def _blocked_response(
    *,
    request_id: str,
    action: str,
    reason: str,
    policy_id: str,
    detection_evidence: dict[str, Any] | None = None,
):
    """Record and return a blocked decision."""

    try:
        event = _audit_event(
            request_id=request_id,
            action=action,
            decision="deny",
            reason=reason,
            policy_id=policy_id,
            execution_status="blocked",
            detection_evidence=detection_evidence,
        )

        audit_event_id = event["event_id"]
        audit_error = None

    except Exception:
        audit_event_id = None
        audit_error = "Audit persistence failed."

    response = {
        "status": "blocked",
        "request_id": request_id,
        "action": action,
        "decision": "deny",
        "reason": reason,
        "policy_id": policy_id,
        "execution_status": "blocked",
    }

    if detection_evidence is not None:
        response["detection"] = detection_evidence

    if audit_event_id:
        response["audit_event_id"] = audit_event_id

    if audit_error:
        response["audit_warning"] = audit_error

    return response


# ============================================================
# AUTHORIZED TOOL EXECUTION
# ============================================================

def _run_authorized_action(
    *,
    request_id: str,
    action: str,
    arguments: dict[str, Any],
    detection_evidence: dict[str, Any] | None = None,
):
    """
    Validate, persist execution intent, execute, and record outcome.

    The tool must not execute unless the execution-intent event
    has been persisted successfully.
    """

    # 1. Authorize the action.
    try:
        policy = authorize_action(action)

    except Exception:
        return _blocked_response(
            request_id=request_id,
            action=action,
            reason="Authorization failed; execution was blocked.",
            policy_id="PS-FAIL-CLOSED-AUTHORIZATION",
            detection_evidence=detection_evidence,
        )

    if policy.decision == Decision.DENY:
        return _blocked_response(
            request_id=request_id,
            action=action,
            reason=policy.reason,
            policy_id=policy.policy_id,
            detection_evidence=detection_evidence,
        )

    # 2. Resolve executor and validate arguments.
    try:
        prepared = prepare_registered_tool(
            action,
            arguments,
        )

    except ToolValidationError as exc:
        reason = str(exc)

        try:
            event = _audit_event(
                request_id=request_id,
                action=action,
                decision="allow",
                reason=reason,
                policy_id=policy.policy_id,
                execution_status="validation_failed",
                detection_evidence=detection_evidence,
            )

            audit_event_id = event["event_id"]
            audit_warning = None

        except Exception:
            audit_event_id = None
            audit_warning = "Audit persistence failed."

        response = {
            "status": "invalid_arguments",
            "request_id": request_id,
            "action": action,
            "decision": "allow",
            "reason": reason,
            "policy_id": policy.policy_id,
            "execution_status": "validation_failed",
        }

        if detection_evidence is not None:
            response["detection"] = detection_evidence

        if audit_event_id:
            response["audit_event_id"] = audit_event_id

        if audit_warning:
            response["audit_warning"] = audit_warning

        return response

    # 3. Persist execution intent before side effects.
    try:
        intent_event = _audit_event(
            request_id=request_id,
            action=action,
            decision="allow",
            reason="Authorization and argument validation succeeded.",
            policy_id=policy.policy_id,
            execution_status="execution_intent",
            detection_evidence=detection_evidence,
        )

    except Exception:
        return {
            "status": "blocked",
            "request_id": request_id,
            "action": action,
            "decision": "deny",
            "reason": (
                "Execution-intent audit persistence failed; "
                "the tool was not executed."
            ),
            "policy_id": "PS-FAIL-CLOSED-AUDIT-INTENT",
            "execution_status": "blocked",
            "audit_warning": "Audit persistence failed.",
            **(
                {"detection": detection_evidence}
                if detection_evidence is not None
                else {}
            ),
        }

    # 4. Execute only after intent persistence succeeds.
    try:
        result = execute_prepared_tool(prepared)

    except ToolExecutionError:
        reason = "The authorized tool failed during execution."

        try:
            outcome_event = _audit_event(
                request_id=request_id,
                action=action,
                decision="allow",
                reason=reason,
                policy_id=policy.policy_id,
                execution_status="execution_failed",
                detection_evidence=detection_evidence,
            )

            outcome_event_id = outcome_event["event_id"]
            audit_warning = None

        except Exception:
            outcome_event_id = None
            audit_warning = "Outcome audit persistence failed."

        response = {
            "status": "execution_failed",
            "request_id": request_id,
            "action": action,
            "decision": "allow",
            "reason": reason,
            "policy_id": policy.policy_id,
            "execution_status": "execution_failed",
            "intent_audit_event_id": intent_event["event_id"],
        }

        if detection_evidence is not None:
            response["detection"] = detection_evidence

        if outcome_event_id:
            response["audit_event_id"] = outcome_event_id

        if audit_warning:
            response["audit_warning"] = audit_warning

        return response

    # 5. Record the actual outcome.
    try:
        outcome_event = _audit_event(
            request_id=request_id,
            action=action,
            decision="allow",
            reason=policy.reason,
            policy_id=policy.policy_id,
            execution_status="executed",
            detection_evidence=detection_evidence,
        )

        outcome_event_id = outcome_event["event_id"]
        audit_warning = None

    except Exception:
        # The tool already ran. Never misreport it as blocked.
        outcome_event_id = None
        audit_warning = (
            "Tool executed, but outcome audit persistence failed."
        )

    response = {
        "status": "success",
        "request_id": request_id,
        "action": action,
        "decision": "allow",
        "reason": policy.reason,
        "policy_id": policy.policy_id,
        "execution_status": "executed",
        "result": result,
        "intent_audit_event_id": intent_event["event_id"],
    }

    if detection_evidence is not None:
        response["detection"] = detection_evidence

    if outcome_event_id:
        response["audit_event_id"] = outcome_event_id

    if audit_warning:
        response["audit_warning"] = audit_warning

    return response


# ============================================================
# TOOL EXECUTION ENDPOINT
# ============================================================

@app.post("/agent/run")
def execute_tool(
    request: ToolRequest,
    _: None = Depends(verify_api_key),
):
    request_id = str(uuid4())

    return _run_authorized_action(
        request_id=request_id,
        action=request.action,
        arguments=request.arguments,
    )


# ============================================================
# DOCUMENT ANALYSIS ENDPOINT
# ============================================================

@app.post("/agent/analyze-document")
def analyze_document(
    request: DocumentAnalysisRequest,
    _: None = Depends(verify_api_key),
):
    request_id = str(uuid4())
    action = request.proposed_action

    # Detection must succeed before authorization or execution.
    try:
        detection = detect_prompt_injection(request.document)

        detection_evidence = {
            "suspicious": detection.suspicious,
            "risk_score": detection.risk_score,
            "matched_indicators": list(
                detection.matched_indicators
            ),
            "explanation": detection.explanation,
        }

    except Exception:
        return _blocked_response(
            request_id=request_id,
            action=action,
            reason="Security detection failed; execution was blocked.",
            policy_id="PS-FAIL-CLOSED-DETECTION",
            detection_evidence={"error": "detector_failure"},
        )

    if detection.suspicious:
        return _blocked_response(
            request_id=request_id,
            action=action,
            reason=(
                "Potential prompt injection detected. "
                "The proposed action was blocked."
            ),
            policy_id="PS-INJECTION-CONTAINMENT",
            detection_evidence=detection_evidence,
        )

    return _run_authorized_action(
        request_id=request_id,
        action=action,
        arguments=request.arguments,
        detection_evidence=detection_evidence,
    )


# ============================================================
# AUTHENTICATED AUDIT EVENTS ENDPOINT
# ============================================================

@app.get("/audit/events")
def get_audit_events(
    limit: int = Query(default=200, ge=1, le=500),
    _: None = Depends(verify_api_key),
):
    """
    Return recent conventional audit events.

    This endpoint is intended for the authenticated dashboard.
    It does not expose integrity checkpoint files.
    """

    if not AUDIT_LOG_PATH.exists():
        return {
            "events": [],
            "count": 0,
        }

    events = []

    try:
        with AUDIT_LOG_PATH.open(
            "r",
            encoding="utf-8",
        ) as file:

            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    events.append(json.loads(line))

                except json.JSONDecodeError:
                    continue

    except OSError:
        raise HTTPException(
            status_code=500,
            detail="Unable to read audit log",
        )

    recent_events = events[-limit:]
    recent_events.reverse()

    return {
        "events": recent_events,
        "count": len(recent_events),
    }
