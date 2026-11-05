
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_LOG = PROJECT_ROOT / "logs" / "stage12_verification.jsonl"

REQUIRED_FIELDS = {
    "event_id",
    "request_id",
    "timestamp",
    "action",
    "decision",
    "reason",
    "policy_id",
    "execution_status",
    "detection_evidence",
}

OUTCOME_STATUSES = {
    "executed",
    "blocked",
    "validation_failed",
    "execution_failed",
}


def load_events(log_path: Path):
    events = []
    findings = []

    if not log_path.exists():
        print(f"ERROR: Audit log not found: {log_path}")
        return events, findings, False

    with log_path.open("r", encoding="utf-8") as file:
        for line_number, raw_line in enumerate(file, start=1):
            if not raw_line.strip():
                findings.append(
                    f"Line {line_number}: blank line in audit log"
                )
                continue

            try:
                event = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                findings.append(
                    f"Line {line_number}: invalid JSON: {exc.msg}"
                )
                continue

            if not isinstance(event, dict):
                findings.append(
                    f"Line {line_number}: event must be a JSON object"
                )
                continue

            events.append((line_number, event))

    return events, findings, True


def validate_audit(log_path: Path) -> int:
    loaded, findings, log_exists = load_events(log_path)

    if not log_exists:
        return 2

    event_ids = defaultdict(list)
    requests = defaultdict(list)

    legacy_count = 0
    current_count = 0

    for line_number, event in loaded:
        missing = REQUIRED_FIELDS - event.keys()

        if missing:
            legacy_count += 1
            findings.append(
                f"Line {line_number}: missing fields: "
                + ", ".join(sorted(missing))
            )
        else:
            current_count += 1

        event_id = event.get("event_id")
        request_id = event.get("request_id")

        if event_id:
            event_ids[event_id].append(line_number)

        if request_id:
            requests[request_id].append((line_number, event))

        status = event.get("execution_status")

        if status == "execution_intent":
            if event.get("decision") != "allow":
                findings.append(
                    f"Line {line_number}: execution intent without allow decision"
                )

        if status == "executed":
            if event.get("decision") != "allow":
                findings.append(
                    f"Line {line_number}: executed event without allow decision"
                )

        if status == "blocked":
            if event.get("decision") != "deny":
                findings.append(
                    f"Line {line_number}: blocked event without deny decision"
                )

        evidence = event.get("detection_evidence")

        if evidence is not None and not isinstance(evidence, dict):
            findings.append(
                f"Line {line_number}: detection_evidence must be an object"
            )

    for event_id, line_numbers in event_ids.items():
        if len(line_numbers) > 1:
            findings.append(
                f"Duplicate event_id {event_id} on lines {line_numbers}"
            )

    complete_pairs = 0
    outcome_without_intent = 0
    multiple_intents = 0
    multiple_outcomes = 0
    blocked_with_intent = 0

    for request_id, records in requests.items():
        records.sort(key=lambda item: item[0])

        intents = [
            (line, event)
            for line, event in records
            if event.get("execution_status") == "execution_intent"
        ]

        outcomes = [
            (line, event)
            for line, event in records
            if event.get("execution_status") in OUTCOME_STATUSES
        ]

        if len(intents) > 1:
            multiple_intents += 1
            findings.append(
                f"Request {request_id}: multiple execution-intent events"
            )

        if len(outcomes) > 1:
            multiple_outcomes += 1
            findings.append(
                f"Request {request_id}: multiple outcome events"
            )

        if intents and any(
            event.get("execution_status") == "blocked"
            for _, event in outcomes
        ):
            blocked_with_intent += 1
            findings.append(
                f"Request {request_id}: blocked outcome and execution intent coexist"
            )

        if outcomes and not intents:
            outcome_without_intent += 1

        if len(intents) == 1 and len(outcomes) == 1:
            intent_line, intent_event = intents[0]
            outcome_line, outcome_event = outcomes[0]

            if intent_line < outcome_line:
                complete_pairs += 1
            else:
                findings.append(
                    f"Request {request_id}: outcome appears before intent"
                )

            if intent_event.get("action") != outcome_event.get("action"):
                findings.append(
                    f"Request {request_id}: action differs between intent and outcome"
                )

            if intent_event.get("decision") != outcome_event.get("decision"):
                findings.append(
                    f"Request {request_id}: decision differs between intent and outcome"
                )

    print("PromptShield Audit Validator v2")
    print("=" * 38)
    print(f"Audit log: {log_path}")
    print(f"Total parsed events: {len(loaded)}")
    print(f"Current-schema events: {current_count}")
    print(f"Legacy-schema events: {legacy_count}")
    print(f"Requests: {len(requests)}")
    print(f"Duplicate event IDs: {sum(len(v) > 1 for v in event_ids.values())}")
    print(f"Ordered intent/outcome pairs: {complete_pairs}")
    print(f"Outcomes without intent: {outcome_without_intent}")
    print(f"Requests with multiple intents: {multiple_intents}")
    print(f"Requests with multiple outcomes: {multiple_outcomes}")
    print(f"Requests with blocked outcome and intent: {blocked_with_intent}")
    print(f"Findings: {len(findings)}")

    if findings:
        print("\nFindings:")
        for finding in findings:
            print(f"- {finding}")

    print("\nValidation complete. No audit records were modified.")

    # Legacy records are reported, but do not by themselves fail validation.
    # Lifecycle anomalies, malformed records, and other findings do fail.
    critical_findings = [
        finding
        for finding in findings
        if not "missing fields:" in finding
    ]

    if critical_findings:
        print("\nRESULT: FAIL — review the findings above.")
        return 1

    print("\nRESULT: PASS — no critical findings detected.")
    return 0


if __name__ == "__main__":
    selected_log = (
        Path(sys.argv[1]).resolve()
        if len(sys.argv) > 1
        else DEFAULT_LOG
    )

    raise SystemExit(validate_audit(selected_log))
