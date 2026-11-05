
import json
import sys
from collections import defaultdict
from pathlib import Path

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

KNOWN_STATUSES = OUTCOME_STATUSES | {"execution_intent"}


def load_events(log_path):
    events = []
    critical = []
    warnings = []

    if not log_path.is_file():
        critical.append(f"Audit log does not exist: {log_path}")
        return events, critical, warnings

    with log_path.open("r", encoding="utf-8") as file:
        for line_number, raw_line in enumerate(file, start=1):
            if not raw_line.strip():
                critical.append(
                    f"Line {line_number}: blank line in audit log"
                )
                continue

            try:
                event = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                critical.append(
                    f"Line {line_number}: invalid JSON: {exc.msg}"
                )
                continue

            if not isinstance(event, dict):
                critical.append(
                    f"Line {line_number}: event must be a JSON object"
                )
                continue

            events.append((line_number, event))

    return events, critical, warnings


def validate_audit(log_path):
    loaded, critical, warnings = load_events(log_path)

    if critical and not loaded:
        print("PromptShield Audit Validator v3")
        print("=" * 38)
        for finding in critical:
            print(f"CRITICAL: {finding}")
        print("\nRESULT: FAIL")
        return 2

    event_ids = defaultdict(list)
    requests = defaultdict(list)

    current_schema_count = 0
    legacy_schema_count = 0

    for line_number, event in loaded:
        missing = REQUIRED_FIELDS - event.keys()

        if missing:
            legacy_schema_count += 1
            warnings.append(
                f"Line {line_number}: legacy/incomplete schema; "
                f"missing {', '.join(sorted(missing))}"
            )
        else:
            current_schema_count += 1

        event_id = event.get("event_id")
        request_id = event.get("request_id")

        if not isinstance(event_id, str) or not event_id:
            critical.append(
                f"Line {line_number}: missing or invalid event_id"
            )
        else:
            event_ids[event_id].append(line_number)

        if not isinstance(request_id, str) or not request_id:
            # Legacy records may not have request IDs.
            if missing:
                continue
            critical.append(
                f"Line {line_number}: missing or invalid request_id"
            )
            continue

        requests[request_id].append((line_number, event))

        status = event.get("execution_status")
        decision = event.get("decision")
        evidence = event.get("detection_evidence")

        if status not in KNOWN_STATUSES:
            critical.append(
                f"Line {line_number}: unknown execution_status {status!r}"
            )

        if status in {"execution_intent", "executed", "execution_failed"}:
            if decision != "allow":
                critical.append(
                    f"Line {line_number}: {status} requires decision='allow'"
                )

        if status == "blocked" and decision != "deny":
            critical.append(
                f"Line {line_number}: blocked requires decision='deny'"
            )

        if evidence is not None and not isinstance(evidence, dict):
            critical.append(
                f"Line {line_number}: detection_evidence must be an object"
            )

    for event_id, line_numbers in event_ids.items():
        if len(line_numbers) > 1:
            critical.append(
                f"Duplicate event_id {event_id} on lines {line_numbers}"
            )

    complete_pairs = 0
    executed_without_intent = 0
    execution_failed_without_intent = 0
    blocked_with_intent = 0
    validation_failed_with_intent = 0
    intents_without_outcome = 0
    multiple_intents = 0
    multiple_outcomes = 0

    for request_id, records in requests.items():
        records.sort(key=lambda record: record[0])

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
            critical.append(
                f"Request {request_id}: multiple execution-intent events"
            )

        if len(outcomes) > 1:
            multiple_outcomes += 1
            critical.append(
                f"Request {request_id}: multiple outcome events"
            )

        statuses = [
            event.get("execution_status")
            for _, event in outcomes
        ]

        if intents and "blocked" in statuses:
            blocked_with_intent += 1
            critical.append(
                f"Request {request_id}: blocked outcome coexists with intent"
            )

        if intents and "validation_failed" in statuses:
            validation_failed_with_intent += 1
            critical.append(
                f"Request {request_id}: validation failure coexists with intent"
            )

        if "executed" in statuses and not intents:
            executed_without_intent += 1
            critical.append(
                f"Request {request_id}: executed without execution intent"
            )

        if "execution_failed" in statuses and not intents:
            execution_failed_without_intent += 1
            critical.append(
                f"Request {request_id}: execution failed without execution intent"
            )

        if intents and not outcomes:
            intents_without_outcome += 1
            warnings.append(
                f"Request {request_id}: intent has no recorded outcome; "
                "investigate audit-write failures or interrupted requests"
            )

        if len(intents) == 1 and len(outcomes) == 1:
            intent_line, intent_event = intents[0]
            outcome_line, outcome_event = outcomes[0]

            if intent_line >= outcome_line:
                critical.append(
                    f"Request {request_id}: outcome appears before intent"
                )
            else:
                complete_pairs += 1

            if intent_event.get("action") != outcome_event.get("action"):
                critical.append(
                    f"Request {request_id}: action mismatch between intent and outcome"
                )

            if intent_event.get("decision") != outcome_event.get("decision"):
                critical.append(
                    f"Request {request_id}: decision mismatch between intent and outcome"
                )

    print("PromptShield Audit Validator v3")
    print("=" * 38)
    print(f"Audit log: {log_path}")
    print(f"Total parsed events: {len(loaded)}")
    print(f"Current-schema events: {current_schema_count}")
    print(f"Legacy/incomplete-schema events: {legacy_schema_count}")
    print(f"Requests: {len(requests)}")
    print(f"Duplicate event IDs: {sum(len(v) > 1 for v in event_ids.values())}")
    print(f"Ordered intent/outcome pairs: {complete_pairs}")
    print(f"Executed without intent: {executed_without_intent}")
    print(f"Execution failures without intent: {execution_failed_without_intent}")
    print(f"Blocked outcomes with intent: {blocked_with_intent}")
    print(f"Validation failures with intent: {validation_failed_with_intent}")
    print(f"Intents without recorded outcomes: {intents_without_outcome}")
    print(f"Requests with multiple intents: {multiple_intents}")
    print(f"Requests with multiple outcomes: {multiple_outcomes}")
    print(f"Critical findings: {len(critical)}")
    print(f"Warnings: {len(warnings)}")

    if critical:
        print("\nCritical findings:")
        for finding in critical:
            print(f"- {finding}")

    if warnings:
        print("\nWarnings:")
        for warning in warnings:
            print(f"- {warning}")

    print("\nValidation complete. No audit records were modified.")

    if critical:
        print("\nRESULT: FAIL — investigate critical findings.")
        return 1

    print("\nRESULT: PASS — no critical findings detected.")

    if warnings:
        print("NOTE: Review warnings before treating the log as fully verified.")

    return 0


if __name__ == "__main__":
    selected_log = (
        Path(sys.argv[1]).resolve()
        if len(sys.argv) > 1
        else DEFAULT_LOG
    )

    raise SystemExit(validate_audit(selected_log))
