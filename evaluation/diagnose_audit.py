
import json
from collections import Counter, defaultdict
from pathlib import Path


AUDIT_PATH = Path("logs/audit.jsonl")

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


def main():
    if not AUDIT_PATH.exists():
        raise SystemExit(f"Audit file not found: {AUDIT_PATH}")

    events = []
    malformed_lines = []
    legacy_lines = []
    missing_fields = Counter()

    for line_number, line in enumerate(
        AUDIT_PATH.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            malformed_lines.append((line_number, str(exc)))
            continue

        if not isinstance(event, dict):
            malformed_lines.append(
                (line_number, "JSON record is not an object")
            )
            continue

        missing = REQUIRED_FIELDS - event.keys()

        if missing:
            legacy_lines.append(
                (line_number, event, missing)
            )

            for field in missing:
                missing_fields[field] += 1

            continue

        events.append((line_number, event))

    grouped = defaultdict(list)

    for position, event in events:
        grouped[event["request_id"]].append((position, event))

    outcomes_without_intent = []
    multiple_intents = []
    multiple_outcomes = []
    blocked_and_intent = []
    valid_intent_outcome_pairs = 0

    for request_id, positioned_events in grouped.items():
        positioned_events.sort(key=lambda item: item[0])

        request_events = [
            event for _, event in positioned_events
        ]

        intents = [
            event for event in request_events
            if event["execution_status"] == "execution_intent"
        ]

        outcomes = [
            event for event in request_events
            if event["execution_status"] in {
                "executed",
                "execution_failed",
            }
        ]

        blocked = [
            event for event in request_events
            if event["execution_status"] == "blocked"
        ]

        if outcomes and not intents:
            outcomes_without_intent.append(
                (request_id, request_events)
            )

        if len(intents) > 1:
            multiple_intents.append(request_id)

        if len(outcomes) > 1:
            multiple_outcomes.append(request_id)

        if blocked and intents:
            blocked_and_intent.append(request_id)

        if intents and outcomes:
            intent_position = next(
                position for position, event in positioned_events
                if event["execution_status"] == "execution_intent"
            )

            outcome_position = next(
                position for position, event in positioned_events
                if event["execution_status"] in {
                    "executed",
                    "execution_failed",
                }
            )

            if intent_position < outcome_position:
                valid_intent_outcome_pairs += 1

    print("PromptShield Audit Diagnostics")
    print("=" * 34)
    print(f"Valid-schema events loaded: {len(events)}")
    print(f"Legacy-schema records: {len(legacy_lines)}")
    print(f"Malformed records: {len(malformed_lines)}")
    print(f"Requests with outcomes but no intent: "
          f"{len(outcomes_without_intent)}")
    print(f"Requests with multiple intents: {len(multiple_intents)}")
    print(f"Requests with multiple outcomes: {len(multiple_outcomes)}")
    print(f"Requests with both blocked and intent: "
          f"{len(blocked_and_intent)}")
    print(f"Ordered intent/outcome pairs: "
          f"{valid_intent_outcome_pairs}")

    print("\nMissing fields in legacy records:")
    for field, count in sorted(missing_fields.items()):
        print(f"  {field}: {count}")

    print("\nExecution outcomes without intent — first 10:")
    for request_id, request_events in outcomes_without_intent[:10]:
        statuses = [
            event["execution_status"]
            for event in request_events
        ]

        print(f"  {request_id}: {statuses}")

    if malformed_lines:
        print("\nMalformed lines — first 10:")
        for line_number, error in malformed_lines[:10]:
            print(f"  Line {line_number}: {error}")

    print(
        "\nDiagnostic complete. No audit records were modified."
    )


if __name__ == "__main__":
    main()
