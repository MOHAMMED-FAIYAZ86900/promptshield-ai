
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


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

VALID_DECISIONS = {"allow", "deny"}

VALID_STATUSES = {
    "blocked",
    "validation_failed",
    "execution_intent",
    "executed",
    "execution_failed",
}


def load_events(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Load valid JSON objects and collect parsing/schema errors."""

    events = []
    errors = []

    if not path.exists():
        return [], [f"Audit file does not exist: {path}"]

    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(
                f"Line {line_number}: invalid JSON: {exc.msg}"
            )
            continue

        if not isinstance(event, dict):
            errors.append(
                f"Line {line_number}: event must be a JSON object."
            )
            continue

        missing = REQUIRED_FIELDS - event.keys()

        if missing:
            errors.append(
                f"Line {line_number}: missing fields: "
                f"{', '.join(sorted(missing))}"
            )
            continue

        events.append(event)

    return events, errors


def validate_events(
    events: list[dict[str, Any]],
) -> list[str]:
    """Check event IDs, field values, and request lifecycle consistency."""

    errors = []

    event_id_counts = Counter(
        event["event_id"] for event in events
    )

    for event_id, count in event_id_counts.items():
        if count > 1:
            errors.append(
                f"Duplicate event_id {event_id}: {count} occurrences."
            )

    grouped = defaultdict(list)

    for position, event in enumerate(events):
        grouped[event["request_id"]].append(
            (position, event)
        )

        if event["decision"] not in VALID_DECISIONS:
            errors.append(
                f"Event {event['event_id']}: invalid decision."
            )

        if event["execution_status"] not in VALID_STATUSES:
            errors.append(
                f"Event {event['event_id']}: invalid execution_status."
            )

        if not isinstance(event["detection_evidence"], dict):
            errors.append(
                f"Event {event['event_id']}: detection_evidence "
                "must be an object."
            )

        if not isinstance(event["action"], str) or not event["action"]:
            errors.append(
                f"Event {event['event_id']}: action must be non-empty."
            )

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

        if len(intents) > 1:
            errors.append(
                f"Request {request_id}: multiple execution-intent events."
            )

        if outcomes and not intents:
            errors.append(
                f"Request {request_id}: execution outcome exists "
                "without an execution-intent event."
            )

        if intents and blocked:
            errors.append(
                f"Request {request_id}: blocked event and execution "
                "intent both exist; investigate the sequence."
            )

        if len(outcomes) > 1:
            errors.append(
                f"Request {request_id}: multiple terminal execution "
                "outcomes exist."
            )

        if intents and outcomes:
            intent_position = next(
                position
                for position, event in positioned_events
                if event["execution_status"] == "execution_intent"
            )

            outcome_position = next(
                position
                for position, event in positioned_events
                if event["execution_status"] in {
                    "executed",
                    "execution_failed",
                }
            )

            if outcome_position <= intent_position:
                errors.append(
                    f"Request {request_id}: execution outcome appears "
                    "before intent in the audit file."
                )

            intent = intents[0]
            outcome = outcomes[0]

            if intent["action"] != outcome["action"]:
                errors.append(
                    f"Request {request_id}: action differs between "
                    "intent and outcome."
                )

            if intent["decision"] != "allow":
                errors.append(
                    f"Request {request_id}: execution intent does "
                    "not have an allow decision."
                )

    return errors


def main():
    events, errors = load_events(AUDIT_PATH)

    errors.extend(validate_events(events))

    print("PromptShield Audit Validation")
    print("=" * 32)
    print(f"Audit file: {AUDIT_PATH}")
    print(f"Events loaded: {len(events)}")

    if errors:
        print(f"\nFindings: {len(errors)}")

        for index, error in enumerate(errors, start=1):
            print(f"{index}. {error}")

        raise SystemExit(1)

    print("Findings: 0")
    print("PASS: All implemented audit checks passed.")


if __name__ == "__main__":
    main()
