import json
from collections import defaultdict, Counter
from pathlib import Path

source = Path("logs/audit.jsonl")
output = Path("reports/stage16_audit_classification.json")

events = [
    json.loads(line)
    for line in source.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

groups = defaultdict(list)
for event in events:
    request_id = event.get("request_id")
    if request_id:
        groups[request_id].append(event)

missing_intent = []
for request_id, request_events in groups.items():
    has_executed = any(
        event.get("execution_status") == "executed"
        for event in request_events
    )
    has_intent = any(
        event.get("execution_status") == "execution_intent"
        for event in request_events
    )
    if has_executed and not has_intent:
        missing_intent.append({
            "request_id": request_id,
            "timestamps": [
                event.get("timestamp") for event in request_events
            ],
            "actions": sorted({
                event.get("action") for event in request_events
            }),
            "classification": "executed_without_recorded_intent",
            "root_cause": "unverified",
        })

incomplete = [
    {
        "event_id": event.get("event_id"),
        "request_id": event.get("request_id"),
        "timestamp": event.get("timestamp"),
        "execution_status": event.get("execution_status"),
        "missing_fields": [
            field for field in ("request_id", "detection_evidence")
            if field not in event
        ],
        "classification": "legacy_or_incomplete_schema",
        "root_cause": "unverified",
    }
    for event in events
    if not event.get("request_id")
    or "detection_evidence" not in event
]

by_date = Counter(
    item["timestamps"][0][:10]
    for item in missing_intent
    if item["timestamps"] and item["timestamps"][0]
)

report = {
    "source": str(source),
    "source_modified": __import__("datetime").datetime.fromtimestamp(
        source.stat().st_mtime
    ).astimezone().isoformat(),
    "total_events": len(events),
    "requests_with_ids": len(groups),
    "executed_without_intent_count": len(missing_intent),
    "executed_without_intent_by_date": dict(sorted(by_date.items())),
    "legacy_or_incomplete_event_count": len(incomplete),
    "root_cause_status": "not_proven",
    "records_modified": False,
    "executed_without_intent": missing_intent,
    "legacy_or_incomplete_events": incomplete,
}

output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(
    json.dumps(report, indent=2, ensure_ascii=False) + "\n",
    encoding="utf-8",
)

print("Report created:", output)
print("Total events:", len(events))
print("Executions without intent:", len(missing_intent))
print("Legacy/incomplete events:", len(incomplete))
print("Original audit log modified: No")
