import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any, Iterable


GENESIS_HASH = "0" * 64
_STORAGE_LOCK = threading.Lock()


class AuditIntegrityError(Exception):
    """Raised when an audit event cannot be safely processed."""


def canonical_json(data: Any) -> str:
    try:
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise AuditIntegrityError(
            f"Event is not valid canonical JSON: {exc}"
        ) from exc


def calculate_event_hash(
    sequence: int,
    previous_hash: str,
    event: dict[str, Any],
) -> str:
    payload = {
        "sequence": sequence,
        "previous_hash": previous_hash,
        "event": event,
    }
    return hashlib.sha256(
        canonical_json(payload).encode("utf-8")
    ).hexdigest()


def build_hash_chain(
    events: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    chained_events = []
    previous_hash = GENESIS_HASH

    for sequence, event in enumerate(events):
        if not isinstance(event, dict):
            raise AuditIntegrityError(
                f"Event at position {sequence} must be a dictionary."
            )

        event_copy = dict(event)
        event_hash = calculate_event_hash(
            sequence, previous_hash, event_copy
        )

        chained_entry = {
            "sequence": sequence,
            "previous_hash": previous_hash,
            "event": event_copy,
            "event_hash": event_hash,
        }

        chained_events.append(chained_entry)
        previous_hash = event_hash

    return chained_events


def verify_hash_chain(
    chained_events: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    errors = []
    expected_previous_hash = GENESIS_HASH

    try:
        entries = list(chained_events)
    except TypeError:
        return {
            "valid": False,
            "events_checked": 0,
            "errors": ["Input must be an iterable of chained events."],
        }

    for position, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(
                f"Entry at position {position} is not a dictionary."
            )
            continue

        required = {
            "sequence", "previous_hash", "event", "event_hash"
        }
        missing = required - entry.keys()

        if missing:
            errors.append(
                f"Entry at position {position} is missing fields: "
                f"{sorted(missing)}"
            )
            continue

        if type(entry["sequence"]) is not int or entry["sequence"] != position:
            errors.append(
                f"Entry at position {position} has invalid sequence."
            )

        if entry["previous_hash"] != expected_previous_hash:
            errors.append(
                f"Entry at position {position} has invalid previous_hash."
            )

        if not isinstance(entry["event"], dict):
            errors.append(
                f"Entry at position {position} has invalid event payload."
            )
            continue

        try:
            expected_hash = calculate_event_hash(
                entry["sequence"],
                entry["previous_hash"],
                entry["event"],
            )
        except (AuditIntegrityError, TypeError, ValueError) as exc:
            errors.append(
                f"Entry at position {position} cannot be hashed: {exc}"
            )
            continue

        if not isinstance(entry["event_hash"], str) or (
            entry["event_hash"] != expected_hash
        ):
            errors.append(
                f"Entry at position {position} has invalid event_hash."
            )

        expected_previous_hash = entry["event_hash"]

    return {
        "valid": len(errors) == 0,
        "events_checked": len(entries),
        "errors": errors,
    }


def _read_chain(log_path: Path) -> list[dict[str, Any]]:
    if not log_path.exists():
        return []

    entries = []

    try:
        with log_path.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                if not line.strip():
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise AuditIntegrityError(
                        f"Invalid JSON at line {line_number}: {exc}"
                    ) from exc
    except OSError as exc:
        raise AuditIntegrityError(
            f"Cannot read integrity log: {exc}"
        ) from exc

    return entries


def verify_integrity_storage(
    log_path: str | Path,
    checkpoint_path: str | Path,
) -> dict[str, Any]:
    log_path = Path(log_path)
    checkpoint_path = Path(checkpoint_path)

    if not log_path.exists() and not checkpoint_path.exists():
        return {
            "valid": True,
            "events_checked": 0,
            "head_hash": GENESIS_HASH,
            "errors": [],
            "checkpoint_present": False,
        }

    if not log_path.exists() or not checkpoint_path.exists():
        return {
            "valid": False,
            "events_checked": 0,
            "head_hash": None,
            "errors": ["Integrity log and checkpoint must both exist."],
            "checkpoint_present": checkpoint_path.exists(),
        }

    try:
        chain = _read_chain(log_path)
        result = verify_hash_chain(chain)

        if not result["valid"]:
            result.update({
                "head_hash": None,
                "checkpoint_present": True,
            })
            return result

        with checkpoint_path.open("r", encoding="utf-8") as file:
            checkpoint = json.load(file)

        head_hash = (
            chain[-1]["event_hash"] if chain else GENESIS_HASH
        )

        checkpoint_valid = (
            isinstance(checkpoint, dict)
            and checkpoint.get("schema_version") == 1
            and type(checkpoint.get("event_count")) is int
            and checkpoint.get("event_count") == len(chain)
            and checkpoint.get("head_hash") == head_hash
        )

        if not checkpoint_valid:
            result["errors"].append(
                "Checkpoint does not match the verified audit chain."
            )

        result.update({
            "valid": checkpoint_valid,
            "head_hash": head_hash,
            "checkpoint_present": True,
        })
        return result

    except (OSError, json.JSONDecodeError, AuditIntegrityError) as exc:
        return {
            "valid": False,
            "events_checked": 0,
            "head_hash": None,
            "errors": [str(exc)],
            "checkpoint_present": checkpoint_path.exists(),
        }


def append_integrity_event(
    event: dict[str, Any],
    log_path: str | Path,
    checkpoint_path: str | Path,
) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise AuditIntegrityError("Event must be a dictionary.")

    log_path = Path(log_path)
    checkpoint_path = Path(checkpoint_path)

    with _STORAGE_LOCK:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)

        if log_path.exists() != checkpoint_path.exists():
            raise AuditIntegrityError(
                "Log/checkpoint state mismatch. Refusing to append."
            )

        if log_path.exists():
            verification = verify_integrity_storage(
                log_path, checkpoint_path
            )
            if not verification["valid"]:
                raise AuditIntegrityError(
                    f"Existing integrity verification failed: "
                    f"{verification['errors']}"
                )
            chain = _read_chain(log_path)
        else:
            chain = []

        previous_hash = (
            chain[-1]["event_hash"] if chain else GENESIS_HASH
        )
        sequence = len(chain)

        entry = {
            "sequence": sequence,
            "previous_hash": previous_hash,
            "event": dict(event),
            "event_hash": calculate_event_hash(
                sequence, previous_hash, event
            ),
        }

        try:
            with log_path.open("a", encoding="utf-8", newline="\n") as file:
                file.write(canonical_json(entry) + "\n")
                file.flush()
                os.fsync(file.fileno())

            checkpoint = {
                "schema_version": 1,
                "event_count": sequence + 1,
                "head_hash": entry["event_hash"],
            }

            temporary_path = checkpoint_path.with_name(
                checkpoint_path.name + ".tmp"
            )

            temporary_path.write_text(
                canonical_json(checkpoint) + "\n",
                encoding="utf-8",
            )

            os.replace(temporary_path, checkpoint_path)

        except OSError as exc:
            raise AuditIntegrityError(
                f"Persistent audit write failed: {exc}"
            ) from exc

        return entry
