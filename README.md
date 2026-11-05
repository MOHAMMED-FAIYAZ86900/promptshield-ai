# PromptShield AI

**Runtime Security Gateway for AI Agents**

PromptShield is a prototype security gateway between an AI agent and the
tools it can invoke. It applies deterministic authorization policies,
detects suspicious prompt-injection patterns, validates tool arguments
before execution, and records execution evidence in conventional and
hash-chained audit logs.

> **Project status:** Core security MVP implemented. The latest recorded
> automated test run reports **43 passing tests**. A live FastAPI
> request and Streamlit dashboard were also verified.
>
> **Security scope:** This is a research/hackathon prototype, not a
> production-certified security product. The detector uses heuristic
> pattern matching, and the local hash-chain checkpoint is not protected
> by an independent trust boundary.

## What it does

-   **Prompt-injection detection:** heuristic detection of suspicious
    instructions in submitted documents.
-   **Deterministic policy enforcement:** explicit allow/deny decisions
    for registered tools.
-   **Controlled tool execution:** validates arguments before any side
    effect.
-   **Execution lifecycle evidence:** records intent before invoking an
    authorized tool, then records the outcome.
-   **Fail-closed intent logging:** if intent persistence fails, the
    tool is not executed.
-   **Audit integrity evidence:** stores events in a separate SHA-256
    hash chain and verifies the chain against a local checkpoint.
-   **Monitoring dashboard:** Streamlit interface for viewing audit data
    and security analytics.

### Current tool policy

  Action                    Policy
  ------------------------- -----------------
  `summarize_document`      Allow
  `create_support_ticket`   Allow
  `read_customer_record`    Deny
  `export_customer_data`    Deny
  Unknown actions           Deny by default

Tools operate on synthetic sandbox data. Do not connect this prototype
to real customer records or production systems without a separate
security review.

## Architecture

``` mermaid
flowchart TD
    A[User / AI Agent Request] --> B[FastAPI API]
    B --> C{Document supplied?}
    C -->|Yes| D[Prompt-injection detector]
    C -->|No| E[Policy engine]
    D -->|Suspicious| X[Block request]
    D -->|Not flagged| E
    E -->|Denied / unknown| X
    E -->|Allowed| F[Tool registry and argument validation]
    F -->|Invalid arguments| Y[Validation failure]
    F -->|Valid| G[Persist execution intent]
    G -->|Persistence failure| X
    G -->|Persisted| H[Execute registered tool]
    H --> I[Persist execution outcome]
    I --> J[API response]
    G -.-> K[Conventional JSONL audit]
    I -.-> K
    K --> L[SHA-256 hash-chain log]
    L --> M[Checkpoint verification]
    K --> N[Streamlit dashboard]
```

### Request lifecycle

1.  Receive a tool request through FastAPI.
2.  If a document is submitted for analysis, run the prompt-injection
    detector.
3.  Apply the deterministic policy engine. Unknown and restricted
    actions are denied.
4.  Resolve the registered executor and validate its arguments without
    executing it.
5.  Persist an `execution_intent` audit event.
6.  Execute the prepared tool only after intent persistence succeeds.
7.  Persist the outcome (`executed` or `execution_failed`).
8.  Return the API result and relevant audit identifiers.

If outcome logging fails after a tool has run, the API does not falsely
report that the operation was blocked; it returns the execution result
with an audit warning.

## Security controls

  -----------------------------------------------------------------------
  Control                             Current implementation
  ----------------------------------- -----------------------------------
  Default-deny authorization          Explicit allowlist; unknown actions
                                      denied

  Restricted operations               Customer-record read and
                                      customer-data export denied

  Prompt-injection detection          Heuristic indicators for
                                      instruction override, secret
                                      extraction, unauthorized access,
                                      privilege escalation, indirect
                                      override and hidden exfiltration
                                      requests

  Argument validation                 Registered executor schemas
                                      validated before execution

  Execution containment               Tool execution occurs only after
                                      authorization, validation and
                                      successful intent persistence

  Fail-closed intent audit            Intent persistence failure prevents
                                      tool execution

  Outcome accuracy                    Outcome audit failure does not
                                      misrepresent an already-executed
                                      action as blocked

  Conventional audit events           JSONL records with event ID,
                                      request ID, timestamp, action,
                                      decision, reason, policy ID,
                                      execution status and detection
                                      evidence

  Hash-chain integrity                SHA-256 chain links each event to
                                      the previous event

  Checkpoint consistency              Verifies event count and chain-head
                                      hash against a separate local
                                      checkpoint

  Tamper tests                        Tests cover modified, deleted,
                                      reordered and duplicated chain
                                      entries, plus checkpoint/log
                                      integrity cases
  -----------------------------------------------------------------------

### Detection score interpretation

The detector uses heuristic pattern matching. Its risk score is an
indicator score derived from matched patterns; it is **not a calibrated
probability** or a substitute for measured precision/recall evaluation.

## Technology stack

-   Python
-   FastAPI
-   Pydantic
-   Streamlit
-   Pytest
-   SHA-256 (`hashlib`)
-   JSON / JSON Lines audit storage

## Project structure

``` text
promptshield/
├── app/
│   ├── audit.py
│   ├── audit_integrity.py
│   ├── detector.py
│   ├── executor.py
│   ├── main.py
│   ├── policy_engine.py
│   ├── schemas.py
│   └── tools.py
├── data/
├── evaluation/
│   ├── diagnose_audit.py
│   ├── run_evaluation.py
│   ├── stage16_classify_audit.py
│   ├── validate_audit.py
│   ├── validate_audit_v2.py
│   └── validate_audit_v3.py
├── logs/
├── reports/
├── tests/
│   ├── test_api.py
│   ├── test_audit_integrity.py
│   ├── test_audit_integrity_integration.py
│   ├── test_audit_integrity_storage.py
│   ├── test_containment.py
│   ├── test_detector.py
│   ├── test_evidence.py
│   ├── test_execution_lifecycle.py
│   └── test_policy.py
├── dashboard.py
├── requirements.txt
└── README.md
```

Review generated logs, local checkpoints, virtual environments, caches
and synthetic/private data before publishing. Keep machine-specific and
temporary files out of version control.

## Requirements

-   Python 3.10 or newer (developed and tested in a Python 3.13 virtual
    environment).
-   Windows, macOS or Linux.
-   `pip`.

Install dependencies from the repository's `requirements.txt`; exact
dependency versions are defined there.

## Installation

### Windows PowerShell

``` powershell
git clone <YOUR_REPOSITORY_URL>
cd promptshield

python -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### macOS / Linux

``` bash
git clone <YOUR_REPOSITORY_URL>
cd promptshield

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run the application

Run the API and dashboard in separate terminals from the project root,
with the virtual environment activated in each.

### 1. Start the FastAPI backend

``` bash
uvicorn app.main:app --reload
```

-   API base URL: `http://127.0.0.1:8000`
-   Interactive API documentation: `http://127.0.0.1:8000/docs`
-   Health endpoint: `http://127.0.0.1:8000/health`

### 2. Start the Streamlit dashboard

``` bash
python -m streamlit run dashboard.py
```

Dashboard: `http://localhost:8501`

### 3. Verify health

``` bash
curl http://127.0.0.1:8000/health
```

Expected response:

``` json
{
  "status": "healthy"
}
```

## API usage

The interactive API documentation at `/docs` is the authoritative
reference for the running application's request schemas.

### Health check

``` http
GET /health
```

### Execute an allowed tool

``` http
POST /agent/run
Content-Type: application/json
```

Example request:

``` json
{
  "action": "summarize_document",
  "arguments": {
    "document": "PromptShield is a runtime security gateway for AI agents."
  }
}
```

A successful response includes execution status, result, request ID and
audit event identifiers. Exact response fields are defined by the
running application.

### Attempt a restricted action

``` json
{
  "action": "read_customer_record",
  "arguments": {
    "customer_id": "CUST-1001"
  }
}
```

This action is denied by the current policy. The identifier is
synthetic; access to customer records is not enabled.

### Analyze a document

``` http
POST /agent/analyze-document
Content-Type: application/json
```

Use `/docs` to inspect the exact `DocumentAnalysisRequest` schema
accepted by the running version. The endpoint applies prompt-injection
detection before the requested registered action is considered for
execution.

## Audit integrity

PromptShield maintains two distinct audit artifacts:

-   **Conventional audit log:** JSONL events written by the application
    audit logger.
-   **Integrity audit log:** a separate JSONL stream where each event
    contains a sequence number, previous-event hash, original event
    payload and SHA-256 event hash.

A separate checkpoint records the event count and current chain-head
hash.

Default paths:

``` text
logs/audit.jsonl
logs/integrity_audit.jsonl
logs/integrity_checkpoint.json
```

The integrity paths can be overridden with environment variables:

``` powershell
$env:PROMPTSHIELD_INTEGRITY_LOG = "logs/integrity_audit.jsonl"
$env:PROMPTSHIELD_INTEGRITY_CHECKPOINT = "logs/integrity_checkpoint.json"
```

Verify the stored chain:

``` powershell
python -c "from app.audit_integrity import verify_integrity_storage; from pathlib import Path; print(verify_integrity_storage(Path('logs/integrity_audit.jsonl'), Path('logs/integrity_checkpoint.json')))"
```

A valid result reports `valid: True`, the number of verified events, the
chain-head hash and an empty error list.

### Integrity limitations

The hash chain detects inconsistencies when events are modified,
removed, reordered or duplicated without recomputing the chain. The
checkpoint detects disagreement between the stored chain and checkpoint.

However, the log and checkpoint are both local writable files. An
attacker who can rewrite both can potentially recompute the chain and
checkpoint. The current implementation does not provide an independently
protected checkpoint, digital signatures, remote immutable storage or
multi-process coordination. The append lock is process-local. Treat this
as **tamper-evident integrity checking within the prototype's trust
assumptions**, not tamper-proof or production-grade audit storage.

The original historical audit log is not retroactively migrated into the
hash chain.

## Testing and evaluation

Run the complete test suite:

``` bash
python -m pytest -v
```

Latest recorded test run:

  Test group                       Passed
  ------------------------------ --------
  API                                   5
  Hash-chain integrity                  7
  Integrity integration                 2
  Persistent integrity storage          5
  Prompt-injection containment          6
  Detector                              5
  Audit evidence                        4
  Execution lifecycle                   4
  Policy engine                         5
  **Total**                        **43**

**Latest recorded result: 43 passed, 0 failed.** One non-blocking
Starlette deprecation warning was reported by the test environment.

### Live verification

A live FastAPI request to `POST /agent/run` was verified to:

-   Return HTTP 200 and a successful execution result.
-   Produce two integrity events in order: `execution_intent`, then
    `executed`.
-   Use the same request ID for both events.
-   Pass hash-chain and checkpoint verification.

A separate integrity verification reported 45 valid events with zero
errors at the time of that check. Counts change as additional requests
and tests write to the configured log.

### Evaluation artifacts

The repository includes:

-   `evaluation/run_evaluation.py` --- synthetic evaluation runner.
-   `reports/security_evaluation.json` --- evaluation output.
-   `evaluation/validate_audit_v3.py` --- audit validation utility.
-   `evaluation/stage16_classify_audit.py` --- historical audit
    classification.
-   `reports/stage16_audit_classification.json` --- historical
    classification report.

Historical audit classification identified 49 executed events without
corresponding intent records and 31 legacy/incomplete events. Their
historical root cause was not proven. These findings remain documented
and should not be described as resolved.

No detector precision, recall, F1 score or false-positive rate is
claimed here; publish those only after confirming the measured results
and evaluation methodology.

## Known limitations

-   Prompt-injection detection is heuristic and regex-based; it is not a
    semantic or model-based classifier.
-   The risk score is not a calibrated probability.
-   The tool set is a controlled synthetic sandbox, not a production
    integration.
-   Local hash-chain and checkpoint files do not protect against an
    attacker who can rewrite both.
-   Audit synchronization is process-local; multi-worker or distributed
    deployment requires stronger coordination.
-   Authentication, role-based access control, secrets management,
    deployment hardening and external monitoring require further work.
-   Historical audit anomalies remain documented and their root cause is
    unproven.

## Roadmap

-   [ ] Add an independently protected checkpoint or remote immutable
    audit storage.
-   [ ] Add digital signatures and key-management controls.
-   [ ] Add multi-process-safe and distributed audit coordination.
-   [ ] Expand prompt-injection datasets and measure precision, recall,
    F1 and false-positive rates.
-   [ ] Add stronger tool input/output inspection and sensitive-data
    controls.
-   [ ] Add authentication, authorization and deployment hardening.
-   [ ] Expand dashboard integrity reporting and operational monitoring.
-   [ ] Add reproducible deployment and security evaluation
    instructions.

## Contributing

For security-sensitive changes, include:

1.  A clear threat or failure scenario.
2.  The expected security invariant.
3.  Automated tests demonstrating the behavior.
4.  Any new limitations or trust assumptions.

Do not submit real credentials, customer records, production audit logs
or other sensitive data.

## License

No license has been specified. Add a `LICENSE` file before presenting
this repository as open source. Until then, all rights remain with the
copyright holder.

------------------------------------------------------------------------

**PromptShield AI --- Runtime Security Gateway for AI Agents**
