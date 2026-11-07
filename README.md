# PromptShield AI

**A runtime security gateway for AI agents that evaluates tool requests,
enforces policy decisions, and records execution activity.**

PromptShield is a portfolio-grade prototype demonstrating how an
AI-agent application can place a security layer between an agent and its
tools. It focuses on preventing unauthorized tool execution, detecting
suspicious instructions, enforcing fail-closed authorization, and
maintaining audit evidence.

> **Project status:** Deployed demonstration. The hosted service is
> intended for portfolio evaluation, not production security or durable
> audit retention.

## Live Demo

-   **Streamlit dashboard:**
    https://promptshield-ai-fklfbyf39eckys9h3gucdc.streamlit.app/
-   **FastAPI backend:** https://promptshield-ai-h37x.onrender.com
-   **Health endpoint:**
    https://promptshield-ai-h37x.onrender.com/health
-   **Audit events endpoint:** `/audit/events` (requires an API key when
    authentication is configured)

The hosted backend runs on Render's free tier. Its local filesystem is
ephemeral unless a persistent disk is configured. Audit files can
therefore be lost after a restart or redeployment.

## Why PromptShield?

AI agents can call tools that read data, create records, or perform
other actions. Prompt injection or an overly permissive tool interface
can cause an agent to request actions beyond its intended authority.

PromptShield introduces a separate policy enforcement layer that:

1.  Receives an agent tool/action request.
2.  Examines the requested action and its arguments.
3.  Evaluates the request against security policy and detection signals.
4.  Allows approved actions or blocks unauthorized actions.
5.  Records execution intent before invoking an authorized tool.
6.  Records the execution outcome and exposes audit events.

The key design principle is **authorization before execution**. A tool
must not execute when the execution-intent audit write fails.

## Architecture

``` mermaid
flowchart TD
    U[User / Agent Request] --> D[Streamlit Dashboard]
    D --> API[FastAPI Security API]
    API --> DET[Threat / Prompt Injection Detector]
    DET --> POL[Policy Engine]
    POL -->|Deny| BLOCK[Blocked Response]
    POL -->|Allow| INTENT[Persist Execution Intent]
    INTENT -->|Write Failure| FAIL[Fail Closed - Do Not Execute]
    INTENT -->|Write Success| EX[Tool Executor]
    EX --> TOOLS[Allowlisted Tools]
    EX --> OUT[Execution Outcome]
    BLOCK --> AUD[Audit Event Store]
    FAIL --> AUD
    OUT --> AUD
    AUD --> CHAIN[Hash-chain Integrity Evidence]
    API --> RESP[API Response]
    RESP --> D[Dashboard Result]
```

### Main components

  -----------------------------------------------------------------------
  Component                           Responsibility
  ----------------------------------- -----------------------------------
  Streamlit dashboard                 User-facing interface for
                                      submitting and reviewing agent
                                      actions

  FastAPI backend                     API endpoints and request
                                      orchestration

  Detector                            Identifies suspicious instruction
                                      and access patterns

  Policy engine                       Applies allow/deny decisions

  Executor                            Invokes only approved tools

  Audit module                        Persists conventional JSONL audit
                                      events

  Audit integrity module              Maintains and verifies a SHA-256
                                      hash chain and checkpoint
  -----------------------------------------------------------------------

## Security Controls

### Tool authorization

The current allowlist includes:

-   `summarize_document`
-   `create_support_ticket`

The following actions are denied:

-   `read_customer_record`
-   `export_customer_data`

Unknown actions are denied by default.

### Detection signals

The detector includes heuristic indicators such as:

-   `instruction_override`
-   `secret_extraction`
-   `unauthorized_record_access`
-   `privilege_escalation`
-   `indirect_instruction_override`
-   `hidden_exfiltration_request`

Risk scores are heuristic signals. They are **not calibrated
probabilities** and should not be interpreted as a measured likelihood
of attack.

### Fail-closed execution lifecycle

For an authorized action, the backend follows this sequence:

1.  Validate the requested action and arguments.
2.  Persist an `execution_intent` audit event.
3.  Execute the tool only after the intent event is persisted.
4.  Persist the execution outcome.

If execution-intent persistence fails, the tool is not executed. If
outcome auditing fails after a tool has already executed, the response
must not misrepresent that action as blocked; the execution may have
succeeded while its outcome record is incomplete.

### API key authentication

When `PROMPTSHIELD_API_KEY` is configured, protected endpoints require
the `X-API-Key` request header. The key is compared using a
constant-time comparison.

For local development, if the environment variable is not configured,
the API's authentication dependency permits requests. Configure a key in
any shared or hosted deployment.

### Audit integrity

PromptShield includes a SHA-256 hash-chain implementation with a
checkpoint. It can detect modifications to the stored chain when checked
against the checkpoint and the stated trust assumptions.

**This is tamper-evident prototype evidence, not tamper-proof storage.**
The log and checkpoint are stored locally and may both be rewritten by
an attacker with filesystem access. The locking mechanism is
process-local, not a distributed or multi-process coordination
mechanism. A crash between appending a chain entry and updating its
checkpoint can also leave a mismatch that causes verification to fail.

The `/audit/events` endpoint returns conventional audit events. It
should not be treated by itself as proof that the separate integrity
chain has verified successfully.

## Technology Stack

-   **Backend:** Python, FastAPI, Uvicorn
-   **Dashboard:** Streamlit
-   **Validation and testing:** pytest
-   **Audit storage:** JSON Lines (JSONL)
-   **Integrity mechanism:** SHA-256 hash chaining and checkpoint
    verification
-   **Deployment:** Render (backend), Streamlit Community Cloud
    (dashboard)

## Repository Structure

``` text
promptshield/
├── app/
│   ├── main.py
│   ├── audit.py
│   ├── audit_integrity.py
│   ├── detector.py
│   ├── executor.py
│   ├── policy_engine.py
│   ├── tools.py
│   └── schemas.py
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
├── logs/
├── dashboard.py
├── requirements.txt
└── README.md
```

The exact repository contents may evolve; this tree describes the
intended application layout.

## Run Locally

### 1. Clone the repository

``` bash
git clone https://github.com/MOHAMMED-FAIYAZ86900/promptshield-ai.git
cd promptshield-ai
```

### 2. Create and activate a virtual environment

**Windows PowerShell**

``` powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS / Linux**

``` bash
python -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

``` bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure environment variables

PowerShell example:

``` powershell
$env:PROMPTSHIELD_API_KEY = "replace-with-a-long-random-secret"
$env:PROMPTSHIELD_AUDIT_LOG = "logs/audit.jsonl"
$env:PROMPTSHIELD_INTEGRITY_LOG = "logs/integrity_audit.jsonl"
$env:PROMPTSHIELD_INTEGRITY_CHECKPOINT = "logs/integrity_checkpoint.json"
```

Use a newly generated secret. Do not commit API keys, `.env` files,
audit logs containing sensitive data, or deployment secrets to Git.

The audit path variables are optional if the application's defaults are
suitable for your environment. Ensure the process has permission to
create and write to the selected directory.

### 5. Start the FastAPI backend

``` bash
uvicorn app.main:app --reload
```

The API is available at:

-   `http://127.0.0.1:8000`
-   Interactive API documentation: `http://127.0.0.1:8000/docs`
-   Health check: `http://127.0.0.1:8000/health`

### 6. Start the dashboard

In a second terminal, activate the same virtual environment and run:

``` bash
streamlit run dashboard.py
```

Configure the dashboard's backend URL and API key using Streamlit
secrets or the configuration mechanism implemented in `dashboard.py`. Do
not place secrets in source control.

## API Overview

The current backend exposes these principal routes:

  ---------------------------------------------------------------------------
  Method                  Endpoint                    Purpose
  ----------------------- --------------------------- -----------------------
  `GET`                   `/`                         Basic service/root
                                                      response

  `GET`                   `/health`                   Health check

  `POST`                  `/agent/run`                Evaluate and process an
                                                      agent tool/action
                                                      request

  `POST`                  `/agent/analyze-document`   Analyze a document
                                                      request through the
                                                      security workflow

  `GET`                   `/audit/events`             Retrieve recent
                                                      conventional audit
                                                      events
  ---------------------------------------------------------------------------

The agent execution and audit routes are protected when
`PROMPTSHIELD_API_KEY` is configured. Supply the key using the
`X-API-Key` header.

### Example: retrieve audit events

``` powershell
$headers = @{
    "X-API-Key" = $env:PROMPTSHIELD_API_KEY
}

Invoke-RestMethod `
    -Uri "http://127.0.0.1:8000/audit/events?limit=50" `
    -Headers $headers `
    -Method Get
```

For exact request and response schemas, use the running API's `/docs`
page. Request payload fields should follow the Pydantic schemas in
`app/schemas.py`.

## Testing

Run the automated test suite from the repository root:

``` bash
python -m pytest -q
```

Run a specific test module:

``` bash
python -m pytest tests/test_execution_lifecycle.py -q
```

Tests cover API behavior, policy decisions, detector signals, execution
lifecycle, audit evidence, and integrity storage. Use the current test
run from your own checkout as the source of truth for the passing test
count; results can change as the project changes.

## Deployment

### Backend --- Render

1.  Create a Render Web Service connected to the GitHub repository.
2.  Install dependencies with `pip install -r requirements.txt`.
3.  Start the service with
    `uvicorn app.main:app --host 0.0.0.0 --port $PORT`.
4.  Configure `PROMPTSHIELD_API_KEY` as a secret environment variable.
5.  Configure the audit paths. For a free-tier ephemeral filesystem,
    relative paths such as the following are suitable for a demo:

``` text
PROMPTSHIELD_AUDIT_LOG=logs/audit.jsonl
PROMPTSHIELD_INTEGRITY_LOG=logs/integrity_audit.jsonl
PROMPTSHIELD_INTEGRITY_CHECKPOINT=logs/integrity_checkpoint.json
```

6.  Confirm `/health` responds and test protected endpoints with the
    configured key.

**Persistence warning:** Relative paths on an ephemeral filesystem do
not provide durable audit retention. Use an appropriately secured
persistent storage service or managed database for production.

### Dashboard --- Streamlit Community Cloud

1.  Deploy `dashboard.py` from the repository.
2.  Configure the backend URL to point to the deployed FastAPI service.
3.  Add the matching API key in Streamlit Secrets using the exact secret
    name expected by the dashboard code.
4.  Verify that the dashboard can reach the backend and submit both
    allowed and denied test cases.

Never add the API key to the repository or include it in screenshots,
logs, or public demonstrations.

## Manual Security Validation

Use the dashboard or API to exercise these scenarios:

  -----------------------------------------------------------------------
  Scenario                            Expected behavior
  ----------------------------------- -----------------------------------
  Benign `summarize_document` request Allowed and executed

  Valid `create_support_ticket`       Allowed and executed
  request                             

  `read_customer_record` request      Blocked

  `export_customer_data` request      Blocked

  Unknown tool/action                 Blocked by default

  Prompt injection or                 Detected and blocked according to
  secret-extraction attempt           policy
  -----------------------------------------------------------------------

After each request, inspect the audit events. Also run the integrity
verification functionality available in the application and inspect its
result independently. A successful API response or an audit-event
listing alone does not establish hash-chain validity.

## Current Limitations

-   Detection is heuristic and may produce false positives or false
    negatives.
-   Risk scores are not calibrated probabilities.
-   The allowlist and policies are prototype-level controls, not a
    complete enterprise authorization system.
-   Local JSONL audit storage is not a substitute for centralized,
    access-controlled, durable logging.
-   The integrity chain and checkpoint share the same local trust
    boundary.
-   Process-local locking does not provide multi-worker or distributed
    write coordination.
-   No claim of production-grade tamper resistance, compliance
    certification, or complete prompt-injection prevention is made.
-   Hosted free-tier storage may be ephemeral.

## Roadmap

Potential next steps for a production-oriented evolution:

-   Move audit storage to durable, access-controlled storage.
-   Use a transactional event-writing design or durable queue for audit
    and execution coordination.
-   Add multi-process-safe concurrency control.
-   Protect integrity checkpoints with an external trust anchor or
    signing key.
-   Expand policy evaluation with scoped identities, permissions, and
    tool-level argument schemas.
-   Add detector evaluation datasets, precision/recall metrics, and
    adversarial regression tests.
-   Add structured observability, alerting, rate limits, and deployment
    hardening.

## Author

**Mohammed Faiyaz**

-   GitHub: https://github.com/MOHAMMED-FAIYAZ86900

## Disclaimer

PromptShield AI is an educational and portfolio project demonstrating
runtime controls for AI-agent tool execution. It is not a guarantee that
an AI system is secure, and it should not be deployed to protect
production data or critical systems without substantial additional
engineering, independent security review, and operational controls.
