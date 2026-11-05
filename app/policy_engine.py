from dataclasses import dataclass
from enum import Enum

class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"

@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    reason: str
    policy_id: str

#Only these actions are permitted in our initial sandbox.
#estricted data access and data export are denied explicitly.

ALLOWED_ACTIONS = {
"summarize_document",
"create_support_ticket",
}

DENIED_ACTIONS = {
"read_customer_record",
"export_customer_data",
}

def authorize_action(action: str) -> PolicyDecision:
    """
    Deterministic authorization for the initial sandbox.

    Every tool invocation must pass through this function.
    Unknown actions are denied by default.
    """

    if action in DENIED_ACTIONS:
        return PolicyDecision(
            decision=Decision.DENY,
            reason="This operation is prohibited by the sandbox security policy.",
            policy_id="PS-DENY-001",
        )

    if action in ALLOWED_ACTIONS:
        return PolicyDecision(
            decision=Decision.ALLOW,
            reason="This operation is permitted by the sandbox security policy.",
            policy_id="PS-ALLOW-001",
        )

    return PolicyDecision(
        decision=Decision.DENY,
        reason="Unknown actions are denied by default.",
        policy_id="PS-DENY-DEFAULT",
    )