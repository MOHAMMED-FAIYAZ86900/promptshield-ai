import re
from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionResult:
    suspicious: bool
    risk_score: int
    matched_indicators: tuple[str, ...]
    explanation: str


PATTERNS = {
    "instruction_override": re.compile(
        r"\b("
        r"ignore|disregard|override|"
        r"do not follow|don't follow"
        r")\b.{0,80}\b("
        r"previous|prior|above|all|system|"
        r"earlier|what came before"
        r")\b.{0,50}\b("
        r"instructions?|rules?|directives?|"
        r"polic(?:y|ies)|guidelines?"
        r")\b",
        re.IGNORECASE,
    ),

    "secret_extraction": re.compile(
        r"\b("
        r"reveal|disclose|exfiltrate|leak|"
        r"send|share|expose|provide|"
        r"transmit|extract"
        r")\b.{0,80}\b("
        r"secrets?|credentials?|passwords?|"
        r"private data|confidential information|"
        r"hidden information|api keys?"
        r")\b",
        re.IGNORECASE,
    ),

    "unauthorized_record_access": re.compile(
        r"\b("
        r"read|retrieve|access|fetch|export|"
        r"download|obtain|extract"
        r")\b.{0,80}\b("
        r"restricted|private|customer|"
        r"confidential|sensitive"
        r")\b.{0,50}\b("
        r"records?|data|database|account|"
        r"information|files?"
        r")\b",
        re.IGNORECASE,
    ),

    "privilege_escalation": re.compile(
        r"\b("
        r"bypass|disable|circumvent|evade|"
        r"skip"
        r")\b.{0,80}\b("
        r"security|authorization|access control|"
        r"permission checks?|authentication|"
        r"security controls?"
        r")\b",
        re.IGNORECASE,
    ),

    "indirect_instruction_override": re.compile(
        r"\b("
        r"disregard|ignore|forget"
        r")\b.{0,60}\b("
        r"what came before|what came earlier|"
        r"earlier directions?|prior guidance|"
        r"previous directions?"
        r")\b",
        re.IGNORECASE,
    ),

    "hidden_exfiltration_request": re.compile(
        r"\b("
        r"hidden request|secret instruction|"
        r"concealed instruction|"
        r"embedded instruction"
        r")\b.{0,100}\b("
        r"send|share|transmit|export|"
        r"forward|leak"
        r")\b.{0,60}\b("
        r"secrets?|credentials?|private data|"
        r"confidential information|"
        r"external destination|external recipient"
        r")\b",
        re.IGNORECASE,
    ),
}


def detect_prompt_injection(text: str) -> DetectionResult:
    """
    Detect configured prompt-injection indicators.

    This is a heuristic detector, not a complete security boundary.
    The risk score is an indicator count, not a calibrated probability.
    """

    matches = tuple(
        indicator
        for indicator, pattern in PATTERNS.items()
        if pattern.search(text)
    )

    score = min(100, len(matches) * 35)

    if matches:
        explanation = (
            "Potentially malicious instructions detected: "
            + ", ".join(matches)
        )
    else:
        explanation = (
            "No configured suspicious patterns were detected."
        )

    return DetectionResult(
        suspicious=bool(matches),
        risk_score=score,
        matched_indicators=matches,
        explanation=explanation,
    )