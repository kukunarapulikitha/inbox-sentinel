"""Deterministic policy engine - the only component that selects actions.

No LLM call happens here, by design. The model reports what it sees; a fixed
policy decides what may be done about it, and anything with real blast radius
requires a human approval step. That boundary is what makes the system
auditable: a prompt injection can at most influence a *finding*, never
directly trigger a quarantine.
"""

from __future__ import annotations

from app.models.incident_models import PolicyDecision

# 0-29 monitor / 30-59 analyst review / 60-79 recommend quarantine /
# 80-100 quarantine + purge + incident
BANDS = [
    (0, 29, "monitor", "No action - monitor", False),
    (30, 59, "analyst_review", "Queue for analyst review", False),
    (60, 79, "recommend_quarantine", "Recommend quarantine (approval required)", True),
    (80, 100, "contain_and_purge", "Quarantine, purge, and open incident (approval required)", True),
]

BAND_ACTIONS = {
    "monitor": [
        "Keep the message in the user's mailbox",
        "No containment required",
    ],
    "analyst_review": [
        "Queue for analyst review",
        "Search for related messages by sender and subject template",
    ],
    "recommend_quarantine": [
        "Recommend quarantine of this message",
        "Warn the recipient before they act on the request",
        "Search the tenant for matching indicators",
    ],
    "contain_and_purge": [
        "Quarantine and purge matching messages tenant-wide",
        "Open an incident record",
        "Notify the affected business function and security team",
        "Reset credentials for any recipient who submitted them",
    ],
}

# Verdict-specific actions layered on top of the band actions.
VERDICT_ACTIONS = {
    "Suspected BEC": [
        "Hold the payment or bank-change request immediately",
        "Verify the change through an independently known phone number, never by replying",
        "Avoid blanket-blocking the vendor domain before confirmation - it may be a compromised legitimate partner",
    ],
    "Payroll fraud suspected": [
        "Do not process payroll changes received by email",
        "Verify with the employee through HRIS or a known phone number",
    ],
    "Invoice fraud suspected": [
        "Hold invoice processing",
        "Match the invoice against open purchase orders",
    ],
    "Payment fraud suspected": [
        "Do not send AP reports or invoice data by email",
        "Confirm requestor identity out of band",
    ],
    "Vendor RFQ fraud suspected": [
        "Validate the buyer organisation before sending pricing",
    ],
    "Credential phishing": [
        "Reset credentials for any user who submitted them",
        "Block the credential-harvesting URL",
    ],
    "Phishing - malicious attachment suspected": [
        "Search for matching attachment hashes tenant-wide",
        "Open an endpoint investigation for recipients who opened the attachment",
    ],
}


def band_for(risk: int) -> tuple[str, str, str, bool]:
    for low, high, name, disposition, approval in BANDS:
        if low <= risk <= high:
            return name, f"{low}-{high}", disposition, approval
    return "contain_and_purge", "80-100", "Quarantine, purge, and open incident (approval required)", True


def evaluate(risk: int, verdict: str, needs_human_review: bool = False) -> PolicyDecision:
    name, band_range, disposition, approval = band_for(max(0, min(100, risk)))
    actions = list(BAND_ACTIONS[name])
    for action in VERDICT_ACTIONS.get(verdict, []):
        if action not in actions:
            actions.append(action)

    justification = f"Risk score {risk} falls in the {band_range} band ({name})."
    if needs_human_review:
        # Conflicting evidence must not auto-escalate past a human.
        approval = True
        actions.insert(0, "Analyst decision required - agent findings conflict")
        justification += " Agent findings conflict, so a human decision is required before any action."

    return PolicyDecision(
        band=name,
        band_range=band_range,
        disposition=disposition,
        actions=actions,
        requires_approval=approval,
        auto_executed=not approval and name != "monitor",
        justification=justification,
    )
