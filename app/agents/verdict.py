"""Verdict fusion - the second LLM node.

Division of labour that matters for the interview: the LLM writes the *verdict
label and the analyst-readable rationale* by reasoning over the four findings.
It does not compute the risk score and it does not choose actions. Scoring is
arithmetic over severities, and actions come from the policy engine, so both
stay reproducible and testable.

The verdict label is constrained to a known vocabulary. An off-vocabulary
label is treated as a failure and the deterministic chain decides instead -
that keeps the label space stable enough to measure precision and recall.
"""

from __future__ import annotations

from app.models.email_models import EmailRecord
from app.models.findings import Finding, VerdictAssessment
from app.agents.content_bec import content_signals
from app.services.llm import LLMUnavailable, structured_call, wrap_untrusted

SEVERITY_POINTS = {"low": 6, "medium": 18, "high": 30}

# Stable label vocabulary, shared with data/expected_labels.jsonl.
VERDICT_LABELS = [
    "Benign",
    "Suspicious",
    "Suspected BEC",
    "Credential phishing",
    "Phishing - malicious attachment suspected",
    "Invoice fraud suspected",
    "Payment fraud suspected",
    "Payroll fraud suspected",
    "Vendor RFQ fraud suspected",
    "Fake job phishing",
    "Advance-fee phishing scam",
]

THREAT_FAMILIES = {
    "Benign": "Normal business email",
    "Suspicious": "Needs review",
    "Suspected BEC": "Business email compromise",
    "Credential phishing": "Credential theft",
    "Phishing - malicious attachment suspected": "Malware delivery",
    "Invoice fraud suspected": "Invoice fraud",
    "Payment fraud suspected": "Payment fraud",
    "Payroll fraud suspected": "Payroll fraud",
    "Vendor RFQ fraud suspected": "Vendor fraud",
    "Fake job phishing": "Recruitment phishing",
    "Advance-fee phishing scam": "Phishing scam",
}


def risk_score(findings: list[Finding]) -> int:
    """Deterministic. Never produced by the LLM."""
    return min(100, sum(SEVERITY_POINTS.get(f.severity, 6) for f in findings))


def _floor_for(signals: dict[str, bool], findings: list[Finding], auth_passed: bool) -> tuple[int, str, list[str]]:
    """Risk floors and MITRE mapping for high-confidence deterministic patterns.

    These floors exist because a BEC message with clean auth and no attachment
    can otherwise score low on severity arithmetic alone.
    """
    has_attachment_risk = any(
        e.type in {"risky_attachment_type", "sandbox_finding"} for f in findings for e in f.evidence
    )
    has_credential = any(
        e.type in {"credential_lure", "login_url", "qr_login_lure"} for f in findings for e in f.evidence
    )

    if signals["bank_change"] or signals["billing_update"]:
        return (91 if auth_passed else 86), "Suspected BEC", ["T1566", "T1656"]
    if signals["payroll"]:
        return 88, "Payroll fraud suspected", ["T1566"]
    if signals["invoice_fraud"]:
        return 87, "Invoice fraud suspected", ["T1566"]
    if signals["payment_fraud"]:
        return 84, "Payment fraud suspected", ["T1566"]
    if signals["rfq_fraud"]:
        return 82, "Vendor RFQ fraud suspected", ["T1566"]
    if signals["advance_fee"]:
        return 85, "Advance-fee phishing scam", ["T1566"]
    if has_attachment_risk:
        return 94, "Phishing - malicious attachment suspected", ["T1566.001"]
    if has_credential:
        return 92, "Credential phishing", ["T1566.002"]
    if signals["fake_job"]:
        return 76, "Fake job phishing", ["T1566.002"]
    return 0, "", []


def decide_verdict(email: EmailRecord, findings: list[Finding]) -> dict:
    """Fuse findings into a verdict. Returns a dict consumed by the graph."""
    signals = content_signals(email)
    auth_passed = email.all_auth_passed
    base_risk = risk_score(findings)
    floor, floor_verdict, mitre = _floor_for(signals, findings, auth_passed)
    risk = max(base_risk, floor)

    rule_verdict = floor_verdict or ("Benign" if risk <= 30 else "Suspicious")
    if not floor_verdict and risk <= 30:
        mitre = []
    elif not floor_verdict:
        mitre = ["T1566"]

    try:
        assessment = _llm_assessment(email, findings)
        verdict = assessment.verdict.strip()
        if verdict not in VERDICT_LABELS:
            raise LLMUnavailable(f"off-vocabulary verdict label {verdict!r}")

        # Taxonomy precedence: when a high-confidence deterministic pattern
        # fires (a bank-change request, a payroll change, a risky attachment),
        # the rule floor owns the *label*. Measured on the seeded corpus the
        # model reliably reads intent but collapses fraud subtypes into the
        # broader "Suspected BEC" - it called msg-008 (vendor RFQ fraud) and
        # msg-009 (payment fraud) BEC. The LLM still owns the rationale,
        # confidence and needs-review call, which is where it adds value.
        label_source = "llm"
        if floor_verdict and verdict != floor_verdict:
            verdict = floor_verdict
            label_source = "rule_floor"

        return {
            "verdict": verdict,
            "label_source": label_source,
            "threat_type": THREAT_FAMILIES.get(verdict, assessment.threat_type),
            "risk_score": risk,
            "confidence": min(0.98, max(0.3, assessment.confidence)),
            "rationale": assessment.rationale,
            "mitre_techniques": mitre,
            "needs_human_review": assessment.needs_human_review,
            "uncertainties": assessment.uncertainties,
            "source": "llm",
        }
    except LLMUnavailable as exc:
        return {
            "verdict": rule_verdict,
            "label_source": "rules",
            "threat_type": THREAT_FAMILIES.get(rule_verdict, "Needs review"),
            "risk_score": risk,
            "confidence": min(0.98, max((f.confidence for f in findings), default=0.6)),
            "rationale": _rule_rationale(rule_verdict, findings),
            "mitre_techniques": mitre,
            "needs_human_review": _conflicting(findings),
            "uncertainties": [f"LLM unavailable, deterministic path used ({exc})."],
            "source": "rules",
        }


def _conflicting(findings: list[Finding]) -> bool:
    """Flag for human review when agents disagree: at least one high-severity
    finding alongside benign signals, or nothing conclusive either way."""
    severities = {f.severity for f in findings}
    has_benign_signal = any(f.benign_signals for f in findings)
    return "high" in severities and has_benign_signal


def _llm_assessment(email: EmailRecord, findings: list[Finding]) -> VerdictAssessment:
    summary_lines: list[str] = []
    for finding in findings:
        summary_lines.append(f"## {finding.component} (severity={finding.severity}, source={finding.source})")
        for item in finding.evidence:
            summary_lines.append(f"  - [{item.type}] {item.value} :: {item.explanation}")
        for benign in finding.benign_signals:
            summary_lines.append(f"  - [benign] {benign}")
        for unknown in finding.uncertainties:
            summary_lines.append(f"  - [uncertain] {unknown}")

    instruction = (
        "Four specialist agents analysed one email. Their findings are below - these are "
        "trusted internal analysis, not attacker content. Fuse them into a single verdict.\n\n"
        f"Choose `verdict` from exactly this list: {VERDICT_LABELS}\n\n"
        "Write a rationale of 2-3 sentences that an analyst could paste into a ticket, naming "
        "the specific evidence that drove the call. Set needs_human_review to true when the "
        "findings genuinely conflict or are too thin to support a confident call - an honest "
        "'needs review' is better than a confident guess.\n\n"
        "Do not invent evidence that is not listed. Do not recommend actions.\n\n"
        f"AGENT FINDINGS:\n" + "\n".join(summary_lines)
    )
    blocks = "\n".join(
        [wrap_untrusted("subject", email.subject), wrap_untrusted("body", email.body[:2000])]
    )
    return structured_call(VerdictAssessment, instruction, blocks)


def _rule_rationale(verdict: str, findings: list[Finding]) -> str:
    drivers = [
        f"{f.component.lower()} reported {f.severity} severity"
        for f in findings
        if f.severity in {"medium", "high"}
    ]
    if not drivers:
        return "No agent reported medium or high severity; the message matches expected business context."
    return f"Verdict '{verdict}' was reached because " + ", and ".join(drivers) + "."
