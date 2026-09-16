"""Content and BEC reasoner - the primary LLM node.

This is the one agent where semantic judgement genuinely beats a keyword list:
intent, impersonation, pretext and manufactured urgency. The deterministic
keyword path is kept as a fallback so the demo never dies on a missing key or
a rate limit, and so the two paths can be compared.
"""

from __future__ import annotations

from app.models.email_models import EmailRecord
from app.models.findings import ContentBecAssessment, Evidence, Finding
from app.services.email_parser import keyword_present
from app.services.llm import LLMUnavailable, structured_call, wrap_untrusted

HIGH_RISK_WORDS = {
    "urgent", "immediately", "expires", "validate", "verify", "confidential",
    "wire", "payment", "bank", "account", "today", "time-sensitive",
    "do not call", "scan", "authenticate", "quote", "source and supply",
    "outstanding invoices", "ap report", "amount due", "w9", "ach",
    "remittance", "direct deposit", "payroll", "no experience",
    "recruitment team", "proposition", "percentage", "funds",
}

INSTRUCTION = """Analyse the email below for business email compromise and social
engineering. Focus on things a keyword filter cannot see: who the sender is
pretending to be, what action they want, whether the pretext is plausible for
this recipient's role, and whether urgency or secrecy is being manufactured to
suppress verification.

Quote specific phrases as evidence. If the message looks like ordinary
business correspondence, say so and set severity to low - false positives cost
analyst trust."""


def content_signals(email: EmailRecord) -> dict[str, bool]:
    """Deterministic threat-pattern flags, shared by the rule fallback and the
    verdict node's fallback path. Kept separate from the LLM so the scoring
    chain stays reproducible."""
    text = f"{email.subject} {email.body}".lower()
    return {
        "bank_change": "bank" in text and ("updated" in text or "change" in text),
        "billing_update": ("ach" in text or "wire" in text)
        and ("remittance" in text or "no longer accept checks" in text),
        "payroll": "direct deposit" in text or "payroll information" in text,
        "invoice_fraud": "amount due" in text and ("invoice" in text or "w9" in text),
        "payment_fraud": "outstanding invoices" in text or "ap report" in text,
        "rfq_fraud": "quote the following items" in text or "source and supply" in text,
        "advance_fee": "proposition" in text and "percentage" in text and "funds" in text,
        "fake_job": "no experience" in text and "recruitment" in text,
        "credential_lure": "expires" in text or "validate" in text or "verify" in text,
        "anti_verification": "do not call" in text or "confidential" in text,
    }


def analyze_content_bec(email: EmailRecord) -> Finding:
    """Try the LLM first; fall back to rules on any failure."""
    try:
        return _llm_finding(email)
    except LLMUnavailable as exc:
        finding = _rule_finding(email)
        finding.uncertainties.append(f"LLM unavailable, deterministic path used ({exc}).")
        return finding


def _llm_finding(email: EmailRecord) -> Finding:
    blocks = "\n".join(
        [
            wrap_untrusted("subject", email.subject),
            wrap_untrusted("body", email.body),
            wrap_untrusted("sender", f"{email.sender_name} <{email.sender_email}>"),
        ]
    )
    context = (
        f"Recipient role: {email.recipient_role}. "
        f"Prior relationship with sender: {email.prior_relationship}. "
        f"Sender authentication (spf/dkim/dmarc): {email.auth_summary}."
    )
    assessment = structured_call(
        ContentBecAssessment, f"{INSTRUCTION}\n\nAnalyst context: {context}", blocks
    )

    severity = assessment.severity.lower().strip()
    if severity not in {"low", "medium", "high"}:
        severity = "medium"

    evidence = list(assessment.evidence)
    if assessment.social_engineering_tactics:
        evidence.append(
            Evidence(
                type="social_engineering_tactics",
                value=", ".join(assessment.social_engineering_tactics),
                explanation="Tactics the model identified in the message.",
            )
        )

    return Finding(
        component="Content and BEC reasoner",
        category="content_bec",
        severity=severity,
        confidence=min(0.98, max(0.3, assessment.confidence)),
        evidence=evidence,
        benign_signals=assessment.benign_signals,
        uncertainties=assessment.uncertainties,
        recommended_actions=[
            "Compare the request against prior sender behaviour",
            "Require out-of-band verification for any payment or payroll change",
        ],
        mitre_techniques=["T1566"] if severity == "high" else [],
        source="llm",
    )


def _rule_finding(email: EmailRecord) -> Finding:
    """Ported keyword path from the MVP. Deliberately unchanged in behaviour so
    it remains a known-good baseline to compare the LLM against."""
    text = f"{email.subject} {email.body}".lower()
    signals = content_signals(email)
    evidence: list[Evidence] = []
    benign: list[str] = []
    severity = "low"
    confidence = 0.72

    matched = sorted(word for word in HIGH_RISK_WORDS if keyword_present(text, word))
    if matched:
        severity = "medium"
        confidence = 0.82
        evidence.append(
            Evidence(
                type="pressure_or_sensitive_request",
                value=", ".join(matched),
                explanation="Message uses urgency, credential, payment, or secrecy language.",
            )
        )

    patterns = [
        ("bank_change", "bank_change_request", "Bank-account change requests are a top BEC indicator.", 0.94),
        ("billing_update", "billing_account_update", "Message attempts to update ACH or wire remittance instructions.", 0.94),
        ("payroll", "payroll_change_request", "Message requests payroll or direct-deposit changes outside the normal portal.", 0.91),
        ("invoice_fraud", "invoice_fraud_pattern", "Specific invoice demand combined with tax-document context.", 0.9),
        ("payment_fraud", "vague_payment_demand", "Asks for AP reports or invoices with no specific business context.", 0.89),
        ("rfq_fraud", "vendor_rfq_fraud_pattern", "Matches RFQ phishing patterns with source-and-supply wording.", 0.88),
        ("advance_fee", "advance_fee_scam_pattern", "Offers a percentage for helping transfer or hold funds.", 0.9),
        ("credential_lure", "credential_lure", "Asks the user to validate or verify account access.", 0.85),
        ("anti_verification", "anti_verification_language", "Message discourages normal verification behaviour.", 0.85),
    ]
    for key, ev_type, explanation, conf in patterns:
        if signals[key]:
            severity = "high"
            confidence = max(confidence, conf)
            evidence.append(Evidence(type=ev_type, value=email.subject, explanation=explanation))

    if signals["fake_job"]:
        severity = "medium" if severity == "low" else severity
        confidence = max(confidence, 0.84)
        evidence.append(
            Evidence(
                type="fake_job_pattern",
                value=email.subject,
                explanation="Fake-job wording with unusually low qualification requirements.",
            )
        )

    if "normal monthly schedule" in text and "known monthly vendor" in (email.prior_relationship or ""):
        benign.append("Request matches the expected vendor invoice pattern.")
        confidence = 0.7

    return Finding(
        component="Content and BEC reasoner",
        category="content_bec",
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        benign_signals=benign,
        uncertainties=[
            "Historical payment-workflow data is needed to confirm business context."
        ]
        if severity in {"medium", "high"}
        else [],
        recommended_actions=[
            "Compare the request against prior sender behaviour",
            "Require out-of-band verification for any payment or payroll change",
        ],
        mitre_techniques=["T1566"] if severity == "high" else [],
        source="rules",
    )
