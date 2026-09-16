"""Identity and authentication analyzer - fully deterministic.

Header and auth logic is mechanical and must be reproducible, so no LLM here.
"""

from __future__ import annotations

from app.models.email_models import EmailRecord
from app.models.findings import Evidence, Finding
from app.services.email_parser import domain_from_email

BRANDS = ("microsoft", "google", "sharepoint", "teams", "docusign", "okta")
AUTH_KEYS = ("spf", "dkim", "dmarc")


def analyze_identity_auth(email: EmailRecord) -> Finding:
    evidence: list[Evidence] = []
    benign: list[str] = []
    severity = "low"
    confidence = 0.68

    sender_domain = domain_from_email(email.sender_email)
    reply_domain = domain_from_email(email.reply_to)
    return_domain = domain_from_email(email.return_path)
    auth_pass_count = sum(email.auth_results.get(key) == "pass" for key in AUTH_KEYS)

    if reply_domain and reply_domain != sender_domain:
        severity = "high"
        confidence = 0.9
        evidence.append(
            Evidence(
                type="reply_to_mismatch",
                value=str(email.reply_to),
                explanation="Reply-to domain differs from the visible sender domain, so replies leave the expected organisation.",
            )
        )

    if return_domain and sender_domain and return_domain != sender_domain:
        evidence.append(
            Evidence(
                type="return_path_mismatch",
                value=str(email.return_path),
                explanation="Return-path domain differs from the visible sender domain.",
            )
        )

    if any(email.auth_results.get(key) == "fail" for key in AUTH_KEYS):
        severity = "high"
        evidence.append(
            Evidence(
                type="auth_failure",
                value=email.auth_summary,
                explanation="One or more sender authentication checks failed.",
            )
        )
    elif auth_pass_count == 3:
        benign.append("SPF, DKIM, and DMARC all passed for the sender.")

    for brand in BRANDS:
        # homoglyph check: micros0ft -> microsoft once digits are folded back
        folded = sender_domain.replace("0", "o").replace("1", "l").replace("rn", "m")
        if brand in folded and brand not in sender_domain:
            evidence.append(
                Evidence(
                    type="lookalike_domain",
                    value=sender_domain,
                    explanation=f"Sender domain is a homoglyph of the {brand} brand.",
                )
            )
            severity = "high"
            confidence = max(confidence, 0.92)

    if "unusual" in (email.prior_relationship or ""):
        evidence.append(
            Evidence(
                type="trusted_sender_unusual_behavior",
                value=email.prior_relationship,
                explanation="Known sender identity, but the request differs from established behaviour - consistent with a compromised account.",
            )
        )
        severity = "medium" if severity == "low" else severity

    uncertainties = []
    if auth_pass_count == 3:
        uncertainties.append(
            "Authentication passing does not prove sender intent; a compromised legitimate account also passes SPF/DKIM/DMARC."
        )

    return Finding(
        component="Identity and authentication analyzer",
        category="identity_auth",
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        benign_signals=benign,
        uncertainties=uncertainties,
        recommended_actions=[
            "Review sender history for this domain",
            "Check reply-to and return-path alignment",
        ],
        source="rules",
    )
