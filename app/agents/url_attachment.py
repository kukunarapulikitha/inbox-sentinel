"""URL and attachment triage - fully deterministic.

No URL is ever fetched and no attachment is ever opened or detonated. This
agent reasons over the *strings and metadata* only.
"""

from __future__ import annotations

from app.models.email_models import EmailRecord
from app.models.findings import Evidence, Finding
from app.services.email_parser import domain_from_email, domain_from_url, similarity

RISKY_EXTENSIONS = (".zip", ".lnk", ".js", ".vbs", ".iso", ".scr", ".hta", ".docm", ".xlsm")
LOGIN_TOKENS = ("login", "verify", "secure", "signin", "auth", "account", "sso")


def analyze_url_attachment(email: EmailRecord) -> Finding:
    evidence: list[Evidence] = []
    benign: list[str] = []
    severity = "low"
    confidence = 0.67

    sender_domain = domain_from_email(email.sender_email)

    for url in email.urls:
        url_domain = domain_from_url(url)

        if url.startswith("qr:"):
            severity = "high"
            confidence = max(confidence, 0.89)
            evidence.append(
                Evidence(
                    type="qr_login_lure",
                    value=url,
                    explanation="QR code decodes to an external login-style URL, which evades link inspection in mail filters.",
                )
            )

        related = bool(sender_domain) and (
            url_domain == sender_domain or url_domain.endswith(f".{sender_domain}")
        )
        if url_domain and sender_domain and not related and similarity(url_domain, sender_domain) < 0.75:
            severity = "medium" if severity == "low" else severity
            evidence.append(
                Evidence(
                    type="external_link_domain",
                    value=url_domain,
                    explanation="Link domain is unrelated to the sender domain.",
                )
            )

        if any(token in url_domain for token in LOGIN_TOKENS):
            severity = "high"
            confidence = max(confidence, 0.9)
            evidence.append(
                Evidence(
                    type="login_url",
                    value=url,
                    explanation="URL host contains login or verification language, typical of a credential-harvesting page.",
                )
            )

    for attachment in email.attachments:
        if attachment.filename.lower().endswith(RISKY_EXTENSIONS):
            severity = "high"
            confidence = max(confidence, 0.93)
            evidence.append(
                Evidence(
                    type="risky_attachment_type",
                    value=attachment.filename,
                    explanation="Attachment type is commonly abused for malware delivery or script execution.",
                )
            )
        sandbox = attachment.mock_sandbox or ""
        if "script" in sandbox or "lnk" in sandbox:
            severity = "high"
            evidence.append(
                Evidence(
                    type="sandbox_finding",
                    value=sandbox,
                    explanation="Sandbox metadata indicates a script-execution chain.",
                )
            )
        if "clean" in sandbox:
            benign.append(f"{attachment.filename} has clean sandbox metadata.")

    if not email.urls and not email.attachments:
        benign.append("No URLs or attachments were present.")

    mitre = []
    if any(a.filename.lower().endswith(RISKY_EXTENSIONS) for a in email.attachments):
        mitre.append("T1566.001")
    if any(e.type in {"login_url", "qr_login_lure"} for e in evidence):
        mitre.append("T1566.002")

    return Finding(
        component="URL and attachment triage",
        category="url_attachment",
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        benign_signals=benign,
        uncertainties=[
            "URLs were not browsed and attachments were not detonated; this triage uses static indicators only."
        ],
        recommended_actions=[
            "Do not open links directly; use an isolated browser",
            "Submit attachment hashes to sandbox tooling",
        ],
        mitre_techniques=sorted(set(mitre)),
        source="rules",
    )
