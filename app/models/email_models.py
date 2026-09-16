"""Typed email artifact models.

Everything in here is *evidence*, never instructions. Body text, URLs, and
attachment metadata are attacker-controlled and are treated as untrusted data
throughout the pipeline.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class Attachment(BaseModel):
    filename: str
    mime_type: str = "application/octet-stream"
    sha256: str = ""
    mock_sandbox: str = "not_submitted"


class EmailRecord(BaseModel):
    id: str
    scenario: str = "ad-hoc submission"
    subject: str = ""
    sender_name: str = ""
    sender_email: str = ""
    reply_to: str | None = None
    return_path: str | None = None
    recipient: str = ""
    recipient_role: str = "unknown"
    body: str = ""
    auth_results: dict[str, str] = Field(default_factory=dict)
    urls: list[str] = Field(default_factory=list)
    attachments: list[Attachment] = Field(default_factory=list)
    timestamp: str = ""
    opened: bool = False
    clicked: bool = False
    replied: bool = False
    submitted_credentials: bool = False
    action_status: str = "delivered"
    prior_relationship: str = "unknown"

    @property
    def auth_summary(self) -> str:
        return "/".join(self.auth_results.get(k, "none") for k in ("spf", "dkim", "dmarc"))

    @property
    def all_auth_passed(self) -> bool:
        return all(self.auth_results.get(k) == "pass" for k in ("spf", "dkim", "dmarc"))

    @property
    def interactions(self) -> list[str]:
        flags = {
            "opened": self.opened,
            "clicked": self.clicked,
            "replied": self.replied,
            "submitted credentials": self.submitted_credentials,
        }
        return [label for label, happened in flags.items() if happened]
