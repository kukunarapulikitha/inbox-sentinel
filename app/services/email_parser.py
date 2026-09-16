"""Email loading, artifact extraction, and shared analysis helpers.

Nothing in here fetches a URL or opens an attachment. Hashes are computed
locally over bytes already in memory; links are parsed as strings only.
"""

from __future__ import annotations

import hashlib
import json
import re
from difflib import SequenceMatcher
from email import message_from_bytes
from email.message import Message
from pathlib import Path
from urllib.parse import urlparse

from app.models.email_models import Attachment, EmailRecord

DATA_DIR = Path(__file__).resolve().parents[2] / "data"

URL_PATTERN = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


# --------------------------------------------------------------------------
# shared helpers (ported from the MVP's analysis module)
# --------------------------------------------------------------------------
def domain_from_email(email_address: str | None) -> str:
    if not email_address or "@" not in email_address:
        return ""
    return email_address.rsplit("@", 1)[1].strip().strip(">").lower()


def domain_from_url(url: str) -> str:
    return urlparse(url.removeprefix("qr:")).netloc.lower()


def similarity(left: str, right: str) -> float:
    return SequenceMatcher(None, left.lower(), right.lower()).ratio()


def keyword_present(text: str, keyword: str) -> bool:
    if " " in keyword or "-" in keyword:
        return keyword in text
    return re.search(rf"\b{re.escape(keyword)}\b", text) is not None


def normalize_subject(subject: str) -> str:
    """Strip reply/forward prefixes and volatile tokens so templated
    campaign subjects collapse to the same key."""
    text = subject.lower()
    text = re.sub(r"^(re|fwd|fw)\s*:\s*", "", text).strip()
    text = re.sub(r"\d+", "#", text)
    return re.sub(r"[^a-z#\s]", " ", text).strip()


# --------------------------------------------------------------------------
# corpus loading
# --------------------------------------------------------------------------
def load_emails(path: Path | None = None) -> list[EmailRecord]:
    source = path or DATA_DIR / "emails.jsonl"
    return [EmailRecord(**json.loads(line)) for line in _read_lines(source)]


def load_interactions(path: Path | None = None) -> list[dict]:
    return [json.loads(line) for line in _read_lines(path or DATA_DIR / "interactions.jsonl")]


def load_expected_labels(path: Path | None = None) -> dict[str, dict]:
    rows = [json.loads(line) for line in _read_lines(path or DATA_DIR / "expected_labels.jsonl")]
    return {row["id"]: row for row in rows}


def _read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line for line in path.read_text().splitlines() if line.strip()]


# --------------------------------------------------------------------------
# sandbox ingestion: raw text or .eml
# --------------------------------------------------------------------------
def extract_urls(text: str) -> list[str]:
    seen: list[str] = []
    for match in URL_PATTERN.findall(text or ""):
        url = match.rstrip(".,;:")
        if url not in seen:
            seen.append(url)
    return seen


def parse_eml(raw: bytes, record_id: str = "sandbox-001") -> EmailRecord:
    """Parse an uploaded .eml into an EmailRecord.

    Attachments are hashed, never written to disk and never executed.
    """
    message: Message = message_from_bytes(raw)
    body_parts: list[str] = []
    attachments: list[Attachment] = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            disposition = str(part.get("Content-Disposition") or "")
            filename = part.get_filename()
            if filename or "attachment" in disposition.lower():
                payload = part.get_payload(decode=True) or b""
                attachments.append(
                    Attachment(
                        filename=filename or "unnamed-attachment",
                        mime_type=part.get_content_type(),
                        sha256=hashlib.sha256(payload).hexdigest(),
                        mock_sandbox="not_submitted",
                    )
                )
            elif part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True) or b""
                body_parts.append(payload.decode(part.get_content_charset() or "utf-8", "replace"))
    else:
        payload = message.get_payload(decode=True) or b""
        body_parts.append(payload.decode(message.get_content_charset() or "utf-8", "replace"))

    body = "\n".join(body_parts).strip()
    return EmailRecord(
        id=record_id,
        scenario="analyst submission (.eml)",
        subject=message.get("Subject", ""),
        sender_name=_display_name(message.get("From", "")),
        sender_email=_address(message.get("From", "")),
        reply_to=_address(message.get("Reply-To", "")) or None,
        return_path=_address(message.get("Return-Path", "")) or None,
        recipient=_address(message.get("To", "")),
        recipient_role="unknown",
        body=body,
        auth_results=parse_auth_results(message.get("Authentication-Results", "")),
        urls=extract_urls(body),
        attachments=attachments,
        timestamp=message.get("Date", ""),
        prior_relationship="unknown",
    )


def parse_raw_text(raw_text: str, record_id: str = "sandbox-001") -> EmailRecord:
    """Parse pasted email text. Handles either a full header block or a bare body."""
    if re.match(r"^[A-Za-z-]+:\s", raw_text.strip().splitlines()[0] if raw_text.strip() else ""):
        return parse_eml(raw_text.encode("utf-8", "replace"), record_id)

    return EmailRecord(
        id=record_id,
        scenario="analyst submission (pasted body)",
        subject="(no subject supplied)",
        body=raw_text,
        urls=extract_urls(raw_text),
        recipient_role="unknown",
    )


def parse_auth_results(header: str) -> dict[str, str]:
    """Pull spf/dkim/dmarc results out of an Authentication-Results header."""
    results: dict[str, str] = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{mechanism}\s*=\s*(\w+)", header or "", re.IGNORECASE)
        if match:
            results[mechanism] = match.group(1).lower()
    return results


def _address(header_value: str) -> str:
    match = re.search(r"<([^>]+)>", header_value or "")
    if match:
        return match.group(1).strip().lower()
    value = (header_value or "").strip()
    return value.lower() if "@" in value else ""


def _display_name(header_value: str) -> str:
    value = (header_value or "").split("<")[0].strip().strip('"')
    return value
