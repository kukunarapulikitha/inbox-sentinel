"""Sandbox ingestion: .eml parsing, header extraction, artifact hashing."""

from __future__ import annotations

import hashlib

from app.services.email_parser import (
    extract_urls,
    normalize_subject,
    parse_auth_results,
    parse_eml,
    parse_raw_text,
)

EML = b"""From: Finance Director <director@trustedvendor.example>
Reply-To: billing@trustedvendor-payments.example
Return-Path: bounce@mailer.example
To: ap@company.example
Subject: Updated bank details
Authentication-Results: mx.company.example; spf=pass dkim=pass dmarc=fail
Content-Type: text/plain

Please update our remittance details before the payment runs today.
Portal: https://verify-trustedvendor.example/login
"""


def test_parse_eml_extracts_headers_and_urls():
    record = parse_eml(EML)
    assert record.sender_email == "director@trustedvendor.example"
    assert record.reply_to == "billing@trustedvendor-payments.example"
    assert record.return_path == "bounce@mailer.example"
    assert record.subject == "Updated bank details"
    assert record.auth_results == {"spf": "pass", "dkim": "pass", "dmarc": "fail"}
    assert not record.all_auth_passed
    assert "https://verify-trustedvendor.example/login" in record.urls


def test_parse_eml_hashes_attachments_without_executing():
    payload = b"fake-zip-bytes"
    multipart = (
        b"From: a@b.example\r\nSubject: invoice\r\n"
        b'Content-Type: multipart/mixed; boundary="X"\r\n\r\n'
        b"--X\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"
        b"--X\r\nContent-Type: application/zip\r\n"
        b'Content-Disposition: attachment; filename="invoice.zip"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        + __import__("base64").encodebytes(payload)
        + b"\r\n--X--\r\n"
    )
    record = parse_eml(multipart)
    assert len(record.attachments) == 1
    attachment = record.attachments[0]
    assert attachment.filename == "invoice.zip"
    assert attachment.sha256 == hashlib.sha256(payload).hexdigest()
    # Nothing was submitted to a real sandbox.
    assert attachment.mock_sandbox == "not_submitted"


def test_parse_raw_text_handles_bare_body():
    record = parse_raw_text("Please wire the funds today. https://x.example/pay")
    assert record.subject == "(no subject supplied)"
    assert record.urls == ["https://x.example/pay"]


def test_parse_raw_text_detects_header_block():
    record = parse_raw_text("Subject: hello\nFrom: a@b.example\n\nbody text")
    assert record.subject == "hello"


def test_auth_results_parsing_is_tolerant():
    assert parse_auth_results("spf=Pass; dkim=FAIL") == {"spf": "pass", "dkim": "fail"}
    assert parse_auth_results("") == {}


def test_url_extraction_strips_trailing_punctuation():
    assert extract_urls("go to https://a.example/x, now") == ["https://a.example/x"]


def test_subject_normalisation_collapses_templates():
    assert normalize_subject("Re: Invoice 4471 due") == normalize_subject("Invoice 9902 due")
