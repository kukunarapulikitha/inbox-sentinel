"""Detection behaviour - the five original MVP assertions, ported to pytest."""

from __future__ import annotations

import pytest

from app.agents.graph import investigate


def test_authenticated_vendor_bank_change_is_bec(by_id):
    """The headline case: all auth passes and it is still BEC."""
    decision, policy = investigate(by_id["msg-005"])
    assert decision.verdict == "Suspected BEC"
    assert decision.risk_score >= 90
    assert decision.requires_human_approval
    assert by_id["msg-005"].all_auth_passed


def test_benign_invoice_stays_low_risk(by_id):
    decision, policy = investigate(by_id["msg-001"])
    assert decision.verdict == "Benign"
    assert decision.risk_score <= 30
    assert policy.band == "monitor"
    assert not policy.requires_approval


def test_credential_phish_detected(by_id):
    decision, _ = investigate(by_id["msg-002"])
    assert decision.verdict == "Credential phishing"
    assert "T1566.002" in decision.mitre_techniques


def test_all_messages_score(emails):
    decisions = [investigate(email)[0] for email in emails]
    assert len(decisions) == 14
    assert all(0 <= d.risk_score <= 100 for d in decisions)
    assert all(d.verdict for d in decisions)


@pytest.mark.parametrize(
    "message_id,expected",
    [
        ("msg-008", "Vendor RFQ fraud suspected"),
        ("msg-009", "Payment fraud suspected"),
        ("msg-010", "Invoice fraud suspected"),
        ("msg-011", "Suspected BEC"),
        ("msg-012", "Payroll fraud suspected"),
        ("msg-013", "Fake job phishing"),
        ("msg-014", "Advance-fee phishing scam"),
    ],
)
def test_scenario_verdicts(by_id, message_id, expected):
    assert investigate(by_id[message_id])[0].verdict == expected


def test_findings_are_attributable(by_id):
    """Every agent must report which path produced its finding."""
    decision, _ = investigate(by_id["msg-005"])
    categories = {f.category for f in decision.evidence_summary}
    assert categories == {"identity_auth", "content_bec", "url_attachment", "campaign_scope"}
    assert all(f.source in {"llm", "rules"} for f in decision.evidence_summary)
