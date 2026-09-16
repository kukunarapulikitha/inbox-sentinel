"""Audit persistence and the corrected detection metrics."""

from __future__ import annotations

import pytest

from app.services import audit_log, evaluator


@pytest.fixture(autouse=True)
def temp_db(monkeypatch, tmp_path):
    """Never touch the real audit database from tests."""
    monkeypatch.setattr(audit_log, "DB_PATH", tmp_path / "audit.db")


def test_approval_writes_row_and_flips_status():
    assert audit_log.get_action_status("msg-005") == "delivered"
    audit_log.approve_action(
        message_id="msg-005",
        action="Quarantine and purge matching messages tenant-wide",
        verdict="Suspected BEC",
        risk_score=91,
        policy_band="contain_and_purge",
        analyst="likitha@company.example",
    )
    assert audit_log.get_action_status("msg-005") == "quarantined"
    rows = audit_log.read_log()
    assert len(rows) == 1
    assert rows[0]["event_type"] == "action_approved"
    assert rows[0]["approved"] == 1
    assert rows[0]["analyst"] == "likitha@company.example"


def test_feedback_is_persisted_and_audited():
    audit_log.record_feedback(
        message_id="msg-003",
        predicted="Suspicious",
        feedback="false negative",
        corrected="Suspected BEC",
    )
    feedback = audit_log.read_feedback()
    assert len(feedback) == 1
    assert feedback[0]["corrected"] == "Suspected BEC"
    # Feedback also lands in the immutable audit trail.
    assert any(row["event_type"] == "analyst_feedback" for row in audit_log.read_log())


def test_precision_and_recall_are_not_the_same_number():
    """Guards the MVP bug where both were reported as correct/total."""
    pairs = [
        ("Benign", "Benign"),
        ("Suspected BEC", "Suspected BEC"),
        ("Benign", "Suspected BEC"),   # false positive for BEC
        ("Suspected BEC", "Benign"),   # false negative for BEC
        ("Suspected BEC", "Suspected BEC"),
    ]
    rows = {row["Class"]: row for row in evaluator.per_class_metrics(pairs)}
    bec = rows["Suspected BEC"]
    assert bec["TP"] == 2 and bec["FP"] == 1 and bec["FN"] == 1
    assert bec["Precision"] == pytest.approx(2 / 3, abs=1e-3)
    assert bec["Recall"] == pytest.approx(2 / 3, abs=1e-3)

    skewed = [("Benign", "Suspected BEC")] * 3 + [("Suspected BEC", "Suspected BEC")] * 1
    row = {r["Class"]: r for r in evaluator.per_class_metrics(skewed)}["Suspected BEC"]
    assert row["Precision"] != row["Recall"]


def test_binary_metrics_report_fpr_and_fnr():
    pairs = [("Benign", "Benign"), ("Benign", "Suspected BEC"), ("Suspected BEC", "Benign")]
    metrics = evaluator.binary_metrics(pairs)
    assert metrics["FP"] == 1 and metrics["FN"] == 1
    assert metrics["FPR"] == pytest.approx(0.5)
    assert metrics["FNR"] == pytest.approx(1.0)


def test_unlabelled_message_does_not_raise(emails):
    """The MVP raised KeyError on any message outside its hardcoded label dict."""
    from app.services.email_parser import parse_raw_text

    extra = parse_raw_text("brand new message", record_id="msg-999")
    pairs = evaluator.confusion_pairs(emails + [extra], {"msg-999": "Suspicious"})
    assert all(expected != "(unlabelled)" for expected, _ in pairs)
    assert evaluator.unlabelled([extra]) == ["msg-999"]
