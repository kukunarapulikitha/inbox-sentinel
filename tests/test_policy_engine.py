"""Policy band boundaries - the exact edges, since these gate real actions."""

from __future__ import annotations

import pytest

from app.services import policy_engine


@pytest.mark.parametrize(
    "risk,band,approval",
    [
        (0, "monitor", False),
        (29, "monitor", False),
        (30, "analyst_review", False),
        (59, "analyst_review", False),
        (60, "recommend_quarantine", True),
        (79, "recommend_quarantine", True),
        (80, "contain_and_purge", True),
        (100, "contain_and_purge", True),
    ],
)
def test_band_boundaries(risk, band, approval):
    decision = policy_engine.evaluate(risk, "Suspicious")
    assert decision.band == band
    assert decision.requires_approval is approval


def test_out_of_range_risk_is_clamped():
    assert policy_engine.evaluate(500, "Suspicious").band == "contain_and_purge"
    assert policy_engine.evaluate(-5, "Benign").band == "monitor"


def test_verdict_specific_actions_are_layered_in():
    decision = policy_engine.evaluate(91, "Suspected BEC")
    joined = " ".join(decision.actions).lower()
    assert "bank-change" in joined or "payment" in joined
    # Must not blanket-block a possibly-compromised legitimate partner.
    assert any("blanket-blocking" in action for action in decision.actions)


def test_needs_human_review_forces_approval():
    decision = policy_engine.evaluate(10, "Benign", needs_human_review=True)
    assert decision.requires_approval
    assert not decision.auto_executed
    assert "conflict" in decision.justification.lower()
