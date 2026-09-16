"""Shared fixtures.

Verdict assertions must be reproducible, so the default fixture forces the
deterministic path by clearing the API key. Tests that specifically exercise
the LLM boundary opt in by patching `structured_call`.
"""

from __future__ import annotations

import pytest

from app.services.email_parser import load_emails


@pytest.fixture(autouse=True)
def force_rule_path(monkeypatch):
    """Clear every provider key so tests run the deterministic path.

    This keeps the suite hermetic and fast. Missing GOOGLE_API_KEY here once
    made the suite issue real Gemini calls, taking it from 0.5s to 224s.
    """
    for env_var in ("GROQ_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(env_var, raising=False)
    # Drop cached clients so a previous test's provider cannot leak in.
    monkeypatch.setattr("app.services.llm._clients", {}, raising=False)


@pytest.fixture
def emails():
    return load_emails()


@pytest.fixture
def by_id(emails):
    return {email.id: email for email in emails}
