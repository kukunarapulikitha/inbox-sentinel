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
    """Clear the key so every test runs the deterministic path.

    Without this, adding a real GROQ_API_KEY to .env would make the suite
    non-deterministic.
    """
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setattr("app.services.llm._client", None, raising=False)


@pytest.fixture
def emails():
    return load_emails()


@pytest.fixture
def by_id(emails):
    return {email.id: email for email in emails}
