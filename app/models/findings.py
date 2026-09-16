"""Typed agent-output contract.

Every agent - deterministic or LLM-backed - returns a `Finding`. Keeping one
schema is what makes evidence fusion and failure attribution possible: if the
verdict is wrong we can point at the agent whose finding was wrong.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class Evidence(BaseModel):
    type: str = Field(description="Machine-readable indicator name, e.g. reply_to_mismatch")
    value: str = Field(description="The observed artifact value")
    explanation: str = Field(description="One sentence on why this matters to an analyst")


class Finding(BaseModel):
    component: str
    category: str
    severity: str = Field(default="low", description="low | medium | high")
    confidence: float = 0.6
    evidence: list[Evidence] = Field(default_factory=list)
    benign_signals: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    # Which path produced this finding: "llm" or "rules". Surfaced in the UI so
    # a fallback is visible rather than silent.
    source: str = "rules"


class ContentBecAssessment(BaseModel):
    """Structured-output schema for the content/BEC LLM node.

    Deliberately narrow: the model reports what it *observes* in the message.
    It cannot set a risk score, choose an action, or change message state.
    """

    severity: str = Field(description="low, medium, or high")
    confidence: float = Field(description="0.0-1.0 confidence in this assessment")
    social_engineering_tactics: list[str] = Field(
        default_factory=list,
        description="Tactics observed, e.g. urgency, authority pressure, secrecy, payment redirection",
    )
    evidence: list[Evidence] = Field(
        default_factory=list, description="Specific quoted artifacts supporting the assessment"
    )
    benign_signals: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(
        default_factory=list, description="What you could not determine from the message alone"
    )
    suspected_threat_type: str = Field(
        default="unknown",
        description="e.g. business email compromise, credential phishing, invoice fraud, benign",
    )


class VerdictAssessment(BaseModel):
    """Structured-output schema for the verdict-fusion LLM node."""

    verdict: str = Field(description="Short verdict label")
    threat_type: str = Field(description="Threat family")
    confidence: float = Field(description="0.0-1.0")
    rationale: str = Field(description="2-3 sentences an analyst can paste into a ticket")
    key_evidence: list[str] = Field(
        default_factory=list, description="The specific findings that drove the verdict"
    )
    uncertainties: list[str] = Field(default_factory=list)
    needs_human_review: bool = Field(
        default=False, description="True when evidence conflicts or is insufficient to call"
    )
