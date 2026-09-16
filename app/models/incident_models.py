"""Incident- and policy-level models."""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.models.findings import Finding


class IncidentDecision(BaseModel):
    verdict: str
    threat_type: str
    risk_score: int
    confidence: float
    evidence_summary: list[Finding] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    requires_human_approval: bool = True
    mitre_techniques: list[str] = Field(default_factory=list)
    rationale: str = ""
    needs_human_review: bool = False
    # "live" when both LLM nodes ran, "fallback" when any node used rules.
    llm_mode: str = "fallback"
    llm_detail: str = ""


class PolicyDecision(BaseModel):
    band: str
    band_range: str
    disposition: str
    actions: list[str] = Field(default_factory=list)
    requires_approval: bool = True
    auto_executed: bool = False
    justification: str = ""
