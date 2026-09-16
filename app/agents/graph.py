"""LangGraph investigation graph.

    parse -> [identity_auth, content_bec, url_attachment, campaign] -> verdict -> policy

The four analyzers fan out from `parse` and fan in at `verdict`. Only
`content_bec` and `verdict` call the LLM; the rest is deterministic, and
`policy` never sees a model at all.
"""

from __future__ import annotations

from typing import Annotated, Any, TypedDict

from langgraph.graph import END, START, StateGraph

from app.agents.campaign import analyze_campaign
from app.agents.content_bec import analyze_content_bec
from app.agents.identity_auth import analyze_identity_auth
from app.agents.url_attachment import analyze_url_attachment
from app.agents.verdict import decide_verdict
from app.models.email_models import EmailRecord
from app.models.findings import Finding
from app.models.incident_models import IncidentDecision, PolicyDecision
from app.services import policy_engine
from app.services.llm import PROVIDER_LABEL


def _merge(existing: list[Finding], incoming: list[Finding]) -> list[Finding]:
    """Reducer so the four parallel analyzer nodes can all append findings."""
    return (existing or []) + (incoming or [])


class InvestigationState(TypedDict, total=False):
    email: EmailRecord
    findings: Annotated[list[Finding], _merge]
    verdict: dict[str, Any]
    policy: PolicyDecision
    decision: IncidentDecision


# --- nodes ---------------------------------------------------------------
def parse_node(state: InvestigationState) -> dict:
    # Artifact extraction already happened in email_parser; this node exists as
    # the graph's single entry point and is where a real ingestion adapter
    # (Gmail / Microsoft Graph) would normalise a message.
    return {"findings": []}


def identity_node(state: InvestigationState) -> dict:
    return {"findings": [analyze_identity_auth(state["email"])]}


def content_node(state: InvestigationState) -> dict:
    return {"findings": [analyze_content_bec(state["email"])]}


def url_node(state: InvestigationState) -> dict:
    return {"findings": [analyze_url_attachment(state["email"])]}


def campaign_node(state: InvestigationState) -> dict:
    return {"findings": [analyze_campaign(state["email"])]}


ORDER = {"identity_auth": 0, "content_bec": 1, "url_attachment": 2, "campaign_scope": 3}


def verdict_node(state: InvestigationState) -> dict:
    # Parallel nodes finish in nondeterministic order; sort so the rendered
    # evidence list and any snapshot test are stable.
    findings = sorted(state["findings"], key=lambda f: ORDER.get(f.category, 99))
    return {"verdict": decide_verdict(state["email"], findings), "findings": []}


def policy_node(state: InvestigationState) -> dict:
    verdict = state["verdict"]
    findings = sorted(state["findings"], key=lambda f: ORDER.get(f.category, 99))
    policy = policy_engine.evaluate(
        risk=verdict["risk_score"],
        verdict=verdict["verdict"],
        needs_human_review=verdict.get("needs_human_review", False),
    )

    llm_sources = {f.source for f in findings if f.category == "content_bec"}
    llm_sources.add(verdict.get("source", "rules"))
    live = llm_sources == {"llm"}

    uncertainties = list(verdict.get("uncertainties", []))
    for finding in findings:
        uncertainties.extend(finding.uncertainties)

    decision = IncidentDecision(
        verdict=verdict["verdict"],
        threat_type=verdict["threat_type"],
        risk_score=verdict["risk_score"],
        confidence=verdict["confidence"],
        evidence_summary=findings,
        recommended_actions=policy.actions,
        requires_human_approval=policy.requires_approval,
        mitre_techniques=verdict.get("mitre_techniques", []),
        rationale=verdict.get("rationale", ""),
        needs_human_review=verdict.get("needs_human_review", False),
        llm_mode="live" if live else "fallback",
        llm_detail=PROVIDER_LABEL if live else "deterministic rules",
    )
    return {"policy": policy, "decision": decision}


# --- graph ---------------------------------------------------------------
def build_graph():
    builder = StateGraph(InvestigationState)
    builder.add_node("parse", parse_node)
    builder.add_node("identity_auth", identity_node)
    builder.add_node("content_bec", content_node)
    builder.add_node("url_attachment", url_node)
    builder.add_node("campaign", campaign_node)
    builder.add_node("verdict", verdict_node)
    builder.add_node("policy", policy_node)

    builder.add_edge(START, "parse")
    for analyzer in ("identity_auth", "content_bec", "url_attachment", "campaign"):
        builder.add_edge("parse", analyzer)
        builder.add_edge(analyzer, "verdict")
    builder.add_edge("verdict", "policy")
    builder.add_edge("policy", END)
    return builder.compile()


_graph = None


def get_graph():
    global _graph
    if _graph is None:
        _graph = build_graph()
    return _graph


def investigate(email: EmailRecord) -> tuple[IncidentDecision, PolicyDecision]:
    """Run the full investigation for one message."""
    final = get_graph().invoke({"email": email, "findings": []})
    return final["decision"], final["policy"]
