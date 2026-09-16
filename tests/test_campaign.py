"""Campaign clustering must work for every message, not just msg-005."""

from __future__ import annotations

from app.agents.campaign import analyze_campaign, blast_radius, build_campaign_graph, find_cluster
from app.services.email_parser import load_emails


def test_clustering_works_on_a_non_msg005_message(by_id):
    """The MVP hardcoded `if email.id == "msg-005"`, so msg-011 - the second
    message in the same vendor-bank-change campaign - reported 'no campaign
    found'. This is the regression guard."""
    finding = analyze_campaign(by_id["msg-011"])
    cluster = find_cluster(by_id["msg-011"])
    assert cluster, "msg-011 shares a sender domain with msg-005"
    assert [c.id for c, _ in cluster] == ["msg-005"]
    assert finding.evidence, "clustered messages must produce evidence"
    assert finding.severity == "high"


def test_unrelated_message_reports_no_campaign(by_id):
    """The inverse guard: a genuinely standalone message must not be forced
    into a cluster just because the clustering code now runs for everything."""
    finding = analyze_campaign(by_id["msg-002"])
    assert find_cluster(by_id["msg-002"]) == []
    assert finding.severity == "low"
    assert finding.benign_signals


def test_every_message_gets_a_campaign_finding(emails):
    for email in emails:
        finding = analyze_campaign(email)
        assert finding.category == "campaign_scope"
        assert finding.evidence or finding.benign_signals


def test_cluster_reasons_are_explained(by_id):
    for _, reasons in find_cluster(by_id["msg-005"]):
        assert reasons and all(isinstance(reason, str) for reason in reasons)


def test_blast_radius_counts_telemetry(by_id):
    radius = blast_radius(by_id["msg-005"])
    assert radius["messages"] > 1
    assert radius["recipients"] >= 10


def test_campaign_graph_has_expected_node_kinds(by_id):
    graph = build_campaign_graph(by_id["msg-005"])
    kinds = {attrs.get("kind") for _, attrs in graph.nodes(data=True)}
    assert {"campaign", "message", "recipient"} <= kinds
    assert graph.number_of_edges() > 0


def test_unknown_sandbox_message_does_not_crash():
    from app.services.email_parser import parse_raw_text

    finding = analyze_campaign(parse_raw_text("no indicators here"))
    assert finding.category == "campaign_scope"
