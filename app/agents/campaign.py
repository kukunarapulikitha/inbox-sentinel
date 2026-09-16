"""Campaign and blast-radius correlator - deterministic clustering.

Replaces the MVP's `if email.id == "msg-005"` special case with real
similarity clustering that works for any message, including analyst
submissions that are not in the corpus at all.
"""

from __future__ import annotations

import networkx as nx

from app.models.email_models import EmailRecord
from app.models.findings import Evidence, Finding
from app.services.email_parser import (
    domain_from_email,
    domain_from_url,
    load_emails,
    load_interactions,
    normalize_subject,
    similarity,
)

SUBJECT_MATCH_THRESHOLD = 0.72


def _shared_indicators(left: EmailRecord, right: EmailRecord) -> list[str]:
    """Why these two messages look like the same campaign."""
    reasons: list[str] = []

    left_sender = domain_from_email(left.sender_email)
    if left_sender and left_sender == domain_from_email(right.sender_email):
        reasons.append(f"shared sender domain {left_sender}")

    left_urls = {domain_from_url(u) for u in left.urls if domain_from_url(u)}
    shared_urls = left_urls & {domain_from_url(u) for u in right.urls if domain_from_url(u)}
    if shared_urls:
        reasons.append(f"shared URL domain {', '.join(sorted(shared_urls))}")

    left_hashes = {a.sha256 for a in left.attachments if a.sha256}
    shared_hashes = left_hashes & {a.sha256 for a in right.attachments if a.sha256}
    if shared_hashes:
        reasons.append(f"shared attachment hash {', '.join(sorted(shared_hashes))}")

    subject_score = similarity(normalize_subject(left.subject), normalize_subject(right.subject))
    if subject_score >= SUBJECT_MATCH_THRESHOLD:
        reasons.append(f"near-identical subject template ({subject_score:.2f})")

    return reasons


def find_cluster(email: EmailRecord, corpus: list[EmailRecord] | None = None) -> list[tuple[EmailRecord, list[str]]]:
    """Messages in the corpus that share indicators with `email`."""
    pool = corpus if corpus is not None else load_emails()
    matches: list[tuple[EmailRecord, list[str]]] = []
    for candidate in pool:
        if candidate.id == email.id:
            continue
        reasons = _shared_indicators(email, candidate)
        if reasons:
            matches.append((candidate, reasons))
    return matches


def related_telemetry(email: EmailRecord) -> list[dict]:
    """Seeded tenant-wide telemetry matching this message's sender domain."""
    sender_domain = domain_from_email(email.sender_email)
    if not sender_domain:
        return []
    return [row for row in load_interactions() if row.get("sender_domain") == sender_domain]


def build_campaign_graph(email: EmailRecord, corpus: list[EmailRecord] | None = None) -> nx.Graph:
    """campaign -> messages -> recipients -> indicators, for the UI graph view."""
    graph = nx.Graph()
    campaign_node = f"campaign::{domain_from_email(email.sender_email) or email.id}"
    graph.add_node(campaign_node, kind="campaign")

    def attach(record: EmailRecord) -> None:
        message_node = f"msg::{record.id}"
        graph.add_node(message_node, kind="message", label=record.subject)
        graph.add_edge(campaign_node, message_node)
        if record.recipient:
            graph.add_node(f"rcpt::{record.recipient}", kind="recipient")
            graph.add_edge(message_node, f"rcpt::{record.recipient}")
        for url in record.urls:
            host = domain_from_url(url)
            if host:
                graph.add_node(f"ioc::{host}", kind="indicator")
                graph.add_edge(message_node, f"ioc::{host}")
        for attachment in record.attachments:
            if attachment.sha256:
                graph.add_node(f"ioc::{attachment.sha256}", kind="indicator")
                graph.add_edge(message_node, f"ioc::{attachment.sha256}")

    attach(email)
    for candidate, _ in find_cluster(email, corpus):
        attach(candidate)

    for row in related_telemetry(email):
        message_node = f"msg::{row['message_id']}"
        graph.add_node(message_node, kind="message", label=row.get("indicator", ""))
        graph.add_edge(campaign_node, message_node)
        graph.add_node(f"rcpt::{row['recipient']}", kind="recipient")
        graph.add_edge(message_node, f"rcpt::{row['recipient']}")

    return graph


def blast_radius(email: EmailRecord, corpus: list[EmailRecord] | None = None) -> dict[str, int]:
    cluster = find_cluster(email, corpus)
    telemetry = related_telemetry(email)
    recipients = {email.recipient} | {c.recipient for c, _ in cluster}
    recipients |= {row["recipient"] for row in telemetry}
    recipients.discard("")
    return {
        "messages": 1 + len(cluster) + len(telemetry),
        "recipients": len(recipients),
        "opened": sum(1 for row in telemetry if row.get("opened")) + sum(1 for c, _ in cluster if c.opened),
        "clicked": sum(1 for row in telemetry if row.get("clicked")) + sum(1 for c, _ in cluster if c.clicked),
        "replied": sum(1 for row in telemetry if row.get("replied")) + sum(1 for c, _ in cluster if c.replied),
        "submitted_credentials": sum(1 for c, _ in cluster if c.submitted_credentials)
        + (1 if email.submitted_credentials else 0),
    }


def analyze_campaign(email: EmailRecord, corpus: list[EmailRecord] | None = None) -> Finding:
    evidence: list[Evidence] = []
    benign: list[str] = []
    severity = "low"
    confidence = 0.74

    cluster = find_cluster(email, corpus)
    telemetry = related_telemetry(email)
    radius = blast_radius(email, corpus)

    if cluster:
        severity = "medium"
        confidence = 0.85
        preview = "; ".join(f"{c.id} ({', '.join(r)})" for c, r in cluster[:4])
        evidence.append(
            Evidence(
                type="clustered_messages",
                value=f"{len(cluster)} related message(s): {preview}",
                explanation="Messages sharing sender domain, URL domain, attachment hash, or subject template are treated as one campaign.",
            )
        )

    if telemetry:
        severity = "high"
        confidence = 0.91
        evidence.append(
            Evidence(
                type="tenant_telemetry",
                value=f"{len(telemetry)} additional deliveries to {radius['recipients']} recipients",
                explanation="Related messages reached multiple recipients across the tenant.",
            )
        )
        if radius["opened"] or radius["replied"]:
            evidence.append(
                Evidence(
                    type="recipient_interactions",
                    value=f"{radius['opened']} opened, {radius['replied']} replied, {radius['clicked']} clicked",
                    explanation="Recipient interaction raises containment urgency beyond simple delivery.",
                )
            )

    if radius["recipients"] >= 10:
        severity = "high"
        evidence.append(
            Evidence(
                type="blast_radius",
                value=f"{radius['recipients']} recipients affected",
                explanation="Wide distribution indicates a campaign rather than a one-off message.",
            )
        )

    if not cluster and not telemetry:
        benign.append("No related messages were found for this sender, URL, hash, or subject template.")

    return Finding(
        component="Campaign and blast-radius correlator",
        category="campaign_scope",
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        benign_signals=benign,
        uncertainties=[
            "Scope is limited to the local corpus and seeded telemetry; a real deployment would query the mail tenant."
        ],
        recommended_actions=[
            "Search the tenant for matching senders, URLs, attachment hashes, and subject templates",
            "Prioritise recipients who clicked or replied",
        ],
        source="rules",
    )
