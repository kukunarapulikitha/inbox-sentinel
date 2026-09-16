"""Inbox Sentinel - analyst console.

Run with:  streamlit run app/ui/streamlit_app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow `streamlit run app/ui/streamlit_app.py` from the repo root.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
import streamlit as st

from app.agents.campaign import blast_radius, build_campaign_graph, find_cluster
from app.agents.graph import investigate
from app.models.email_models import EmailRecord
from app.services import audit_log, evaluator
from app.services.email_parser import load_emails, parse_eml, parse_raw_text
from app.services.llm import PROVIDER_LABEL, api_key_present

st.set_page_config(page_title="Inbox Sentinel", page_icon="IS", layout="wide")

st.markdown(
    """
    <style>
      .stApp { background-color: #0e1117; }
      .verdict-card { background:#1a1f2b; border-left:4px solid #4c8bf5; padding:1rem 1.25rem;
                      border-radius:6px; margin-bottom:1rem; }
      .sev-high { color:#ff6b6b; font-weight:600; }
      .sev-medium { color:#ffa94d; font-weight:600; }
      .sev-low { color:#69db7c; font-weight:600; }
      .evidence { background:#161b26; border-radius:6px; padding:.6rem .8rem; margin:.3rem 0;
                  font-family:ui-monospace,monospace; font-size:.85rem; }
      .email-body { background:#0b0e14; border:1px solid #262c3a; border-radius:6px;
                    padding:.9rem; white-space:pre-wrap; font-family:ui-monospace,monospace;
                    font-size:.82rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

SEVERITY_CLASS = {"high": "sev-high", "medium": "sev-medium", "low": "sev-low"}


# --------------------------------------------------------------------------
# data + investigation caching
# --------------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def get_emails() -> list[EmailRecord]:
    return load_emails()


@st.cache_data(show_spinner="Running the agent graph...")
def run_investigation(email_json: str):
    """Cached per message. Keyed on the serialised record so sandbox
    submissions re-run when their content changes."""
    email = EmailRecord.model_validate_json(email_json)
    decision, policy = investigate(email)
    return decision, policy


def investigate_email(email: EmailRecord):
    return run_investigation(email.model_dump_json())


def llm_badge() -> None:
    if api_key_present():
        st.sidebar.success(f"LLM: live ({PROVIDER_LABEL})")
    else:
        st.sidebar.warning("LLM: fallback (rules)\n\nNo GROQ_API_KEY - deterministic path only.")


# --------------------------------------------------------------------------
# shared renderers
# --------------------------------------------------------------------------
def render_verdict_card(email: EmailRecord, decision, policy) -> None:
    mode = "live" if decision.llm_mode == "live" else "fallback"
    st.markdown(
        f"""<div class="verdict-card">
        <h3 style="margin:0">{decision.verdict}</h3>
        <p style="margin:.35rem 0 0 0;opacity:.85">{decision.threat_type} &middot;
        risk <b>{decision.risk_score}</b>/100 &middot; confidence <b>{decision.confidence:.2f}</b>
        &middot; reasoning path <b>{mode}</b></p>
        </div>""",
        unsafe_allow_html=True,
    )

    left, right = st.columns([3, 2])
    with left:
        st.markdown("**Rationale**")
        st.write(decision.rationale or "_No rationale produced._")
        if decision.needs_human_review:
            st.warning("Flagged **needs human review** - agent findings conflict or are inconclusive.")
    with right:
        st.metric("Policy band", policy.band_range, policy.band)
        st.caption(policy.disposition)
        if decision.mitre_techniques:
            st.markdown("**MITRE ATT&CK**: " + ", ".join(decision.mitre_techniques))


def render_findings(decision) -> None:
    for finding in decision.evidence_summary:
        css = SEVERITY_CLASS.get(finding.severity, "sev-low")
        with st.expander(
            f"{finding.component} - {finding.severity.upper()} "
            f"(confidence {finding.confidence:.2f}, {finding.source})",
            expanded=finding.severity == "high",
        ):
            st.markdown(
                f"Severity: <span class='{css}'>{finding.severity}</span> &nbsp;|&nbsp; "
                f"Source: <code>{finding.source}</code>",
                unsafe_allow_html=True,
            )
            for item in finding.evidence:
                st.markdown(
                    f"<div class='evidence'><b>{item.type}</b><br>{item.value}<br>"
                    f"<i style='opacity:.75'>{item.explanation}</i></div>",
                    unsafe_allow_html=True,
                )
            if finding.benign_signals:
                st.markdown("**Benign signals**")
                for signal in finding.benign_signals:
                    st.markdown(f"- {signal}")
            if finding.uncertainties:
                st.markdown("**Uncertainties**")
                for note in finding.uncertainties:
                    st.markdown(f"- {note}")
            if finding.mitre_techniques:
                st.caption("MITRE: " + ", ".join(finding.mitre_techniques))


def render_email(email: EmailRecord) -> None:
    st.markdown(
        f"**From** `{email.sender_name} <{email.sender_email}>` &nbsp; "
        f"**Reply-To** `{email.reply_to or 'none'}` &nbsp; "
        f"**Return-Path** `{email.return_path or 'none'}`"
    )
    st.markdown(
        f"**To** `{email.recipient or 'unknown'}` ({email.recipient_role}) &nbsp; "
        f"**Auth** `{email.auth_summary}` &nbsp; **Sent** `{email.timestamp or 'unknown'}`"
    )
    st.markdown(f"**Subject** {email.subject}")
    st.markdown(f"<div class='email-body'>{email.body}</div>", unsafe_allow_html=True)
    if email.urls:
        st.caption("URLs (never fetched): " + ", ".join(f"`{u}`" for u in email.urls))
    if email.attachments:
        st.caption(
            "Attachments (never opened): "
            + ", ".join(f"`{a.filename}` [{a.mime_type}] sha256={a.sha256[:16]}" for a in email.attachments)
        )


# --------------------------------------------------------------------------
# pages
# --------------------------------------------------------------------------
def page_alert_queue(emails: list[EmailRecord]) -> None:
    st.title("Alert queue")
    st.caption(
        "Every row is produced by running the full agent graph over the message - "
        "no precomputed or illustrative values."
    )

    statuses = audit_log.all_action_statuses()
    rows = []
    for email in emails:
        decision, policy = investigate_email(email)
        rows.append(
            {
                "ID": email.id,
                "Received": email.timestamp,
                "Subject": email.subject,
                "Sender": email.sender_email,
                "Recipient": email.recipient,
                "Verdict": decision.verdict,
                "Risk": decision.risk_score,
                "Confidence": round(decision.confidence, 2),
                "Band": policy.band,
                "Auth": email.auth_summary,
                "Interaction": ", ".join(email.interactions) or "none",
                "Status": statuses.get(email.id, email.action_status),
                "Review": "yes" if decision.needs_human_review else "",
            }
        )

    frame = pd.DataFrame(rows).sort_values("Risk", ascending=False)
    high = int((frame["Risk"] >= 80).sum())
    mid = int(((frame["Risk"] >= 60) & (frame["Risk"] < 80)).sum())
    a, b, c, d = st.columns(4)
    a.metric("Messages", len(frame))
    b.metric("Contain band (80+)", high)
    c.metric("Quarantine recommended (60-79)", mid)
    d.metric("Needs human review", int((frame["Review"] == "yes").sum()))

    st.dataframe(frame, use_container_width=True, hide_index=True)
    st.caption("Risk bands: 0-29 monitor, 30-59 analyst review, 60-79 recommend quarantine, 80-100 contain and purge.")


def page_investigation(emails: list[EmailRecord]) -> None:
    st.title("Investigation")
    labels = {f"{e.id} - {e.subject}": e for e in emails}
    default = next((i for i, key in enumerate(labels) if key.startswith("msg-005")), 0)
    choice = st.selectbox("Alert", list(labels), index=default)
    email = labels[choice]

    decision, policy = investigate_email(email)
    render_verdict_card(email, decision, policy)

    tab_evidence, tab_message, tab_actions = st.tabs(["Agent findings", "Message", "Policy and actions"])
    with tab_evidence:
        render_findings(decision)
    with tab_message:
        render_email(email)
    with tab_actions:
        st.markdown(f"**Policy decision** - {policy.justification}")
        for action in policy.actions:
            st.markdown(f"- {action}")

        current = audit_log.get_action_status(email.id, email.action_status)
        st.info(f"Current message state: **{current}**")

        if policy.requires_approval and policy.band != "monitor":
            st.markdown("#### Approve containment")
            st.caption("Simulated - no live mail tenant is connected. The approval is written to the audit log.")
            selected = st.selectbox("Action to approve", policy.actions, key=f"act-{email.id}")
            analyst = st.text_input("Analyst", "analyst@company.example", key=f"an-{email.id}")
            if st.button("Approve and record", type="primary", key=f"btn-{email.id}"):
                audit_log.approve_action(
                    message_id=email.id,
                    action=selected,
                    verdict=decision.verdict,
                    risk_score=decision.risk_score,
                    policy_band=policy.band,
                    analyst=analyst,
                    llm_mode=decision.llm_mode,
                )
                st.success(f"Recorded. {email.id} is now **quarantined**.")
                st.rerun()
        else:
            st.caption("This band does not require or permit a containment action.")

        st.markdown("#### Analyst feedback")
        st.caption("Feedback is persisted and feeds the evaluation set.")
        col1, col2 = st.columns(2)
        with col1:
            verdict_feedback = st.radio(
                "Was the verdict correct?",
                ["correct", "false positive", "false negative", "escalate"],
                key=f"fb-{email.id}",
            )
        with col2:
            corrected = st.text_input("Corrected verdict (optional)", "", key=f"cv-{email.id}")
            notes = st.text_input("Notes (optional)", "", key=f"nt-{email.id}")
        if st.button("Submit feedback", key=f"fbbtn-{email.id}"):
            audit_log.record_feedback(
                message_id=email.id,
                predicted=decision.verdict,
                feedback=verdict_feedback,
                corrected=corrected,
                notes=notes,
            )
            st.success("Feedback recorded.")


def page_campaign(emails: list[EmailRecord]) -> None:
    st.title("Campaign scope and blast radius")
    st.caption(
        "Clustering is computed for every message from shared sender domain, URL domain, "
        "attachment hash, and normalised subject template."
    )
    labels = {f"{e.id} - {e.subject}": e for e in emails}
    choice = st.selectbox("Pivot from message", list(labels))
    email = labels[choice]

    radius = blast_radius(email)
    cluster = find_cluster(email)
    cols = st.columns(5)
    cols[0].metric("Messages in campaign", radius["messages"])
    cols[1].metric("Recipients", radius["recipients"])
    cols[2].metric("Opened", radius["opened"])
    cols[3].metric("Clicked", radius["clicked"])
    cols[4].metric("Replied", radius["replied"])

    if cluster:
        st.markdown("#### Clustered messages and why they matched")
        st.dataframe(
            pd.DataFrame(
                [
                    {"ID": c.id, "Subject": c.subject, "Sender": c.sender_email,
                     "Recipient": c.recipient, "Shared indicators": "; ".join(reasons)}
                    for c, reasons in cluster
                ]
            ),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No related messages share indicators with this one.")

    graph = build_campaign_graph(email)
    st.markdown("#### Campaign graph")
    st.caption(f"{graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges "
               "(campaign -> messages -> recipients -> indicators)")
    kinds = {}
    for _, attrs in graph.nodes(data=True):
        kinds[attrs.get("kind", "other")] = kinds.get(attrs.get("kind", "other"), 0) + 1
    st.dataframe(
        pd.DataFrame([{"Node type": k, "Count": v} for k, v in sorted(kinds.items())]),
        use_container_width=True,
        hide_index=True,
    )
    with st.expander("Indicators to sweep the tenant for"):
        for node, attrs in graph.nodes(data=True):
            if attrs.get("kind") == "indicator":
                st.markdown(f"- `{node.removeprefix('ioc::')}`")


def page_sandbox() -> None:
    st.title("Email sandbox")
    st.error(
        "**Safety:** links are never fetched, attachments are never opened or executed. "
        "Attachment hashes are computed locally in memory. Submitted content is treated as "
        "untrusted evidence and is fenced before it reaches any model."
    )
    st.caption(
        "Drop in any email and the same agent graph that scores the seeded corpus runs against it. "
        "In production this ingestion point would be the Gmail or Microsoft Graph API."
    )

    mode = st.radio("Input", ["Paste raw email", "Upload .eml"], horizontal=True)
    email: EmailRecord | None = None

    if mode == "Paste raw email":
        placeholder = (
            "From: Finance Director <director@trustedvendor.example>\n"
            "Reply-To: director@trustedvendor-billing.example\n"
            "Subject: Updated bank details for this month's payment\n"
            "Authentication-Results: spf=pass dkim=pass dmarc=pass\n\n"
            "Hi - we have changed banks. Please update our remittance details and "
            "process the outstanding payment today. Keep this confidential until it clears."
        )
        raw = st.text_area("Email text (headers optional)", placeholder, height=260)
        if st.button("Investigate", type="primary") and raw.strip():
            email = parse_raw_text(raw, record_id="sandbox-paste")
    else:
        upload = st.file_uploader("Choose an .eml file", type=["eml", "txt"])
        if upload is not None:
            email = parse_eml(upload.getvalue(), record_id=f"sandbox-{upload.name}")

    if email is None:
        return

    st.divider()
    st.markdown("### Parsed artifacts")
    render_email(email)

    decision, policy = investigate_email(email)
    st.divider()
    st.markdown("### Verdict")
    render_verdict_card(email, decision, policy)
    render_findings(decision)

    st.markdown("### Policy recommendation")
    st.markdown(f"_{policy.justification}_")
    for action in policy.actions:
        st.markdown(f"- {action}")

    audit_log.record_event(
        message_id=email.id,
        event_type="sandbox_submission",
        verdict=decision.verdict,
        risk_score=decision.risk_score,
        policy_band=policy.band,
        llm_mode=decision.llm_mode,
        notes="Analyst-submitted message investigated in the sandbox.",
    )


def page_detection_quality(emails: list[EmailRecord]) -> None:
    st.title("Detection quality")
    st.caption(
        "Precision and recall are computed per class from true/false positives and negatives - "
        "they are not accuracy under two names."
    )

    predictions, confidences = {}, {}
    for email in emails:
        decision, _ = investigate_email(email)
        predictions[email.id] = decision.verdict
        confidences[email.id] = decision.confidence

    pairs = evaluator.confusion_pairs(emails, predictions)
    binary = evaluator.binary_metrics(pairs)

    cols = st.columns(6)
    cols[0].metric("Accuracy", binary["Accuracy"])
    cols[1].metric("Precision", binary["Precision"])
    cols[2].metric("Recall", binary["Recall"])
    cols[3].metric("F1", binary["F1"])
    cols[4].metric("FPR", binary["FPR"])
    cols[5].metric("FNR", binary["FNR"])
    st.caption(
        f"Malicious vs benign: TP={binary['TP']} TN={binary['TN']} "
        f"FP={binary['FP']} FN={binary['FN']} over {len(pairs)} labelled messages."
    )

    st.markdown("#### Per-class metrics")
    st.dataframe(pd.DataFrame(evaluator.per_class_metrics(pairs)), use_container_width=True, hide_index=True)

    st.markdown("#### Expected vs predicted")
    st.dataframe(
        pd.DataFrame(evaluator.detail_rows(emails, predictions, confidences)),
        use_container_width=True,
        hide_index=True,
    )

    st.markdown("#### Confusion matrix")
    if pairs:
        matrix = pd.crosstab(
            pd.Series([p[0] for p in pairs], name="Expected"),
            pd.Series([p[1] for p in pairs], name="Predicted"),
        )
        st.dataframe(matrix, use_container_width=True)

    st.markdown("#### Low-confidence queue")
    queue = evaluator.low_confidence_queue(emails, confidences)
    if queue:
        st.dataframe(pd.DataFrame(queue), use_container_width=True, hide_index=True)
        st.caption("These are where analyst review adds the most value.")
    else:
        st.info("No messages below the confidence threshold.")

    missing = evaluator.unlabelled(emails)
    if missing:
        st.warning("Unlabelled messages excluded from metrics: " + ", ".join(missing))


def page_audit() -> None:
    st.title("Audit log")
    st.caption(
        "Append-only SQLite at `data/audit.db`. Corrections are new rows; nothing is ever "
        "updated or deleted in place."
    )
    rows = audit_log.read_log()
    if rows:
        frame = pd.DataFrame(rows)[
            ["timestamp", "message_id", "event_type", "verdict", "risk_score",
             "policy_band", "action", "approved", "analyst", "llm_mode", "notes"]
        ]
        st.dataframe(frame, use_container_width=True, hide_index=True)
    else:
        st.info("No audit events yet. Approve a containment action on the Investigation page.")

    st.markdown("#### Analyst feedback")
    feedback = audit_log.read_feedback()
    if feedback:
        st.dataframe(
            pd.DataFrame(feedback)[
                ["timestamp", "message_id", "predicted", "feedback", "corrected", "analyst", "notes"]
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No analyst feedback recorded yet.")


def page_architecture() -> None:
    st.title("How it works")
    st.code(
        """parse
  |-- identity_auth    (deterministic)  headers, SPF/DKIM/DMARC, lookalike domains
  |-- content_bec      (LLM)            intent, impersonation, pretext, urgency
  |-- url_attachment   (deterministic)  URL structure, risky types, hashes
  |-- campaign         (deterministic)  clustering, blast radius, IOC graph
        |
        v  fan-in
     verdict           (LLM)            evidence fusion + analyst rationale
        |
        v
     policy_engine     (deterministic)  risk bands -> actions, approval gates""",
        language="text",
    )
    st.markdown(
        """
**Why only two LLM nodes?**

Header parsing, auth results, URL structure, hashing and clustering are
deterministic problems with exact answers. Sending them through a model makes
them slower, more expensive and non-reproducible without making them more
accurate. The LLM is used where judgement genuinely beats pattern matching:
reading intent and pretext, and writing an evidence summary an analyst can act
on. That split also means failure attribution is possible - when a verdict is
wrong, the finding that caused it is visible.

**Trust boundary.** The model never selects an action, sets a risk score, or
changes message state. It emits findings and rationale only; the deterministic
policy engine decides what may happen, and every band with real blast radius
requires human approval.

**Prompt injection.** Email content is fenced in `<untrusted_email>` tags with
a system instruction that it is evidence, never instructions. Injection
attempts are reported as evidence of manipulation rather than obeyed.

**Graceful degradation.** Every LLM node has a deterministic fallback. A
missing key, rate limit, timeout or schema-validation failure drops that node
to rules and the sidebar badge shows `fallback` instead of `live`.
        """
    )


PAGES = {
    "Alert queue": page_alert_queue,
    "Investigation": page_investigation,
    "Campaign scope": page_campaign,
    "Email sandbox": page_sandbox,
    "Detection quality": page_detection_quality,
    "Audit log": page_audit,
    "How it works": page_architecture,
}


def main() -> None:
    st.sidebar.title("Inbox Sentinel")
    st.sidebar.caption("Agentic email-security investigation")
    llm_badge()
    choice = st.sidebar.radio("View", list(PAGES))
    st.sidebar.divider()
    st.sidebar.caption(
        "Synthetic corpus only. No live mailbox is connected, no URL is fetched, "
        "and no attachment is executed."
    )

    page = PAGES[choice]
    if choice in {"Email sandbox", "Audit log", "How it works"}:
        page()
    else:
        page(get_emails())


main()
