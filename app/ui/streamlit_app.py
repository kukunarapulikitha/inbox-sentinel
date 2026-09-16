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
from app.services.llm import available_models

st.set_page_config(page_title="Inbox Sentinel", page_icon="IS", layout="wide")

# ---------------------------------------------------------------------------
# Design tokens.
#
# Severity and policy band are *status* channels, not categorical series, so
# they use the reserved status palette (good / warning / serious / critical)
# and always ship with an icon and a text label - status colour never carries
# meaning on its own. All four clear 3:1 against the dark surface. Severity
# itself uses only good/warning/critical: warning and serious sit too close to
# separate reliably, so the middle step is reserved for the band scale, where a
# name is always rendered beside it.
# ---------------------------------------------------------------------------
CSS = """
<style>
  :root {
    --surface-0: #121211;   /* page */
    --surface-1: #1a1a19;   /* card - the validated dark surface */
    --surface-2: #222220;   /* raised / hover */
    --border:    #2e2e2b;
    --border-strong: #3d3d39;

    --text-primary:   #ffffff;
    --text-secondary: #c3c2b7;
    --text-muted:     #8a8a80;

    --accent: #3987e5;      /* categorical slot 1, dark step */

    --good:     #0ca30c;
    --warning:  #fab219;
    --serious:  #ec835a;
    --critical: #d03b3b;

    --radius: 10px;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, "Helvetica Neue", sans-serif;
    --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
  }

  .stApp { background: var(--surface-0); }
  html, body, [class*="css"], .stMarkdown, .stApp { font-family: var(--sans); }

  /* Trim Streamlit chrome so the content leads */
  #MainMenu, footer, header { visibility: hidden; }
  .block-container { padding-top: 2.2rem; max-width: 1400px; }

  h1 { font-size: 1.65rem !important; font-weight: 640 !important;
       letter-spacing: -0.021em; color: var(--text-primary); margin-bottom: .15rem !important; }
  h2 { font-size: 1.16rem !important; font-weight: 620 !important; letter-spacing: -0.012em; }
  h3 { font-size: 1.0rem !important; font-weight: 620 !important; }
  h4 { font-size: .8rem !important; font-weight: 640 !important;
       text-transform: uppercase; letter-spacing: .07em; color: var(--text-muted) !important;
       margin: 1.5rem 0 .55rem 0 !important; }

  /* ---- stat tiles: label (sentence case) + value (proportional figures) ---- */
  .tile-row { display: flex; gap: .7rem; margin: .5rem 0 1.4rem 0; flex-wrap: wrap; }
  .tile { flex: 1 1 0; min-width: 128px; background: var(--surface-1);
          border: 1px solid var(--border); border-radius: var(--radius);
          padding: .85rem .95rem; }
  .tile-label { font-size: .7rem; text-transform: uppercase; letter-spacing: .075em;
                color: var(--text-muted); font-weight: 600; margin-bottom: .3rem; }
  .tile-value { font-size: 1.75rem; font-weight: 650; line-height: 1.05;
                color: var(--text-primary); letter-spacing: -0.02em; }
  .tile-note { font-size: .74rem; color: var(--text-secondary); margin-top: .22rem; }
  .tile[data-tone="good"]     { border-left: 3px solid var(--good); }
  .tile[data-tone="warning"]  { border-left: 3px solid var(--warning); }
  .tile[data-tone="serious"]  { border-left: 3px solid var(--serious); }
  .tile[data-tone="critical"] { border-left: 3px solid var(--critical); }

  /* ---- hero figure: the one number the view leads with ---- */
  .hero { background: var(--surface-1); border: 1px solid var(--border);
          border-radius: var(--radius); padding: 1.15rem 1.3rem; margin-bottom: 1rem; }
  .hero-top { display: flex; justify-content: space-between; align-items: flex-start;
              gap: 1rem; flex-wrap: wrap; }
  .hero-verdict { font-size: 1.5rem; font-weight: 660; letter-spacing: -0.02em;
                  color: var(--text-primary); }
  .hero-threat { font-size: .82rem; color: var(--text-secondary); margin-top: .18rem; }
  .hero-score { text-align: right; }
  .hero-figure { font-size: 3rem; font-weight: 660; line-height: 1;
                 letter-spacing: -0.03em; color: var(--text-primary); }
  .hero-of { font-size: .72rem; color: var(--text-muted); letter-spacing: .05em;
             text-transform: uppercase; }

  /* ---- meter: fill carries severity, track is a lighter step of it ---- */
  .meter { height: 7px; border-radius: 4px; margin-top: .9rem; overflow: hidden;
           background: color-mix(in oklab, var(--meter-hue) 22%, var(--surface-2)); }
  .meter-fill { height: 100%; border-radius: 4px; background: var(--meter-hue); }

  /* ---- status pill: icon + label, never colour alone ---- */
  .pill { display: inline-flex; align-items: center; gap: .34rem;
          font-size: .705rem; font-weight: 650; letter-spacing: .045em;
          text-transform: uppercase; padding: .17rem .5rem; border-radius: 5px;
          border: 1px solid; white-space: nowrap; }
  .pill-good     { color: var(--good);     border-color: color-mix(in oklab, var(--good) 45%, transparent);
                   background: color-mix(in oklab, var(--good) 13%, transparent); }
  .pill-warning  { color: var(--warning);  border-color: color-mix(in oklab, var(--warning) 45%, transparent);
                   background: color-mix(in oklab, var(--warning) 13%, transparent); }
  .pill-serious  { color: var(--serious);  border-color: color-mix(in oklab, var(--serious) 45%, transparent);
                   background: color-mix(in oklab, var(--serious) 13%, transparent); }
  .pill-critical { color: var(--critical); border-color: color-mix(in oklab, var(--critical) 45%, transparent);
                   background: color-mix(in oklab, var(--critical) 13%, transparent); }
  .pill-neutral  { color: var(--text-secondary); border-color: var(--border-strong);
                   background: var(--surface-2); }

  /* ---- finding card ---- */
  .finding { background: var(--surface-1); border: 1px solid var(--border);
             border-left: 3px solid var(--fc); border-radius: var(--radius);
             padding: .8rem .95rem; margin-bottom: .55rem; }
  .finding-head { display: flex; justify-content: space-between; align-items: center;
                  gap: .7rem; flex-wrap: wrap; }
  .finding-name { font-size: .93rem; font-weight: 620; color: var(--text-primary); }
  .finding-meta { font-size: .72rem; color: var(--text-muted); font-family: var(--mono); }

  .evidence { background: var(--surface-0); border: 1px solid var(--border);
              border-radius: 7px; padding: .5rem .65rem; margin: .4rem 0 0 0; }
  .ev-type { font-family: var(--mono); font-size: .715rem; color: var(--accent);
             font-weight: 600; letter-spacing: .02em; }
  .ev-value { font-family: var(--mono); font-size: .765rem; color: var(--text-primary);
              margin: .17rem 0; word-break: break-word; }
  .ev-why { font-size: .755rem; color: var(--text-secondary); line-height: 1.45; }

  .email-body { background: var(--surface-0); border: 1px solid var(--border);
                border-radius: var(--radius); padding: .9rem 1rem; white-space: pre-wrap;
                font-family: var(--mono); font-size: .79rem; line-height: 1.55;
                color: var(--text-secondary); }
  .kv { font-size: .765rem; color: var(--text-secondary); line-height: 1.85; }
  .kv b { color: var(--text-muted); font-weight: 600; text-transform: uppercase;
          font-size: .685rem; letter-spacing: .06em; }
  .kv code { font-family: var(--mono); color: var(--text-primary);
             background: var(--surface-2); padding: .07rem .3rem; border-radius: 4px;
             font-size: .755rem; }

  /* tabular figures only in columns of numbers */
  [data-testid="stDataFrame"] { font-variant-numeric: tabular-nums;
                                border-radius: var(--radius); overflow: hidden; }
  .stTabs [data-baseweb="tab-list"] { gap: .3rem; border-bottom: 1px solid var(--border); }
  .stTabs [data-baseweb="tab"] { font-size: .84rem; font-weight: 580; }
  section[data-testid="stSidebar"] { background: var(--surface-1);
                                     border-right: 1px solid var(--border); }
  .note { font-size: .775rem; color: var(--text-muted); line-height: 1.5; }
</style>
"""

st.markdown(CSS, unsafe_allow_html=True)

# severity -> (status role, icon). Icon + label is the non-colour channel.
SEVERITY_TONE = {"high": ("critical", "\u25b2"), "medium": ("warning", "\u25c6"), "low": ("good", "\u25ac")}
# policy band -> status role, ordered by escalation
BAND_TONE = {
    "monitor": ("good", "\u25ac"),
    "analyst_review": ("warning", "\u25c6"),
    "recommend_quarantine": ("serious", "\u25b2"),
    "contain_and_purge": ("critical", "\u25cf"),
}
TONE_VAR = {"good": "var(--good)", "warning": "var(--warning)",
            "serious": "var(--serious)", "critical": "var(--critical)"}


def pill(label: str, tone: str, icon: str = "") -> str:
    glyph = f"<span>{icon}</span>" if icon else ""
    return f'<span class="pill pill-{tone}">{glyph}{label}</span>'


def severity_pill(severity: str) -> str:
    tone, icon = SEVERITY_TONE.get(severity, ("neutral", ""))
    return pill(severity, tone, icon)


def band_pill(band: str) -> str:
    tone, icon = BAND_TONE.get(band, ("neutral", ""))
    return pill(band.replace("_", " "), tone, icon)


def risk_tone(risk: int) -> str:
    """Matches the policy bands so colour and policy never disagree."""
    if risk >= 80:
        return "critical"
    if risk >= 60:
        return "serious"
    if risk >= 30:
        return "warning"
    return "good"


def stat_tiles(items: list[dict]) -> None:
    """KPI row. `items` = [{label, value, note?, tone?}].

    Values use proportional figures - tabular-nums makes a large standalone
    number look loose, so it is reserved for table columns.
    """
    cells = []
    for item in items:
        tone = f' data-tone="{item["tone"]}"' if item.get("tone") else ""
        note = f'<div class="tile-note">{item["note"]}</div>' if item.get("note") else ""
        cells.append(
            f'<div class="tile"{tone}><div class="tile-label">{item["label"]}</div>'
            f'<div class="tile-value">{item["value"]}</div>{note}</div>'
        )
    st.markdown(f'<div class="tile-row">{"".join(cells)}</div>', unsafe_allow_html=True)


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
    models = available_models()
    if not models:
        st.sidebar.warning(
            "**LLM: fallback (rules)**\n\nNo provider key set - deterministic path "
            "only. Every page still works."
        )
        return
    st.sidebar.success(f"**LLM: live**\n\n{models[0]}")
    with st.sidebar.expander(f"Fallback chain ({len(models)})"):
        for index, model in enumerate(models):
            st.markdown(f"{index + 1}. `{model}`" + ("  \u2190 primary" if index == 0 else ""))
        st.caption(
            "Tried in order; the chain spans two providers, then drops to "
            "deterministic rules. Groq no longer serves a general-purpose Llama "
            "chat model, so there is no Llama entry."
        )


# --------------------------------------------------------------------------
# shared renderers
# --------------------------------------------------------------------------
def render_verdict_card(email: EmailRecord, decision, policy) -> None:
    """The view's single hero figure: the risk score."""
    tone = risk_tone(decision.risk_score)
    mode_pill = {
        "live": pill("llm live", "good", "\u25cf"),
        "partial": pill("partial fallback", "warning", "\u25c6"),
        "fallback": pill("rules only", "neutral", "\u25ac"),
    }.get(decision.llm_mode, pill(decision.llm_mode, "neutral"))
    review_pill = pill("needs human review", "warning", "\u25c6") if decision.needs_human_review else ""

    st.markdown(
        f"""<div class="hero">
          <div class="hero-top">
            <div>
              <div class="hero-verdict">{decision.verdict}</div>
              <div class="hero-threat">{decision.threat_type}</div>
              <div style="margin-top:.6rem;display:flex;gap:.35rem;flex-wrap:wrap">
                {band_pill(policy.band)}{mode_pill}
                {pill(f"confidence {decision.confidence:.2f}", "neutral")}{review_pill}
              </div>
            </div>
            <div class="hero-score">
              <div class="hero-figure">{decision.risk_score}</div>
              <div class="hero-of">risk / 100</div>
            </div>
          </div>
          <div class="meter" style="--meter-hue:{TONE_VAR[tone]}">
            <div class="meter-fill" style="width:{max(2, decision.risk_score)}%"></div>
          </div>
        </div>""",
        unsafe_allow_html=True,
    )

    left, right = st.columns([3, 2])
    with left:
        st.markdown("#### Rationale")
        st.write(decision.rationale or "_No rationale produced._")
        if decision.needs_human_review:
            st.warning("Agent findings conflict or are inconclusive - a human decides.")
    with right:
        st.markdown("#### Disposition")
        mitre = ", ".join(f"<code>{m}</code>" for m in decision.mitre_techniques) or "none"
        st.markdown(
            f'<div class="kv"><b>Band</b> <code>{policy.band_range}</code><br>'
            f'<b>Action</b> {policy.disposition}<br>'
            f'<b>Reasoning path</b> <code>{decision.llm_detail}</code><br>'
            f'<b>MITRE</b> {mitre}</div>',
            unsafe_allow_html=True,
        )


def render_findings(decision) -> None:
    for finding in decision.evidence_summary:
        tone, _ = SEVERITY_TONE.get(finding.severity, ("neutral", ""))
        st.markdown(
            f"""<div class="finding" style="--fc:{TONE_VAR.get(tone, 'var(--border-strong)')}">
              <div class="finding-head">
                <span class="finding-name">{finding.component}</span>
                <span style="display:flex;gap:.3rem;align-items:center">
                  {severity_pill(finding.severity)}{pill(finding.source, "neutral")}
                  <span class="finding-meta">{finding.confidence:.2f}</span>
                </span>
              </div>
            </div>""",
            unsafe_allow_html=True,
        )
        with st.expander(f"Evidence \u2014 {finding.component}", expanded=finding.severity == "high"):
            if not finding.evidence:
                st.markdown('<div class="note">No positive indicators.</div>', unsafe_allow_html=True)
            for item in finding.evidence:
                st.markdown(
                    f'<div class="evidence"><div class="ev-type">{item.type}</div>'
                    f'<div class="ev-value">{item.value}</div>'
                    f'<div class="ev-why">{item.explanation}</div></div>',
                    unsafe_allow_html=True,
                )
            if finding.benign_signals:
                st.markdown("#### Benign signals")
                for signal in finding.benign_signals:
                    st.markdown(f'<div class="note">\u2022 {signal}</div>', unsafe_allow_html=True)
            if finding.uncertainties:
                st.markdown("#### Uncertainties")
                for note in finding.uncertainties:
                    st.markdown(f'<div class="note">\u2022 {note}</div>', unsafe_allow_html=True)
            if finding.mitre_techniques:
                st.caption("MITRE: " + ", ".join(finding.mitre_techniques))


def render_email(email: EmailRecord) -> None:
    auth_tone = "good" if email.all_auth_passed else "critical"
    st.markdown(
        f'<div class="kv">'
        f'<b>From</b> <code>{email.sender_name} &lt;{email.sender_email}&gt;</code><br>'
        f'<b>Reply-to</b> <code>{email.reply_to or "none"}</code> &nbsp; '
        f'<b>Return-path</b> <code>{email.return_path or "none"}</code><br>'
        f'<b>To</b> <code>{email.recipient or "unknown"}</code> ({email.recipient_role})<br>'
        f'<b>Auth</b> {pill(email.auth_summary, auth_tone, "\u25cf")} &nbsp; '
        f'<b>Sent</b> <code>{email.timestamp or "unknown"}</code>'
        f'</div>',
        unsafe_allow_html=True,
    )
    st.markdown(f"#### {email.subject}")
    st.markdown(f'<div class="email-body">{email.body}</div>', unsafe_allow_html=True)
    if email.urls:
        st.markdown(
            '<div class="note" style="margin-top:.5rem">Links, never fetched: '
            + ", ".join(f"<code>{u}</code>" for u in email.urls) + "</div>",
            unsafe_allow_html=True,
        )
    if email.attachments:
        st.markdown(
            '<div class="note" style="margin-top:.35rem">Attachments, never opened: '
            + ", ".join(
                f"<code>{a.filename}</code> [{a.mime_type}] <code>{a.sha256[:16]}</code>"
                for a in email.attachments
            ) + "</div>",
            unsafe_allow_html=True,
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
    stat_tiles(
        [
            {"label": "Messages", "value": len(frame), "note": "scored this run"},
            {"label": "Contain and purge", "value": high, "note": "risk 80-100",
             "tone": "critical"},
            {"label": "Quarantine recommended", "value": mid, "note": "risk 60-79",
             "tone": "serious"},
            {"label": "Needs human review", "value": int((frame["Review"] == "yes").sum()),
             "note": "conflicting findings", "tone": "warning"},
        ]
    )

    frame["Band"] = frame["Band"].str.replace("_", " ")
    st.dataframe(frame, width="stretch", hide_index=True)
    st.markdown(
        '<div class="note">Bands: 0-29 monitor \u00b7 30-59 analyst review \u00b7 '
        '60-79 recommend quarantine \u00b7 80-100 contain and purge. '
        'Every row is a real graph run, not a precomputed value.</div>',
        unsafe_allow_html=True,
    )


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
    stat_tiles(
        [
            {"label": "Messages", "value": radius["messages"], "note": "in campaign"},
            {"label": "Recipients", "value": radius["recipients"], "note": "blast radius"},
            {"label": "Opened", "value": radius["opened"],
             "tone": "warning" if radius["opened"] else None},
            {"label": "Clicked", "value": radius["clicked"],
             "tone": "critical" if radius["clicked"] else None},
            {"label": "Replied", "value": radius["replied"],
             "tone": "critical" if radius["replied"] else None},
        ]
    )

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
            width="stretch",
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
        width="stretch",
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

    stat_tiles(
        [
            {"label": "Accuracy", "value": binary["Accuracy"]},
            {"label": "Precision", "value": binary["Precision"], "note": "of flagged, truly bad"},
            {"label": "Recall", "value": binary["Recall"], "note": "of bad, caught"},
            {"label": "F1", "value": binary["F1"]},
            {"label": "False positive rate", "value": binary["FPR"],
             "tone": "warning" if binary["FPR"] else "good"},
            {"label": "False negative rate", "value": binary["FNR"],
             "tone": "critical" if binary["FNR"] else "good"},
        ]
    )
    st.caption(
        f"Malicious vs benign: TP={binary['TP']} TN={binary['TN']} "
        f"FP={binary['FP']} FN={binary['FN']} over {len(pairs)} labelled messages."
    )

    st.markdown("#### Per-class metrics")
    st.dataframe(pd.DataFrame(evaluator.per_class_metrics(pairs)), width="stretch", hide_index=True)

    st.markdown("#### Expected vs predicted")
    st.dataframe(
        pd.DataFrame(evaluator.detail_rows(emails, predictions, confidences)),
        width="stretch",
        hide_index=True,
    )

    st.markdown("#### Confusion matrix")
    if pairs:
        matrix = pd.crosstab(
            pd.Series([p[0] for p in pairs], name="Expected"),
            pd.Series([p[1] for p in pairs], name="Predicted"),
        )
        st.dataframe(matrix, width="stretch")

    st.markdown("#### Low-confidence queue")
    queue = evaluator.low_confidence_queue(emails, confidences)
    if queue:
        st.dataframe(pd.DataFrame(queue), width="stretch", hide_index=True)
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
        st.dataframe(frame, width="stretch", hide_index=True)
    else:
        st.info("No audit events yet. Approve a containment action on the Investigation page.")

    st.markdown("#### Analyst feedback")
    feedback = audit_log.read_feedback()
    if feedback:
        st.dataframe(
            pd.DataFrame(feedback)[
                ["timestamp", "message_id", "predicted", "feedback", "corrected", "analyst", "notes"]
            ],
            width="stretch",
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
