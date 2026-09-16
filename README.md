# Inbox Sentinel

An agentic email-security investigation platform. A LangGraph agent graph
triages a suspicious email, produces evidence-backed findings, fuses them into
a verdict with an analyst-readable rationale, and routes it through a
deterministic policy engine that requires human approval before anything with
real blast radius happens.

Built as a focused demonstration of applied AI engineering in a security
context: where an LLM genuinely helps, where it must not be trusted, and how
to keep the whole thing auditable.

## The 90-second pitch

A finance employee gets an email from a known vendor asking to update bank
details before this month's payment. SPF, DKIM and DMARC all pass - the vendor
account is genuinely compromised, so authentication tells you nothing. A
keyword filter sees "bank" and "payment", which also appear in every
legitimate invoice.

Inbox Sentinel runs four specialist agents over the message, clusters it
against 14 near-identical messages already delivered to the AP team, scores it
91/100, and hands the analyst a verdict, the specific evidence behind it, a
MITRE mapping, and a containment action that will not execute without an
approval click. The approval is written to an append-only audit log.

## Architecture

```
parse
  |-- identity_auth    (deterministic)  headers, SPF/DKIM/DMARC, lookalike domains
  |-- content_bec      (LLM)            intent, impersonation, pretext, urgency
  |-- url_attachment   (deterministic)  URL structure, risky types, hashes
  |-- campaign         (deterministic)  clustering, blast radius, IOC graph
        |
        v  fan-in
     verdict           (LLM)            evidence fusion + analyst rationale
        |
        v
     policy_engine     (deterministic)  risk bands -> actions, approval gates
```

### Why two LLM calls and not ten agents

Header parsing, authentication results, URL structure, hashing and clustering
are deterministic problems with exact answers. Routing them through a model
makes them slower, costlier and non-reproducible without making them more
accurate. The LLM is used in the two places where judgement genuinely beats
pattern matching:

1. **Content/BEC reasoning** - intent, impersonation, plausibility of the
   pretext for this recipient's role, and whether urgency is manufactured to
   suppress verification.
2. **Verdict fusion** - turning four findings into one call plus a rationale
   an analyst can paste into a ticket.

The payoff is failure attribution. Every agent returns the same typed `Finding`
schema, so when a verdict is wrong you can point at the finding that caused it
instead of re-reading one giant prompt.

### Measured results on the seeded corpus

Model: `openai/gpt-oss-120b` on Groq, temperature 0, structured output.
14 labelled messages, verdict agreement against `data/expected_labels.jsonl`:

| Configuration | Agreement | Notes |
|---|---|---|
| Deterministic rules only | 12/14 | misses msg-003 (BEC) and msg-007 (Teams-branded phish) |
| LLM labels the verdict | 11/14 | fixes msg-003, but collapses msg-008 and msg-009 into "Suspected BEC" |
| **Hybrid (shipped)** | **13/14** | rule floors own the subtype label, LLM owns intent and rationale |

Binary malicious-vs-benign is P=1.0 / R=1.0 / FPR=0 / FNR=0 in all three
configurations - every disagreement is a subtype confusion, not a missed
threat.

The hybrid result is the actual finding of this build. The model reads intent
reliably - it upgraded msg-003 from "Suspicious" to BEC by recognising the
pretext - but it flattens fraud taxonomy, calling vendor RFQ fraud and payment
fraud "Suspected BEC" because they are all broadly BEC-shaped. So when a
high-confidence deterministic pattern fires, the rule floor owns the label and
the LLM keeps the rationale, confidence and needs-review call. Neither path
alone is as good as the split.

Remaining miss: msg-007, a Teams-branded credential phish on
`teams-alerts.example`. The lookalike check only catches homoglyphs
(`micros0ft`), so a domain that legitimately *contains* a brand name passes.
Detecting "contains a brand token but is not that brand's domain" is the next
detection rule to add.

### Trust boundary

The model never selects a containment action, sets a risk score, or changes
message state. It emits findings and rationale; the deterministic policy engine
decides what may happen. A prompt injection can at most influence a *finding* -
it can never directly trigger a quarantine.

| Risk | Band | Disposition |
|---|---|---|
| 0-29 | monitor | leave in mailbox |
| 30-59 | analyst_review | queue for review |
| 60-79 | recommend_quarantine | quarantine **on approval** |
| 80-100 | contain_and_purge | quarantine, purge, open incident **on approval** |

Conflicting findings produce a `needs_human_review` verdict instead of a forced
call, and always require a human.

### Graceful degradation

Every LLM node has a deterministic fallback. A missing key, rate limit, timeout
or schema-validation failure drops that node to its rule path, records which
path ran, and the sidebar badge reads `LLM: fallback (rules)` instead of
`LLM: live`. The app is fully functional with no API key at all.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env        # then paste your Groq key into GROQ_API_KEY
streamlit run app/ui/streamlit_app.py
```

Without a key the app still runs end to end on the rule path.

```bash
pytest -q                   # test suite
```

## Demo script

1. **Alert queue** - 14 messages, each scored by an actual graph run. Sorted by
   risk, with the policy band and whether a human is required.
2. **Investigation -> `msg-005`** - the vendor bank-change BEC. Note all three
   auth checks pass and the verdict is still `Suspected BEC` at 91+: the
   evidence is the reply-to mismatch, the remittance-change language, and AP
   targeting, not the auth result.
3. **Campaign scope** - pivot on `msg-005` and show the cluster of related
   deliveries, the blast radius, and the IOC graph to sweep the tenant with.
4. **Policy and actions** - approve the containment. The message flips to
   `quarantined` and the approval lands in the audit log with the analyst's
   identity.
5. **Email sandbox** - paste any email, or upload an `.eml`. Same graph, same
   verdict card. This is the part that makes it a tool rather than a slideshow.
6. **Detection quality** - per-class precision, recall, F1, plus FPR/FNR and a
   low-confidence queue.
7. **Audit log** - every approval and feedback event, append-only.

To demonstrate the fallback: rename `.env`, reload, and note the badge changes
to `fallback` while every page keeps working.

## Layout

```
app/
  agents/    graph.py, identity_auth.py, content_bec.py, url_attachment.py,
             campaign.py, verdict.py
  services/  email_parser.py, policy_engine.py, audit_log.py, evaluator.py, llm.py
  models/    email_models.py, findings.py, incident_models.py
  ui/        streamlit_app.py
data/        emails.jsonl, interactions.jsonl, expected_labels.jsonl
tests/
```

## Next integration points

Deliberately scoped out of this build, in rough priority order:

- **Live ingestion.** The sandbox's parser is the seam. Gmail API
  (`users.messages.get`, `format=RAW`) or Microsoft Graph
  (`/messages/{id}/$value`) both hand back RFC-822 bytes that
  `parse_eml` already accepts, so ingestion is an adapter, not a rewrite.
  Needs OAuth, delegated least-privilege scopes, and a webhook/pull loop.
- **FastAPI service layer + Docker** so the graph is callable from a SOAR
  playbook rather than only a UI.
- **Real enrichment**: URL sandboxing, attachment detonation, threat-intel
  reputation lookups, QR image decoding.
- **Eval harness in CI** over a larger labelled corpus, gating prompt changes
  on precision/recall regression.

See [threat_model.md](threat_model.md) for the security posture.
