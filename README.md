# Inbox Sentinel

An agentic email-security investigation platform. A LangGraph agent graph
triages a suspicious email, produces evidence-backed findings, fuses them into
a verdict with an analyst-readable rationale, and routes it through a
deterministic policy engine that requires human approval before anything with
real blast radius happens.

Built as a focused demonstration of applied AI engineering in a security
context: where an LLM genuinely helps, where it must not be trusted, and how
to keep the whole thing auditable.

![Inbox Sentinel architecture](assets/inbox_sentinel_architecture.png)

| Document | What it covers |
|---|---|
| **README** (this file) | pitch, agent flow and handoff, implementation stack, retry logic, setup, demo script |
| [ARCHITECTURE.md](ARCHITECTURE.md) | design rationale: why the graph is shaped this way, the measured taxonomy-precedence finding, extension seams, known limitations |
| [threat_model.md](threat_model.md) | security posture: injection handling, least privilege, auditability |

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

A condensed view; [ARCHITECTURE.md](ARCHITECTURE.md) has the full technical walkthrough.

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

Every LLM node walks the model chain above before it gives up. Only when every
model fails does the node drop to its rule path. The app records which path ran
per node, so the badge distinguishes `live`, `partial` (one node on rules) and
`fallback` (fully deterministic) rather than collapsing the middle case. It is
fully functional with no API key at all.

This was not hypothetical: the model this was first built against,
`llama-3.3-70b-versatile`, was decommissioned by Groq mid-build, and every LLM
node silently degraded to rules until the chain was added.

## Agent flow and handoff

```
EmailRecord
    |
  parse --+- identity_auth  --+
          +- content_bec    --+   4 in parallel,
          +- url_attachment --+   each returns one Finding
          +- campaign       --+
                             |
                             v  fan-in
                         verdict      reads all 4 -> dict
                             |
                             v
                          policy      -> IncidentDecision + PolicyDecision
```

| Node | Input | Output | Writes to state |
|---|---|---|---|
| `parse` | `EmailRecord` | `[]` | `findings` |
| `identity_auth` | `state["email"]` | one `Finding` | `findings` (append) |
| `content_bec` | `state["email"]` | one `Finding` | `findings` (append) |
| `url_attachment` | `state["email"]` | one `Finding` | `findings` (append) |
| `campaign` | `state["email"]` + corpus | one `Finding` | `findings` (append) |
| `verdict` | `state["findings"]` (all four) | `dict` - verdict, risk, rationale, confidence | `verdict` |
| `policy` | `state["verdict"]` + `findings` | `IncidentDecision`, `PolicyDecision` | `decision`, `policy` |

### The handoff mechanism

Agents never call each other. They only read and write shared state:

```python
class InvestigationState(TypedDict, total=False):
    email:    EmailRecord
    findings: Annotated[list[Finding], _merge]   # <- the handoff
    verdict:  dict
    policy:   PolicyDecision
    decision: IncidentDecision
```

`Annotated[..., _merge]` is the load-bearing part. Four nodes write `findings`
concurrently; without a reducer LangGraph raises on the concurrent update. The
reducer concatenates instead:

```python
def _merge(existing, incoming):
    return (existing or []) + (incoming or [])
```

Each analyzer returns `{"findings": [one_finding]}` and LangGraph merges the
four lists. `verdict_node` then re-sorts by a fixed `ORDER` map, because
parallel nodes complete in nondeterministic order.

### What gets passed

Between the analyzers and verdict fusion there is **one uniform contract**, so
verdict fusion does not care which agent produced what:

```python
Finding(component, category, severity, confidence,
        evidence=[Evidence(type, value, explanation)],
        benign_signals, uncertainties, mitre_techniques,
        source="llm" | "rules")
```

Verdict emits a plain dict rather than a model, since policy still has to add
actions:

```python
{verdict, threat_type, risk_score, confidence, rationale,
 mitre_techniques, needs_human_review, label_source, source}
```

`investigate()` returns the tuple `(IncidentDecision, PolicyDecision)`.

Dependencies run one way throughout: `models <- services <- agents <- ui`. No
agent imports another agent, except `verdict` importing `content_signals` for
its fallback path.

## Implementation stack

**No browser automation anywhere** - no Playwright, Selenium, Chromium, or HTTP
client ever touches email content. Parsing is entirely Python standard library.
This is a security decision, not a shortcut: fetching a URL out of a phishing
email confirms a live target to the attacker, trips tracking pixels, and can
pull a payload onto the host. The only outbound calls in the system are to the
LLM APIs.

| Module | Role | Libraries / functions used | Technique |
|---|---|---|---|
| `models/email_models.py` | Input schema | **Pydantic v2** `BaseModel`, `Field(default_factory=...)`, `@property` | Declarative validation; `auth_summary` / `all_auth_passed` / `interactions` are computed, not stored |
| `models/findings.py` | Agent output schema | Pydantic v2 `Field(description=...)` | `description=` is not documentation - it becomes the LLM's structured-output JSON schema |
| `models/incident_models.py` | Final output | Pydantic v2, nested `list[Finding]` | Model composition |
| `services/email_parser.py` | Parsing + helpers | **stdlib only**: `email.message_from_bytes`, `Message.walk()`, `get_payload(decode=True)`, `hashlib.sha256`, `re`, `difflib.SequenceMatcher`, `urllib.parse.urlparse`, `pathlib`, `json` | MIME tree walk, no external parser |
| `services/llm.py` | Provider cascade | `langchain_groq.ChatGroq`, `langchain_google_genai.ChatGoogleGenerativeAI`, `.with_structured_output()`, `python-dotenv`, `typing.TypeVar` | Generic-typed structured output, three-layer retry |
| `services/policy_engine.py` | Action selection | **zero external imports** | Pure function - dependency-free so it is trivially auditable |
| `services/audit_log.py` | Persistence | `sqlite3`, `contextlib.closing`, `datetime(timezone.utc)` | Raw SQL, no ORM; `INSERT ... ON CONFLICT DO UPDATE` upsert |
| `services/evaluator.py` | Metrics | **pure Python, no sklearn** | Hand-computed TP/FP/FN so the arithmetic is reviewable |
| `agents/identity_auth.py` | Header analysis | `domain_from_email` | String comparison + homoglyph folding; no regex |
| `agents/content_bec.py` | Intent (**LLM**) | `structured_call`, `wrap_untrusted`, `keyword_present` | LLM primary, keyword rules as fallback |
| `agents/url_attachment.py` | Artifact triage | `str.endswith`, `in`, `similarity` | Static string inspection - never fetches |
| `agents/campaign.py` | Correlation | **NetworkX** `nx.Graph`, set intersection, `SequenceMatcher` | Set algebra + fuzzy clustering |
| `agents/verdict.py` | Fusion (**LLM**) | `structured_call`, `content_signals` | LLM rationale, deterministic arithmetic scoring |
| `agents/graph.py` | Orchestration | **LangGraph** `StateGraph`, `START`, `END`, `TypedDict`, `Annotated[list, reducer]` | Parallel fan-out / fan-in |
| `ui/streamlit_app.py` | Console | `streamlit`, `pandas` (`DataFrame`, `crosstab`), `@st.cache_data` | Thin render layer, no detection logic |

### Rule-matching techniques per agent

**`identity_auth`** - pure string operations, no regex. Homoglyph detection is
character folding:

```python
folded = sender_domain.replace("0","o").replace("1","l").replace("rn","m")
if brand in folded and brand not in sender_domain:   # micros0ft -> microsoft
```

The `brand not in sender_domain` clause stops a genuine brand domain being
flagged - and is also the known cause of the `msg-007` miss, since
`teams-alerts.example` legitimately contains "teams". Auth checking is a
`sum()` of equality tests over `("spf","dkim","dmarc")`.

**`content_bec`** - the rule fallback is a hybrid substring/regex matcher:

```python
def keyword_present(text, keyword):
    if " " in keyword or "-" in keyword:
        return keyword in text                              # substring for phrases
    return re.search(rf"\b{re.escape(keyword)}\b", text)    # word boundary for single words
```

Word boundaries stop "account" matching inside "accountant"; `re.escape`
prevents the keyword list from being injectable as a regex. 30 terms in
`HIGH_RISK_WORDS` (a `set`, so O(1) membership) plus 10 compound-pattern
booleans in `content_signals()`.

**`url_attachment`** - `endswith` against a tuple of 9 risky extensions, `in`
against 7 login tokens, and `SequenceMatcher` similarity `< 0.75` for
sender/URL domain divergence. `hashlib.sha256` runs on bytes already in memory;
nothing is written to disk, unpacked, or opened.

**`campaign`** - four independent indicators, each returning *why* it matched:

| Indicator | Mechanism |
|---|---|
| Sender domain | string equality |
| URL domain | `set & set` intersection |
| Attachment hash | `set & set` on SHA-256 |
| Subject template | `SequenceMatcher` ratio >= **0.72** on a normalised subject |

Subject normalisation is regex-based - strip `Re:`/`Fwd:`, then `\d+` -> `#`, so
"Invoice 4471 due" and "Invoice 9902 due" collapse to one key. NetworkX
provides the graph structure and traversal, not layout rendering.

**`verdict`** - scoring is deliberately not LLM work:

```python
SEVERITY_POINTS = {"low": 6, "medium": 18, "high": 30}
risk = min(100, sum(...))     # arithmetic
risk = max(risk, floor)       # pattern floors, e.g. bank_change -> 91
```

Plus an output allowlist: a label outside `VERDICT_LABELS` raises
`LLMUnavailable`, so a hallucinated verdict cannot corrupt the label space.

### Retry and failure logic - three nested layers

| Layer | Mechanism | Config |
|---|---|---|
| 1. SDK retry | `ChatGroq(max_retries=1, timeout=20)` | 1 retry, so 2 attempts per model |
| 2. Model cascade | `for provider, model in MODEL_CHAIN` inside `structured_call` | 4 entries across 2 providers |
| 3. Node fallback | `try: _llm_finding() except LLMUnavailable: _rule_finding()` | deterministic rules |

Worst case for a single LLM node is **4 models x 2 attempts = 8 API attempts,
then rules** - and the graph still returns a valid `IncidentDecision`.

Everything funnels into one exception type:

```python
except Exception as exc:   # network, 401 auth, 429 rate limit,
    failures.append(...)   # 503 overload, 504 timeout,
    continue               # Pydantic schema validation failure
```

- **`temperature=0`** everywhere - reproducibility over creativity.
- **Failures accumulate.** Every failure string is collected and raised
  together (`"all models failed -> groq/...: 401 | google/...: 503"`) rather
  than only the last one. That is how the decommissioned Llama model was
  diagnosed.
- **Providers without a key are skipped**, not attempted.
- **Clients are cached** per `(provider, model)` pair.
- **No `tenacity` or `backoff`.** The cascade *is* the retry strategy -
  retrying a decommissioned model harder never helps, so trying a different
  model is the correct response.

### Testing libraries

`pytest` (fixtures, `parametrize`, `monkeypatch`, `approx`) plus
`streamlit.testing.v1.AppTest`, the official harness that executes the app
headlessly and reports exceptions - which is how all 7 pages are verified to
render, rather than only curling the health endpoint.

The suite is hermetic: `conftest.py` clears every provider key and drops cached
clients, so it makes zero network calls. LLM-boundary tests inject a fake
`structured_call` that dispatches on the requested schema.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env        # then paste your Groq key into GROQ_API_KEY
streamlit run app/ui/streamlit_app.py
```

Without a key the app still runs end to end on the rule path, and the sidebar
badge reads `LLM: fallback (rules)` instead of `LLM: live`.

`GOOGLE_API_KEY` is optional. When set it becomes the tail of the model chain:

```
groq/openai/gpt-oss-120b -> groq/openai/gpt-oss-20b
  -> groq/qwen/qwen3.8-27b -> google/gemini-3.5-flash -> deterministic rules
```

The chain spans two providers on purpose - the first three share a Groq
dependency, so the Gemini tail is what survives a whole-provider outage.

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
tests/       51 tests, hermetic, ~1s
assets/      architecture diagram
```

Dependencies run one way only: `models` <- `services` <- `agents` <- `ui`, so
the whole detection stack is testable without Streamlit. See
[ARCHITECTURE.md](ARCHITECTURE.md) for what each module does.

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
