# CLAUDE.md

Context for Claude Code working in this repo. Read this before editing.

## What this is

Inbox Sentinel — an agentic email-security investigation platform. A LangGraph
graph triages a suspicious email through four specialist agents, fuses their
findings into a verdict, and routes it through a deterministic policy engine
that gates containment behind human approval.

- `README.md` — pitch, agent flow/handoff tables, implementation stack, retry
  layers, setup, demo script
- `ARCHITECTURE.md` — design rationale, measured findings, limitations
- `threat_model.md` — security posture

## ⚠️ Two folders exist — use the right one

| Path | Status |
|---|---|
| `~/Desktop/inbox-sentinel` (hyphenated, lowercase) | **canonical.** This repo. Pushed to `github.com/kukunarapulikitha/inbox-sentinel` |
| `~/Desktop/InboxSentinel` (CamelCase) | the original deterministic MVP, kept **deliberately** as a working demo fallback. Not a git repo. |

Do not "clean up" the CamelCase folder — deleting it removes the fallback demo.
The agents were ported from its `inbox_sentinel/analysis.py`.

Note: Claude Code sessions started from the two folders file their history
under different project slugs, so earlier conversations may appear missing.

## Commands

All from the repo root. **Use the venv's binaries directly** — `python3` on
this machine is 3.14 with none of the deps.

```bash
.venv/bin/python -m pytest -q                              # 51 tests, ~1s
.venv/bin/streamlit run app/ui/streamlit_app.py            # analyst console
.venv/bin/python -m pip install -r requirements.txt
```

Verify every page renders without exceptions (health-checking the port is not
enough — it only proves the server booted):

```bash
.venv/bin/python - <<'EOF'
from streamlit.testing.v1 import AppTest
for page in ["Alert queue","Investigation","Campaign scope","Email sandbox",
             "Detection quality","Audit log","How it works"]:
    at = AppTest.from_file("app/ui/streamlit_app.py", default_timeout=300).run()
    at.sidebar.radio[0].set_value(page).run()
    print(page, "exceptions:", len(at.exception))
EOF
```

## Invariants — do not break these

These are load-bearing. Changing any of them changes what the project *claims*.

1. **Never fetch a URL or open an attachment.** No Playwright, Selenium,
   Chromium, `requests.get`, or `urlopen` against email content. Attachments
   are hashed in memory only. This is the core security claim in
   `threat_model.md`.
2. **The LLM must never select actions, set a risk score, or change message
   state.** Action selection lives only in `services/policy_engine.py`, a pure
   function of `(risk, verdict, needs_human_review)`. This is the structural
   defence against prompt injection — not the prompt.
3. **Keep `Annotated[list[Finding], _merge]`** in `InvestigationState`. Four
   analyzer nodes write `findings` concurrently; without the reducer LangGraph
   raises on the concurrent update.
4. **Sort findings before use.** Parallel nodes finish in nondeterministic
   order; `verdict_node` sorts by the `ORDER` map so output is reproducible.
5. **Verdict labels stay inside `VERDICT_LABELS`** (`agents/verdict.py`). An
   off-vocabulary label raises `LLMUnavailable` and the rule chain decides.
   Detection metrics depend on a stable label space.
6. **Rule floors own the verdict label when one fires.** See "taxonomy
   precedence" below — this is measured behaviour, not a preference.
7. **`services/audit_log.py` is append-only.** No UPDATE or DELETE path. A
   correction is a new row.
8. **`tests/conftest.py` must clear *every* provider key** (`GROQ_API_KEY`,
   `GOOGLE_API_KEY`) and drop cached clients. See gotchas.

## Taxonomy precedence (measured, non-obvious)

Verdict agreement on the 14-message corpus:

| Configuration | Agreement |
|---|---|
| rules only | 12/14 |
| LLM owns the label | 11/14 |
| **hybrid (shipped)** | **13/14** |

The LLM reads intent well but flattens fraud subtypes — it labels vendor RFQ
fraud and payment fraud both as "Suspected BEC". So when a deterministic floor
fires it owns the *label*, and the LLM keeps the rationale, confidence and
needs-review call. When no floor fires, the LLM's label stands (this is what
fixed `msg-003`). Both directions are pinned in `tests/test_llm_fallback.py`.

Binary malicious-vs-benign is P=1.0 / R=1.0 in all three configurations —
every disagreement is a subtype confusion, never a missed threat.

## Gotchas that have already cost time

- **Groq retired the general-purpose Llama chat models.** The original
  `llama-3.3-70b-versatile` 404s. The only Llama models Groq still serves are
  `llama-prompt-guard-2-22m/86m`, which are injection *classifiers* and cannot
  produce structured output. Don't add a Llama entry to `MODEL_CHAIN` without
  checking `client.models.list()` first.
- **`gemini-3.8-flash` returns 503/504 under load.** `gemini-3.5-flash` is
  reliable; that's why it's the chain tail.
- **If the test suite takes minutes instead of ~1s, a provider key leaked into
  the test environment** and the suite is making real API calls. Check
  `conftest.py`.
- **Python is 3.14** in this venv. Some wheels are recent; prefer `.venv/bin/pip`.
- **`use_container_width` is removed** in this Streamlit version — use
  `width="stretch"`. It still renders but prints a deprecation banner on every
  table, which is visible during a demo.
- **`timeout` is not available** as a shell builtin on this machine (zsh).
- **Don't trust `llm_mode == "live"` as binary.** There are three states:
  `live`, `partial` (one LLM node fell to rules), `fallback`. A partial
  degradation once reported as a total outage while a model had plainly
  written the rationale on screen.

## Conventions in this codebase

- **Dependency direction is one-way:** `models ← services ← agents ← ui`. No
  model imports a service; no service imports an agent. The only agent-to-agent
  import is `verdict` → `content_signals`, for its fallback path.
- **Every agent returns the same `Finding`**, including `source` (`"llm"` or
  `"rules"`) so failures stay attributable.
- **Agents never call each other** — they read and write graph state.
- Pydantic v2 throughout for models; `TypedDict` for graph state.
- `temperature=0` on every LLM call.
- Comments explain *why*, especially where behaviour looks wrong but is
  deliberate (risk floors, taxonomy precedence, the reducer). Match that
  density — this codebase is read as an interview artifact.
- Tests assert on behaviour and include regression guards naming the original
  MVP defect they protect against.

## Open issue

`msg-007` is still misclassified — a Teams-branded credential phish on
`teams-alerts.example`. The lookalike check only catches homoglyphs
(`micros0ft` → `microsoft`), so a domain that legitimately *contains* a brand
token passes. The fix is a "contains a brand token but is not that brand's
domain" rule in `agents/identity_auth.py`.

## Secrets

`.env` is gitignored and verified absent from git history. `.env.example` holds
blank placeholders. `GROQ_API_KEY` is required for the live path;
`GOOGLE_API_KEY` is the optional cross-provider tail.

The keys currently in `.env` were pasted into a chat transcript and **should be
rotated**. Never commit `.env` or echo a key into terminal output.
