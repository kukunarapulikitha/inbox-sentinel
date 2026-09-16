# Threat model and security posture

This tool analyses attacker-controlled content, so it is itself a target. The
posture below is deliberate, not incidental.

## Data handling

- **Synthetic corpus only.** The 14 seeded messages in `data/emails.jsonl` are
  fabricated. No real mailbox, tenant or customer data is present, and no
  mailbox is connected.
- **No live URL fetching.** URLs are parsed as strings. Nothing resolves DNS,
  issues a request, or follows a redirect. This avoids confirming a live target
  to an attacker, tripping a tracking pixel, or pulling a payload onto the host.
- **No attachment execution.** Attachments are hashed in memory
  (SHA-256) and described by filename and MIME type. Nothing is written to
  disk, unpacked, or opened. `mock_sandbox` fields are seeded metadata, not
  real detonation output.
- **Local only.** Sandbox submissions are held in memory for the request. Email
  content is sent to the Groq API when an API key is configured; with no key,
  nothing leaves the machine. Do not paste real customer email into a hosted
  deployment without a data-processing review.

## Prompt injection

Email bodies are the canonical untrusted-input problem: the thing being
analysed wants to control the analyser.

- All attacker-controlled text is wrapped in `<untrusted_email>` delimiters by
  `app/services/llm.py`, with a system instruction stating it is evidence to
  analyse and never instructions to follow.
- Closing-tag sequences in the content are neutralised so the fence cannot be
  broken from inside.
- Injection attempts are treated as *evidence of manipulation* and reported,
  rather than obeyed.
- The structural control matters more than the prompt: **the model has no
  action-selection capability.** It cannot quarantine, purge, notify, set a
  risk score, or change message state. A successful injection can skew one
  finding; it cannot cause an action.

## Least privilege and human control

- Action selection lives entirely in the deterministic `policy_engine`.
- Bands 60+ require explicit human approval before any containment.
- Conflicting agent findings produce `needs_human_review` rather than a forced
  verdict, and always route to a human.
- Actions are simulated. A production deployment would need scoped mail-tenant
  credentials, and quarantine/purge should be a separate service with its own
  authorisation, not something the analysis process can call directly.

## Auditability

- `data/audit.db` is append-only: every approval, action and feedback event is
  a new row with timestamp, message ID, verdict, risk score, policy band,
  analyst identity, and which reasoning path ran. No UPDATE or DELETE path
  exists in `audit_log.py`.
- Each `Finding` records `source` (`llm` or `rules`), so a verdict produced
  during an LLM outage is distinguishable after the fact.
- LLM calls are temperature 0 with structured output, so a given input and
  model version reproduce the same finding as closely as the provider allows.

## Uncertainty handling

- Agents report `uncertainties` explicitly rather than implying false
  precision - for example, that passing SPF/DKIM/DMARC does not establish
  sender intent when an account is compromised.
- Low-confidence messages surface in a dedicated queue on the Detection
  quality page instead of being silently auto-actioned.
- Campaign scope is explicitly labelled as limited to the local corpus and
  seeded telemetry.

## Known limitations

- The seeded `interactions.jsonl` telemetry is fabricated; blast-radius figures
  are illustrative of the mechanism, not measurements.
- The label set in `expected_labels.jsonl` is small (14 messages), so detection
  metrics are a demonstration of correct measurement, not a validated accuracy
  claim.
- No authentication on the Streamlit app. It is a local demo, not a
  multi-tenant service.
