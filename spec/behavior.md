# Confidential Safety System -- Behavior Specification

## Overview

A safety evaluation layer that runs inside Trusted Execution Environments (TEEs) alongside confidential ML inference. The system enforces safety policies (blocking bioterrorism, cyberattacks, CSAM, CBRN, weapons content) while preserving the confidentiality guarantee that no user data is visible outside the TEE.

## Core Invariants

### I1: Content Never Leaves the TEE
User prompts, model completions, and intermediate values MUST never appear outside the TEE boundary in any form. Only structured safety verdicts (containing no user content) may exit.

### I2: Safety Checks Cannot Be Bypassed
Every inference request and every agent action MUST pass through the safety pipeline. There is no code path from TLS termination to model inference that skips classification and gating.

### I3: Safety Policy Is Attested
The safety policy file is baked into the Docker image and is part of the TEE attestation measurement. Any change to the policy changes the image hash, which changes the attestation report, which is detectable by users and auditors.

### I4: Classifier Verdicts Are Verified
When a classification model is called (local or remote), its response MUST be cryptographically signed by a TEE-bound ECDSA key. The safety pipeline MUST verify the signature and attestation before trusting the verdict. Unverified classifier responses MUST be treated as classification failures and handled according to the fail-closed policy.

### I5: Fail Closed
If any safety component fails (classifier timeout, verification failure, policy parse error), the system MUST block the request rather than allow it through unchecked. The only exception is the health check endpoint.

---

## Tier 1: Inference Safety

### Behavior: Request Processing

Given a user sends an inference request (prompt):

1. **Input Classification** (parallel execution):
   - All configured classifiers run simultaneously on the prompt
   - Pattern match classifiers check against known dangerous content signatures
   - Verified model classifiers send content + nonce to classification models, receive signed verdicts, and verify signatures + attestation
   - Each classifier produces zero or more `ClassifierFinding` values: `{category, confidence, classifier_id}`

2. **Pre-Inference Gate**:
   - Combines findings from all classifiers
   - For each risk category, takes the highest confidence score
   - Compares against per-category `input_threshold` from policy
   - Decision: `ALLOW` (no threshold exceeded) or `BLOCK` (one or more exceeded)
   - If BLOCK: return error response to user with `ExternalVerdict`, skip inference

3. **Inference**:
   - Forward prompt to model serving backend
   - Receive completion

4. **Output Classification** (parallel execution):
   - Same classifier set runs on the model's completion
   - For streaming responses: classifiers operate on a sliding window, checking incrementally

5. **Post-Inference Gate**:
   - Same logic as pre-inference gate but using `output_threshold` values
   - Additional action: `REDACT` (replace flagged content spans with redaction markers)
   - If BLOCK: return error response, discard completion
   - If REDACT: return modified completion with flagged spans replaced

6. **Verdict Emission**:
   - Append full `SafetyVerdict` to the in-TEE hash-chained audit log
   - Produce `ExternalVerdict` (minimal, no user content) and send to Provider Safety Service
   - If any finding exceeds `mandatory_disclosure_threshold`: produce `MandatoryDisclosure`, encrypt to designated authority's public key, send to Provider Safety Service for relay

### Behavior: Blocked Responses

When a request is blocked:
- The user receives an HTTP 451 (Unavailable for Legal Reasons) or 400 response
- The response body contains the `ExternalVerdict` with `risk_category` and `action: BLOCK`
- The response MUST NOT contain any description of what specifically triggered the block (this could help adversaries refine their prompts)
- The `verdict_id` is included so the provider can correlate with their audit records

### Behavior: Redacted Responses

When output is redacted:
- Flagged spans are replaced with `[REDACTED]` markers
- The `ExternalVerdict` includes `action: REDACT` and the `risk_category`
- The original unredacted content is never transmitted outside the TEE

---

## Tier 2: Agent Safety

### Behavior: Session Lifecycle

1. **Session Creation**: Client calls `POST /v1/agent/session` to start a new agent session. The system initializes `SessionState` with: empty action history, zero cumulative risk, zero turn count, `Normal` escalation level, full capability budget.

2. **Turn Processing**: Each `POST /v1/agent/turn` call:
   a. Runs Tier 1 pipeline on the user message / assistant generation
   b. For each tool call the model produces:
      - `ACTION_VALIDATE`: check tool name against restricted list, check parameters against capability budget, classify tool call content
      - If allowed: execute tool, record in session state, decrement capability budget
      - If blocked: inject refusal into agent context, record blocked action
   c. After all tool calls: `TRAJECTORY_ANALYZE` runs on recent action history
   d. All verdicts emitted

3. **Session Termination**: Client calls `DELETE /v1/agent/session/{id}`, or system auto-terminates when escalation reaches `Terminate`.

### Behavior: Action Validation

Given an agent wants to execute a tool call `{tool_name, parameters}`:

- If `tool_name` is in `restricted_tools` list: BLOCK unconditionally
- If capability budget for this tool type is exhausted: BLOCK
- If parameters contain content that classifiers flag above threshold: BLOCK
- Otherwise: ALLOW, record action, update capability usage

### Behavior: Trajectory Analysis

After each turn, the trajectory analyzer:

1. Slides a window of size `trajectory_window_turns` over recent action history
2. Matches action sequences against `attack_chain_patterns` (e.g., "network_scan, port_probe, exploit_attempt" indicates an attack chain)
3. Updates `cumulative_risk_score` based on findings
4. Determines escalation level:
   - `Normal`: no restrictions, continue
   - `Warn`: log warning in audit, continue with monitoring
   - `Restrict`: reduce capability budget (e.g., disable network_requests), notify in response
   - `Terminate`: end session immediately, emit verdicts, return termination response to client

### Behavior: Escalation

Escalation is monotonic within a session -- it can only increase, never decrease:
- `Normal` -> `Warn` -> `Restrict` -> `Terminate`
- Triggered by: cumulative risk score exceeding thresholds, suspicious action count exceeding `max_suspicious_actions`, attack chain pattern match

---

## Safety Reporting

### Behavior: ExternalVerdict Emission

For every request (Tier 1) and every turn (Tier 2):
- An `ExternalVerdict` is sent to the Provider Safety Service endpoint
- Contains: `verdict_id`, `stage`, `risk_category`, `action`, `policy_version`, `timestamp`
- Contains NO: user content, session identity, IP address, authentication tokens
- The Provider Safety Service uses these for compliance dashboards, operational metrics, and abuse detection

### Behavior: MandatoryDisclosure Emission

When a classifier finding exceeds the `mandatory_disclosure_threshold` for its risk category:

1. A `MandatoryDisclosure` is constructed inside the TEE:
   - `disclosure_id`: unique identifier
   - `risk_category`: which category triggered (CSAM, BIOTERROR, etc.)
   - `confidence`: classifier confidence score
   - `timestamp`: when the detection occurred
   - `session_id_hash`: SHA-256 of the session identifier (allows correlation if law enforcement has the session ID from other evidence)
   - `content_hash`: SHA-256 of the flagged content (CSAM only -- enables matching against known databases)
   - `attestation_quote`: proves disclosure came from genuine TEE running attested code

2. The disclosure is encrypted to the designated authority's public key (from policy.toml):
   - CSAM -> NCMEC (US) / IWF (UK) / jurisdiction-appropriate authority
   - BIOTERROR/CBRN -> FBI WMD Directorate (US) / jurisdiction-appropriate LEA
   - CYBER_ATTACK -> CISA (US) / jurisdiction-appropriate CERT

3. The encrypted blob is sent to the Provider Safety Service, which relays it to the designated authority's reporting endpoint. The provider cannot decrypt it.

4. The designated authority decrypts the disclosure and can:
   - Verify the attestation quote proves it came from genuine TEE hardware
   - Use the content_hash to match against known databases (CSAM)
   - Use the session_id_hash for correlation with other evidence
   - Trust the confidence score because the classifier is attested

### Behavior: Audit Log

- Every safety verdict is appended to a hash-chained log inside the TEE
- Each entry: `{sequence_number, previous_hash, verdict, entry_hash}` where `entry_hash = SHA-256(seq || prev_hash || verdict_bytes)`
- The log is append-only; entries cannot be modified or deleted
- Periodic signed summaries can be exported: `{entry_count, head_hash, time_range, policy_version}` -- signed by the TEE-bound key
- Summaries prove the safety pipeline processed N requests without revealing any content

---

## Attestation

### Behavior: Attestation Endpoint

`GET /v1/attestation?nonce={client_nonce}` returns:

- `attestation_quote`: hardware-signed TDX quote containing image measurement and signing address
- `policy_hash`: SHA-256 of the safety policy file
- `policy_version`: human-readable version string
- `classifier_manifest`: map of classifier_id -> {hash, version, type}
- `model_hash`: SHA-256 of the model weights being served
- `nonce`: echoed back, included in quote to prevent replay

A client verifying this can conclude: "The code running in this TEE includes safety policy P with classifiers C1..Cn, serving model M. Nobody can see my data, and the safety checks cannot be bypassed."

### Behavior: Signature Endpoint

`GET /v1/signature/{request_id}` returns the signed verdict for a specific request, allowing external verification that a particular safety verdict was produced by this TEE instance.

---

## Error Handling

| Failure Mode | Behavior |
|---|---|
| Classifier timeout | Block request (fail closed) |
| Classifier verification failure | Block request, log verification error |
| Policy file missing/corrupt | Refuse to start |
| Model hash mismatch | Refuse to start |
| Audit log full (memory pressure) | Block new requests until log is exported/trimmed |
| Provider Safety Service unreachable | Queue verdicts in TEE memory, retry with backoff. Do NOT block inference -- safety enforcement is local, reporting is best-effort. |
| Designated authority unreachable | Queue encrypted disclosures, retry with backoff. Log the queued disclosure in audit log. |
| TEE attestation failure | Refuse to start |
