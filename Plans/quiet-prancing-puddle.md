# Confidential Inference Safety System

## Context

Confidential inference (running ML models inside TEEs so nobody can see user data) has a critical gap: **no mechanism for safety enforcement**. The NEAR AI paper on Decentralized Confidential ML describes how TEEs + Docker containers + attestation create fully private inference, but says nothing about preventing the system from being used for bioterrorism, cyberattacks, or CSAM.

The core tension: privacy says nobody outside the TEE sees user data; safety says dangerous content must be detected. Our resolution: **safety checks run inside the TEE as part of the attested Docker image**. Only structured verdicts (pass/fail + risk category) exit the TEE -- never raw user content.

## Architecture Overview

### Two Tiers

**Tier 1 -- Inference Safety** (stateless, per-request):
```
User -> TLS -> [TEE Boundary]
                 -> INPUT_CLASSIFY (parallel: pattern match + verified model calls)
                 -> PRE_INFERENCE_GATE (allow/block decision)
                 -> INFERENCE (model generates completion)
                 -> OUTPUT_CLASSIFY (parallel: pattern match + verified model calls)
                 -> POST_INFERENCE_GATE (allow/block/redact)
                 -> VERDICT_EMIT (audit log + external verdict + optional disclosure)
               -> TLS -> User
```

**Tier 2 -- Agent Safety** (stateful, per-session): wraps Tier 1 and adds:
- `ACTION_VALIDATE` before every tool call (check tool name, params, capability budget)
- `TRAJECTORY_ANALYZE` after every turn (detect attack chains, update escalation level)
- Session state in encrypted TEE memory, never persisted plaintext

### Classifier Architecture: Pattern Matching + Verified Inference

Classifiers combine two approaches:

1. **Pattern matching** (in-process, fast): Aho-Corasick multi-pattern matching against known dangerous content signatures. Runs directly inside the safety TEE.

2. **Verified model inference** (local or remote classification models): Safety classifier models (e.g., a fine-tuned model for bioterror detection) run in their own TEE. Each verdict is **cryptographically signed** with a TEE-bound key, following the NEAR AI verification pattern:

```
Safety Pipeline TEE                     Classifier Model TEE
  |                                       |
  | --- classify(content, nonce) -------> |
  |                                       | runs classifier inference
  |                                       | signs verdict with TEE-bound ECDSA key
  | <-- { verdict, signature, addr } ---- |
  |                                       |
  | verify signature (recover addr)       |
  | fetch attestation report for addr     |
  | verify TDX quote + report_data        |
  | confirm addr is bound to genuine TEE  |
  | --> verdict is cryptographically      |
  |     proven to come from attested      |
  |     classifier in genuine hardware    |
```

This follows the NEAR AI cloud verification flow:
- **Key generation**: Classifier generates ECDSA signing keypair inside TEE at init
- **Hardware attestation**: TDX report binds signing address (first 32 bytes of report_data) to hardware
- **Verdict signing**: Every classification result is signed with the TEE-bound private key
- **Verification**: Safety pipeline recovers signer address, fetches attestation report, verifies TDX quote via `dcap-qvl`, confirms report_data binding

The classifier can be **local** (same machine, different TEE enclave) or **remote** (different machine). Verification works identically in both cases because it relies on attestation, not network topology.

### Docker Layers

| Layer | Contents | Purpose |
|-------|----------|---------|
| 1 - Base | TEE attestation (Intel TDX primary), TLS (rustls), audit log, hardware RNG | Platform foundation |
| 2 - Safety | Pattern matchers, verified classifier client, policy engine, verdicts | Safety enforcement |
| 3a - Inference | Model serving integration (mock), model hash verification, HTTP API | Inference serving |
| 3b - Agent | Session manager, action validator, trajectory analyzer | Agent serving |

Safety policy is baked into the Docker image at `/etc/confidential-safety/policy.toml`, making it part of the attestation measurement. Users can verify which policy runs; providers can prove compliance.

### Safety Reporting Architecture

Both ExternalVerdicts and MandatoryDisclosures are written to a **Provider Safety Service** (API endpoint run by/for the inference provider).

```
TEE (Safety Pipeline)
  |
  |-- ExternalVerdict (readable) ---------> Provider Safety Service
  |                                           -> compliance dashboard, metrics, audit trail
  |
  |-- MandatoryDisclosure (encrypted) ----> Provider Safety Service (relay only)
  |                                           -> forwards opaque blob to Designated Authority
  |
  |-- AuditLog (stays inside TEE) --------> periodic signed summaries exportable for compliance
```

**ExternalVerdict** (every request, provider-readable): Contains verdict_id, stage, risk_category, action, policy_version, timestamp. No user content, no session identity. Provider needs this for operational metrics, compliance proof, and abuse detection.

**MandatoryDisclosure** (extreme cases, provider-opaque): Encrypted to designated authority's public key using `age`. Provider relays the opaque blob but cannot read it. Contains risk_category, confidence, timestamp, session_id_hash, content_hash (CSAM only), attestation quote.

**Designated Authorities** are configured per risk category in policy.toml:

| Risk Category | Authority (US) | Legal Basis |
|---|---|---|
| CSAM | NCMEC | 18 USC §2258A (ESP mandatory reporting) |
| BIOTERROR / CBRN | FBI WMD Directorate | Imminent threat exception |
| CYBER_ATTACK | CISA | Critical infrastructure protection |

Different jurisdictions configure different authorities (e.g., IWF for CSAM in UK). Each authority entry in policy.toml specifies: name, categories, jurisdiction, public_key, reporting_endpoint.

**AuditLog** (inside TEE): hash-chained append-only log. Periodic signed summaries (entry count, head hash, time range) can be exported for compliance without revealing content.

### Spec Directory

- `spec/behavior.md`: Desired system behavior specification
- `spec/evals.md`: High-level evaluation criteria

### Attestation Chain

Users verify end-to-end:
1. **Hardware attestation** (Intel TDX quote via DCAP) proves CVM is genuine
2. **Docker image measurement** in TDX report proves which container is running (including safety policy)
3. **Signing key binding** in report_data proves verdicts come from that specific TEE
4. **Container provenance** via Sigstore confirms supply chain integrity
5. **Model hash** verified at startup proves which model is served

This gives: "I am talking to model M, protected by safety policy P, with classifiers verified via attestation, running inside a genuine TEE where nobody can see my data."

## Implementation Plan

### Rust Workspace Structure

```
missoula/
  Cargo.toml                          # workspace
  crates/
    core/                             # types, traits, policy parsing
      src/lib.rs, verdict.rs, policy.rs, pipeline.rs, error.rs
    classifier/                       # classifier implementations
      src/lib.rs, pattern.rs, verified_model.rs, ensemble.rs
    inference/                        # Tier 1 middleware
      src/lib.rs, middleware.rs, input_gate.rs, output_gate.rs
    agent/                            # Tier 2 middleware
      src/lib.rs, action_validator.rs, trajectory.rs, capability.rs, session.rs
    tee/                              # TEE integration (Intel TDX primary)
      src/lib.rs, attestation.rs, audit_log.rs, disclosure.rs,
          signing.rs, verification.rs
    server/                           # HTTP server
      src/main.rs, routes.rs, config.rs, tls.rs
  policy.toml                         # default safety policy
  docker/
    Dockerfile.base
    Dockerfile.inference
    Dockerfile.agent
```

### Phase 1: Core Types and Policy (`crates/core`)

Files to create:
- `verdict.rs`: `RiskCategory` enum (None, Bioterror, Csam, CyberAttack, Cbrn, Weapons), `SafetyAction` enum, `PipelineStage` enum, `SafetyVerdict`, `ExternalVerdict`, `MandatoryDisclosure`
- `policy.rs`: Parse `policy.toml` (TOML) into `PolicyConfig` with per-category thresholds, classifier assignments (pattern vs verified-model), agent capability budgets, disclosure settings
- `pipeline.rs`: `Classifier` trait (async classify -> Vec<ClassifierFinding>), `Gate` trait, `InferencePipeline` trait, `AgentPipeline` trait
- `error.rs`: Error types

### Phase 2: TEE Integration (`crates/tee`)

Follows the NEAR AI verification pattern (reference: `nearai-cloud-verifier`).

Files to create:
- `attestation.rs`: Intel TDX attestation -- generate TDX quotes, verify quotes via `dcap-qvl`. Mock implementation for testing. Report data structure: first 32 bytes = signing address, last 32 bytes = nonce.
- `signing.rs`: ECDSA key generation inside TEE (secp256k1), sign verdicts, bind public key to TDX report_data. Uses `k256` crate.
- `verification.rs`: Verify signed verdicts -- recover ECDSA signer address, fetch attestation report for that address, verify TDX quote, confirm report_data binding. This is what proves classifier verdicts are genuine.
- `audit_log.rs`: Hash-chained append-only log with `SHA-256(seq || prev_hash || verdict_bytes)`
- `disclosure.rs`: Encrypt MandatoryDisclosure with `age` to recipient public key, attach attestation quote

### Phase 3: Classifiers (`crates/classifier`)

Files to create:
- `pattern.rs`: `PatternMatchClassifier` using `aho-corasick` for known dangerous content signatures. Fast, in-process, no external calls.
- `verified_model.rs`: `VerifiedModelClassifier` that calls a classification model (local or remote) and **verifies** the response using the TEE verification flow from Phase 2. Sends content + nonce, receives verdict + signature + signing_address, verifies signature and attestation. This is the critical integration point with NEAR AI's verification system.
- `ensemble.rs`: `EnsembleClassifier` combining pattern match + verified model results with configurable scoring weights per risk category.

### Phase 4: Tier 1 Pipeline (`crates/inference`)

Files to create:
- `middleware.rs`: `InferenceSafetyMiddleware` wiring classifiers to gates. Runs pattern matching and verified model calls in parallel via `tokio::join!`.
- `input_gate.rs`: `PreInferenceGate` evaluates combined findings against policy thresholds
- `output_gate.rs`: `PostInferenceGate` evaluates output findings, supports streaming via sliding window

### Phase 5: HTTP Server (`crates/server`)

Files to create:
- `routes.rs`:
  - `POST /v1/chat/completions` (OpenAI-compatible, Tier 1 pipeline wrapping mock backend)
  - `POST /v1/agent/turn`, `POST /v1/agent/session`, `DELETE /v1/agent/session/{id}` (Tier 2)
  - `GET /v1/attestation` (returns TDX quote + policy hash + classifier manifest + signing address)
  - `GET /v1/signature/{request_id}` (returns signed verdict for external verification)
  - `GET /v1/health`
- `tls.rs`: TLS termination with `rustls` (keys live only inside TEE)
- `config.rs`: Server configuration from env/args

### Phase 6: Tier 2 Agent Pipeline (`crates/agent`)

Files to create:
- `session.rs`: `SessionManager` with encrypted in-memory session state
- `action_validator.rs`: Check tool calls against restricted list and capability budget. Tool call parameters are also classified (e.g., shell commands checked for exploit patterns).
- `trajectory.rs`: `TrajectoryAnalyzer` with attack chain pattern detection (recon -> enumerate -> exploit), sliding window over recent turns, escalation levels (Normal -> Warn -> Restrict -> Terminate)
- `capability.rs`: `CapabilityBudget` tracking (network_requests, file_writes, shell_commands) with per-session consumption

### Phase 7: Docker Images

Files to create:
- `docker/Dockerfile.base`: Ubuntu 24.04 + TDX attestation libs + compiled Rust binaries
- `docker/Dockerfile.inference`: Extends safety layer, mock model backend, entrypoint `--mode=inference`
- `docker/Dockerfile.agent`: Extends safety layer, session management, entrypoint `--mode=agent`
- Multi-stage builds for reproducible, deterministic image hashes

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `serde` / `serde_json` / `toml` | Serialization and policy parsing |
| `uuid` (v7) | Time-ordered verdict IDs |
| `sha2` | Hashing (audit log, content hashes, model verification) |
| `aho-corasick` | Pattern matching classifier |
| `k256` | ECDSA secp256k1 signing/verification (matches NEAR AI pattern) |
| `age` | Asymmetric encryption for mandatory disclosures |
| `axum` | HTTP server |
| `reqwest` | HTTP client for remote classifier + attestation calls |
| `rustls` / `tokio-rustls` | TLS termination |
| `tokio` | Async runtime |
| `tracing` | Structured logging |

## Verification

1. **Unit tests per crate**: Policy parsing, verdict serialization, pattern matching accuracy, gate logic, audit log integrity, ECDSA signing/verification round-trip
2. **Verified classifier test**: Mock classifier signs a verdict, safety pipeline verifies signature and (mock) attestation, confirms the verified model flow works end-to-end
3. **Tier 1 integration test**: Feed a prompt through full pipeline (pattern match + verified model call), verify correct verdict, confirm no user content in ExternalVerdict
4. **Tier 2 agent session test**: Multi-turn scenario with escalating suspicious actions, verify trajectory analyzer triggers Warn -> Restrict -> Terminate
5. **Audit log integrity test**: Append entries, verify hash chain, tamper with one entry, confirm detection
6. **Disclosure test**: Produce MandatoryDisclosure, encrypt with `age`, decrypt with recipient key, verify contents
7. **Docker build test**: Build all layers, verify deterministic image hashes
8. **`cargo test --workspace`** runs full suite
