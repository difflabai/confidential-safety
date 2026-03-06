# confidential-safety

A safety system for confidential AI inference providers. The goal is to reduce risks and prevent harms from confidential AI both at a provider level and across providers while preserving privacy and providing transparency.

This project proposes a complete confidential safety system designed for ML inference providers operating within Trusted Execution Environments (TEEs). It focuses on preventing misuse -- such as bioterrorism, cyberattack facilitation, or CSAM dissemination -- while maintaining user data privacy through privacy-preserving safety enforcement mechanisms and verified model inference.

## The Problem

Confidential inference lets users run ML models inside TEEs so that nobody -- not even the hardware operator -- can see their data. This is a strong privacy guarantee, but it creates a safety gap: if nobody can see user data, how do you prevent the system from being used to generate bioweapon synthesis routes, exploit code, or child sexual abuse material?

Existing approaches force a choice: either the provider can see user data (breaking confidentiality) or safety checks are absent (enabling misuse). This project resolves that tension.

## How It Works

Safety checks run **inside the TEE** as part of the attested Docker image. The checks see user content (they must, to classify it), but they are the only code that does, and they are cryptographically proven to be running via hardware attestation. Only structured safety verdicts exit the TEE -- never raw user content.

```
User -> TLS -> [TEE Boundary]
                 -> INPUT_CLASSIFY (pattern match + verified model classifiers)
                 -> PRE_INFERENCE_GATE (allow / block)
                 -> INFERENCE (model generates completion)
                 -> OUTPUT_CLASSIFY (pattern match + verified model classifiers)
                 -> POST_INFERENCE_GATE (allow / block / redact)
                 -> VERDICT_EMIT (audit log + external verdict + optional disclosure)
               -> TLS -> User
```

### Core Invariants

1. **Content never leaves the TEE.** User prompts, completions, and intermediate values never appear outside the TEE boundary. Only structured verdicts (no user content) may exit.
2. **Safety checks cannot be bypassed.** Every request passes through the classification and gating pipeline. There is no code path that skips it.
3. **Safety policy is attested.** The policy is baked into the Docker image and is part of the TEE attestation measurement. Users and auditors can verify which policy is running.
4. **Classifier verdicts are verified.** Classification model responses are cryptographically signed by TEE-bound ECDSA keys and verified before being trusted.
5. **Fail closed.** If any safety component fails, the request is blocked rather than allowed through unchecked.

### Two Tiers

**Tier 1 -- Inference Safety** (stateless, per-request): Classifies inputs and outputs against risk categories (bioterror, CSAM, cyberattack, CBRN, weapons). Blocks or redacts content that exceeds policy thresholds.

**Tier 2 -- Agent Safety** (stateful, per-session): Wraps Tier 1 and adds action validation (restricted tools, capability budgets), trajectory analysis (detects attack chain patterns like recon -> enumerate -> exploit), and escalation (Normal -> Warn -> Restrict -> Terminate).

### Verified Classifier Inference

Safety classifiers can run locally or remotely. Each classifier signs its verdict with a TEE-bound ECDSA key following the [NEAR AI verification pattern](https://docs.near.ai/cloud/verification). The safety pipeline verifies signatures and attestation before trusting any verdict, providing cryptographic proof that the classification actually ran inside a genuine TEE.

### Privacy-Preserving Reporting

| Output | Who can read it | What it contains |
|--------|----------------|-----------------|
| **ExternalVerdict** | Provider | verdict_id, risk_category, action, policy_version, timestamp. No user content. |
| **MandatoryDisclosure** | Designated authority only | Encrypted to authority's public key. risk_category, confidence, session_id_hash, content_hash (CSAM only). Provider relays but cannot decrypt. |
| **AuditLog** | Stays inside TEE | Hash-chained append-only log. Signed summaries (entry count, head hash, time range) exportable for compliance. |

Mandatory disclosures are produced only for extreme-confidence detections (>99.9%) and are encrypted to the designated authority for that risk category:

| Risk Category | Designated Authority (US) | Legal Basis |
|---|---|---|
| CSAM | NCMEC | 18 USC 2258A |
| Bioterror / CBRN | FBI WMD Directorate | Imminent threat exception |
| Cyberattack | CISA | Critical infrastructure protection |

## Architecture

### Crate Structure

```
crates/
  core/          Types, traits, policy parsing (Classifier, Gate, Pipeline traits)
  tee/           TEE attestation (Intel TDX), ECDSA signing, audit log, disclosure encryption
  classifier/    Pattern matching (Aho-Corasick), verified model classifier, ensemble combiner
  inference/     Tier 1 middleware: input/output gates, safety pipeline
  agent/         Tier 2: session management, action validation, trajectory analysis
  server/        HTTP server with OpenAI-compatible API
```

### Docker Layers

| Layer | Contents | Purpose |
|-------|----------|---------|
| 1 - Base | TEE attestation (Intel TDX), TLS (rustls), audit log | Platform foundation |
| 2 - Safety | Pattern matchers, verified classifier client, policy engine | Safety enforcement |
| 3a - Inference | Model serving integration, model hash verification, HTTP API | Inference serving |
| 3b - Agent | Session manager, action validator, trajectory analyzer | Agent serving |

The safety policy (`policy.toml`) is baked into the Docker image at build time, making it part of the attestation measurement.

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/chat/completions` | POST | OpenAI-compatible inference with safety pipeline |
| `/v1/agent/session` | POST | Create an agent session |
| `/v1/agent/turn` | POST | Process an agent turn (tool calls + trajectory analysis) |
| `/v1/attestation` | GET | Returns TDX quote, policy hash, classifier manifest |
| `/v1/health` | GET | Health check |

## Building

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace
```

## Configuration

Safety policy is defined in `policy.toml`. See the default policy for the full schema including:

- Per-category risk thresholds and classifier assignments
- Agent capability budgets and restricted tool lists
- Attack chain patterns for trajectory analysis
- Designated authority configurations for mandatory disclosure

## Documentation

- [`spec/behavior.md`](spec/behavior.md) -- Complete behavior specification
- [`spec/evals.md`](spec/evals.md) -- Evaluation criteria (20 criteria across 5 categories)
- [`Plans/quiet-prancing-puddle.md`](Plans/quiet-prancing-puddle.md) -- Design document

## References

- [Decentralized Confidential Machine Learning](https://raw.githubusercontent.com/nearai/por/refs/heads/main/DecentralizedConfidentialMachineLearning.pdf) -- NEAR AI paper on TEE-based confidential inference
- [NEAR AI Cloud Verification](https://docs.near.ai/cloud/verification) -- Verification protocol for TEE-bound signing
- [nearai-cloud-verifier](https://github.com/nearai/nearai-cloud-verifier) -- Reference verifier implementation

## License

MIT
