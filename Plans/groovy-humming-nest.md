# Provider Compatibility Layers for Encrypted Inference Providers

## Context

The confidential-safety system currently uses a mock inference backend (`routes.rs:243` returns `"This is a mock response from {model}."`). To be useful in production, it needs to forward inference requests to real encrypted inference providers. This plan adds a new `crates/provider` crate with compatibility layers for the 7 providers listed on [confidentialinference.net](https://confidentialinference.net/).

**Providers researched** (6 with public APIs, 1 stub):
| Provider | Base URL | Auth | API Format | TEE |
|---|---|---|---|---|
| **Tinfoil** | `https://api.tinfoil.sh/v1` (inferred) | Bearer token | OpenAI-compat | Intel TDX, EHBP |
| **Redpill** | `https://api.redpill.ai/v1` | Bearer token | OpenAI-compat | Phala GPU TEE |
| **Chutes** | `https://api.chutes.ai` | `cpk_...` key | Custom (`/{chute_id}/chat_stream`) | Bittensor TEE |
| **NEAR AI** | `https://cloud-api.near.ai/v1` | Bearer token | OpenAI-compat | Intel TDX + NVIDIA H200 |
| **Privatemode** | `http://localhost:8080` (local proxy) | Bearer token | OpenAI-compat | Cosmian VM |
| **NanoGPT** | `https://nano-gpt.com/api/v1` | Bearer or `x-api-key` | OpenAI-compat | GPU-TEE + ECDSA attestation |
| **Maple** | N/A | N/A | N/A | AMD SEV-SNP (no public docs) |

---

## New crate: `crates/provider/`

### File Structure
```
crates/provider/
  Cargo.toml
  src/
    lib.rs              -- Provider trait, shared types, build_provider() factory
    error.rs            -- ProviderError enum (thiserror)
    config.rs           -- ProviderConfig, ProviderType enum, ProviderSettings
    providers/
      mod.rs            -- Re-exports
      openai_compat.rs  -- Shared OpenAI wire format types + send_openai_request() helper
      tinfoil.rs        -- TinfoilProvider
      redpill.rs        -- RedpillProvider (+ attestation verification)
      chutes.rs         -- ChutesProvider (custom endpoint format)
      near.rs           -- NearAiProvider
      privatemode.rs    -- PrivateModeProvider
      nanogpt.rs        -- NanoGptProvider (+ TEE attestation endpoint)
      maple.rs          -- MapleProvider (stub, returns error)
      mock.rs           -- MockProvider (replaces inline mock)
```

### Provider Trait (mirrors `Classifier` pattern from `core/src/pipeline.rs`)
```rust
#[async_trait]
pub trait Provider: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    async fn chat_completion(&self, req: &ChatCompletionRequest) -> Result<ChatCompletionResponse, ProviderError>;
    async fn list_models(&self) -> Result<Vec<String>, ProviderError> { Ok(vec![]) }
    async fn verify_attestation(&self) -> Result<(), ProviderError> { Ok(()) }
}
```

### Shared Types
- `ChatCompletionRequest` { model, messages, temperature, max_tokens, stop }
- `ChatCompletionResponse` { content, model, metadata, finish_reason, usage }
- `ProviderMetadata` { request_id, attestation, extra } -- captures provider-specific data

### openai_compat.rs (shared by 5/7 providers)
- `OpenAiRequest` / `OpenAiResponse` structs matching the wire format
- `send_openai_request(client, url, request, auth_header, extra_headers)` helper
- Conversion impls between internal types and wire types

---

## Provider-Specific Details

**Redpill** -- Most fully documented. Custom headers (`x-redpill-provider`, `x-redpill-trace-id`). Attestation via `GET /v1/attestation/report`. Signature verification via `GET /v1/signature/{request_id}`.

**NanoGPT** -- TEE attestation at `GET /api/v1/tee/attestation` (ECDSA). Supports both `Authorization: Bearer` and `x-api-key` headers.

**Chutes** -- Does NOT use openai_compat. Routes via `/{chute_id}/chat_stream`. Requires model-to-chute_id mapping in config. Auth header is raw key (no "Bearer" prefix).

**Tinfoil** -- OpenAI-compat but SDK adds EHBP encryption + cert pinning. Initial impl: standard HTTPS only. EHBP as future enhancement.

**Privatemode** -- Calls local proxy (`http://localhost:8080`), which handles E2EE. Must allow HTTP (not just HTTPS) for localhost.

**NEAR AI** -- Standard OpenAI-compat. On-chain attestation is a future enhancement.

**Maple** -- Stub only. `maple.build` has no public inference API docs (site is a floor planning tool). Returns `ProviderError::ConfigError`.

---

## Configuration

Add `[provider]` section to `policy.toml` or server config:
```toml
[provider]
provider = "redpill"
base_url = "https://api.redpill.ai/v1"
api_key_env = "REDPILL_API_KEY"  # reads key from env var
timeout_ms = 30000
```

Config structs use serde tagged enum (`ProviderSettings`) for provider-specific fields. Factory function `build_provider(config) -> Box<dyn Provider>`.

---

## Server Integration

### Files to modify:
1. **`Cargo.toml`** (workspace root) -- Add `crates/provider` to members + deps
2. **`crates/server/Cargo.toml`** -- Add `confidential-safety-provider` dependency
3. **`crates/server/src/routes.rs`** -- Add `provider: Box<dyn Provider>` to `AppState`, replace mock at line 241-243 with `state.provider.chat_completion()` call, add `BAD_GATEWAY` error path for provider failures
4. **`crates/server/src/config.rs`** -- Add `provider: Option<ProviderConfig>` field
5. **`crates/server/src/main.rs`** -- Build provider from config, verify attestation at startup, inject into `AppState`

### The key change in `routes.rs` chat_completions handler:
Replace the mock inference (line 241-243) with:
```rust
let provider_response = match state.provider.chat_completion(&provider_request).await {
    Ok(r) => r,
    Err(e) => { /* fail-closed: return 502 BAD_GATEWAY with safety block */ }
};
```

---

## Test Strategy

Following pattern from `crates/classifier/src/verified_model.rs` (mock HTTP server tests):

1. **Per-provider unit tests** -- Each provider file has `#[cfg(test)] mod tests` with an axum mock server mimicking the provider's API. Tests: success, auth failure, timeout, invalid response, rate limiting, non-200 status.
2. **Chutes-specific tests** -- Missing chute_id mapping, custom response format.
3. **Attestation tests** -- For Redpill and NanoGPT: valid/invalid attestation responses.
4. **Factory test** -- `build_provider()` with each `ProviderType`.
5. **Server integration test** -- End-to-end: start server with MockProvider, POST `/v1/chat/completions`, verify response uses provider output, verify safety blocking still works.

---

## Verification

1. `cargo build --workspace` -- compiles without errors
2. `cargo test --workspace` -- all existing + new tests pass
3. `cargo clippy --workspace` -- no warnings
4. Manual: start server with `MockProvider`, curl `/v1/chat/completions`, verify response
5. Manual: start server with a real provider (e.g., Redpill with API key), verify end-to-end inference + safety
