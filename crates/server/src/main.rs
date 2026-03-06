use std::sync::{Arc, Mutex};

use confidential_safety_core::policy::PolicyConfig;
use confidential_safety_inference::middleware::InferenceSafetyMiddleware;
use confidential_safety_tee::audit_log::AuditLog;

mod config;
mod routes;

use config::ServerConfig;
use routes::{AppState, build_router};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    let config = ServerConfig::default();

    // Load policy
    let policy_toml = match std::fs::read_to_string(&config.policy_path) {
        Ok(s) => s,
        Err(e) => {
            // For development, use an embedded default policy
            tracing::warn!(
                "Could not load policy from {:?}: {e}. Using default policy.",
                config.policy_path
            );
            include_str!("../../../policy.toml").to_string()
        }
    };

    let policy = PolicyConfig::from_toml(&policy_toml).expect("Failed to parse safety policy");
    let policy_hash = PolicyConfig::hash(&policy_toml);
    let policy_version = policy.policy.version.clone();

    tracing::info!(
        policy_version = %policy_version,
        policy_hash = %hex_encode(&policy_hash),
        mode = ?config.mode,
        "Safety policy loaded"
    );

    // Verify model hash at startup (if configured)
    if let (Some(model_path), Some(expected_hash)) =
        (&config.model_path, &config.expected_model_hash)
    {
        tracing::info!(?model_path, "Verifying model hash...");
        let actual_hash = sha256_file(model_path).expect("Failed to hash model file");
        let actual_hex = hex_encode(&actual_hash);
        if actual_hex != *expected_hash {
            panic!(
                "Model hash mismatch: expected {expected_hash}, got {actual_hex}. Refusing to start."
            );
        }
        tracing::info!("Model hash verified.");
    }

    // Build the inference provider
    let provider_config = config
        .provider
        .clone()
        .unwrap_or_default();

    let provider = confidential_safety_provider::build_provider(&provider_config)
        .expect("Failed to build inference provider");

    tracing::info!(
        provider = provider.name(),
        "Inference provider initialized"
    );

    // Build the safety pipeline (with no classifiers in default mode -- add via config)
    let audit_log = Arc::new(Mutex::new(AuditLog::new()));
    let pipeline = InferenceSafetyMiddleware::new(vec![], policy.clone(), audit_log);

    let state = Arc::new(AppState {
        pipeline,
        provider,
        policy: policy.clone(),
        mode: config.mode,
        policy_hash,
        policy_version: policy_version.clone(),
    });

    let router = build_router(state);

    let listener = tokio::net::TcpListener::bind(&config.bind_addr)
        .await
        .expect("Failed to bind");

    tracing::info!(addr = %config.bind_addr, "Server listening");

    axum::serve(listener, router).await.expect("Server error");
}

fn sha256_file(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let data = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(hasher.finalize().into())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
