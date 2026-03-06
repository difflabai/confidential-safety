//! Verified model classifier -- calls a classification model (local or remote)
//! and verifies the response signature using TEE-bound ECDSA keys.
//!
//! The protocol:
//! 1. Generate a random nonce (32 bytes, hex-encoded)
//! 2. POST `ClassifyRequest` to `{endpoint}/classify`
//! 3. Receive `ClassifyResponse` containing the verdict payload, signature, and
//!    public key
//! 4. Verify the nonce matches what we sent
//! 5. Verify the ECDSA signature over the JSON-serialized verdict
//! 6. Optionally verify the signer's address matches an expected address
//! 7. Convert to `ClassifierFinding`

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use confidential_safety_core::error::SafetyError;
use confidential_safety_core::pipeline::{Classifier, ClassifierFinding, ContentRef};
use confidential_safety_core::verdict::RiskCategory;
use confidential_safety_tee::signing;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

/// Request sent to the classifier model endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifyRequest {
    /// The content to classify (text representation).
    pub content: String,
    /// Hex-encoded 32-byte random nonce for replay protection.
    pub nonce: String,
    /// Unique identifier for this classification request.
    pub request_id: Uuid,
}

/// The signed verdict payload returned by the classifier model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifierVerdictPayload {
    /// Must match the request_id from the request.
    pub request_id: Uuid,
    /// Must match the nonce from the request.
    pub nonce: String,
    /// The detected risk category.
    pub category: RiskCategory,
    /// Confidence score in [0.0, 1.0].
    pub confidence: f64,
    /// Identifier of the classifier that produced this verdict.
    pub classifier_id: String,
}

/// Response from the classifier model endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifyResponse {
    /// The verdict payload.
    pub verdict: ClassifierVerdictPayload,
    /// Hex-encoded DER ECDSA signature over the JSON-serialized verdict.
    pub signature: String,
    /// Hex-encoded SEC1 public key of the signer.
    pub public_key: String,
}

// ---------------------------------------------------------------------------
// VerifiedModelClassifier
// ---------------------------------------------------------------------------

/// A classifier that calls a remote/local classification model and verifies
/// the cryptographic signature on the response.
pub struct VerifiedModelClassifier {
    id: String,
    endpoint: String,
    expected_signing_address: Option<[u8; 20]>,
    timeout: Duration,
    http_client: reqwest::Client,
}

impl VerifiedModelClassifier {
    /// Create a new verified model classifier.
    ///
    /// - `id`: unique identifier for this classifier instance
    /// - `endpoint`: base URL of the classifier model (e.g. `http://localhost:8081`)
    /// - `expected_signing_address`: if set, the signer's derived address must match
    /// - `timeout`: maximum time to wait for a response
    pub fn new(
        id: String,
        endpoint: String,
        expected_signing_address: Option<[u8; 20]>,
        timeout: Duration,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("failed to build HTTP client");

        Self {
            id,
            endpoint,
            expected_signing_address,
            timeout,
            http_client,
        }
    }

    /// Extract text content from a `ContentRef` for classification.
    fn content_to_string(content: &ContentRef<'_>) -> Option<String> {
        match content {
            ContentRef::Text(text) => Some(text.to_string()),
            ContentRef::ToolCall {
                tool_name,
                parameters,
            } => Some(format!("{} {}", tool_name, parameters)),
            ContentRef::Bytes(_) | ContentRef::ActionSequence(_) => None,
        }
    }

    /// Generate a random 32-byte nonce as a hex string.
    fn generate_nonce() -> String {
        let mut bytes = [0u8; 32];
        rand::fill(&mut bytes);
        signing::hex_encode(&bytes)
    }

    /// Verify the response from the classifier model.
    fn verify_response(
        &self,
        response: &ClassifyResponse,
        expected_nonce: &str,
    ) -> Result<(), SafetyError> {
        // Step 1: Verify nonce matches
        if response.verdict.nonce != expected_nonce {
            return Err(SafetyError::VerificationFailure {
                classifier_id: self.id.clone(),
                reason: "nonce mismatch".into(),
            });
        }

        // Step 2: Deserialize the public key from hex
        let pk_bytes =
            signing::hex_decode(&response.public_key).map_err(|e| {
                SafetyError::VerificationFailure {
                    classifier_id: self.id.clone(),
                    reason: format!("invalid public key hex: {e}"),
                }
            })?;

        let verifying_key = signing::VerifyingKey::from_sec1_bytes(&pk_bytes).map_err(|e| {
            SafetyError::VerificationFailure {
                classifier_id: self.id.clone(),
                reason: format!("invalid public key: {e}"),
            }
        })?;

        // Step 3: Deserialize the signature from hex
        let sig_bytes =
            signing::hex_decode(&response.signature).map_err(|e| {
                SafetyError::VerificationFailure {
                    classifier_id: self.id.clone(),
                    reason: format!("invalid signature hex: {e}"),
                }
            })?;

        let signature = k256::ecdsa::Signature::from_der(&sig_bytes).map_err(|e| {
            SafetyError::VerificationFailure {
                classifier_id: self.id.clone(),
                reason: format!("invalid signature DER: {e}"),
            }
        })?;

        // Step 4: Verify the ECDSA signature over the JSON-serialized verdict
        let verdict_json = serde_json::to_vec(&response.verdict).map_err(|e| {
            SafetyError::VerificationFailure {
                classifier_id: self.id.clone(),
                reason: format!("failed to serialize verdict for verification: {e}"),
            }
        })?;

        if !verifying_key.verify(&verdict_json, &signature) {
            return Err(SafetyError::VerificationFailure {
                classifier_id: self.id.clone(),
                reason: "signature verification failed".into(),
            });
        }

        // Step 5: If expected signing address is set, verify it matches
        if let Some(expected_addr) = &self.expected_signing_address {
            let actual_addr = verifying_key.signing_address();
            if &actual_addr != expected_addr {
                return Err(SafetyError::VerificationFailure {
                    classifier_id: self.id.clone(),
                    reason: format!(
                        "signer address mismatch: expected {}, got {}",
                        signing::hex_encode(expected_addr),
                        signing::hex_encode(&actual_addr)
                    ),
                });
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Classifier for VerifiedModelClassifier {
    fn id(&self) -> &str {
        &self.id
    }

    fn supported_categories(&self) -> &[RiskCategory] {
        // Verified model classifiers dynamically report their category via
        // the verdict response, so we cannot enumerate them statically.
        &[]
    }

    async fn classify(
        &self,
        content: &ContentRef<'_>,
    ) -> Result<Vec<ClassifierFinding>, SafetyError> {
        let text = match Self::content_to_string(content) {
            Some(t) => t,
            None => return Ok(Vec::new()),
        };

        let nonce = Self::generate_nonce();
        let request_id = Uuid::now_v7();

        let request = ClassifyRequest {
            content: text,
            nonce: nonce.clone(),
            request_id,
        };

        let url = format!("{}/classify", self.endpoint);

        let http_response = self
            .http_client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    SafetyError::ClassifierTimeout {
                        classifier_id: self.id.clone(),
                        timeout_ms: self.timeout.as_millis() as u64,
                    }
                } else {
                    SafetyError::ClassifierFailure {
                        classifier_id: self.id.clone(),
                        reason: format!("HTTP request failed: {e}"),
                    }
                }
            })?;

        if !http_response.status().is_success() {
            return Err(SafetyError::ClassifierFailure {
                classifier_id: self.id.clone(),
                reason: format!("classifier returned HTTP {}", http_response.status()),
            });
        }

        let response: ClassifyResponse =
            http_response.json().await.map_err(|e| {
                SafetyError::ClassifierFailure {
                    classifier_id: self.id.clone(),
                    reason: format!("failed to parse response: {e}"),
                }
            })?;

        // Verify the cryptographic signature and nonce
        self.verify_response(&response, &nonce)?;

        // Convert to ClassifierFinding
        let verdict = &response.verdict;
        if verdict.category == RiskCategory::None || verdict.confidence <= 0.0 {
            return Ok(Vec::new());
        }

        Ok(vec![ClassifierFinding {
            category: verdict.category,
            confidence: verdict.confidence,
            classifier_id: self.id.clone(),
        }])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Json;
    use axum::routing::post;
    use axum::Router;
    use confidential_safety_tee::signing::SigningKey;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    /// A mock classifier server that generates correctly signed responses.
    struct MockClassifierServer {
        signing_key: SigningKey,
        category: RiskCategory,
        confidence: f64,
    }

    impl MockClassifierServer {
        fn new(category: RiskCategory, confidence: f64) -> Self {
            Self {
                signing_key: SigningKey::generate(),
                category,
                confidence,
            }
        }

        fn signing_address(&self) -> [u8; 20] {
            self.signing_key.signing_address()
        }

        fn verifying_key_hex(&self) -> String {
            let vk = self.signing_key.verifying_key();
            signing::hex_encode(&vk.to_sec1_bytes())
        }

        fn sign_verdict_payload(&self, verdict: &ClassifierVerdictPayload) -> String {
            let verdict_json = serde_json::to_vec(verdict).unwrap();
            let sig: k256::ecdsa::Signature = self.signing_key.sign(&verdict_json);
            signing::hex_encode(sig.to_der().as_bytes())
        }

        fn make_response(&self, request: &ClassifyRequest) -> ClassifyResponse {
            let verdict = ClassifierVerdictPayload {
                request_id: request.request_id,
                nonce: request.nonce.clone(),
                category: self.category,
                confidence: self.confidence,
                classifier_id: "mock_model".into(),
            };
            let signature = self.sign_verdict_payload(&verdict);
            let public_key = self.verifying_key_hex();

            ClassifyResponse {
                verdict,
                signature,
                public_key,
            }
        }
    }

    /// Start a mock classifier HTTP server, returning the bound address.
    async fn start_mock_server(mock: Arc<MockClassifierServer>) -> SocketAddr {
        let app = Router::new().route(
            "/classify",
            post(move |Json(req): Json<ClassifyRequest>| {
                let mock = Arc::clone(&mock);
                async move { Json(mock.make_response(&req)) }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        addr
    }

    /// Start a mock server that returns a response with a tampered nonce.
    async fn start_tampered_nonce_server(mock: Arc<MockClassifierServer>) -> SocketAddr {
        let app = Router::new().route(
            "/classify",
            post(move |Json(req): Json<ClassifyRequest>| {
                let mock = Arc::clone(&mock);
                async move {
                    let mut response = mock.make_response(&req);
                    // Change the nonce in the verdict (re-sign so sig is valid
                    // but nonce won't match what the caller sent)
                    response.verdict.nonce = "tampered_nonce_value".into();
                    response.signature = mock.sign_verdict_payload(&response.verdict);
                    Json(response)
                }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        addr
    }

    /// Start a mock server that signs with a different key than expected.
    async fn start_wrong_signer_server() -> (SocketAddr, [u8; 20]) {
        let legit_key = SigningKey::generate();
        let legit_addr = legit_key.signing_address();

        // The server uses a DIFFERENT key (not the "legitimate" one)
        let wrong_mock = Arc::new(MockClassifierServer::new(
            RiskCategory::Bioterror,
            0.9,
        ));

        let app = Router::new().route(
            "/classify",
            post(move |Json(req): Json<ClassifyRequest>| {
                let mock = Arc::clone(&wrong_mock);
                async move { Json(mock.make_response(&req)) }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (addr, legit_addr)
    }

    /// Start a mock server that returns a corrupted signature.
    async fn start_bad_signature_server(mock: Arc<MockClassifierServer>) -> SocketAddr {
        let app = Router::new().route(
            "/classify",
            post(move |Json(req): Json<ClassifyRequest>| {
                let mock = Arc::clone(&mock);
                async move {
                    let mut response = mock.make_response(&req);
                    // Replace signature with garbage hex
                    response.signature = "deadbeefcafebabe0000111122223333".into();
                    Json(response)
                }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        addr
    }

    // -----------------------------------------------------------------------
    // Successful classification
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn successful_classification() {
        let mock = Arc::new(MockClassifierServer::new(
            RiskCategory::Bioterror,
            0.95,
        ));
        let addr = start_mock_server(Arc::clone(&mock)).await;

        let classifier = VerifiedModelClassifier::new(
            "test_verified".into(),
            format!("http://{addr}"),
            None,
            Duration::from_secs(5),
        );

        let content = ContentRef::Text("some suspicious content");
        let findings = classifier.classify(&content).await.unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, RiskCategory::Bioterror);
        assert!((findings[0].confidence - 0.95).abs() < f64::EPSILON);
        assert_eq!(findings[0].classifier_id, "test_verified");
    }

    // -----------------------------------------------------------------------
    // Address verification
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn successful_classification_with_address_check() {
        let mock = Arc::new(MockClassifierServer::new(
            RiskCategory::CyberAttack,
            0.88,
        ));
        let expected_addr = mock.signing_address();
        let addr = start_mock_server(Arc::clone(&mock)).await;

        let classifier = VerifiedModelClassifier::new(
            "test_addr_check".into(),
            format!("http://{addr}"),
            Some(expected_addr),
            Duration::from_secs(5),
        );

        let content = ContentRef::Text("test content");
        let findings = classifier.classify(&content).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, RiskCategory::CyberAttack);
    }

    // -----------------------------------------------------------------------
    // Nonce mismatch
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn nonce_mismatch_rejected() {
        let mock = Arc::new(MockClassifierServer::new(
            RiskCategory::Bioterror,
            0.9,
        ));
        let addr = start_tampered_nonce_server(Arc::clone(&mock)).await;

        let classifier = VerifiedModelClassifier::new(
            "test_nonce".into(),
            format!("http://{addr}"),
            None,
            Duration::from_secs(5),
        );

        let content = ContentRef::Text("test");
        let result = classifier.classify(&content).await;

        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("nonce mismatch"),
            "expected 'nonce mismatch' in error: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Wrong signer address
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn wrong_signer_address_rejected() {
        let (addr, legit_addr) = start_wrong_signer_server().await;

        let classifier = VerifiedModelClassifier::new(
            "test_wrong_signer".into(),
            format!("http://{addr}"),
            Some(legit_addr),
            Duration::from_secs(5),
        );

        let content = ContentRef::Text("test");
        let result = classifier.classify(&content).await;

        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("address mismatch"),
            "expected 'address mismatch' in error: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Bad signature
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn bad_signature_rejected() {
        let mock = Arc::new(MockClassifierServer::new(
            RiskCategory::Bioterror,
            0.9,
        ));
        let addr = start_bad_signature_server(Arc::clone(&mock)).await;

        let classifier = VerifiedModelClassifier::new(
            "test_bad_sig".into(),
            format!("http://{addr}"),
            None,
            Duration::from_secs(5),
        );

        let content = ContentRef::Text("test");
        let result = classifier.classify(&content).await;

        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("signature") || msg.contains("DER"),
            "expected signature-related error: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Timeout
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn timeout_returns_error() {
        // Use a non-routable address (RFC 5737 TEST-NET) to trigger timeout
        let classifier = VerifiedModelClassifier::new(
            "test_timeout".into(),
            "http://192.0.2.1:1".into(),
            None,
            Duration::from_millis(200),
        );

        let content = ContentRef::Text("test");
        let result = classifier.classify(&content).await;

        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("timeout") || msg.contains("timed out") || msg.contains("failed"),
            "expected timeout-related error: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // None category returns empty
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn none_category_returns_empty() {
        let mock = Arc::new(MockClassifierServer::new(
            RiskCategory::None,
            0.0,
        ));
        let addr = start_mock_server(Arc::clone(&mock)).await;

        let classifier = VerifiedModelClassifier::new(
            "test_none".into(),
            format!("http://{addr}"),
            None,
            Duration::from_secs(5),
        );

        let content = ContentRef::Text("safe content");
        let findings = classifier.classify(&content).await.unwrap();
        assert!(findings.is_empty());
    }

    // -----------------------------------------------------------------------
    // Non-text content
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn bytes_content_returns_empty() {
        // No server needed since bytes are skipped before any HTTP call
        let classifier = VerifiedModelClassifier::new(
            "test_bytes".into(),
            "http://localhost:1".into(),
            None,
            Duration::from_secs(1),
        );

        let content = ContentRef::Bytes(b"binary data");
        let findings = classifier.classify(&content).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn action_sequence_returns_empty() {
        let classifier = VerifiedModelClassifier::new(
            "test_actions".into(),
            "http://localhost:1".into(),
            None,
            Duration::from_secs(1),
        );

        let content = ContentRef::ActionSequence(&[]);
        let findings = classifier.classify(&content).await.unwrap();
        assert!(findings.is_empty());
    }

    // -----------------------------------------------------------------------
    // Tool call content
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn tool_call_sends_combined_text() {
        let mock = Arc::new(MockClassifierServer::new(
            RiskCategory::CyberAttack,
            0.75,
        ));
        let addr = start_mock_server(Arc::clone(&mock)).await;

        let classifier = VerifiedModelClassifier::new(
            "test_tool".into(),
            format!("http://{addr}"),
            None,
            Duration::from_secs(5),
        );

        let params = serde_json::json!({"cmd": "exploit"});
        let content = ContentRef::ToolCall {
            tool_name: "shell_exec",
            parameters: &params,
        };
        let findings = classifier.classify(&content).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, RiskCategory::CyberAttack);
    }

    // -----------------------------------------------------------------------
    // Metadata
    // -----------------------------------------------------------------------

    #[test]
    fn classifier_id_and_metadata() {
        let classifier = VerifiedModelClassifier::new(
            "my_model".into(),
            "http://localhost:8080".into(),
            None,
            Duration::from_secs(5),
        );
        assert_eq!(classifier.id(), "my_model");
        assert!(classifier.supported_categories().is_empty());
    }
}
