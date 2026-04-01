use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// HTTP client for the Ollama REST API.
pub struct OllamaClient {
    base_url: String,
    model: String,
    fallback_model: String,
    timeout: Duration,
    available: AtomicBool,
}

impl OllamaClient {
    /// Create a new client from AI config values.
    pub fn new(base_url: String, model: String, fallback_model: String, timeout_ms: u64) -> Self {
        Self {
            base_url,
            model,
            fallback_model,
            timeout: Duration::from_millis(timeout_ms),
            available: AtomicBool::new(false),
        }
    }

    /// Check if Ollama is reachable (GET /api/tags).
    pub async fn health_check(&self) -> bool {
        let client = Client::builder(TokioExecutor::new()).build_http();
        let url = format!("{}/api/tags", self.base_url);
        let req = match Request::get(&url).body(http_body_util::Empty::<Bytes>::new()) {
            Ok(r) => r,
            Err(_) => return false,
        };

        let result = tokio::time::timeout(Duration::from_secs(3), client.request(req)).await;
        let ok = matches!(result, Ok(Ok(resp)) if resp.status().is_success());
        self.available.store(ok, Ordering::Relaxed);
        ok
    }

    /// Whether the last health check succeeded.
    pub fn is_available(&self) -> bool {
        self.available.load(Ordering::Relaxed)
    }

    /// Send a classification prompt to the LLM. Tries primary, then fallback.
    pub async fn classify_threat(&self, prompt: &str) -> Result<String> {
        let body = self.build_body(prompt, &self.model)?;
        match self.send(&body).await {
            Ok(r) => Ok(r),
            Err(e) => {
                tracing::warn!("primary model failed: {}, trying fallback", e);
                let fallback_body = self.build_body(prompt, &self.fallback_model)?;
                self.send(&fallback_body).await
            }
        }
    }

    fn build_body(&self, prompt: &str, model: &str) -> Result<Vec<u8>> {
        let body = serde_json::json!({
            "model": model,
            "messages": [
                {"role": "system", "content": super::classifier::CLASSIFICATION_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "stream": false,
            "options": {
                "num_predict": 256,
                "temperature": 0.1,
            },
        });
        serde_json::to_vec(&body).context("serialize request")
    }

    async fn send(&self, body: &[u8]) -> Result<String> {
        let client = Client::builder(TokioExecutor::new()).build_http();
        let req = Request::post(format!("{}/api/chat", self.base_url))
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body.to_vec())))
            .context("build request")?;

        let resp = tokio::time::timeout(self.timeout, client.request(req))
            .await
            .context("LLM request timed out")?
            .context("HTTP request failed")?;

        let bytes = resp
            .into_body()
            .collect()
            .await
            .context("read response body")?
            .to_bytes();

        let json: serde_json::Value = serde_json::from_slice(&bytes).context("invalid JSON")?;

        json["message"]["content"]
            .as_str()
            .map(|s| s.to_string())
            .context("missing content in response")
    }
}
