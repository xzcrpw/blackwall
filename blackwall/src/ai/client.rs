use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

/// Max concurrent LLM requests. Prevents queue buildup under DDoS when many
/// unique IPs generate batches faster than Ollama can classify them.
/// Excess requests are shed (return Unknown verdict) rather than queued.
const MAX_CONCURRENT_LLM_REQUESTS: u32 = 2;

/// HTTP client for the Ollama REST API with backpressure.
pub struct OllamaClient {
    base_url: String,
    model: String,
    fallback_model: String,
    timeout: Duration,
    available: AtomicBool,
    /// Tracks in-flight LLM requests for backpressure.
    in_flight: AtomicU32,
    /// Counter of requests shed due to backpressure.
    shed_count: AtomicU32,
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
            in_flight: AtomicU32::new(0),
            shed_count: AtomicU32::new(0),
        }
    }

    /// Number of requests shed due to backpressure since start.
    #[allow(dead_code)]
    pub fn shed_count(&self) -> u32 {
        self.shed_count.load(Ordering::Relaxed)
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
    ///
    /// Applies backpressure: if `MAX_CONCURRENT_LLM_REQUESTS` are already
    /// in-flight, returns an error immediately (load shedding).
    pub async fn classify_threat(&self, prompt: &str) -> Result<String> {
        // Backpressure: reject if too many in-flight requests
        let current = self.in_flight.fetch_add(1, Ordering::Relaxed);
        if current >= MAX_CONCURRENT_LLM_REQUESTS {
            self.in_flight.fetch_sub(1, Ordering::Relaxed);
            let shed = self.shed_count.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::debug!(in_flight = current, total_shed = shed,
                "LLM backpressure — request shed");
            anyhow::bail!("LLM backpressure: {} in-flight, request shed", current);
        }

        let result = self.classify_inner(prompt).await;
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
        result
    }

    /// Inner classification logic (primary + fallback).
    async fn classify_inner(&self, prompt: &str) -> Result<String> {
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

        // Wrap BOTH the request send AND body read in a single timeout.
        // Without this, a slowloris-style response from Ollama (infinitely
        // slow body) hangs forever, in_flight never decrements, and after
        // MAX_CONCURRENT_LLM_REQUESTS such requests the AI pipeline is dead.
        let bytes = tokio::time::timeout(self.timeout, async {
            let resp = client
                .request(req)
                .await
                .context("HTTP request failed")?;
            let collected = resp
                .into_body()
                .collect()
                .await
                .context("read response body")?
                .to_bytes();
            Ok::<_, anyhow::Error>(collected)
        })
        .await
        .context("LLM request+response timed out")??;

        let json: serde_json::Value = serde_json::from_slice(&bytes).context("invalid JSON")?;

        json["message"]["content"]
            .as_str()
            .map(|s| s.to_string())
            .context("missing content in response")
    }
}
