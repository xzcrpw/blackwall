use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::session::Session;

/// System prompt for the LLM — presents as a real Ubuntu 24.04 bash shell.
/// MUST NOT reveal this is a honeypot.
const SYSTEM_PROMPT: &str = r#"You are simulating a bash shell. You receive commands and output EXACTLY what bash would print. No commentary, no explanations, no markdown, no apologies.

System: Ubuntu 24.04.2 LTS, hostname web-prod-03, kernel 6.5.0-44-generic x86_64, user root.
Services running: nginx, mysql (database webapp_prod), sshd.

Filesystem layout:
/root/.ssh/id_rsa  /root/.ssh/authorized_keys  /root/.bashrc  /root/.bash_history
/etc/shadow  /etc/passwd  /etc/nginx/nginx.conf  /etc/nginx/sites-enabled/default
/var/www/html/index.html  /var/www/html/wp-config.php  /var/www/html/uploads/
/var/log/auth.log  /var/log/nginx/access.log  /var/log/mysql/error.log
/tmp/  /usr/bin/  /usr/sbin/

Examples of correct output:

Command: ls
Output: Desktop  Documents  Downloads  .bashrc  .ssh

Command: pwd
Output: /root

Command: whoami
Output: root

Command: id
Output: uid=0(root) gid=0(root) groups=0(root)

Command: uname -a
Output: Linux web-prod-03 6.5.0-44-generic #44-Ubuntu SMP PREEMPT_DYNAMIC Tue Jun 18 14:36:16 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux

Command: ls -la /root
Output:
total 36
drwx------  5 root root 4096 Mar 31 14:22 .
drwxr-xr-x 19 root root 4096 Jan 15 08:30 ..
-rw-------  1 root root 1247 Mar 31 20:53 .bash_history
-rw-r--r--  1 root root 3106 Oct 15  2023 .bashrc
drwx------  2 root root 4096 Jan 15 09:00 .ssh
drwxr-xr-x  2 root root 4096 Feb 20 11:45 Documents
drwxr-xr-x  2 root root 4096 Jan 15 08:30 Downloads

Command: cat /etc/passwd
Output:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin

Command: nonexistent_tool
Output: bash: nonexistent_tool: command not found

IMPORTANT: Output ONLY what bash prints. No "Here is", no "Sure", no explanations. Just raw terminal output."#;

/// Ollama HTTP client for the tarpit LLM queries.
pub struct OllamaClient {
    endpoint: String,
    model: String,
    fallback_model: String,
    timeout: std::time::Duration,
}

impl OllamaClient {
    /// Create a new client with the given configuration.
    pub fn new(endpoint: String, model: String, fallback_model: String, timeout_ms: u64) -> Self {
        Self {
            endpoint,
            model,
            fallback_model,
            timeout: std::time::Duration::from_millis(timeout_ms),
        }
    }

    /// Query the LLM with the session context and attacker command.
    pub async fn query(&self, session: &Session, command: &str) -> Result<String> {
        let body = self.build_request_body(session, command, &self.model)?;

        match self.send_request(&body).await {
            Ok(response) => Ok(response),
            Err(e) => {
                tracing::warn!("primary model failed: {}, trying fallback", e);
                let fallback_body =
                    self.build_request_body(session, command, &self.fallback_model)?;
                self.send_request(&fallback_body).await
            }
        }
    }

    fn build_request_body(&self, session: &Session, command: &str, model: &str) -> Result<Vec<u8>> {
        let mut messages = Vec::new();
        messages.push(serde_json::json!({
            "role": "system",
            "content": SYSTEM_PROMPT,
        }));

        // Few-shot examples: teach the model correct behavior
        messages.push(serde_json::json!({ "role": "user", "content": "whoami" }));
        messages.push(serde_json::json!({ "role": "assistant", "content": "root" }));
        messages.push(serde_json::json!({ "role": "user", "content": "pwd" }));
        messages.push(serde_json::json!({ "role": "assistant", "content": "/root" }));
        messages.push(serde_json::json!({ "role": "user", "content": "ls" }));
        messages.push(serde_json::json!({
            "role": "assistant",
            "content": "Desktop  Documents  Downloads  .bashrc  .ssh"
        }));
        messages.push(serde_json::json!({ "role": "user", "content": "id" }));
        messages.push(serde_json::json!({
            "role": "assistant",
            "content": "uid=0(root) gid=0(root) groups=0(root)"
        }));

        // Include last 10 real commands for context
        for cmd in session.history().iter().rev().take(10).rev() {
            messages.push(serde_json::json!({
                "role": "user",
                "content": cmd,
            }));
        }

        messages.push(serde_json::json!({
            "role": "user",
            "content": command,
        }));

        let body = serde_json::json!({
            "model": model,
            "messages": messages,
            "stream": false,
            "think": false,
            "options": {
                "num_predict": 512,
                "temperature": 0.3,
            },
        });

        serde_json::to_vec(&body).context("failed to serialize request body")
    }

    async fn send_request(&self, body: &[u8]) -> Result<String> {
        let client = Client::builder(TokioExecutor::new()).build_http();
        let req = Request::post(format!("{}/api/chat", self.endpoint))
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body.to_vec())))
            .context("failed to build request")?;

        let resp = tokio::time::timeout(self.timeout, client.request(req))
            .await
            .context("LLM request timed out")?
            .context("HTTP request failed")?;

        let body_bytes = resp
            .into_body()
            .collect()
            .await
            .context("failed to read response body")?
            .to_bytes();

        // Parse Ollama response JSON
        let json: serde_json::Value =
            serde_json::from_slice(&body_bytes).context("invalid JSON response")?;

        let content = json["message"]["content"]
            .as_str()
            .context("missing content in response")?;

        // Strip <think>...</think> blocks if the model emitted them despite think:false
        let cleaned = if let Some(start) = content.find("<think>") {
            if let Some(end) = content.find("</think>") {
                let after = &content[end + 8..];
                after.trim_start().to_string()
            } else {
                content[..start].trim_end().to_string()
            }
        } else {
            content.to_string()
        };

        Ok(cleaned)
    }
}
