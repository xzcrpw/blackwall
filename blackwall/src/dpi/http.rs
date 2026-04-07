//! HTTP request/response dissector.
//!
//! Parses HTTP/1.x request lines and headers from raw bytes.
//! Extracts method, path, Host header, User-Agent, and Content-Type.

/// Extracted HTTP request metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpInfo {
    /// HTTP method (GET, POST, PUT, etc.)
    pub method: String,
    /// Request path
    pub path: String,
    /// HTTP version (e.g., "1.1", "1.0")
    pub version: String,
    /// Host header value
    pub host: Option<String>,
    /// User-Agent header value
    pub user_agent: Option<String>,
    /// Content-Type header value
    pub content_type: Option<String>,
}

/// Known suspicious paths that scanners frequently probe.
const SUSPICIOUS_PATHS: &[&str] = &[
    "/wp-login.php",
    "/wp-admin",
    "/xmlrpc.php",
    "/phpmyadmin",
    "/admin",
    "/administrator",
    "/.env",
    "/.git/config",
    "/config.php",
    "/shell",
    "/cmd",
    "/eval",
    "/actuator",
    "/solr",
    "/console",
    "/manager/html",
    "/cgi-bin/",
    "/../",
];

/// Known malicious User-Agent patterns.
const SUSPICIOUS_USER_AGENTS: &[&str] = &[
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "zgrab",
    "gobuster",
    "dirbuster",
    "wpscan",
    "nuclei",
    "httpx",
    "curl/",
    "python-requests",
    "go-http-client",
];

/// Parse an HTTP request from raw bytes.
pub fn parse_request(data: &[u8]) -> Option<HttpInfo> {
    // HTTP requests start with a method followed by space
    let text = std::str::from_utf8(data).ok()?;

    // Find the request line (first line)
    let request_line = text.lines().next()?;
    let mut parts = request_line.splitn(3, ' ');

    let method = parts.next()?;
    // Validate method
    if !matches!(
        method,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "CONNECT" | "TRACE"
    ) {
        return None;
    }

    let path = parts.next().unwrap_or("/");
    let version_str = parts.next().unwrap_or("HTTP/1.1");
    let version = version_str.strip_prefix("HTTP/").unwrap_or("1.1");

    // Parse headers
    let mut host = None;
    let mut user_agent = None;
    let mut content_type = None;

    for line in text.lines().skip(1) {
        if line.is_empty() {
            break; // End of headers
        }
        if let Some((name, value)) = line.split_once(':') {
            let name_lower = name.trim().to_lowercase();
            let value = value.trim();
            match name_lower.as_str() {
                "host" => host = Some(value.to_string()),
                "user-agent" => user_agent = Some(value.to_string()),
                "content-type" => content_type = Some(value.to_string()),
                _ => {}
            }
        }
    }

    Some(HttpInfo {
        method: method.to_string(),
        path: path.to_string(),
        version: version.to_string(),
        host,
        user_agent,
        content_type,
    })
}

/// Check if the request path is suspicious (known scanner targets).
pub fn is_suspicious_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    SUSPICIOUS_PATHS.iter().any(|p| lower.contains(p))
}

/// Check if the User-Agent matches known scanning tools.
pub fn is_suspicious_user_agent(ua: &str) -> bool {
    let lower = ua.to_lowercase();
    SUSPICIOUS_USER_AGENTS.iter().any(|p| lower.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_get() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let info = parse_request(data).unwrap();
        assert_eq!(info.method, "GET");
        assert_eq!(info.path, "/");
        assert_eq!(info.version, "1.1");
        assert_eq!(info.host, Some("example.com".into()));
    }

    #[test]
    fn parse_post_with_headers() {
        let data = b"POST /api/login HTTP/1.1\r\nHost: app.local\r\n\
                     User-Agent: Mozilla/5.0\r\nContent-Type: application/json\r\n\r\n";
        let info = parse_request(data).unwrap();
        assert_eq!(info.method, "POST");
        assert_eq!(info.path, "/api/login");
        assert_eq!(info.user_agent, Some("Mozilla/5.0".into()));
        assert_eq!(info.content_type, Some("application/json".into()));
    }

    #[test]
    fn reject_non_http() {
        assert!(parse_request(b"SSH-2.0-OpenSSH\r\n").is_none());
        assert!(parse_request(b"\x00\x01\x02").is_none());
    }

    #[test]
    fn suspicious_path_detection() {
        assert!(is_suspicious_path("/wp-login.php"));
        assert!(is_suspicious_path("/foo/../etc/passwd"));
        assert!(is_suspicious_path("/.env"));
        assert!(!is_suspicious_path("/index.html"));
        assert!(!is_suspicious_path("/api/v1/users"));
    }

    #[test]
    fn suspicious_user_agent_detection() {
        assert!(is_suspicious_user_agent("sqlmap/1.7.2"));
        assert!(is_suspicious_user_agent("Nikto/2.1.6"));
        assert!(is_suspicious_user_agent("python-requests/2.28.0"));
        assert!(!is_suspicious_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"));
    }
}
