//! HTTP honeypot: fake web server responses.
//!
//! Serves realistic-looking error pages, fake WordPress admin panels,
//! and phpMyAdmin pages to attract and analyze web scanner behavior.

use tokio::net::TcpStream;

use crate::jitter;

/// Fake WordPress login page HTML.
const FAKE_WP_LOGIN: &str = r#"<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8">
<title>Log In &lsaquo; Web Production &#8212; WordPress</title>
<style>body{background:#f1f1f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,sans-serif}
.login{width:320px;margin:100px auto;padding:26px 24px;background:#fff;border:1px solid #c3c4c7;border-radius:4px}
.login h1{text-align:center;margin-bottom:24px}
.login input[type=text],.login input[type=password]{width:100%;padding:8px;margin:6px 0;box-sizing:border-box;border:1px solid #8c8f94;border-radius:4px}
.login input[type=submit]{width:100%;padding:8px;background:#2271b1;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:14px}
</style>
</head>
<body>
<div class="login">
<h1>WordPress</h1>
<form method="post" action="/wp-login.php">
<p><label>Username or Email Address<br><input type="text" name="log" size="20"></label></p>
<p><label>Password<br><input type="password" name="pwd" size="20"></label></p>
<p><input type="submit" name="wp-submit" value="Log In"></p>
</form>
</div>
</body>
</html>"#;

/// Fake server error page.
#[allow(dead_code)]
const FAKE_500: &str = r#"<!DOCTYPE html>
<html>
<head><title>500 Internal Server Error</title></head>
<body>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request.</p>
<hr>
<address>Apache/2.4.58 (Ubuntu) Server at web-prod-03 Port 80</address>
</body>
</html>"#;

/// Fake 404 page.
const FAKE_404: &str = r#"<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.58 (Ubuntu) Server at web-prod-03 Port 80</address>
</body>
</html>"#;

/// Fake Apache default page.
const FAKE_INDEX: &str = r#"<!DOCTYPE html>
<html>
<head><title>Apache2 Ubuntu Default Page</title></head>
<body>
<h1>It works!</h1>
<p>This is the default welcome page used to test the correct operation
of the Apache2 server after installation on Ubuntu systems.</p>
</body>
</html>"#;

/// Handle an HTTP request and send a deceptive response.
pub async fn handle_request(stream: &mut TcpStream, request: &str) -> anyhow::Result<()> {
    let first_line = request.lines().next().unwrap_or("");
    let path = first_line.split_whitespace().nth(1).unwrap_or("/");

    let (status, body) = match path {
        "/" | "/index.html" => ("200 OK", FAKE_INDEX),
        "/wp-login.php" | "/wp-admin" | "/wp-admin/" => ("200 OK", FAKE_WP_LOGIN),
        "/phpmyadmin" | "/phpmyadmin/" | "/pma" => ("403 Forbidden", FAKE_404),
        "/.env" | "/.git/config" | "/config.php" => ("403 Forbidden", FAKE_404),
        "/robots.txt" => {
            let robots = "User-agent: *\nDisallow: /wp-admin/\nDisallow: /wp-includes/\n\
                          Allow: /wp-admin/admin-ajax.php\nSitemap: http://web-prod-03/sitemap.xml";
            send_response(stream, "200 OK", "text/plain", robots).await?;
            return Ok(());
        }
        _ => ("404 Not Found", FAKE_404),
    };

    send_response(stream, status, "text/html", body).await
}

/// Send an HTTP response with tarpit delay.
async fn send_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> anyhow::Result<()> {
    let response = format!(
        "HTTP/1.1 {}\r\n\
         Server: Apache/2.4.58 (Ubuntu)\r\n\
         Content-Type: {}; charset=UTF-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         X-Powered-By: PHP/8.3.6\r\n\
         \r\n\
         {}",
        status,
        content_type,
        body.len(),
        body,
    );

    // Stream response slowly to waste attacker time
    jitter::stream_with_tarpit(stream, &response).await
}
