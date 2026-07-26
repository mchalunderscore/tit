use crate::http;

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use http::RunningWebServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_the_semantic_shell_without_javascript() {
    let server = start().await;

    let home = request(server.address(), "GET", "/", &[]).await;
    assert_eq!(home.status, 200);
    assert_eq!(home.header("content-type"), "text/html; charset=utf-8");
    assert_eq!(home.header("cache-control"), "no-store");
    assert!(home.body.contains("<header class=\"site-header\">"));
    assert!(home.body.contains("<hr class=\"site-header-rule\">"));
    assert!(home.body.contains("<nav aria-label=\"Primary\">"));
    assert!(home.body.contains("<main id=\"main\">"));
    assert!(home.body.contains("<footer>"));
    assert!(!home.body.contains("Open a repository"));
    assert!(!home.body.contains("<form action=\"/go\""));
    assert!(!home.body.to_ascii_lowercase().contains("<script"));
    assert_security_policy(&home);
    assert_snapshot(&home, include_str!("snapshots/web/home.html"));

    let account = request(server.address(), "GET", "/account", &[]).await;
    assert_eq!(account.status, 200);
    assert!(
        account
            .body
            .contains("<h1 id=\"account-heading\">Account</h1>")
    );
    assert!(account.body.contains("href=\"/login\""));
    assert!(account.body.contains("href=\"/signup\""));
    assert!(account.body.contains("href=\"/recover\""));
    assert_security_policy(&account);

    let request_id = home.header("x-request-id");
    assert_request_id(request_id);
    assert!(home.body.contains(&format!("<code>{request_id}</code>")));

    let removed_repository_form = request(
        server.address(),
        "GET",
        "/go?owner=alice&repository=example",
        &[],
    )
    .await;
    assert_eq!(removed_repository_form.status, 404);
    assert_security_policy(&removed_repository_form);

    let head = request(server.address(), "HEAD", "/", &[]).await;
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());
    assert_eq!(head.header("content-length"), home.body.len().to_string());
    assert_security_policy(&head);

    let css = request(server.address(), "GET", "/assets/style.css", &[]).await;
    assert_eq!(css.status, 200);
    assert_eq!(css.header("content-type"), "text/css; charset=utf-8");
    assert_eq!(css.header("cache-control"), "no-cache");
    assert_eq!(css.body, include_str!("../assets/style.css"));
    assert!(css.body.contains("font-family: \"Space Mono\""));
    assert!(css.body.contains(".background-icon"));
    assert!(css.body.contains("@media (max-width: 44rem)"));
    assert!(css.body.contains(".two-column"));
    assert!(css.body.contains(".home-grid > section"));
    assert!(css.body.contains(".repository-navigation"));
    assert_security_policy(&css);

    let css_head = request(server.address(), "HEAD", "/assets/style.css", &[]).await;
    assert_eq!(css_head.status, 200);
    assert!(css_head.body.is_empty());
    assert_eq!(
        css_head.header("content-length"),
        css.body.len().to_string()
    );

    let regular_font = request(
        server.address(),
        "HEAD",
        "/assets/SpaceMono-Regular.ttf",
        &[],
    )
    .await;
    assert_eq!(regular_font.status, 200);
    assert_eq!(regular_font.header("content-type"), "font/ttf");
    assert_eq!(
        regular_font.header("content-length"),
        include_bytes!("../assets/SpaceMono-Regular.ttf")
            .len()
            .to_string()
    );
    assert_security_policy(&regular_font);

    let bold_font = request(server.address(), "HEAD", "/assets/SpaceMono-Bold.ttf", &[]).await;
    assert_eq!(bold_font.status, 200);
    assert_eq!(bold_font.header("content-type"), "font/ttf");
    assert_eq!(
        bold_font.header("content-length"),
        include_bytes!("../assets/SpaceMono-Bold.ttf")
            .len()
            .to_string()
    );
    assert_security_policy(&bold_font);

    let signup = request(server.address(), "GET", "/signup", &[]).await;
    assert_eq!(signup.status, 200);
    assert!(
        signup
            .body
            .contains("<form action=\"/signup\" method=\"post\">")
    );
    assert!(signup.body.contains("name=\"invitation\""));
    let recovery = request(server.address(), "GET", "/recover", &[]).await;
    assert_eq!(recovery.status, 200);
    assert!(
        recovery
            .body
            .contains("<form action=\"/recover\" method=\"post\">")
    );
    assert!(recovery.body.contains("name=\"recovery\""));

    let wrong_signup_method = request(server.address(), "PUT", "/signup", &[]).await;
    assert_eq!(wrong_signup_method.status, 405);
    assert_eq!(wrong_signup_method.header("allow"), "GET, HEAD, POST");

    server.shutdown().await.expect("stop the Web server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_useful_errors_and_owns_request_ids() {
    let server = start().await;

    let missing = request(server.address(), "GET", "/missing", &[]).await;
    assert_eq!(missing.status, 404);
    assert!(missing.body.contains("<h1>Page not found</h1>"));
    assert!(missing.body.contains("The requested page does not exist."));
    assert_security_policy(&missing);
    assert_snapshot(&missing, include_str!("snapshots/web/not-found.html"));

    let missing_head = request(server.address(), "HEAD", "/missing", &[]).await;
    assert_eq!(missing_head.status, 404);
    assert!(missing_head.body.is_empty());
    assert_eq!(
        missing_head.header("content-length"),
        missing.body.len().to_string()
    );

    let method = request(server.address(), "POST", "/", &[]).await;
    assert_eq!(method.status, 405);
    assert_eq!(method.header("allow"), "GET, HEAD");
    assert!(method.body.contains("<h1>Method not allowed</h1>"));
    assert!(
        method
            .body
            .contains("This page does not accept the request method.")
    );
    assert_security_policy(&method);
    assert_snapshot(
        &method,
        include_str!("snapshots/web/method-not-allowed.html"),
    );

    let first = request(
        server.address(),
        "GET",
        "/",
        &[("X-Request-ID", "attacker-controlled")],
    )
    .await;
    let second = request(server.address(), "GET", "/", &[]).await;
    assert_request_id(first.header("x-request-id"));
    assert_request_id(second.header("x-request-id"));
    assert_ne!(first.header("x-request-id"), "attacker-controlled");
    assert_ne!(first.header("x-request-id"), second.header("x-request-id"));

    server.shutdown().await.expect("stop the Web server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enforces_request_and_login_attempt_limits() {
    let server = start().await;

    for attempt in 0..10 {
        let forwarded = format!("for=192.0.2.{attempt}");
        assert_eq!(
            request(
                server.address(),
                "POST",
                "/login",
                &[
                    ("Forwarded", &forwarded),
                    ("X-Forwarded-For", "198.51.100.1")
                ]
            )
            .await
            .status,
            400
        );
    }
    let limited = request(server.address(), "POST", "/login", &[]).await;
    assert_eq!(limited.status, 429);
    assert_eq!(limited.body, "Login attempt limit exceeded.\n");

    let oversized = request_with_declared_length(server.address(), "/", 1024 * 1024 + 1).await;
    assert_eq!(oversized.status, 413);

    server.shutdown().await.expect("stop the Web server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limits_signup_and_recovery() {
    for path in ["/signup", "/recover"] {
        let server = start().await;
        for _ in 0..10 {
            assert_eq!(
                request(server.address(), "POST", path, &[]).await.status,
                400
            );
        }
        let limited = request(server.address(), "POST", path, &[]).await;
        assert_eq!(limited.status, 429);
        assert_eq!(limited.body, "Account attempt limit exceeded.\n");
        server.shutdown().await.expect("stop the Web server");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancels_a_connection_after_the_shutdown_drain_limit() {
    let server = start().await;
    let mut stalled = tokio::net::TcpStream::connect(server.address())
        .await
        .expect("connect a stalled client");
    stalled
        .write_all(
            b"POST /login HTTP/1.1\r\n\
              Host: localhost\r\n\
              Content-Type: application/x-www-form-urlencoded\r\n\
              Content-Length: 10\r\n\
              Expect: 100-continue\r\n\r\n",
        )
        .await
        .expect("write an incomplete request");
    let mut response = [0_u8; 25];
    stalled
        .read_exact(&mut response)
        .await
        .expect("read the continue response");
    assert_eq!(&response, b"HTTP/1.1 100 Continue\r\n\r\n");

    assert!(
        !server
            .shutdown_bounded(Duration::from_millis(20))
            .await
            .expect("stop the Web server")
    );
}

async fn start() -> RunningWebServer {
    RunningWebServer::start(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("start the Web server")
}

async fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> HttpResponse {
    let bytes = tokio::time::timeout(RESPONSE_TIMEOUT, async {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("connect to the Web server");
        let mut request =
            format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("Content-Length: 0\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write an HTTP request");
        let mut bytes = Vec::new();
        stream
            .read_to_end(&mut bytes)
            .await
            .expect("read an HTTP response");
        bytes
    })
    .await
    .expect("receive an HTTP response before the deadline");
    HttpResponse::parse(&bytes)
}

async fn request_with_declared_length(
    address: SocketAddr,
    path: &str,
    content_length: usize,
) -> HttpResponse {
    let bytes = tokio::time::timeout(RESPONSE_TIMEOUT, async {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("connect to the Web server");
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Length: {content_length}\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write an HTTP request");
        let mut bytes = Vec::new();
        stream
            .read_to_end(&mut bytes)
            .await
            .expect("read an HTTP response");
        bytes
    })
    .await
    .expect("receive an HTTP response before the deadline");
    HttpResponse::parse(&bytes)
}

fn assert_security_policy(response: &HttpResponse) {
    assert_eq!(
        response.header("content-security-policy"),
        "default-src 'none'; style-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    );
    assert_eq!(response.header("x-content-type-options"), "nosniff");
    assert_eq!(response.header("x-frame-options"), "DENY");
    assert_eq!(response.header("referrer-policy"), "no-referrer");
    assert_eq!(
        response.header("permissions-policy"),
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    );
    assert_eq!(response.header("cross-origin-opener-policy"), "same-origin");
    assert_request_id(response.header("x-request-id"));
}

fn assert_request_id(value: &str) {
    assert_eq!(value.len(), 32);
    assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(value, value.to_ascii_lowercase());
}

fn assert_snapshot(response: &HttpResponse, expected: &str) {
    let normalized = response
        .body
        .replace(response.header("x-request-id"), "<request-id>");
    assert_eq!(normalized, expected.strip_suffix('\n').unwrap_or(expected));
}

struct HttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: String,
}

impl HttpResponse {
    fn parse(bytes: &[u8]) -> Self {
        let split = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("an HTTP response header terminator");
        let head = std::str::from_utf8(&bytes[..split]).expect("UTF-8 HTTP response headers");
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .expect("an HTTP status line")
            .split_whitespace()
            .nth(1)
            .expect("an HTTP status code")
            .parse()
            .expect("a numeric HTTP status code");
        let headers = lines
            .map(|line| {
                let (name, value) = line.split_once(':').expect("a valid HTTP response header");
                (name.to_ascii_lowercase(), value.trim().to_owned())
            })
            .collect();
        let body = String::from_utf8(bytes[split + 4..].to_vec()).expect("a UTF-8 response body");
        Self {
            status,
            headers,
            body,
        }
    }

    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .unwrap_or_else(|| panic!("missing {name} response header"))
    }
}
