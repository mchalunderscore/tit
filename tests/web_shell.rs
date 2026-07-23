#[allow(dead_code, reason = "the Web shell test uses only username validation")]
#[path = "../src/auth.rs"]
mod auth;
#[allow(
    dead_code,
    reason = "the Web shell test uses only repository slug validation"
)]
#[path = "../src/domain/mod.rs"]
mod domain;
#[path = "../src/http/mod.rs"]
mod http;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};

use http::RunningWebServer;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_the_semantic_shell_without_javascript() {
    let server = start().await;

    let home = request(server.address(), "GET", "/", &[]);
    assert_eq!(home.status, 200);
    assert_eq!(home.header("content-type"), "text/html; charset=utf-8");
    assert_eq!(home.header("cache-control"), "no-store");
    assert!(home.body.contains("<header class=\"site-header\">"));
    assert!(home.body.contains("<nav aria-label=\"Primary\">"));
    assert!(home.body.contains("<main id=\"main\">"));
    assert!(home.body.contains("<footer>"));
    assert!(home.body.contains("<form action=\"/go\" method=\"get\">"));
    assert!(home.body.contains("name=\"owner\""));
    assert!(home.body.contains("name=\"repository\""));
    assert!(!home.body.to_ascii_lowercase().contains("<script"));
    assert_security_policy(&home);
    assert_snapshot(&home, include_str!("snapshots/web/home.html"));

    let request_id = home.header("x-request-id");
    assert_request_id(request_id);
    assert!(home.body.contains(&format!("<code>{request_id}</code>")));

    let head = request(server.address(), "HEAD", "/", &[]);
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());
    assert_eq!(head.header("content-length"), home.body.len().to_string());
    assert_security_policy(&head);

    let css = request(server.address(), "GET", "/assets/style.css", &[]);
    assert_eq!(css.status, 200);
    assert_eq!(css.header("content-type"), "text/css; charset=utf-8");
    assert_eq!(css.header("cache-control"), "public, max-age=3600");
    assert_eq!(css.body, include_str!("../assets/style.css"));
    assert_security_policy(&css);

    let css_head = request(server.address(), "HEAD", "/assets/style.css", &[]);
    assert_eq!(css_head.status, 200);
    assert!(css_head.body.is_empty());
    assert_eq!(
        css_head.header("content-length"),
        css.body.len().to_string()
    );

    server.shutdown().await.expect("stop the Web server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submits_the_repository_form_with_plain_http() {
    let server = start().await;

    let redirect = request(
        server.address(),
        "GET",
        "/go?owner=alice&repository=example",
        &[],
    );
    assert_eq!(redirect.status, 302);
    assert_eq!(redirect.header("location"), "/alice/example");
    assert_eq!(redirect.header("cache-control"), "no-store");
    assert!(redirect.body.is_empty());
    assert_security_policy(&redirect);

    for path in [
        "/go",
        "/go?owner=Alice&repository=example",
        "/go?owner=alice&repository=../example",
        "/go?owner=alice&owner=bob&repository=example",
        "/go?owner=alice&repository=example&extra=value",
        "/go?owner=alice&repository=%",
    ] {
        let response = request(server.address(), "GET", path, &[]);
        assert_eq!(response.status, 400, "unexpected status for {path}");
        assert!(response.body.contains("role=\"alert\""));
        assert!(
            response
                .body
                .contains("Enter a valid lowercase owner and repository.")
        );
        assert_security_policy(&response);
    }

    let injection = request(
        server.address(),
        "GET",
        "/go?owner=%3Cscript%3E&repository=example",
        &[],
    );
    assert_eq!(injection.status, 400);
    assert!(injection.body.contains("value=\"&#60;script&#62;\""));
    assert!(!injection.body.contains("value=\"<script>\""));
    assert!(!injection.body.to_ascii_lowercase().contains("<script"));
    assert_snapshot(&injection, include_str!("snapshots/web/bad-request.html"));

    let oversized = format!("/go?owner={}&repository=example", "a".repeat(512));
    assert_eq!(
        request(server.address(), "GET", &oversized, &[]).status,
        400
    );

    server.shutdown().await.expect("stop the Web server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_useful_errors_and_owns_request_ids() {
    let server = start().await;

    let missing = request(server.address(), "GET", "/missing", &[]);
    assert_eq!(missing.status, 404);
    assert!(missing.body.contains("<h1>Page not found</h1>"));
    assert!(missing.body.contains("The requested page does not exist."));
    assert_security_policy(&missing);
    assert_snapshot(&missing, include_str!("snapshots/web/not-found.html"));

    let missing_head = request(server.address(), "HEAD", "/missing", &[]);
    assert_eq!(missing_head.status, 404);
    assert!(missing_head.body.is_empty());
    assert_eq!(
        missing_head.header("content-length"),
        missing.body.len().to_string()
    );

    let method = request(server.address(), "POST", "/", &[]);
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
    );
    let second = request(server.address(), "GET", "/", &[]);
    assert_request_id(first.header("x-request-id"));
    assert_request_id(second.header("x-request-id"));
    assert_ne!(first.header("x-request-id"), "attacker-controlled");
    assert_ne!(first.header("x-request-id"), second.header("x-request-id"));

    server.shutdown().await.expect("stop the Web server");
}

async fn start() -> RunningWebServer {
    RunningWebServer::start(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("start the Web server")
}

fn request(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> HttpResponse {
    let mut stream = TcpStream::connect(address).expect("connect to the Web server");
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("Content-Length: 0\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .expect("write an HTTP request");
    let mut bytes = Vec::new();
    stream
        .read_to_end(&mut bytes)
        .expect("read an HTTP response");
    HttpResponse::parse(&bytes)
}

fn assert_security_policy(response: &HttpResponse) {
    assert_eq!(
        response.header("content-security-policy"),
        "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
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
