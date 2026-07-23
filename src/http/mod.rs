mod public;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::body::{Body, HttpBody};
use axum::extract::{Extension, RawQuery, Request};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinHandle;

use crate::auth::validate_username;
use crate::domain::repository::validate_slug;

use self::public::PublicWeb;

const STYLE: &str = include_str!("../../assets/style.css");
const MAX_LOCATION_QUERY_BYTES: usize = 512;
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
const MAX_BLOCKING_WEB_JOBS: usize = 8;

#[derive(Clone)]
struct WebState {
    public: Option<PublicWeb>,
}

#[derive(Clone, Debug)]
pub(crate) struct PublicWebConfig {
    pub(crate) instance_dir: PathBuf,
    pub(crate) http_clone_base: String,
    pub(crate) ssh_clone_base: String,
}

pub(crate) struct RunningWebServer {
    address: SocketAddr,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<std::io::Result<()>>,
}

impl RunningWebServer {
    pub(crate) async fn start(address: SocketAddr) -> Result<Self, WebError> {
        Self::start_with_state(address, WebState { public: None }).await
    }

    pub(crate) async fn start_public(
        address: SocketAddr,
        config: PublicWebConfig,
    ) -> Result<Self, WebError> {
        let public = PublicWeb::open(config, Arc::new(Semaphore::new(MAX_BLOCKING_WEB_JOBS)))?;
        Self::start_with_state(
            address,
            WebState {
                public: Some(public),
            },
        )
        .await
    }

    async fn start_with_state(address: SocketAddr, state: WebState) -> Result<Self, WebError> {
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router_with_state(state))
                .with_graceful_shutdown(async {
                    let _ = receiver.await;
                })
                .await
        });
        Ok(Self {
            address,
            shutdown,
            task,
        })
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) async fn shutdown(self) -> Result<(), WebError> {
        let _ = self.shutdown.send(());
        self.task.await.map_err(|_| WebError::Join)??;
        Ok(())
    }
}

pub(crate) fn router() -> Router {
    router_with_state(WebState { public: None })
}

fn router_with_state(state: WebState) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/go", get(go_to_repository))
        .route("/assets/style.css", get(style))
        .merge(public::routes())
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state)
        .layer(middleware::from_fn(response_policy))
}

async fn home(Extension(request_id): Extension<RequestId>) -> Response {
    render_home(StatusCode::OK, &request_id.0, "", "", "")
}

async fn go_to_repository(
    Extension(request_id): Extension<RequestId>,
    RawQuery(query): RawQuery,
) -> Response {
    match parse_location_query(query.as_deref()) {
        Ok((owner, repository)) => {
            let location = format!("/{owner}/{repository}");
            Response::builder()
                .status(StatusCode::FOUND)
                .header(header::LOCATION, location)
                .header(header::CACHE_CONTROL, "no-store")
                .body(Body::empty())
                .expect("the repository redirect is valid")
        }
        Err(LocationQueryError { owner, repository }) => render_home(
            StatusCode::BAD_REQUEST,
            &request_id.0,
            &owner,
            &repository,
            "Enter a valid lowercase owner and repository.",
        ),
    }
}

async fn style() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/css; charset=utf-8")
        .header(header::CACHE_CONTROL, "public, max-age=3600")
        .body(Body::from(STYLE))
        .expect("the embedded CSS response is valid")
}

async fn not_found(Extension(request_id): Extension<RequestId>) -> Response {
    render_error(
        StatusCode::NOT_FOUND,
        &request_id.0,
        "Page not found",
        "The requested page does not exist.",
    )
}

async fn method_not_allowed(Extension(request_id): Extension<RequestId>) -> Response {
    let mut response = render_error(
        StatusCode::METHOD_NOT_ALLOWED,
        &request_id.0,
        "Method not allowed",
        "This page does not accept the request method.",
    );
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
    response
}

async fn response_policy(mut request: Request, next: Next) -> Response {
    let request_id = RequestId(format!("{:032x}", rand::random::<u128>()));
    let is_head = request.method() == Method::HEAD;
    request.extensions_mut().insert(request_id.clone());
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&request_id.0).expect("the generated request ID is a header value"),
    );

    if is_head {
        let length = response.body().size_hint().exact();
        *response.body_mut() = Body::empty();
        if let Some(length) = length
            && !response.headers().contains_key(header::CONTENT_LENGTH)
        {
            response.headers_mut().insert(
                header::CONTENT_LENGTH,
                HeaderValue::from_str(&length.to_string())
                    .expect("a content length is a header value"),
            );
        }
    }
    response
}

fn render_home(
    status: StatusCode,
    request_id: &str,
    owner: &str,
    repository: &str,
    error: &str,
) -> Response {
    render(
        status,
        &HomeTemplate {
            request_id,
            owner,
            repository,
            error,
            has_error: !error.is_empty(),
        },
    )
}

fn render_error(status: StatusCode, request_id: &str, heading: &str, message: &str) -> Response {
    render(
        status,
        &ErrorTemplate {
            request_id,
            status: heading,
            message,
        },
    )
}

fn render(status: StatusCode, template: &impl Template) -> Response {
    match template.render() {
        Ok(body) => Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::from(body))
            .expect("the HTML response is valid"),
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::from("Template rendering failed.\n"))
            .expect("the template error response is valid"),
    }
}

fn parse_location_query(query: Option<&str>) -> Result<(String, String), LocationQueryError> {
    let query = query.ok_or_else(LocationQueryError::default)?;
    if query.len() > MAX_LOCATION_QUERY_BYTES || !valid_percent_encoding(query.as_bytes()) {
        return Err(LocationQueryError::default());
    }
    let mut owner = None;
    let mut repository = None;
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match name.as_ref() {
            "owner" if owner.is_none() => owner = Some(value.into_owned()),
            "repository" if repository.is_none() => repository = Some(value.into_owned()),
            _ => return Err(LocationQueryError::default()),
        }
    }
    let owner = owner.unwrap_or_default();
    let repository = repository.unwrap_or_default();
    if validate_username(&owner).is_err() || validate_slug(&repository).is_err() {
        return Err(LocationQueryError { owner, repository });
    }
    Ok((owner, repository))
}

fn valid_percent_encoding(input: &[u8]) -> bool {
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'%' {
            if index + 2 >= input.len()
                || !input[index + 1].is_ascii_hexdigit()
                || !input[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

#[derive(Clone)]
struct RequestId(String);

#[derive(Default)]
struct LocationQueryError {
    owner: String,
    repository: String,
}

#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate<'a> {
    request_id: &'a str,
    owner: &'a str,
    repository: &'a str,
    error: &'a str,
    has_error: bool,
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate<'a> {
    request_id: &'a str,
    status: &'a str,
    message: &'a str,
}

#[derive(Debug, Error)]
pub(crate) enum WebError {
    #[error("HTTP listener error: {0}")]
    Io(#[from] std::io::Error),
    #[error("public Web configuration error: {0}")]
    Public(#[from] public::PublicWebError),
    #[error("HTTP server task failed")]
    Join,
}
