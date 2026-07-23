mod public;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::body::{Body, Bytes, HttpBody};
use axum::extract::{DefaultBodyLimit, Extension, OriginalUri, RawQuery, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinHandle;

use crate::account::{AccountError, AccountService};
use crate::auth::validate_username;
use crate::domain::repository::validate_slug;
use crate::store::StoreError;

use self::public::PublicWeb;

const STYLE: &str = include_str!("../../assets/style.css");
const MAX_LOCATION_QUERY_BYTES: usize = 512;
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
const MAX_BLOCKING_WEB_JOBS: usize = 8;

#[derive(Clone)]
struct WebState {
    public: Option<PublicWeb>,
    accounts: Option<AccountService>,
    jobs: Arc<Semaphore>,
    key_reloader: Option<AccountKeyReloader>,
}

type AccountKeyReloader = Arc<dyn Fn(&AccountService) -> Result<(), AccountError> + Send + Sync>;

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
        Self::start_with_state(
            address,
            WebState {
                public: None,
                accounts: None,
                jobs: Arc::new(Semaphore::new(MAX_BLOCKING_WEB_JOBS)),
                key_reloader: None,
            },
        )
        .await
    }

    pub(crate) async fn start_public(
        address: SocketAddr,
        config: PublicWebConfig,
    ) -> Result<Self, WebError> {
        Self::start_public_inner(address, config, None).await
    }

    pub(crate) async fn start_public_with_key_reload(
        address: SocketAddr,
        config: PublicWebConfig,
        key_reloader: AccountKeyReloader,
    ) -> Result<Self, WebError> {
        Self::start_public_inner(address, config, Some(key_reloader)).await
    }

    async fn start_public_inner(
        address: SocketAddr,
        config: PublicWebConfig,
        key_reloader: Option<AccountKeyReloader>,
    ) -> Result<Self, WebError> {
        let jobs = Arc::new(Semaphore::new(MAX_BLOCKING_WEB_JOBS));
        let accounts = AccountService::new(config.instance_dir.join(crate::store::DATABASE_FILE));
        let public = PublicWeb::open(config, Arc::clone(&jobs))?;
        Self::start_with_state(
            address,
            WebState {
                public: Some(public),
                accounts: Some(accounts),
                jobs,
                key_reloader,
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
    router_with_state(WebState {
        public: None,
        accounts: None,
        jobs: Arc::new(Semaphore::new(MAX_BLOCKING_WEB_JOBS)),
        key_reloader: None,
    })
}

fn router_with_state(state: WebState) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/go", get(go_to_repository))
        .route(
            "/signup",
            get(signup_form)
                .post(signup)
                .layer(DefaultBodyLimit::max(20 * 1024)),
        )
        .route(
            "/recover",
            get(recovery_form)
                .post(recover)
                .layer(DefaultBodyLimit::max(20 * 1024)),
        )
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

async fn signup_form(Extension(request_id): Extension<RequestId>) -> Response {
    render_account_form(&request_id.0, AccountFormKind::Signup, "", "")
}

async fn recovery_form(Extension(request_id): Extension<RequestId>) -> Response {
    render_account_form(&request_id.0, AccountFormKind::Recovery, "", "")
}

async fn signup(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_account_form(&headers, &body, "invitation") {
        Ok(fields) => fields,
        Err(()) => {
            return render_account_error(
                &request_id.0,
                AccountFormKind::Signup,
                "",
                "The signup request is not valid.",
                StatusCode::BAD_REQUEST,
            );
        }
    };
    let username = fields.username.clone();
    let result = account_job(state, move |accounts| {
        accounts.signup(&fields.credential, &fields.username, &fields.public_key)
    })
    .await;
    account_result(result, &request_id.0, AccountFormKind::Signup, &username)
}

async fn recover(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_account_form(&headers, &body, "recovery") {
        Ok(fields) => fields,
        Err(()) => {
            return render_account_error(
                &request_id.0,
                AccountFormKind::Recovery,
                "",
                "The recovery request is not valid.",
                StatusCode::BAD_REQUEST,
            );
        }
    };
    let username = fields.username.clone();
    let result = account_job(state, move |accounts| {
        accounts.recover(&fields.username, &fields.credential, &fields.public_key)
    })
    .await;
    account_result(result, &request_id.0, AccountFormKind::Recovery, &username)
}

async fn account_job<T: Send + 'static>(
    state: WebState,
    operation: impl FnOnce(AccountService) -> Result<T, AccountError> + Send + 'static,
) -> Result<T, AccountError> {
    let accounts = state.accounts.ok_or_else(|| {
        AccountError::Store(StoreError::Integrity(
            "account service is unavailable".to_owned(),
        ))
    })?;
    let permit = state.jobs.acquire_owned().await.map_err(|_| {
        AccountError::Store(StoreError::Integrity(
            "account worker pool is unavailable".to_owned(),
        ))
    })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let result = operation(accounts.clone());
        if result.is_ok()
            && let Some(reload) = state.key_reloader
        {
            reload(&accounts)?;
        }
        result
    })
    .await
    .map_err(|_| AccountError::Store(StoreError::Integrity("account worker failed".to_owned())))?
}

fn account_result(
    result: Result<String, AccountError>,
    request_id: &str,
    kind: AccountFormKind,
    username: &str,
) -> Response {
    match result {
        Ok(recovery) => render(
            StatusCode::OK,
            &RecoveryCodeTemplate {
                request_id,
                recovery: &recovery,
            },
        ),
        Err(AccountError::Store(StoreError::UsernameUnavailable(_))) => render_account_error(
            request_id,
            kind,
            username,
            "That username is not available.",
            StatusCode::CONFLICT,
        ),
        Err(
            AccountError::Auth(_)
            | AccountError::InvalidSecret
            | AccountError::Store(StoreError::InvalidInvitation)
            | AccountError::Store(StoreError::InvalidRecovery),
        ) => render_account_error(
            request_id,
            kind,
            username,
            "The credential, username, or SSH public key is not valid.",
            StatusCode::BAD_REQUEST,
        ),
        Err(_) => render_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            request_id,
            "Internal server error",
            "The account request could not be completed.",
        ),
    }
}

fn parse_account_form(
    headers: &HeaderMap,
    body: &[u8],
    credential_name: &str,
) -> Result<AccountForm, ()> {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        != Some("application/x-www-form-urlencoded")
        || !valid_percent_encoding(body)
    {
        return Err(());
    }
    let mut username = None;
    let mut credential = None;
    let mut public_key = None;
    for (name, value) in url::form_urlencoded::parse(body) {
        match name.as_ref() {
            "username" if username.is_none() => username = Some(value.into_owned()),
            name if name == credential_name && credential.is_none() => {
                credential = Some(value.into_owned());
            }
            "public-key" if public_key.is_none() => public_key = Some(value.into_owned()),
            _ => return Err(()),
        }
    }
    Ok(AccountForm {
        username: username.ok_or(())?,
        credential: credential.ok_or(())?,
        public_key: public_key.ok_or(())?,
    })
}

fn render_account_form(
    request_id: &str,
    kind: AccountFormKind,
    username: &str,
    error: &str,
) -> Response {
    render_account_error(request_id, kind, username, error, StatusCode::OK)
}

fn render_account_error(
    request_id: &str,
    kind: AccountFormKind,
    username: &str,
    error: &str,
    status: StatusCode,
) -> Response {
    render(
        status,
        &AccountFormTemplate {
            request_id,
            username,
            error,
            has_error: !error.is_empty(),
            recovery: matches!(kind, AccountFormKind::Recovery),
        },
    )
}

struct AccountForm {
    username: String,
    credential: String,
    public_key: String,
}

#[derive(Clone, Copy)]
enum AccountFormKind {
    Signup,
    Recovery,
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

async fn method_not_allowed(
    Extension(request_id): Extension<RequestId>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let mut response = render_error(
        StatusCode::METHOD_NOT_ALLOWED,
        &request_id.0,
        "Method not allowed",
        "This page does not accept the request method.",
    );
    let allow = match uri.path() {
        "/signup" | "/recover" => "GET, HEAD, POST",
        path if path.ends_with("/git-upload-pack") => "POST",
        _ => "GET, HEAD",
    };
    response.headers_mut().insert(
        header::ALLOW,
        HeaderValue::from_str(allow).expect("the method list is a header value"),
    );
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

#[derive(Template)]
#[template(path = "account.html")]
struct AccountFormTemplate<'a> {
    request_id: &'a str,
    username: &'a str,
    error: &'a str,
    has_error: bool,
    recovery: bool,
}

#[derive(Template)]
#[template(path = "recovery-code.html")]
struct RecoveryCodeTemplate<'a> {
    request_id: &'a str,
    recovery: &'a str,
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
