mod feeds;
mod issues;
mod metadata_search;
mod public;
mod pull_requests;
mod repository_settings;
mod watches;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use askama::Template;
use axum::Router;
use axum::body::{Body, Bytes, HttpBody};
use axum::extract::{
    ConnectInfo, DefaultBodyLimit, Extension, OriginalUri, Path, Query, RawQuery, Request, State,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinHandle;
use tower_http::limit::RequestBodyLimitLayer;

use crate::account::{AccountError, AccountKeyRequest, AccountService};
use crate::auth::validate_username;
use crate::domain::repository::validate_slug;
use crate::feed_token::FeedTokenService;
use crate::issue::IssueService;
use crate::maintenance::MaintenanceGate;
use crate::pull_request::PullRequestService;
use crate::rate_limit::AttemptLimiter;
use crate::repository::{RepositoryService, RepositoryServiceError};
use crate::search::MetadataSearchService;
use crate::session::{SessionError, WebLoginService};
use crate::store::StoreError;
use crate::telemetry::Telemetry;
use crate::watch::WatchService;

use self::public::PublicWeb;

const STYLE: &str = include_str!("../../assets/style.css");
const MAX_LOCATION_QUERY_BYTES: usize = 512;
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
const MAX_BLOCKING_WEB_JOBS: usize = 8;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONCURRENCY_WAIT: Duration = Duration::from_secs(1);
const LOGIN_ATTEMPTS_PER_MINUTE: usize = 10;
const MAX_LOGIN_CLIENTS: usize = 4096;
const MAX_LOGIN_MULTIPART_FIELDS: usize = 4;
const MAX_LOGIN_MULTIPART_FIELD_BYTES: usize = 48 * 1024;
const MAX_LOGIN_MULTIPART_DECODED_BYTES: usize = 60 * 1024;
const SESSION_COOKIE: &str = "tit-session";
const CSRF_COOKIE: &str = "tit-csrf";
const LOGIN_CSRF_COOKIE: &str = "tit-login-csrf";

mod filters {
    use askama::{Result, Values};

    #[askama::filter_fn]
    pub fn human_time<T: std::borrow::Borrow<i64>>(timestamp: T, _: &dyn Values) -> Result<String> {
        Ok(
            jiff::Timestamp::from_second(*timestamp.borrow()).map_or_else(
                |_| "Invalid time".to_owned(),
                |timestamp| timestamp.strftime("%Y-%m-%d %H:%M UTC").to_string(),
            ),
        )
    }

    #[askama::filter_fn]
    pub fn short_id<T: AsRef<str>>(id: T, _: &dyn Values) -> Result<String> {
        Ok(id.as_ref().chars().take(12).collect())
    }

    #[askama::filter_fn]
    pub fn event_name<T: AsRef<str>>(kind: T, _: &dyn Values) -> Result<String> {
        let name = match kind.as_ref() {
            "issue-created" => "created the issue",
            "issue-edited" => "edited the issue",
            "issue-commented" => "added a comment",
            "issue-opened" | "issue-reopened" => "reopened the issue",
            "issue-closed" => "closed the issue",
            "pull-request-opened" => "opened the pull request",
            "pull-request-revised" => "recorded a new revision",
            "pull-request-edited" => "edited the pull request",
            "pull-request-closed" => "closed the pull request",
            "pull-request-reopened" => "reopened the pull request",
            "pull-request-commented" => "added a review comment",
            "pull-request-approved" => "approved the pull request",
            "pull-request-changes-requested" => "requested changes",
            "pull-request-merged" => "merged the pull request",
            other => return Ok(other.replace('-', " ")),
        };
        Ok(name.to_owned())
    }
}

fn format_time(timestamp: i64) -> String {
    jiff::Timestamp::from_second(timestamp).map_or_else(
        |_| "Invalid time".to_owned(),
        |timestamp| timestamp.strftime("%Y-%m-%d %H:%M UTC").to_string(),
    )
}

#[derive(Clone)]
struct WebState {
    public: Option<PublicWeb>,
    accounts: Option<AccountService>,
    jobs: Arc<Semaphore>,
    requests: Arc<Semaphore>,
    login_attempts: AttemptLimiter<IpAddr>,
    account_attempts: AttemptLimiter<IpAddr>,
    max_request_bytes: usize,
    telemetry: Telemetry,
    key_reloader: Option<AccountKeyReloader>,
    login: Option<WebLoginService>,
    ssh_login_target: Option<SshLoginTarget>,
    repositories: Option<RepositoryService>,
    issues: Option<IssueService>,
    pull_requests: Option<PullRequestService>,
    feeds: Option<FeedTokenService>,
    search: Option<MetadataSearchService>,
    watches: Option<WatchService>,
    readiness: Option<ListenerReadiness>,
    secure_cookies: bool,
}

#[derive(Clone)]
struct SshLoginTarget {
    host: String,
    port: u16,
}

impl SshLoginTarget {
    fn command(&self, secret: &str) -> String {
        format!(
            "ssh -p {} {} auth {}",
            self.port,
            shell_word(&self.host),
            secret
        )
    }
}

#[derive(Clone)]
pub(super) struct RequestActor(pub(super) Option<String>);

#[derive(Clone, Copy)]
struct ClientAddress(IpAddr);

type AccountKeyReloader = Arc<dyn Fn(&AccountService) -> Result<(), AccountError> + Send + Sync>;

#[derive(Clone, Debug)]
pub(crate) struct PublicWebConfig {
    pub(crate) instance_dir: PathBuf,
    pub(crate) http_clone_base: String,
    pub(crate) ssh_clone_base: String,
    pub(crate) max_request_bytes: usize,
    pub(crate) max_connections: usize,
}

#[derive(Clone, Default)]
pub(crate) struct ListenerReadiness {
    ready: Arc<AtomicBool>,
}

impl ListenerReadiness {
    pub(crate) fn mark_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    pub(crate) fn mark_stopping(&self) {
        self.ready.store(false, Ordering::Release);
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
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
                requests: Arc::new(Semaphore::new(1024)),
                login_attempts: login_attempt_limiter(),
                account_attempts: login_attempt_limiter(),
                max_request_bytes: 1024 * 1024,
                telemetry: Telemetry::default(),
                key_reloader: None,
                login: None,
                ssh_login_target: None,
                repositories: None,
                issues: None,
                pull_requests: None,
                feeds: None,
                search: None,
                watches: None,
                readiness: None,
                secure_cookies: false,
            },
        )
        .await
    }

    pub(crate) async fn start_public(
        address: SocketAddr,
        config: PublicWebConfig,
    ) -> Result<Self, WebError> {
        Self::start_public_inner(address, config, None, None, None, Telemetry::default()).await
    }

    pub(crate) async fn start_public_with_key_reload(
        address: SocketAddr,
        config: PublicWebConfig,
        key_reloader: AccountKeyReloader,
        readiness: ListenerReadiness,
        maintenance: MaintenanceGate,
        telemetry: Telemetry,
    ) -> Result<Self, WebError> {
        Self::start_public_inner(
            address,
            config,
            Some(key_reloader),
            Some(readiness),
            Some(maintenance),
            telemetry,
        )
        .await
    }

    async fn start_public_inner(
        address: SocketAddr,
        config: PublicWebConfig,
        key_reloader: Option<AccountKeyReloader>,
        readiness: Option<ListenerReadiness>,
        maintenance: Option<MaintenanceGate>,
        telemetry: Telemetry,
    ) -> Result<Self, WebError> {
        let jobs = Arc::new(Semaphore::new(MAX_BLOCKING_WEB_JOBS));
        let requests = Arc::new(Semaphore::new(config.max_connections));
        let max_request_bytes = config.max_request_bytes;
        let ssh_login_target = parse_ssh_login_target(&config.ssh_clone_base)?;
        let database = config.instance_dir.join(crate::store::DATABASE_FILE);
        let accounts = AccountService::new(database.clone());
        let public_url = url::Url::parse(&format!("{}/", config.http_clone_base))
            .map_err(WebError::CanonicalUrl)?;
        let secure_cookies = public_url.scheme() == "https";
        let login = WebLoginService::new(database, &public_url)?;
        let public = PublicWeb::open(config, Arc::clone(&jobs))?;
        let repositories = match maintenance.clone() {
            Some(gate) => {
                RepositoryService::new_with_gate(public.database(), public.repository_root(), gate)
            }
            None => RepositoryService::new(public.database(), public.repository_root()),
        };
        let issues = IssueService::new(public.database());
        let pull_requests = match maintenance {
            Some(gate) => {
                PullRequestService::new_with_gate(public.database(), public.repository_root(), gate)
            }
            None => PullRequestService::new(public.database(), public.repository_root()),
        };
        let feeds = FeedTokenService::new(public.database());
        let search = MetadataSearchService::new(public.database());
        let watches = WatchService::new(public.database());
        Self::start_with_state(
            address,
            WebState {
                public: Some(public),
                accounts: Some(accounts),
                jobs,
                requests,
                login_attempts: login_attempt_limiter(),
                account_attempts: login_attempt_limiter(),
                max_request_bytes,
                telemetry,
                key_reloader,
                login: Some(login),
                ssh_login_target: Some(ssh_login_target),
                repositories: Some(repositories),
                issues: Some(issues),
                pull_requests: Some(pull_requests),
                feeds: Some(feeds),
                search: Some(search),
                watches: Some(watches),
                readiness,
                secure_cookies,
            },
        )
        .await
    }

    async fn start_with_state(address: SocketAddr, state: WebState) -> Result<Self, WebError> {
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                router_with_state(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
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

    pub(crate) async fn shutdown_bounded(mut self, limit: Duration) -> Result<bool, WebError> {
        let _ = self.shutdown.send(());
        match tokio::time::timeout(limit, &mut self.task).await {
            Ok(result) => {
                result.map_err(|_| WebError::Join)??;
                Ok(true)
            }
            Err(_) => {
                self.task.abort();
                let _ = self.task.await;
                Ok(false)
            }
        }
    }
}

pub(crate) fn router() -> Router {
    router_with_state(WebState {
        public: None,
        accounts: None,
        jobs: Arc::new(Semaphore::new(MAX_BLOCKING_WEB_JOBS)),
        requests: Arc::new(Semaphore::new(1024)),
        login_attempts: login_attempt_limiter(),
        account_attempts: login_attempt_limiter(),
        max_request_bytes: 1024 * 1024,
        telemetry: Telemetry::default(),
        key_reloader: None,
        login: None,
        ssh_login_target: None,
        repositories: None,
        issues: None,
        pull_requests: None,
        feeds: None,
        search: None,
        watches: None,
        readiness: None,
        secure_cookies: false,
    })
}

fn router_with_state(state: WebState) -> Router {
    let max_request_bytes = state.max_request_bytes;
    let repository_routes = metadata_search::routes()
        .merge(watches::routes())
        .merge(issues::routes())
        .merge(pull_requests::routes())
        .merge(repository_settings::routes())
        .merge(public::routes());
    Router::new()
        .route("/", get(home))
        .route("/healthz", get(health))
        .route("/metrics", get(metrics))
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
        .route(
            "/login",
            get(login_form)
                .post(login_challenge)
                .layer(DefaultBodyLimit::max(32 * 1024)),
        )
        .route(
            "/login/ssh",
            axum::routing::post(login_ssh).layer(DefaultBodyLimit::max(1024)),
        )
        .route(
            "/login/ssh/complete",
            axum::routing::post(login_ssh_complete).layer(DefaultBodyLimit::max(1024)),
        )
        .route(
            "/login/verify",
            axum::routing::post(login_verify).layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .route(
            "/login/verify-file",
            axum::routing::post(login_verify_file).layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .route(
            "/login/challenge.txt",
            axum::routing::post(login_challenge_download).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route("/account", get(account_page))
        .route(
            "/account/profile",
            axum::routing::post(update_profile).layer(DefaultBodyLimit::max(2048)),
        )
        .route(
            "/account/repositories",
            axum::routing::post(create_repository).layer(DefaultBodyLimit::max(4 * 1024)),
        )
        .route(
            "/account/keys/add",
            axum::routing::post(begin_key_add).layer(DefaultBodyLimit::max(32 * 1024)),
        )
        .route(
            "/account/keys/add/complete",
            axum::routing::post(complete_key_add).layer(DefaultBodyLimit::max(32 * 1024)),
        )
        .route(
            "/account/keys/revoke",
            axum::routing::post(begin_key_revoke).layer(DefaultBodyLimit::max(4 * 1024)),
        )
        .route(
            "/account/keys/revoke/complete",
            axum::routing::post(complete_key_revoke).layer(DefaultBodyLimit::max(4 * 1024)),
        )
        .route(
            "/logout",
            get(logout_form)
                .post(logout)
                .layer(DefaultBodyLimit::max(1024)),
        )
        .route("/assets/style.css", get(style))
        .merge(feeds::routes())
        .merge(repository_routes)
        .route("/{username}", get(public_profile))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(RequestBodyLimitLayer::new(max_request_bytes))
        .layer(middleware::from_fn_with_state(state.clone(), request_actor))
        .layer(middleware::from_fn_with_state(state.clone(), request_guard))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            response_policy,
        ))
        .with_state(state)
}

async fn metrics(State(state): State<WebState>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(state.telemetry.metrics()))
        .expect("the metrics response is valid")
}

fn login_attempt_limiter() -> AttemptLimiter<IpAddr> {
    AttemptLimiter::new(
        LOGIN_ATTEMPTS_PER_MINUTE,
        Duration::from_secs(60),
        MAX_LOGIN_CLIENTS,
    )
}

fn parse_ssh_login_target(value: &str) -> Result<SshLoginTarget, WebError> {
    let url = url::Url::parse(value).map_err(WebError::CanonicalUrl)?;
    let host = url.host_str().ok_or_else(|| {
        WebError::PublicConfig("the SSH clone URL does not have a host".to_owned())
    })?;
    Ok(SshLoginTarget {
        host: if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        },
        port: url.port().unwrap_or(22),
    })
}

fn shell_word(value: &str) -> String {
    if value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'[' | b']' | b':')
    }) {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

async fn request_guard(
    State(state): State<WebState>,
    mut request: Request,
    next: Next,
) -> Response {
    let address = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|peer| peer.0.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    request.extensions_mut().insert(ClientAddress(address));
    let permit = match tokio::time::timeout(
        CONCURRENCY_WAIT,
        state.requests.clone().acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        _ => return limit_response(StatusCode::SERVICE_UNAVAILABLE, "Server is busy.\n"),
    };
    let response = tokio::time::timeout(REQUEST_TIMEOUT, next.run(request)).await;
    drop(permit);
    match response {
        Ok(response) => response,
        Err(_) => limit_response(
            StatusCode::REQUEST_TIMEOUT,
            "Request time limit exceeded.\n",
        ),
    }
}

fn limit_response(status: StatusCode, message: &'static str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(message))
        .expect("the limit response is valid")
}

fn allow_login_attempt(state: &WebState, peer: ClientAddress) -> bool {
    state.login_attempts.allow(peer.0)
}

fn allow_account_attempt(state: &WebState, peer: ClientAddress) -> bool {
    state.account_attempts.allow(peer.0)
}

async fn request_actor(
    State(state): State<WebState>,
    mut request: Request,
    next: Next,
) -> Response {
    let actor = match cookie(request.headers(), SESSION_COOKIE) {
        Some(session) => login_job(state, move |login| login.authenticate(&session, None))
            .await
            .ok()
            .map(|record| record.username),
        None => None,
    };
    request.extensions_mut().insert(RequestActor(actor));
    next.run(request).await
}

async fn home(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Extension(actor): Extension<RequestActor>,
    headers: HeaderMap,
) -> Response {
    let signed_in = actor.0.is_some();
    let username = actor.0.clone().unwrap_or_default();
    let csrf = cookie(&headers, CSRF_COOKIE).unwrap_or_default();
    if state.repositories.is_none() {
        return render_home(
            StatusCode::OK,
            &request_id.0,
            HomePage {
                owner: "",
                repository: "",
                error: "",
                signed_in,
                username: &username,
                csrf: &csrf,
                repositories: &[],
                recent_repositories: &[],
            },
        );
    }
    let result = repository_job(state, move |repositories| {
        let owned = match actor.0.as_deref() {
            Some(owner) => repositories.home(Some(owner))?,
            None => Vec::new(),
        };
        let recent = repositories.home(None)?;
        Ok((owned, recent))
    })
    .await;
    match result {
        Ok((repositories, recent_repositories)) => render_home(
            StatusCode::OK,
            &request_id.0,
            HomePage {
                owner: "",
                repository: "",
                error: "",
                signed_in,
                username: &username,
                csrf: &csrf,
                repositories: &repositories,
                recent_repositories: &recent_repositories,
            },
        ),
        Err(_) => render_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &request_id.0,
            "Home error",
            "The repository overview could not be completed.",
        ),
    }
}

async fn health(State(state): State<WebState>) -> Response {
    let ready = state
        .readiness
        .as_ref()
        .is_none_or(ListenerReadiness::is_ready);
    let (status, body) = if ready {
        (StatusCode::OK, "ready\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
    };
    Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body))
        .expect("the readiness response is valid")
}

async fn go_to_repository(
    Extension(request_id): Extension<RequestId>,
    Extension(actor): Extension<RequestActor>,
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
            HomePage {
                owner: &owner,
                repository: &repository,
                error: "Enter a valid lowercase owner and repository.",
                signed_in: actor.0.is_some(),
                username: actor.0.as_deref().unwrap_or_default(),
                csrf: "",
                repositories: &[],
                recent_repositories: &[],
            },
        ),
    }
}

async fn signup_form(
    Extension(request_id): Extension<RequestId>,
    Extension(actor): Extension<RequestActor>,
) -> Response {
    if actor.0.is_some() {
        return account_redirect();
    }
    render_account_form(&request_id.0, AccountFormKind::Signup, "", "")
}

async fn recovery_form(
    Extension(request_id): Extension<RequestId>,
    Extension(actor): Extension<RequestActor>,
) -> Response {
    if actor.0.is_some() {
        return account_redirect();
    }
    render_account_form(&request_id.0, AccountFormKind::Recovery, "", "")
}

async fn signup(
    State(state): State<WebState>,
    Extension(peer): Extension<ClientAddress>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !allow_account_attempt(&state, peer) {
        return limit_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Account attempt limit exceeded.\n",
        );
    }
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
    let correlation_id = request_id.0.clone();
    let result = account_job(state, move |accounts| {
        accounts.signup(
            &fields.credential,
            &fields.username,
            &fields.public_key,
            &correlation_id,
        )
    })
    .await;
    account_result(result, &request_id.0, AccountFormKind::Signup, &username)
}

async fn recover(
    State(state): State<WebState>,
    Extension(peer): Extension<ClientAddress>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !allow_account_attempt(&state, peer) {
        return limit_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Account attempt limit exceeded.\n",
        );
    }
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
    let correlation_id = request_id.0.clone();
    let result = account_job(state, move |accounts| {
        accounts.recover(
            &fields.username,
            &fields.credential,
            &fields.public_key,
            &correlation_id,
        )
    })
    .await;
    account_result(result, &request_id.0, AccountFormKind::Recovery, &username)
}

async fn login_form(
    Extension(request_id): Extension<RequestId>,
    Extension(actor): Extension<RequestActor>,
) -> Response {
    if actor.0.is_some() {
        return account_redirect();
    }
    render(
        StatusCode::OK,
        &LoginTemplate {
            request_id: &request_id.0,
            username: "",
            error: "",
            has_error: false,
            signed_in: false,
        },
    )
}

async fn login_challenge(
    State(state): State<WebState>,
    Extension(peer): Extension<ClientAddress>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !allow_login_attempt(&state, peer) {
        return limit_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Login attempt limit exceeded.\n",
        );
    }
    let fields = match parse_named_form(&headers, &body, &["username"]) {
        Ok(fields) => fields,
        Err(()) => return login_error(&request_id.0, "", "The login request is not valid."),
    };
    let username = fields[0].clone();
    let display_username = username.clone();
    let secure = state.secure_cookies;
    let result = login_job(state, move |login| login.issue(&username)).await;
    match result {
        Ok(challenge) => {
            let mut response = render(
                StatusCode::OK,
                &LoginChallengeTemplate {
                    request_id: &request_id.0,
                    username: &display_username,
                    challenge: &challenge.challenge,
                    login_csrf: &challenge.login_csrf,
                    error: "",
                    has_error: false,
                    signed_in: false,
                },
            );
            append_cookie(
                response.headers_mut(),
                LOGIN_CSRF_COOKIE,
                &challenge.login_csrf,
                true,
                secure,
                5 * 60,
            );
            response
        }
        Err(_) => login_error(
            &request_id.0,
            &display_username,
            "The username is not valid or the account is not active.",
        ),
    }
}

async fn login_ssh(
    State(state): State<WebState>,
    Extension(peer): Extension<ClientAddress>,
    Extension(request_id): Extension<RequestId>,
) -> Response {
    if !allow_login_attempt(&state, peer) {
        return limit_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Login attempt limit exceeded.\n",
        );
    }
    let Some(target) = state.ssh_login_target.clone() else {
        return login_error(
            &request_id.0,
            "",
            "SSH login is not available on this instance.",
        );
    };
    let secure = state.secure_cookies;
    match login_job(state, |login| login.issue_approval()).await {
        Ok(approval) => {
            let command = target.command(&approval.secret);
            let mut response = render(
                StatusCode::OK,
                &LoginSshTemplate {
                    request_id: &request_id.0,
                    command: &command,
                    secret: &approval.secret,
                    login_csrf: &approval.login_csrf,
                    error: "",
                    has_error: false,
                    signed_in: false,
                },
            );
            append_cookie(
                response.headers_mut(),
                LOGIN_CSRF_COOKIE,
                &approval.login_csrf,
                true,
                secure,
                5 * 60,
            );
            response
        }
        Err(_) => login_error(
            &request_id.0,
            "",
            "The SSH login request could not be created.",
        ),
    }
}

async fn login_ssh_complete(
    State(state): State<WebState>,
    Extension(peer): Extension<ClientAddress>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !allow_login_attempt(&state, peer) {
        return limit_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Login attempt limit exceeded.\n",
        );
    }
    let fields = match parse_named_form(&headers, &body, &["secret", "login-csrf"]) {
        Ok(fields) => fields,
        Err(()) => {
            return rejected_login(state, &request_id.0, "", "The login response is not valid.")
                .await;
        }
    };
    let secret = fields[0].clone();
    let login_csrf = fields[1].clone();
    if cookie(&headers, LOGIN_CSRF_COOKIE).as_deref() != Some(login_csrf.as_str()) {
        return rejected_login(state, &request_id.0, "", "The login response is not valid.").await;
    }
    let secure = state.secure_cookies;
    let correlation_id = request_id.0.clone();
    let result = login_job(state.clone(), {
        let secret = secret.clone();
        let login_csrf = login_csrf.clone();
        move |login| login.complete_approval(&secret, &login_csrf, &correlation_id)
    })
    .await;
    match result {
        Ok(session) => login_success(session, secure),
        Err(SessionError::Store(StoreError::LoginApprovalPending)) => {
            let Some(target) = state.ssh_login_target else {
                return login_error(
                    &request_id.0,
                    "",
                    "SSH login is not available on this instance.",
                );
            };
            let command = target.command(&secret);
            render(
                StatusCode::CONFLICT,
                &LoginSshTemplate {
                    request_id: &request_id.0,
                    command: &command,
                    secret: &secret,
                    login_csrf: &login_csrf,
                    error: "Authenticate with SSH before you continue.",
                    has_error: true,
                    signed_in: false,
                },
            )
        }
        Err(_) => login_error(
            &request_id.0,
            "",
            "The SSH login request is invalid or has expired.",
        ),
    }
}

async fn login_verify(
    State(state): State<WebState>,
    Extension(peer): Extension<ClientAddress>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !allow_login_attempt(&state, peer) {
        return limit_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Login attempt limit exceeded.\n",
        );
    }
    let fields = match parse_named_form(
        &headers,
        &body,
        &["username", "challenge", "signature", "login-csrf"],
    ) {
        Ok(fields) => fields,
        Err(()) => {
            return rejected_login(state, &request_id.0, "", "The login response is not valid.")
                .await;
        }
    };
    let username = fields[0].clone();
    let challenge = fields[1].clone();
    let signature = fields[2].clone();
    let login_csrf = fields[3].clone();
    if cookie(&headers, LOGIN_CSRF_COOKIE).as_deref() != Some(login_csrf.as_str()) {
        return rejected_login(
            state,
            &request_id.0,
            &username,
            "The login response is not valid.",
        )
        .await;
    }
    complete_login(
        state,
        &request_id.0,
        username,
        challenge,
        signature,
        login_csrf,
    )
    .await
}

async fn login_challenge_download(headers: HeaderMap, body: Bytes) -> Response {
    let fields = match parse_named_form(&headers, &body, &["username", "challenge", "login-csrf"]) {
        Ok(fields) => fields,
        Err(()) => return limit_response(StatusCode::BAD_REQUEST, "The request is not valid.\n"),
    };
    if cookie(&headers, LOGIN_CSRF_COOKIE).as_deref() != Some(fields[2].as_str()) {
        return limit_response(StatusCode::FORBIDDEN, "The request is not authorized.\n");
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"tit-login-challenge.txt\"",
        )
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(normalize_browser_newlines(fields[1].clone())))
        .expect("the login challenge download is valid")
}

async fn login_verify_file(
    State(state): State<WebState>,
    Extension(peer): Extension<ClientAddress>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if !allow_login_attempt(&state, peer) {
        return limit_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Login attempt limit exceeded.\n",
        );
    }
    let Some(content_type) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return rejected_login(state, &request_id.0, "", "The login response is not valid.").await;
    };
    let Ok(boundary) = multra::parse_boundary(content_type) else {
        return rejected_login(state, &request_id.0, "", "The login response is not valid.").await;
    };
    let mut multipart = multra::Multipart::new(body.into_data_stream(), boundary);
    let mut username = None;
    let mut challenge = None;
    let mut signature = None;
    let mut login_csrf = None;
    let mut field_count = 0_usize;
    let mut decoded_bytes = 0_usize;
    loop {
        let mut field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(_) => {
                return rejected_login(
                    state,
                    &request_id.0,
                    "",
                    "The login response is not valid.",
                )
                .await;
            }
        };
        field_count += 1;
        if field_count > MAX_LOGIN_MULTIPART_FIELDS {
            return rejected_login(state, &request_id.0, "", "The login response is not valid.")
                .await;
        }
        let value = match read_login_field(&mut field, &mut decoded_bytes).await {
            Ok(value) => value,
            Err(()) => {
                return rejected_login(
                    state,
                    &request_id.0,
                    "",
                    "The login response is not valid.",
                )
                .await;
            }
        };
        match field.name() {
            Some("username") if username.is_none() => username = Some(value),
            Some("challenge") if challenge.is_none() => challenge = Some(value),
            Some("signature-file") if signature.is_none() => signature = Some(value),
            Some("login-csrf") if login_csrf.is_none() => login_csrf = Some(value),
            _ => {
                return rejected_login(
                    state,
                    &request_id.0,
                    "",
                    "The login response is not valid.",
                )
                .await;
            }
        }
    }
    let (Some(username), Some(challenge), Some(signature), Some(login_csrf)) =
        (username, challenge, signature, login_csrf)
    else {
        return rejected_login(state, &request_id.0, "", "The login response is not valid.").await;
    };
    if cookie(&headers, LOGIN_CSRF_COOKIE).as_deref() != Some(login_csrf.as_str()) {
        return rejected_login(
            state,
            &request_id.0,
            &username,
            "The login response is not valid.",
        )
        .await;
    }
    complete_login(
        state,
        &request_id.0,
        username,
        challenge,
        signature,
        login_csrf,
    )
    .await
}

async fn read_login_field(
    field: &mut multra::Field<'_>,
    decoded_bytes: &mut usize,
) -> Result<String, ()> {
    let mut bytes = Vec::new();
    while let Some(chunk) = field.chunk().await.map_err(|_| ())? {
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|size| size > MAX_LOGIN_MULTIPART_FIELD_BYTES)
        {
            return Err(());
        }
        *decoded_bytes = decoded_bytes.checked_add(chunk.len()).ok_or(())?;
        if *decoded_bytes > MAX_LOGIN_MULTIPART_DECODED_BYTES {
            return Err(());
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| ())
}

async fn complete_login(
    state: WebState,
    request_id: &str,
    username: String,
    challenge: String,
    signature: String,
    login_csrf: String,
) -> Response {
    let display_username = username.clone();
    let challenge = normalize_browser_newlines(challenge);
    let display_challenge = challenge.clone();
    let display_login_csrf = login_csrf.clone();
    let secure = state.secure_cookies;
    let correlation_id = request_id.to_owned();
    let result = login_job(state, move |login| {
        login.verify(
            &username,
            &challenge,
            &signature,
            &login_csrf,
            &correlation_id,
        )
    })
    .await;
    match result {
        Ok(session) => login_success(session, secure),
        Err(_) => render(
            StatusCode::BAD_REQUEST,
            &LoginChallengeTemplate {
                request_id,
                username: &display_username,
                challenge: &display_challenge,
                login_csrf: &display_login_csrf,
                error: "The signature is not valid or the challenge has expired.",
                has_error: true,
                signed_in: false,
            },
        ),
    }
}

fn login_success(session: crate::session::NewSession, secure: bool) -> Response {
    let mut response = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/account")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::empty())
        .expect("the login redirect is valid");
    append_cookie(
        response.headers_mut(),
        SESSION_COOKIE,
        &session.token,
        true,
        secure,
        SESSION_COOKIE_MAX_AGE,
    );
    append_cookie(
        response.headers_mut(),
        LOGIN_CSRF_COOKIE,
        "",
        true,
        secure,
        0,
    );
    append_cookie(
        response.headers_mut(),
        CSRF_COOKIE,
        &session.csrf,
        false,
        secure,
        SESSION_COOKIE_MAX_AGE,
    );
    response
}

fn normalize_browser_newlines(value: String) -> String {
    if value.contains("\r\n") {
        value.replace("\r\n", "\n")
    } else {
        value
    }
}

const SESSION_COOKIE_MAX_AGE: i64 = 7 * 24 * 60 * 60;

async fn account_page(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Response {
    let Some(session_token) = cookie(&headers, SESSION_COOKIE) else {
        return login_redirect(false);
    };
    let Some(csrf) = cookie(&headers, CSRF_COOKIE) else {
        return login_redirect(true);
    };
    let csrf_for_auth = csrf.clone();
    match login_job(state.clone(), move |login| {
        login.authenticate(&session_token, Some(&csrf_for_auth))
    })
    .await
    {
        Ok(session) => {
            let username = session.username.clone();
            let details = account_job(state, move |accounts| {
                let profile = accounts.profile(&username)?;
                let keys = accounts.keys(&username)?;
                Ok((profile, keys))
            })
            .await;
            match details {
                Ok((profile, keys)) => render(
                    StatusCode::OK,
                    &AccountTemplate {
                        request_id: &request_id.0,
                        username: &session.username,
                        administrator: session.is_administrator,
                        csrf: &csrf,
                        bio: &profile.bio,
                        contact_email: &profile.contact_email,
                        keys: keys
                            .iter()
                            .map(|key| AccountKeyView {
                                label: &key.label,
                                fingerprint: &key.fingerprint,
                                created_at: format_time(key.created_at),
                                last_used_at: key
                                    .last_used_at
                                    .map(format_time)
                                    .unwrap_or_else(|| "Never".to_owned()),
                                active: key.revoked_at.is_none(),
                            })
                            .collect(),
                        active_key_count: keys
                            .iter()
                            .filter(|key| key.revoked_at.is_none())
                            .count(),
                        signed_in: true,
                    },
                ),
                Err(_) => render_error_with_auth(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &request_id.0,
                    "Account error",
                    "The account profile could not be read.",
                    true,
                ),
            }
        }
        Err(_) => login_redirect(true),
    }
}

async fn begin_key_add(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "label", "public-key"]) {
        Ok(fields) => fields,
        Err(()) => return key_error(&request_id.0, "The key request is not valid."),
    };
    let username =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(username) => username,
            Err(response) => return response,
        };
    let Some(target) = state.ssh_login_target.clone() else {
        return key_error(&request_id.0, "SSH authentication is not available.");
    };
    let csrf = fields[0].clone();
    let approval = login_job(state, {
        let username = username.clone();
        let csrf = csrf.clone();
        move |login| login.issue_account_approval(&username, &csrf)
    })
    .await;
    match approval {
        Ok(approval) => {
            let command = target.command(&approval.secret);
            render(
                StatusCode::OK,
                &AccountKeyAuthTemplate {
                    request_id: &request_id.0,
                    heading: "Add SSH key",
                    action: "/account/keys/add/complete",
                    command: &command,
                    secret: &approval.secret,
                    csrf: &csrf,
                    label: &fields[1],
                    public_key: &fields[2],
                    fingerprint: "",
                    adding: true,
                    signed_in: true,
                },
            )
        }
        Err(_) => key_error(
            &request_id.0,
            "The authentication request could not be created.",
        ),
    }
}

async fn complete_key_add(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "secret", "label", "public-key"])
    {
        Ok(fields) => fields,
        Err(()) => return key_error(&request_id.0, "The key request is not valid."),
    };
    let username =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(username) => username,
            Err(response) => return response,
        };
    let Some(session) = cookie(&headers, SESSION_COOKIE) else {
        return login_redirect(false);
    };
    let correlation_id = request_id.0.clone();
    let result = account_job(state, move |accounts| {
        accounts.complete_key_add(
            &AccountKeyRequest {
                username: &username,
                session: &session,
                csrf: &fields[0],
                secret: &fields[1],
                correlation_id: &correlation_id,
            },
            &fields[2],
            &fields[3],
        )
    })
    .await;
    key_change_result(result.map(|_| ()), &request_id.0)
}

async fn begin_key_revoke(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "fingerprint"]) {
        Ok(fields) => fields,
        Err(()) => return key_error(&request_id.0, "The key request is not valid."),
    };
    let username =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(username) => username,
            Err(response) => return response,
        };
    let Some(target) = state.ssh_login_target.clone() else {
        return key_error(&request_id.0, "SSH authentication is not available.");
    };
    let csrf = fields[0].clone();
    let approval = login_job(state, {
        let username = username.clone();
        let csrf = csrf.clone();
        move |login| login.issue_account_approval(&username, &csrf)
    })
    .await;
    match approval {
        Ok(approval) => {
            let command = target.command(&approval.secret);
            render(
                StatusCode::OK,
                &AccountKeyAuthTemplate {
                    request_id: &request_id.0,
                    heading: "Revoke SSH key",
                    action: "/account/keys/revoke/complete",
                    command: &command,
                    secret: &approval.secret,
                    csrf: &csrf,
                    label: "",
                    public_key: "",
                    fingerprint: &fields[1],
                    adding: false,
                    signed_in: true,
                },
            )
        }
        Err(_) => key_error(
            &request_id.0,
            "The authentication request could not be created.",
        ),
    }
}

async fn complete_key_revoke(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "secret", "fingerprint"]) {
        Ok(fields) => fields,
        Err(()) => return key_error(&request_id.0, "The key request is not valid."),
    };
    let username =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(username) => username,
            Err(response) => return response,
        };
    let Some(session) = cookie(&headers, SESSION_COOKIE) else {
        return login_redirect(false);
    };
    let correlation_id = request_id.0.clone();
    let result = account_job(state, move |accounts| {
        accounts.complete_key_revoke(
            &AccountKeyRequest {
                username: &username,
                session: &session,
                csrf: &fields[0],
                secret: &fields[1],
                correlation_id: &correlation_id,
            },
            &fields[2],
        )
    })
    .await;
    key_change_result(result, &request_id.0)
}

fn key_change_result(result: Result<(), AccountError>, request_id: &str) -> Response {
    match result {
        Ok(()) => account_redirect(),
        Err(AccountError::Store(StoreError::LastKey)) => key_error(
            request_id,
            "An account must keep at least one active SSH key.",
        ),
        Err(AccountError::Store(StoreError::KeyExists)) => {
            key_error(request_id, "The key or active key label already exists.")
        }
        Err(
            AccountError::Auth(_)
            | AccountError::InvalidLabel
            | AccountError::InvalidSecret
            | AccountError::Store(StoreError::InvalidLoginApproval)
            | AccountError::Store(StoreError::KeyNotFound),
        ) => key_error(
            request_id,
            "The key request is invalid, expired, or already used.",
        ),
        Err(_) => key_error(request_id, "The key request could not be completed."),
    }
}

fn key_error(request_id: &str, message: &str) -> Response {
    render_error_with_auth(
        StatusCode::BAD_REQUEST,
        request_id,
        "SSH key error",
        message,
        true,
    )
}

async fn public_profile(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Extension(actor): Extension<RequestActor>,
    Path(username): Path<String>,
    Query(query): Query<ProfileQuery>,
) -> Response {
    let signed_in = actor.0.is_some();
    if validate_username(&username).is_err() || state.accounts.is_none() {
        return render_error_with_auth(
            StatusCode::NOT_FOUND,
            &request_id.0,
            "Page not found",
            "The requested page does not exist.",
            signed_in,
        );
    }
    let page_number = query.page.unwrap_or(1);
    let result = account_job(state, move |accounts| {
        accounts.profile_page(&username, page_number)
    })
    .await;
    match result {
        Ok(profile) => render(
            StatusCode::OK,
            &PublicProfileTemplate {
                request_id: &request_id.0,
                signed_in,
                username: &profile.username,
                bio: &profile.bio,
                contact_email: &profile.contact_email,
                repositories: profile
                    .repositories
                    .iter()
                    .map(|repository| HomeRepositoryView {
                        owner: &repository.owner,
                        slug: &repository.slug,
                        visibility: &repository.visibility,
                        state: &repository.state,
                        description: &repository.description,
                        updated_at: repository.updated_at,
                    })
                    .collect(),
                has_previous: profile.page > 1,
                has_next: profile.has_next,
                previous_page: profile.page.saturating_sub(1),
                next_page: profile.page.saturating_add(1),
            },
        ),
        Err(AccountError::Auth(_) | AccountError::Store(StoreError::AccountNotFound(_))) => {
            render_error_with_auth(
                StatusCode::NOT_FOUND,
                &request_id.0,
                "Not found",
                "The profile was not found.",
                signed_in,
            )
        }
        Err(_) => render_error_with_auth(
            StatusCode::INTERNAL_SERVER_ERROR,
            &request_id.0,
            "Profile error",
            "The profile could not be read.",
            signed_in,
        ),
    }
}

async fn update_profile(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "bio", "contact-email"]) {
        Ok(fields) => fields,
        Err(()) => {
            return render_error_with_auth(
                StatusCode::BAD_REQUEST,
                &request_id.0,
                "Profile error",
                "The profile request is not valid.",
                true,
            );
        }
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    let bio = fields[1].clone();
    let email = fields[2].clone();
    match account_job(state, move |accounts| {
        accounts.update_profile(&actor, &bio, &email)
    })
    .await
    {
        Ok(()) => account_redirect(),
        Err(AccountError::InvalidProfile) => render_error_with_auth(
            StatusCode::BAD_REQUEST,
            &request_id.0,
            "Profile error",
            "The bio or contact email is not valid.",
            true,
        ),
        Err(_) => render_error_with_auth(
            StatusCode::INTERNAL_SERVER_ERROR,
            &request_id.0,
            "Profile error",
            "The profile could not be saved.",
            true,
        ),
    }
}

async fn create_repository(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "name"]) {
        Ok(fields) => fields,
        Err(()) => {
            return repository_form_error(
                &request_id.0,
                StatusCode::BAD_REQUEST,
                "The repository request is not valid.",
            );
        }
    };
    let Some(session_token) = cookie(&headers, SESSION_COOKIE) else {
        return login_redirect(false);
    };
    let Some(csrf) = cookie(&headers, CSRF_COOKIE) else {
        return login_redirect(true);
    };
    if fields[0] != csrf {
        return repository_form_error(
            &request_id.0,
            StatusCode::FORBIDDEN,
            "The request is not authorized.",
        );
    }
    let csrf_for_auth = csrf.clone();
    let session = match login_job(state.clone(), move |login| {
        login.authenticate(&session_token, Some(&csrf_for_auth))
    })
    .await
    {
        Ok(session) => session,
        Err(_) => return login_redirect(true),
    };
    let owner = session.username;
    let slug = fields[1].clone();
    let correlation_id = request_id.0.clone();
    let owner_for_job = owner.clone();
    let slug_for_job = slug.clone();
    let result = repository_job(state, move |repositories| {
        repositories.create_for_account(
            &owner_for_job,
            &slug_for_job,
            gix::hash::Kind::Sha1,
            &correlation_id,
        )
    })
    .await;
    match result {
        Ok(_) => Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, format!("/{owner}/{slug}"))
            .body(Body::empty())
            .expect("the repository redirect is valid"),
        Err(RepositoryServiceError::Auth(_)) | Err(RepositoryServiceError::RepositoryName(_)) => {
            repository_form_error(
                &request_id.0,
                StatusCode::BAD_REQUEST,
                "The repository name is not valid.",
            )
        }
        Err(RepositoryServiceError::Store(StoreError::RepositoryExists(_, _))) => {
            repository_form_error(
                &request_id.0,
                StatusCode::CONFLICT,
                "A repository with this name already exists.",
            )
        }
        Err(_) => repository_form_error(
            &request_id.0,
            StatusCode::INTERNAL_SERVER_ERROR,
            "The repository could not be created.",
        ),
    }
}

fn repository_form_error(request_id: &str, status: StatusCode, message: &str) -> Response {
    render_error(status, request_id, "Repository error", message)
}

async fn logout_form(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Response {
    let Some(session_token) = cookie(&headers, SESSION_COOKIE) else {
        return login_redirect(false);
    };
    let Some(csrf) = cookie(&headers, CSRF_COOKIE) else {
        return login_redirect(true);
    };
    let csrf_for_auth = csrf.clone();
    let result = login_job(state, move |login| {
        login.authenticate(&session_token, Some(&csrf_for_auth))
    })
    .await;
    match result {
        Ok(_) => render(
            StatusCode::OK,
            &LogoutTemplate {
                request_id: &request_id.0,
                csrf: &csrf,
                signed_in: true,
            },
        ),
        Err(_) => login_redirect(true),
    }
}

async fn logout(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "confirm"]) {
        Ok(fields) => fields,
        Err(()) => {
            return render_error(
                StatusCode::FORBIDDEN,
                &request_id.0,
                "Forbidden",
                "The request is not authorized.",
            );
        }
    };
    let Some(session_token) = cookie(&headers, SESSION_COOKIE) else {
        return login_redirect(true);
    };
    let Some(csrf) = cookie(&headers, CSRF_COOKIE) else {
        return login_redirect(true);
    };
    if fields[0] != csrf {
        return render_error(
            StatusCode::FORBIDDEN,
            &request_id.0,
            "Forbidden",
            "The request is not authorized.",
        );
    }
    if fields[1] != "yes" {
        return Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, "/account")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::empty())
            .expect("the account redirect is valid");
    }
    let result = login_job(state, move |login| {
        let session = login.authenticate(&session_token, Some(&csrf))?;
        login.end_all(&session.username)
    })
    .await;
    if result.is_err() {
        return login_redirect(true);
    }
    login_redirect(true)
}

async fn login_job<T: Send + 'static>(
    state: WebState,
    operation: impl FnOnce(WebLoginService) -> Result<T, SessionError> + Send + 'static,
) -> Result<T, SessionError> {
    let login = state.login.ok_or(SessionError::Unavailable)?;
    let permit = state
        .jobs
        .acquire_owned()
        .await
        .map_err(|_| SessionError::Unavailable)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation(login)
    })
    .await
    .map_err(|_| SessionError::Unavailable)?
}

async fn repository_job<T: Send + 'static>(
    state: WebState,
    operation: impl FnOnce(RepositoryService) -> Result<T, RepositoryServiceError> + Send + 'static,
) -> Result<T, RepositoryServiceError> {
    let repositories = state.repositories.ok_or_else(|| {
        RepositoryServiceError::Store(StoreError::Integrity(
            "repository service is unavailable".to_owned(),
        ))
    })?;
    let permit = state.jobs.acquire_owned().await.map_err(|_| {
        RepositoryServiceError::Store(StoreError::Integrity(
            "repository worker pool is unavailable".to_owned(),
        ))
    })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation(repositories)
    })
    .await
    .map_err(|_| {
        RepositoryServiceError::Store(StoreError::Integrity("repository worker failed".to_owned()))
    })?
}

async fn authenticate_mutation(
    state: WebState,
    headers: &HeaderMap,
    submitted_csrf: &str,
    request_id: &str,
) -> Result<String, Response> {
    let Some(session_token) = cookie(headers, SESSION_COOKIE) else {
        return Err(login_redirect(false));
    };
    let Some(csrf) = cookie(headers, CSRF_COOKIE) else {
        return Err(login_redirect(true));
    };
    if submitted_csrf != csrf {
        return Err(render_error(
            StatusCode::FORBIDDEN,
            request_id,
            "Forbidden",
            "The request is not authorized.",
        ));
    }
    login_job(state, move |login| {
        login.authenticate(&session_token, Some(&csrf))
    })
    .await
    .map(|session| session.username)
    .map_err(|_| login_redirect(true))
}

fn parse_named_form(
    headers: &HeaderMap,
    body: &[u8],
    expected: &[&str],
) -> Result<Vec<String>, ()> {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        != Some("application/x-www-form-urlencoded")
        || !valid_percent_encoding(body)
    {
        return Err(());
    }
    let mut values = vec![None; expected.len()];
    for (name, value) in url::form_urlencoded::parse(body) {
        let Some(index) = expected.iter().position(|candidate| *candidate == name) else {
            return Err(());
        };
        if values[index].is_some() {
            return Err(());
        }
        values[index] = Some(value.into_owned());
    }
    values.into_iter().collect::<Option<Vec<_>>>().ok_or(())
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let value = headers.get(header::COOKIE)?.to_str().ok()?;
    let mut found = None;
    for pair in value.split(';') {
        let (candidate, value) = pair.trim().split_once('=')?;
        if candidate == name {
            if found.is_some() || value.is_empty() || value.len() > 128 {
                return None;
            }
            found = Some(value.to_owned());
        }
    }
    found
}

fn append_cookie(
    headers: &mut HeaderMap,
    name: &str,
    value: &str,
    http_only: bool,
    secure: bool,
    max_age: i64,
) {
    let mut cookie = format!("{name}={value}; Path=/; SameSite=Strict; Max-Age={max_age}");
    if http_only {
        cookie.push_str("; HttpOnly");
    }
    if secure {
        cookie.push_str("; Secure");
    }
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("the session cookie is a header value"),
    );
}

fn login_redirect(clear: bool) -> Response {
    let mut response = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/login")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::empty())
        .expect("the login redirect is valid");
    if clear {
        append_cookie(response.headers_mut(), SESSION_COOKIE, "", true, false, 0);
        append_cookie(response.headers_mut(), CSRF_COOKIE, "", false, false, 0);
    }
    response
}

fn account_redirect() -> Response {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/account")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::empty())
        .expect("the account redirect is valid")
}

fn login_error(request_id: &str, username: &str, error: &str) -> Response {
    render(
        StatusCode::BAD_REQUEST,
        &LoginTemplate {
            request_id,
            username,
            error,
            has_error: true,
            signed_in: false,
        },
    )
}

async fn rejected_login(
    state: WebState,
    request_id: &str,
    username: &str,
    error: &str,
) -> Response {
    let username_for_audit = username.to_owned();
    let correlation_id = request_id.to_owned();
    let _ = login_job(state, move |login| {
        login.record_login_failure(&username_for_audit, &correlation_id)
    })
    .await;
    login_error(request_id, username, error)
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
                signed_in: false,
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
            signed_in: false,
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
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(STYLE))
        .expect("the embedded CSS response is valid")
}

async fn not_found(
    Extension(request_id): Extension<RequestId>,
    Extension(actor): Extension<RequestActor>,
) -> Response {
    render_error_with_auth(
        StatusCode::NOT_FOUND,
        &request_id.0,
        "Page not found",
        "The requested page does not exist.",
        actor.0.is_some(),
    )
}

async fn method_not_allowed(
    Extension(request_id): Extension<RequestId>,
    Extension(actor): Extension<RequestActor>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let mut response = render_error_with_auth(
        StatusCode::METHOD_NOT_ALLOWED,
        &request_id.0,
        "Method not allowed",
        "This page does not accept the request method.",
        actor.0.is_some(),
    );
    let allow = match uri.path() {
        "/signup" | "/recover" | "/login" | "/logout" => "GET, HEAD, POST",
        "/login/verify" | "/login/verify-file" => "POST",
        path if path.ends_with("/git-upload-pack") => "POST",
        _ => "GET, HEAD",
    };
    response.headers_mut().insert(
        header::ALLOW,
        HeaderValue::from_str(allow).expect("the method list is a header value"),
    );
    response
}

async fn response_policy(
    State(state): State<WebState>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = RequestId(format!("{:032x}", rand::random::<u128>()));
    let method = logged_method(request.method());
    let started = Instant::now();
    let _in_flight = state.telemetry.http_start();
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
    state.telemetry.http_finish(
        &request_id.0,
        method,
        response.status().as_u16(),
        started.elapsed(),
    );
    response
}

fn logged_method(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::OPTIONS => "OPTIONS",
        Method::CONNECT => "CONNECT",
        Method::TRACE => "TRACE",
        _ => "OTHER",
    }
}

fn render_home(status: StatusCode, request_id: &str, page: HomePage<'_>) -> Response {
    render(
        status,
        &HomeTemplate {
            request_id,
            owner: page.owner,
            repository: page.repository,
            error: page.error,
            has_error: !page.error.is_empty(),
            signed_in: page.signed_in,
            username: page.username,
            csrf: page.csrf,
            repositories: page
                .repositories
                .iter()
                .map(|repository| HomeRepositoryView {
                    owner: &repository.owner,
                    slug: &repository.slug,
                    visibility: &repository.visibility,
                    state: &repository.state,
                    description: &repository.description,
                    updated_at: repository.updated_at,
                })
                .collect(),
            recent_repositories: page
                .recent_repositories
                .iter()
                .map(|repository| HomeRepositoryView {
                    owner: &repository.owner,
                    slug: &repository.slug,
                    visibility: &repository.visibility,
                    state: &repository.state,
                    description: &repository.description,
                    updated_at: repository.updated_at,
                })
                .collect(),
        },
    )
}

struct HomePage<'a> {
    owner: &'a str,
    repository: &'a str,
    error: &'a str,
    signed_in: bool,
    username: &'a str,
    csrf: &'a str,
    repositories: &'a [crate::store::HomeRepositoryRecord],
    recent_repositories: &'a [crate::store::HomeRepositoryRecord],
}

fn render_error(status: StatusCode, request_id: &str, heading: &str, message: &str) -> Response {
    render_error_with_auth(status, request_id, heading, message, false)
}

fn render_error_with_auth(
    status: StatusCode,
    request_id: &str,
    heading: &str,
    message: &str,
    signed_in: bool,
) -> Response {
    render(
        status,
        &ErrorTemplate {
            request_id,
            status: heading,
            message,
            signed_in,
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

#[derive(Default, serde::Deserialize)]
struct ProfileQuery {
    page: Option<usize>,
}

#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate<'a> {
    request_id: &'a str,
    owner: &'a str,
    repository: &'a str,
    error: &'a str,
    has_error: bool,
    signed_in: bool,
    username: &'a str,
    csrf: &'a str,
    repositories: Vec<HomeRepositoryView<'a>>,
    recent_repositories: Vec<HomeRepositoryView<'a>>,
}

struct HomeRepositoryView<'a> {
    owner: &'a str,
    slug: &'a str,
    visibility: &'a str,
    state: &'a str,
    description: &'a str,
    updated_at: i64,
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate<'a> {
    request_id: &'a str,
    status: &'a str,
    message: &'a str,
    signed_in: bool,
}

#[derive(Template)]
#[template(path = "account.html")]
struct AccountFormTemplate<'a> {
    request_id: &'a str,
    username: &'a str,
    error: &'a str,
    has_error: bool,
    recovery: bool,
    signed_in: bool,
}

#[derive(Template)]
#[template(path = "recovery-code.html")]
struct RecoveryCodeTemplate<'a> {
    request_id: &'a str,
    recovery: &'a str,
    signed_in: bool,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate<'a> {
    request_id: &'a str,
    username: &'a str,
    error: &'a str,
    has_error: bool,
    signed_in: bool,
}

#[derive(Template)]
#[template(path = "login-challenge.html")]
struct LoginChallengeTemplate<'a> {
    request_id: &'a str,
    username: &'a str,
    challenge: &'a str,
    login_csrf: &'a str,
    error: &'a str,
    has_error: bool,
    signed_in: bool,
}

#[derive(Template)]
#[template(path = "login-ssh.html")]
struct LoginSshTemplate<'a> {
    request_id: &'a str,
    command: &'a str,
    secret: &'a str,
    login_csrf: &'a str,
    error: &'a str,
    has_error: bool,
    signed_in: bool,
}

#[derive(Template)]
#[template(path = "account-page.html")]
struct AccountTemplate<'a> {
    request_id: &'a str,
    username: &'a str,
    administrator: bool,
    csrf: &'a str,
    bio: &'a str,
    contact_email: &'a str,
    keys: Vec<AccountKeyView<'a>>,
    active_key_count: usize,
    signed_in: bool,
}

struct AccountKeyView<'a> {
    label: &'a str,
    fingerprint: &'a str,
    created_at: String,
    last_used_at: String,
    active: bool,
}

#[derive(Template)]
#[template(path = "account-key-auth.html")]
struct AccountKeyAuthTemplate<'a> {
    request_id: &'a str,
    heading: &'a str,
    action: &'a str,
    command: &'a str,
    secret: &'a str,
    csrf: &'a str,
    label: &'a str,
    public_key: &'a str,
    fingerprint: &'a str,
    adding: bool,
    signed_in: bool,
}

#[derive(Template)]
#[template(path = "profile.html")]
struct PublicProfileTemplate<'a> {
    request_id: &'a str,
    signed_in: bool,
    username: &'a str,
    bio: &'a str,
    contact_email: &'a str,
    repositories: Vec<HomeRepositoryView<'a>>,
    has_previous: bool,
    has_next: bool,
    previous_page: usize,
    next_page: usize,
}

#[derive(Template)]
#[template(path = "logout.html")]
struct LogoutTemplate<'a> {
    request_id: &'a str,
    csrf: &'a str,
    signed_in: bool,
}

#[derive(Debug, Error)]
pub(crate) enum WebError {
    #[error("HTTP listener error: {0}")]
    Io(#[from] std::io::Error),
    #[error("public Web configuration error: {0}")]
    Public(#[from] public::PublicWebError),
    #[error("canonical URL error: {0}")]
    CanonicalUrl(url::ParseError),
    #[error("public Web configuration error: {0}")]
    PublicConfig(String),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error("HTTP server task failed")]
    Join,
}
