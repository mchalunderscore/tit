use askama::Template;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use serde::Deserialize;

use crate::feed::{ActivityFeedPage, FeedFormat, PAGE_SIZE};
use crate::feed_token::{FeedTokenError, IssuedFeedToken};
use crate::store::{FeedTokenRecord, StoreError};

use super::filters;
use super::public::conditional_feed;
use super::{
    CSRF_COOKIE, RequestId, SESSION_COOKIE, WebState, authenticate_mutation, cookie, login_job,
    login_redirect, parse_named_form, render, render_error,
};

pub(super) fn routes() -> Router<WebState> {
    Router::new()
        .route("/feeds", get(feed_tokens))
        .route(
            "/feeds/tokens",
            post(issue_token).layer(DefaultBodyLimit::max(4096)),
        )
        .route(
            "/feeds/tokens/{id}/rotate",
            post(rotate_token).layer(DefaultBodyLimit::max(1024)),
        )
        .route(
            "/feeds/tokens/{id}/revoke",
            post(revoke_token).layer(DefaultBodyLimit::max(1024)),
        )
        .route("/feeds/{token}/atom.xml", get(atom_feed))
        .route("/feeds/{token}/rss.xml", get(rss_feed))
}

async fn feed_tokens(
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
    let actor = match login_job(state.clone(), move |login| {
        login.authenticate(&session_token, Some(&csrf_for_auth))
    })
    .await
    {
        Ok(session) => session.username,
        Err(_) => return login_redirect(true),
    };
    let Some(service) = state.feeds.clone() else {
        return feed_internal(&request_id.0);
    };
    let result = feed_job(state, move || service.list(&actor)).await;
    match result {
        Ok(tokens) => render(
            StatusCode::OK,
            &FeedTokensTemplate {
                request_id: &request_id.0,
                signed_in: true,
                csrf: &csrf,
                tokens: tokens.iter().map(token_view).collect(),
            },
        ),
        Err(_) => feed_internal(&request_id.0),
    }
}

async fn issue_token(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "scope", "owner", "repository"])
    {
        Ok(fields) => fields,
        Err(()) => return feed_bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    let Some(service) = state.feeds.clone() else {
        return feed_internal(&request_id.0);
    };
    let scope = fields[1].clone();
    let owner = nonempty(fields[2].clone());
    let repository = nonempty(fields[3].clone());
    let result = feed_job(state, move || {
        service.issue(&actor, &scope, owner.as_deref(), repository.as_deref())
    })
    .await;
    issued_response(result, &request_id.0)
}

async fn rotate_token(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<TokenIdPath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "confirm"]) {
        Ok(fields) => fields,
        Err(()) => return feed_bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    if fields[1] != "yes" {
        return feed_tokens_redirect();
    }
    let Some(service) = state.feeds.clone() else {
        return feed_internal(&request_id.0);
    };
    let result = feed_job(state, move || service.rotate(&actor, &path.id)).await;
    issued_response(result, &request_id.0)
}

async fn revoke_token(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<TokenIdPath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "confirm"]) {
        Ok(fields) => fields,
        Err(()) => return feed_bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    if fields[1] != "yes" {
        return feed_tokens_redirect();
    }
    let Some(service) = state.feeds.clone() else {
        return feed_internal(&request_id.0);
    };
    let result = feed_job(state, move || service.revoke(&actor, &path.id)).await;
    match result {
        Ok(()) => feed_tokens_redirect(),
        Err(error) => feed_management_error(error, &request_id.0),
    }
}

fn feed_tokens_redirect() -> Response {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/feeds")
        .header(header::CACHE_CONTROL, "no-store")
        .body(axum::body::Body::empty())
        .expect("the feed token redirect is valid")
}

async fn atom_feed(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<TokenPath>,
    headers: HeaderMap,
) -> Response {
    token_feed(state, request_id, path.token, headers, FeedFormat::Atom).await
}

async fn rss_feed(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<TokenPath>,
    headers: HeaderMap,
) -> Response {
    token_feed(state, request_id, path.token, headers, FeedFormat::Rss).await
}

async fn token_feed(
    state: WebState,
    request_id: RequestId,
    token: String,
    headers: HeaderMap,
    format: FeedFormat,
) -> Response {
    let Some(service) = state.feeds.clone() else {
        return feed_not_found(&request_id.0);
    };
    let Some(public) = state.public.clone() else {
        return feed_not_found(&request_id.0);
    };
    let base_url = public.http_clone_base().to_owned();
    let token_for_url = token.clone();
    let result = feed_job(state, move || service.read(&token, PAGE_SIZE)).await;
    let page = match result {
        Ok(page) => page,
        Err(_) => return feed_not_found(&request_id.0),
    };
    let name = match format {
        FeedFormat::Atom => "atom.xml",
        FeedFormat::Rss => "rss.xml",
    };
    let self_url = format!("{base_url}/feeds/{token_for_url}/{name}");
    let newest = page
        .events
        .iter()
        .map(|record| record.event.created_at)
        .max()
        .unwrap_or(0);
    let body = match (ActivityFeedPage {
        base_url: &base_url,
        self_url: &self_url,
        scope: &page.scope,
        username: &page.username,
        target: page.target.as_deref(),
        events: &page.events,
    })
    .render(format)
    {
        Ok(body) => body,
        Err(_) => return feed_internal(&request_id.0),
    };
    conditional_feed(&headers, name, body, newest, false)
}

async fn feed_job<T: Send + 'static>(
    state: WebState,
    operation: impl FnOnce() -> Result<T, FeedTokenError> + Send + 'static,
) -> Result<T, FeedTokenError> {
    let permit = state.jobs.acquire_owned().await.map_err(|_| {
        FeedTokenError::Store(StoreError::Integrity(
            "feed worker pool is unavailable".to_owned(),
        ))
    })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation()
    })
    .await
    .map_err(|_| FeedTokenError::Store(StoreError::Integrity("feed worker failed".to_owned())))?
}

fn issued_response(result: Result<IssuedFeedToken, FeedTokenError>, request_id: &str) -> Response {
    match result {
        Ok(issued) => render(
            StatusCode::CREATED,
            &IssuedFeedTokenTemplate {
                request_id,
                signed_in: true,
                token: &issued.token,
                scope: scope_label(&issued.record.scope),
                target: token_target(&issued.record),
            },
        ),
        Err(error) => feed_management_error(error, request_id),
    }
}

fn token_view(record: &FeedTokenRecord) -> FeedTokenView<'_> {
    FeedTokenView {
        id: &record.id,
        scope: scope_label(&record.scope),
        target: token_target(record),
        created_at: record.created_at,
        active: record.revoked_at.is_none(),
    }
}

fn token_target(record: &FeedTokenRecord) -> String {
    match (&record.owner, &record.repository) {
        (Some(owner), Some(repository)) => format!("{owner}/{repository}"),
        _ => "Your account".to_owned(),
    }
}

fn scope_label(scope: &str) -> &'static str {
    match scope {
        "repository" => "Repository activity",
        "watched" => "Watched activity",
        "assignments" => "Assignments",
        "mentions" => "Mentions",
        _ => "Unknown",
    }
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn feed_management_error(error: FeedTokenError, request_id: &str) -> Response {
    match error {
        FeedTokenError::InvalidScope
        | FeedTokenError::InvalidToken
        | FeedTokenError::Auth(_)
        | FeedTokenError::RepositoryName(_) => feed_bad_request(request_id),
        FeedTokenError::Store(
            StoreError::FeedTokenDenied
            | StoreError::FeedTokenNotFound
            | StoreError::RepositoryNotFound(_, _),
        ) => feed_not_found(request_id),
        FeedTokenError::Store(StoreError::FeedTokenLimit) => render_error(
            StatusCode::TOO_MANY_REQUESTS,
            request_id,
            "Feed token limit",
            "Revoke an active feed token before you create another token.",
        ),
        _ => feed_internal(request_id),
    }
}

fn feed_bad_request(request_id: &str) -> Response {
    render_error(
        StatusCode::BAD_REQUEST,
        request_id,
        "Feed token error",
        "The feed token request is not valid.",
    )
}

fn feed_not_found(request_id: &str) -> Response {
    render_error(
        StatusCode::NOT_FOUND,
        request_id,
        "Feed not found",
        "The feed does not exist.",
    )
}

fn feed_internal(request_id: &str) -> Response {
    render_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        request_id,
        "Feed error",
        "The feed request could not be completed.",
    )
}

#[derive(Deserialize)]
struct TokenPath {
    token: String,
}

#[derive(Deserialize)]
struct TokenIdPath {
    id: String,
}

struct FeedTokenView<'a> {
    id: &'a str,
    scope: &'static str,
    target: String,
    created_at: i64,
    active: bool,
}

#[derive(Template)]
#[template(path = "feed-tokens.html")]
struct FeedTokensTemplate<'a> {
    request_id: &'a str,
    signed_in: bool,
    csrf: &'a str,
    tokens: Vec<FeedTokenView<'a>>,
}

#[derive(Template)]
#[template(path = "feed-token-issued.html")]
struct IssuedFeedTokenTemplate<'a> {
    request_id: &'a str,
    signed_in: bool,
    token: &'a str,
    scope: &'static str,
    target: String,
}
