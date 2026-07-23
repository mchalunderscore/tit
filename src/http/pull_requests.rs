use askama::Template;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use serde::Deserialize;

use crate::markdown::{self, RenderedMarkdown};
use crate::pull_request::PullRequestError;
use crate::store::StoreError;

use super::{
    CSRF_COOKIE, RequestActor, RequestId, WebState, authenticate_mutation, cookie,
    parse_named_form, render, render_error,
};

const MAX_PULL_REQUEST_BYTES: usize = 300 * 1024;

pub(super) fn routes() -> Router<WebState> {
    Router::new()
        .route(
            "/{owner}/{repository}/pulls",
            get(pull_request_list).post(open_pull_request),
        )
        .route(
            "/{owner}/{repository}/pulls/{number}",
            get(pull_request_detail),
        )
        .route(
            "/{owner}/{repository}/pulls/{number}/revisions",
            post(revise_pull_request),
        )
        .route(
            "/{owner}/{repository}/pulls/{number}/reviews",
            post(create_review),
        )
        .route(
            "/{owner}/{repository}/pulls/{number}/merge",
            post(merge_pull_request),
        )
        .layer(DefaultBodyLimit::max(MAX_PULL_REQUEST_BYTES))
}

async fn pull_request_list(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Extension(actor): Extension<RequestActor>,
    Path(path): Path<RepositoryPath>,
    headers: HeaderMap,
) -> Response {
    let Some(service) = state.pull_requests.clone() else {
        return internal(&request_id.0);
    };
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    let signed_in = actor.0.is_some();
    let result = job(state, move || {
        service.list(&owner, &repository, actor.0.as_deref())
    })
    .await;
    match result {
        Ok((record, pull_requests, can_create)) => {
            let csrf = cookie(&headers, CSRF_COOKIE).unwrap_or_default();
            render(
                StatusCode::OK,
                &PullRequestListTemplate {
                    request_id: &request_id.0,
                    signed_in,
                    owner: &record.owner,
                    repository: &record.slug,
                    pull_requests: pull_requests
                        .iter()
                        .map(|pull_request| PullRequestListItem {
                            number: pull_request.number,
                            title: &pull_request.title,
                            state: &pull_request.state,
                            author: &pull_request.author,
                            updated_at: pull_request.updated_at,
                        })
                        .collect(),
                    csrf: &csrf,
                    can_create: can_create && !csrf.is_empty(),
                },
            )
        }
        Err(error) => read_error(error, &request_id.0),
    }
}

async fn pull_request_detail(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Extension(actor): Extension<RequestActor>,
    Path(path): Path<PullRequestPath>,
    Query(query): Query<RevisionQuery>,
    headers: HeaderMap,
) -> Response {
    let Some(service) = state.pull_requests.clone() else {
        return internal(&request_id.0);
    };
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    let signed_in = actor.0.is_some();
    let result = job(state, move || {
        service.compare(
            &owner,
            &repository,
            path.number,
            query.revision,
            actor.0.as_deref(),
        )
    })
    .await;
    match result {
        Ok(result) => {
            let csrf = cookie(&headers, CSRF_COOKIE).unwrap_or_default();
            let detail = &result.detail;
            let pull_request = &detail.pull_request;
            render(
                StatusCode::OK,
                &PullRequestTemplate {
                    request_id: &request_id.0,
                    signed_in,
                    owner: &detail.repository.owner,
                    repository: &detail.repository.slug,
                    pull_request,
                    body_html: markdown::render(&pull_request.body),
                    revisions: &detail.revisions,
                    reviews: detail
                        .reviews
                        .iter()
                        .map(|review| ReviewView {
                            id: &review.id,
                            revision: review.revision,
                            author: &review.author,
                            kind: &review.kind,
                            body_html: markdown::render(&review.body),
                            has_body: !review.body.is_empty(),
                            commit_object_id: review.commit_object_id.as_deref().unwrap_or(""),
                            path: review
                                .path
                                .as_deref()
                                .map(|path| String::from_utf8_lossy(path).into_owned())
                                .unwrap_or_default(),
                            side: review.side.as_deref().unwrap_or(""),
                            line: review
                                .line
                                .map_or_else(String::new, |line| line.to_string()),
                            outdated: review.kind == "line-comment"
                                && review.revision != pull_request_revision(detail),
                            created_at: review.created_at,
                        })
                        .collect(),
                    timeline: detail
                        .timeline
                        .iter()
                        .map(|event| TimelineView {
                            sequence: event.sequence,
                            kind: &event.kind,
                            actor: &event.actor,
                            created_at: event.created_at,
                        })
                        .collect(),
                    selected_revision: result.revision.number,
                    comparison: ComparisonView::from(&result.comparison),
                    csrf: &csrf,
                    can_revise: detail.can_revise && !csrf.is_empty(),
                    can_review: detail.can_review
                        && !csrf.is_empty()
                        && result.revision.number == pull_request_revision(detail),
                    can_merge: detail.can_merge
                        && !csrf.is_empty()
                        && result.revision.number == pull_request_revision(detail),
                },
            )
        }
        Err(error) => read_error(error, &request_id.0),
    }
}

async fn merge_pull_request(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<PullRequestPath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "method"]) {
        Ok(fields) => fields,
        Err(()) => return bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    let Some(service) = state.pull_requests.clone() else {
        return internal(&request_id.0);
    };
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    let number = path.number;
    let result = job(state, move || {
        service.merge(&owner, &repository, number, &actor, &fields[1])
    })
    .await;
    match result {
        Ok(_) => redirect(&path.owner, &path.repository, number),
        Err(error) => mutation_error(error, &request_id.0),
    }
}

async fn create_review(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<PullRequestPath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(
        &headers,
        &body,
        &[
            "csrf", "revision", "kind", "body", "path-hex", "side", "line",
        ],
    ) {
        Ok(fields) => fields,
        Err(()) => return bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    let revision = match fields[1].parse::<i64>() {
        Ok(revision) => revision,
        Err(_) => return bad_request(&request_id.0),
    };
    let path_bytes = if fields[4].is_empty() {
        None
    } else {
        match decode_hex(&fields[4]) {
            Some(path) => Some(path),
            None => return bad_request(&request_id.0),
        }
    };
    let side = (!fields[5].is_empty()).then(|| fields[5].clone());
    let line = if fields[6].is_empty() {
        None
    } else {
        match fields[6].parse::<i64>() {
            Ok(line) => Some(line),
            Err(_) => return bad_request(&request_id.0),
        }
    };
    let Some(service) = state.pull_requests.clone() else {
        return internal(&request_id.0);
    };
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    let number = path.number;
    let result = job(state, move || {
        service.review(
            &owner,
            &repository,
            number,
            revision,
            &actor,
            &fields[2],
            &fields[3],
            path_bytes.as_deref(),
            side.as_deref(),
            line,
        )
    })
    .await;
    match result {
        Ok(_) => redirect(&path.owner, &path.repository, number),
        Err(error) => mutation_error(error, &request_id.0),
    }
}

async fn open_pull_request(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<RepositoryPath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(
        &headers,
        &body,
        &["csrf", "title", "body", "base-ref", "head-ref"],
    ) {
        Ok(fields) => fields,
        Err(()) => return bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    let Some(service) = state.pull_requests.clone() else {
        return internal(&request_id.0);
    };
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    let result = job(state, move || {
        service.open(
            &owner,
            &repository,
            &actor,
            &fields[1],
            &fields[2],
            &fields[3],
            &fields[4],
        )
    })
    .await;
    match result {
        Ok(pull_request) => redirect(&path.owner, &path.repository, pull_request.number),
        Err(error) => mutation_error(error, &request_id.0),
    }
}

async fn revise_pull_request(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<PullRequestPath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf"]) {
        Ok(fields) => fields,
        Err(()) => return bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    let Some(service) = state.pull_requests.clone() else {
        return internal(&request_id.0);
    };
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    let number = path.number;
    let result = job(state, move || {
        service.revise(&owner, &repository, number, &actor)
    })
    .await;
    match result {
        Ok(_) => redirect(&path.owner, &path.repository, number),
        Err(error) => mutation_error(error, &request_id.0),
    }
}

async fn job<T: Send + 'static>(
    state: WebState,
    operation: impl FnOnce() -> Result<T, PullRequestError> + Send + 'static,
) -> Result<T, PullRequestError> {
    let permit = state.jobs.acquire_owned().await.map_err(|_| {
        PullRequestError::Store(StoreError::Integrity("Web work queue is closed".to_owned()))
    })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation()
    })
    .await
    .map_err(|_| PullRequestError::Store(StoreError::Integrity("Web task stopped".to_owned())))?
}

fn read_error(error: PullRequestError, request_id: &str) -> Response {
    match error {
        PullRequestError::Store(
            StoreError::RepositoryNotFound(_, _)
            | StoreError::PullRequestNotFound(_, _, _)
            | StoreError::PullRequestHidden,
        ) => render_error(
            StatusCode::NOT_FOUND,
            request_id,
            "Not found",
            "The pull request was not found.",
        ),
        PullRequestError::Number
        | PullRequestError::Revision
        | PullRequestError::Auth(_)
        | PullRequestError::RepositoryName(_) => bad_request(request_id),
        _ => internal(request_id),
    }
}

fn mutation_error(error: PullRequestError, request_id: &str) -> Response {
    match error {
        PullRequestError::Store(StoreError::PullRequestDenied) => render_error(
            StatusCode::FORBIDDEN,
            request_id,
            "Pull-request error",
            "You cannot change pull requests in this repository.",
        ),
        PullRequestError::Store(StoreError::PullRequestState) => render_error(
            StatusCode::CONFLICT,
            request_id,
            "Pull-request conflict",
            "The pull request is not open.",
        ),
        PullRequestError::Store(
            StoreError::RepositoryNotFound(_, _)
            | StoreError::PullRequestNotFound(_, _, _)
            | StoreError::PullRequestHidden,
        ) => read_error(error, request_id),
        PullRequestError::Title
        | PullRequestError::Body
        | PullRequestError::Branch
        | PullRequestError::Number
        | PullRequestError::Unchanged
        | PullRequestError::Revision
        | PullRequestError::ReviewKind
        | PullRequestError::ReviewBody
        | PullRequestError::ReviewAnchor
        | PullRequestError::MergeMethod
        | PullRequestError::Store(StoreError::PullRequestRevisionNotFound)
        | PullRequestError::Store(StoreError::PullRequestReviewAnchor)
        | PullRequestError::Git(crate::git::repository::GitRepositoryError::MissingReference(_)) => {
            bad_request(request_id)
        }
        PullRequestError::StaleRevision | PullRequestError::Mergeability => render_error(
            StatusCode::CONFLICT,
            request_id,
            "Pull-request conflict",
            "The pull request cannot be merged in its current state.",
        ),
        _ => internal(request_id),
    }
}

fn pull_request_revision(detail: &crate::store::PullRequestDetail) -> i64 {
    detail
        .revisions
        .last()
        .map_or(0, |revision| revision.number)
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

fn bad_request(request_id: &str) -> Response {
    render_error(
        StatusCode::BAD_REQUEST,
        request_id,
        "Pull-request error",
        "The pull-request request is not valid.",
    )
}

fn internal(request_id: &str) -> Response {
    render_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        request_id,
        "Pull-request error",
        "The pull-request request could not be completed.",
    )
}

fn redirect(owner: &str, repository: &str, number: i64) -> Response {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(
            header::LOCATION,
            format!("/{owner}/{repository}/pulls/{number}"),
        )
        .header(header::CACHE_CONTROL, "no-store")
        .body(axum::body::Body::empty())
        .expect("the pull-request redirect is valid")
}

#[derive(Clone, Deserialize)]
struct RepositoryPath {
    owner: String,
    repository: String,
}

#[derive(Clone, Deserialize)]
struct PullRequestPath {
    owner: String,
    repository: String,
    number: i64,
}

#[derive(Clone, Default, Deserialize)]
struct RevisionQuery {
    revision: Option<i64>,
}

#[derive(Template)]
#[template(path = "pull_requests.html")]
struct PullRequestListTemplate<'a> {
    request_id: &'a str,
    signed_in: bool,
    owner: &'a str,
    repository: &'a str,
    pull_requests: Vec<PullRequestListItem<'a>>,
    csrf: &'a str,
    can_create: bool,
}

struct PullRequestListItem<'a> {
    number: i64,
    title: &'a str,
    state: &'a str,
    author: &'a str,
    updated_at: i64,
}

#[derive(Template)]
#[template(path = "pull_request.html")]
struct PullRequestTemplate<'a> {
    request_id: &'a str,
    signed_in: bool,
    owner: &'a str,
    repository: &'a str,
    pull_request: &'a crate::store::PullRequestRecord,
    body_html: RenderedMarkdown,
    revisions: &'a [crate::store::PullRequestRevisionRecord],
    reviews: Vec<ReviewView<'a>>,
    timeline: Vec<TimelineView<'a>>,
    selected_revision: i64,
    comparison: ComparisonView,
    csrf: &'a str,
    can_revise: bool,
    can_review: bool,
    can_merge: bool,
}

struct ReviewView<'a> {
    id: &'a str,
    revision: i64,
    author: &'a str,
    kind: &'a str,
    body_html: RenderedMarkdown,
    has_body: bool,
    commit_object_id: &'a str,
    path: String,
    side: &'a str,
    line: String,
    outdated: bool,
    created_at: i64,
}

struct TimelineView<'a> {
    sequence: i64,
    kind: &'a str,
    actor: &'a str,
    created_at: i64,
}

struct ComparisonView {
    merge_base: String,
    mergeability: &'static str,
    commits: Vec<CommitView>,
    changed_paths: Vec<String>,
    files: Vec<DiffView>,
}

struct CommitView {
    id: String,
    message: String,
}

struct DiffView {
    path: String,
    path_hex: String,
    binary: bool,
    has_base: bool,
    has_head: bool,
    hunks: String,
}

impl From<&crate::git::read::Comparison> for ComparisonView {
    fn from(comparison: &crate::git::read::Comparison) -> Self {
        use crate::git::read::Mergeability;

        Self {
            merge_base: comparison
                .merge_base
                .map_or_else(|| "none".to_owned(), |id| id.to_string()),
            mergeability: match comparison.mergeability {
                Mergeability::Unrelated => "unrelated histories",
                Mergeability::AlreadyMerged => "already merged",
                Mergeability::FastForward => "fast-forward",
                Mergeability::Clean => "clean merge",
                Mergeability::Conflicting => "conflicts",
            },
            commits: comparison
                .commits
                .iter()
                .map(|commit| CommitView {
                    id: commit.id.to_string(),
                    message: String::from_utf8_lossy(&commit.message).into_owned(),
                })
                .collect(),
            changed_paths: comparison
                .changed_paths
                .iter()
                .map(|path| String::from_utf8_lossy(path).into_owned())
                .collect(),
            files: comparison
                .files
                .iter()
                .map(|file| DiffView {
                    path: String::from_utf8_lossy(&file.path).into_owned(),
                    path_hex: encode_hex(&file.path),
                    binary: file.binary,
                    has_base: file.old_id.is_some(),
                    has_head: file.new_id.is_some(),
                    hunks: String::from_utf8_lossy(&file.hunks).into_owned(),
                })
                .collect(),
        }
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write;
        write!(encoded, "{byte:02x}").expect("a string write cannot fail");
    }
    encoded
}
