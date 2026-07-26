use askama::Template;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use serde::Deserialize;

use crate::codec::{decode_ascii_hex, encode_lower_hex};
use crate::git::read::{Comparison, Mergeability};
use crate::git::repository::GitRepositoryError;
use crate::markdown::{self, RenderedMarkdown};
use crate::pull_request::{ActivityPages, NewPullRequest, PullRequestError, PullRequestReview};
use crate::store::StoreError;

use super::filters;
use super::public::{patch_response, stream_patch};
use super::{
    CSRF_COOKIE, RequestActor, RequestId, WebState, authenticate_mutation, cookie,
    parse_named_form, render, render_error, repository_can_manage,
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
            "/{owner}/{repository}/pulls/{number}/revisions/{revision}",
            get(download_revision_patch),
        )
        .route(
            "/{owner}/{repository}/pulls/{number}/edit",
            post(edit_pull_request),
        )
        .route(
            "/{owner}/{repository}/pulls/{number}/state",
            post(change_pull_request_state),
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

async fn download_revision_patch(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Extension(actor): Extension<RequestActor>,
    Path(path): Path<PullRequestRevisionPath>,
) -> Response {
    let Some(service) = state.pull_requests.clone() else {
        return internal(&request_id.0);
    };
    let Some(revision) = path.revision.strip_suffix(".patch") else {
        return bad_request(&request_id.0);
    };
    let Ok(revision) = revision.parse::<i64>() else {
        return bad_request(&request_id.0);
    };
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    let number = path.number;
    let result = job(state.clone(), move || {
        service.compare_page(
            &owner,
            &repository,
            number,
            Some(revision),
            actor.0.as_deref(),
            ActivityPages {
                reviews: 1,
                timeline: 1,
            },
        )
    })
    .await;
    let comparison = match result {
        Ok(comparison) => comparison,
        Err(error) => return read_error(error, &request_id.0),
    };
    let is_public = comparison.detail.repository.visibility == "public";
    let body = match stream_patch(state.jobs.clone(), comparison.comparison.files).await {
        Ok(body) => body,
        Err(()) => return internal(&request_id.0),
    };
    patch_response(
        body,
        &format!(
            "{}-{}-pr-{}-revision-{}.patch",
            path.owner, path.repository, path.number, revision
        ),
        is_public,
    )
}

async fn pull_request_list(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Extension(actor): Extension<RequestActor>,
    Path(path): Path<RepositoryPath>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
) -> Response {
    let Some(service) = state.pull_requests.clone() else {
        return internal(&request_id.0);
    };
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    let signed_in = actor.0.is_some();
    let actor_name = actor.0;
    let can_manage = repository_can_manage(
        state.clone(),
        actor_name.clone(),
        owner.clone(),
        repository.clone(),
    )
    .await;
    let actor_for_list = actor_name.clone();
    let state_filter = query.state.unwrap_or_else(|| "open".to_owned());
    let page_number = query.page.unwrap_or(1);
    if page_number == 0 {
        return bad_request(&request_id.0);
    }
    let state_for_job = state_filter.clone();
    let result = job(state.clone(), move || {
        service.list_page(
            &owner,
            &repository,
            actor_for_list.as_deref(),
            &state_for_job,
            page_number,
        )
    })
    .await;
    match result {
        Ok((record, page, can_create)) => {
            let csrf = cookie(&headers, CSRF_COOKIE).unwrap_or_default();
            let branches = match state.public.as_ref() {
                Some(public) => match public
                    .branch_names(actor_name, record.owner.clone(), record.slug.clone())
                    .await
                {
                    Ok(branches) => branches,
                    Err(_) => return internal(&request_id.0),
                },
                None => Vec::new(),
            };
            let default_owner = record.owner.clone();
            let default_repository = record.slug.clone();
            let default_branch = super::repository_job(state, move |repositories| {
                repositories.default_branch(&default_owner, &default_repository)
            })
            .await;
            let default_branch = match default_branch {
                Ok(default_branch) => default_branch,
                Err(_) => return internal(&request_id.0),
            };
            render(
                StatusCode::OK,
                &PullRequestListTemplate {
                    request_id: &request_id.0,
                    signed_in,
                    can_manage,
                    owner: &record.owner,
                    repository: &record.slug,
                    pull_requests: page
                        .items
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
                    branches,
                    default_branch: &default_branch,
                    state: &state_filter,
                    state_all: state_filter == "all",
                    state_open: state_filter == "open",
                    state_closed: state_filter == "closed",
                    state_merged: state_filter == "merged",
                    has_previous: page.page > 1,
                    has_next: page.has_next,
                    previous_page: page.page.saturating_sub(1),
                    next_page: page.page.saturating_add(1),
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
    let can_manage = repository_can_manage(
        state.clone(),
        actor.0.clone(),
        owner.clone(),
        repository.clone(),
    )
    .await;
    let reviews_page = query.reviews_page.unwrap_or(1);
    let timeline_page = query.timeline_page.unwrap_or(1);
    if reviews_page == 0 || timeline_page == 0 {
        return bad_request(&request_id.0);
    }
    let result = job(state, move || {
        service.compare_page(
            &owner,
            &repository,
            path.number,
            query.revision,
            actor.0.as_deref(),
            ActivityPages {
                reviews: reviews_page,
                timeline: timeline_page,
            },
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
                    can_manage,
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
                    can_edit: detail.can_edit && !csrf.is_empty(),
                    can_change_state: detail.can_change_state && !csrf.is_empty(),
                    is_open: pull_request.state == "open",
                    reviews_page: detail.reviews_page,
                    reviews_has_previous: detail.reviews_page > 1,
                    reviews_has_next: detail.reviews_has_next,
                    reviews_previous_page: detail.reviews_page.saturating_sub(1),
                    reviews_next_page: detail.reviews_page.saturating_add(1),
                    timeline_page: detail.timeline_page,
                    timeline_has_previous: detail.timeline_page > 1,
                    timeline_has_next: detail.timeline_has_next,
                    timeline_previous_page: detail.timeline_page.saturating_sub(1),
                    timeline_next_page: detail.timeline_page.saturating_add(1),
                },
            )
        }
        Err(error) => read_error(error, &request_id.0),
    }
}

async fn edit_pull_request(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<PullRequestPath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "title", "body"]) {
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
        service.edit(&owner, &repository, number, &actor, &fields[1], &fields[2])
    })
    .await;
    match result {
        Ok(()) => redirect(&path.owner, &path.repository, path.number),
        Err(error) => mutation_error(error, &request_id.0),
    }
}

async fn change_pull_request_state(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<PullRequestPath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "state"]) {
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
        service.set_state(&owner, &repository, number, &actor, &fields[1])
    })
    .await;
    match result {
        Ok(()) => redirect(&path.owner, &path.repository, path.number),
        Err(error) => mutation_error(error, &request_id.0),
    }
}

async fn merge_pull_request(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<PullRequestPath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "method", "confirm"]) {
        Ok(fields) => fields,
        Err(()) => return bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    if fields[2] != "yes" {
        return redirect(&path.owner, &path.repository, path.number);
    }
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
        &["csrf", "revision", "kind", "body", "path-hex", "anchor"],
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
    let (side, line) = match parse_review_anchor(&fields[5]) {
        Ok(anchor) => anchor,
        Err(()) => return bad_request(&request_id.0),
    };
    let Some(service) = state.pull_requests.clone() else {
        return internal(&request_id.0);
    };
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    let number = path.number;
    let result = job(state, move || {
        service.review(&PullRequestReview {
            owner: &owner,
            repository: &repository,
            number,
            revision,
            actor: &actor,
            kind: &fields[2],
            body: &fields[3],
            path: path_bytes.as_deref(),
            side: side.as_deref(),
            line,
        })
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
        service.open(&NewPullRequest {
            owner: &owner,
            repository: &repository,
            actor: &actor,
            title: &fields[1],
            body: &fields[2],
            base_ref: &fields[3],
            head_ref: &fields[4],
        })
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
        | PullRequestError::State
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
        | PullRequestError::State
        | PullRequestError::Unchanged
        | PullRequestError::Revision
        | PullRequestError::ReviewKind
        | PullRequestError::ReviewBody
        | PullRequestError::ReviewAnchor
        | PullRequestError::MergeMethod
        | PullRequestError::Store(StoreError::PullRequestRevisionNotFound)
        | PullRequestError::Store(StoreError::PullRequestReviewAnchor)
        | PullRequestError::Git(GitRepositoryError::MissingReference(_)) => bad_request(request_id),
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
    decode_ascii_hex(value.as_bytes())
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

#[derive(Clone, Deserialize)]
struct PullRequestRevisionPath {
    owner: String,
    repository: String,
    number: i64,
    revision: String,
}

#[derive(Clone, Default, Deserialize)]
struct RevisionQuery {
    revision: Option<i64>,
    reviews_page: Option<usize>,
    timeline_page: Option<usize>,
}

#[derive(Clone, Default, Deserialize)]
struct ListQuery {
    state: Option<String>,
    page: Option<usize>,
}

#[derive(Template)]
#[template(path = "pull_requests.html")]
struct PullRequestListTemplate<'a> {
    request_id: &'a str,
    signed_in: bool,
    can_manage: bool,
    owner: &'a str,
    repository: &'a str,
    pull_requests: Vec<PullRequestListItem<'a>>,
    csrf: &'a str,
    can_create: bool,
    branches: Vec<String>,
    default_branch: &'a str,
    state: &'a str,
    state_all: bool,
    state_open: bool,
    state_closed: bool,
    state_merged: bool,
    has_previous: bool,
    has_next: bool,
    previous_page: usize,
    next_page: usize,
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
    can_manage: bool,
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
    can_edit: bool,
    can_change_state: bool,
    is_open: bool,
    reviews_page: usize,
    reviews_has_previous: bool,
    reviews_has_next: bool,
    reviews_previous_page: usize,
    reviews_next_page: usize,
    timeline_page: usize,
    timeline_has_previous: bool,
    timeline_has_next: bool,
    timeline_previous_page: usize,
    timeline_next_page: usize,
}

struct ReviewView<'a> {
    id: &'a str,
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
    lines: Vec<DiffLineView>,
}

struct DiffLineView {
    kind: &'static str,
    marker: &'static str,
    text: String,
    base_line: i64,
    head_line: i64,
    base_anchor: String,
    head_anchor: String,
    has_base: bool,
    has_head: bool,
    is_hunk: bool,
    is_meta: bool,
}

impl From<&Comparison> for ComparisonView {
    fn from(comparison: &Comparison) -> Self {
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
                    path_hex: encode_lower_hex(&file.path),
                    binary: file.binary,
                    lines: parse_diff_lines(&String::from_utf8_lossy(&file.hunks)),
                })
                .collect(),
        }
    }
}

fn parse_review_anchor(value: &str) -> Result<(Option<String>, Option<i64>), ()> {
    if value.is_empty() {
        return Ok((None, None));
    }
    let (side, line) = value.split_once(':').ok_or(())?;
    if !matches!(side, "base" | "head") || line.contains(':') {
        return Err(());
    }
    let line = line.parse::<i64>().map_err(|_| ())?;
    if line < 1 {
        return Err(());
    }
    Ok((Some(side.to_owned()), Some(line)))
}

fn parse_diff_lines(hunks: &str) -> Vec<DiffLineView> {
    let mut base_line = 0;
    let mut head_line = 0;
    let mut lines = Vec::new();
    for source in hunks.lines() {
        if source.starts_with("@@") {
            if let Some((base, head)) = parse_hunk_starts(source) {
                base_line = base;
                head_line = head;
            }
            lines.push(diff_meta_line(source, true));
        } else if let Some(text) = source.strip_prefix('-') {
            lines.push(diff_content_line(
                "deletion",
                "-",
                text,
                Some(base_line),
                None,
            ));
            base_line += 1;
        } else if let Some(text) = source.strip_prefix('+') {
            lines.push(diff_content_line(
                "addition",
                "+",
                text,
                None,
                Some(head_line),
            ));
            head_line += 1;
        } else if let Some(text) = source.strip_prefix(' ') {
            lines.push(diff_content_line(
                "context",
                " ",
                text,
                Some(base_line),
                Some(head_line),
            ));
            base_line += 1;
            head_line += 1;
        } else {
            lines.push(diff_meta_line(source, false));
        }
    }
    lines
}

fn parse_hunk_starts(header: &str) -> Option<(i64, i64)> {
    let mut fields = header.split_whitespace();
    (fields.next()? == "@@").then_some(())?;
    let base = parse_hunk_start(fields.next()?, '-')?;
    let head = parse_hunk_start(fields.next()?, '+')?;
    Some((base, head))
}

fn parse_hunk_start(range: &str, prefix: char) -> Option<i64> {
    range.strip_prefix(prefix)?.split(',').next()?.parse().ok()
}

fn diff_meta_line(text: &str, is_hunk: bool) -> DiffLineView {
    DiffLineView {
        kind: if is_hunk { "hunk" } else { "meta" },
        marker: "",
        text: text.to_owned(),
        base_line: 0,
        head_line: 0,
        base_anchor: String::new(),
        head_anchor: String::new(),
        has_base: false,
        has_head: false,
        is_hunk,
        is_meta: !is_hunk,
    }
}

fn diff_content_line(
    kind: &'static str,
    marker: &'static str,
    text: &str,
    base: Option<i64>,
    head: Option<i64>,
) -> DiffLineView {
    DiffLineView {
        kind,
        marker,
        text: text.to_owned(),
        base_line: base.unwrap_or_default(),
        head_line: head.unwrap_or_default(),
        base_anchor: base.map_or_else(String::new, |line| format!("base:{line}")),
        head_anchor: head.map_or_else(String::new, |line| format!("head:{line}")),
        has_base: base.is_some(),
        has_head: head.is_some(),
        is_hunk: false,
        is_meta: false,
    }
}

#[cfg(test)]
mod diff_view_tests {
    use super::{parse_diff_lines, parse_review_anchor};

    #[test]
    fn maps_unified_diff_lines_to_visible_comment_anchors() {
        let lines = parse_diff_lines(
            "@@ -2,3 +2,4 @@ heading\n unchanged\n-removed\n+added\n+second addition\n",
        );

        assert!(lines[0].is_hunk);
        assert_eq!(lines[1].base_anchor, "base:2");
        assert_eq!(lines[1].head_anchor, "head:2");
        assert_eq!(lines[2].base_anchor, "base:3");
        assert!(!lines[2].has_head);
        assert_eq!(lines[3].head_anchor, "head:3");
        assert!(!lines[3].has_base);
        assert_eq!(lines[4].head_anchor, "head:4");
    }

    #[test]
    fn accepts_only_explicit_positive_review_anchors() {
        assert_eq!(
            parse_review_anchor("head:12"),
            Ok((Some("head".to_owned()), Some(12)))
        );
        assert_eq!(parse_review_anchor(""), Ok((None, None)));
        assert!(parse_review_anchor("side:12").is_err());
        assert!(parse_review_anchor("base:0").is_err());
        assert!(parse_review_anchor("head:1:2").is_err());
    }
}
