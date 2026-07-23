use askama::Template;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use serde::Deserialize;

use crate::issue::{IssueError, IssueService};
use crate::markdown::{self, RenderedMarkdown};
use crate::store::{IssueDetail, StoreError};

use super::filters;
use super::{
    CSRF_COOKIE, RequestActor, RequestId, WebState, authenticate_mutation, cookie,
    parse_named_form, render, render_error,
};

const MAX_ISSUE_REQUEST_BYTES: usize = 300 * 1024;

pub(super) fn routes() -> Router<WebState> {
    Router::new()
        .route(
            "/{owner}/{repository}/issues",
            get(issue_list).post(create_issue),
        )
        .route("/{owner}/{repository}/issues/{number}", get(issue_detail))
        .route(
            "/{owner}/{repository}/issues/{number}/edit",
            post(edit_issue),
        )
        .route(
            "/{owner}/{repository}/issues/{number}/comments",
            post(comment_issue),
        )
        .route(
            "/{owner}/{repository}/issues/{number}/state",
            post(change_state),
        )
        .route(
            "/{owner}/{repository}/issues/{number}/labels",
            post(change_label),
        )
        .route(
            "/{owner}/{repository}/issues/{number}/assignees",
            post(change_assignee),
        )
        .layer(DefaultBodyLimit::max(MAX_ISSUE_REQUEST_BYTES))
}

async fn issue_list(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Extension(actor): Extension<RequestActor>,
    Path(path): Path<RepositoryPath>,
    headers: HeaderMap,
) -> Response {
    let Some(service) = state.issues.clone() else {
        return issue_read_error(
            IssueError::Store(StoreError::Integrity(
                "issue service is unavailable".to_owned(),
            )),
            &request_id.0,
        );
    };
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    let authenticated = actor.0.is_some();
    let result = issue_job(state, move || {
        service.list(&owner, &repository, actor.0.as_deref())
    })
    .await;
    match result {
        Ok((record, issues)) => {
            let csrf = cookie(&headers, CSRF_COOKIE).unwrap_or_default();
            render(
                StatusCode::OK,
                &IssueListTemplate {
                    request_id: &request_id.0,
                    signed_in: authenticated,
                    owner: &record.owner,
                    repository: &record.slug,
                    issues: issues
                        .iter()
                        .map(|issue| IssueListItem {
                            number: issue.number,
                            title: &issue.title,
                            state: &issue.state,
                            author: &issue.author,
                            updated_at: issue.updated_at,
                        })
                        .collect(),
                    csrf: &csrf,
                    can_create: authenticated && !csrf.is_empty(),
                },
            )
        }
        Err(error) => issue_read_error(error, &request_id.0),
    }
}

async fn issue_detail(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Extension(actor): Extension<RequestActor>,
    Path(path): Path<IssuePath>,
    headers: HeaderMap,
) -> Response {
    let Some(service) = state.issues.clone() else {
        return issue_read_error(
            IssueError::Store(StoreError::Integrity(
                "issue service is unavailable".to_owned(),
            )),
            &request_id.0,
        );
    };
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    let number = path.number;
    let result = issue_job(state, move || {
        service.get(&owner, &repository, number, actor.0.as_deref())
    })
    .await;
    match result {
        Ok(detail) => render_issue(&request_id.0, &headers, &detail),
        Err(error) => issue_read_error(error, &request_id.0),
    }
}

async fn create_issue(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<RepositoryPath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "title", "body"]) {
        Ok(fields) => fields,
        Err(()) => return issue_bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    let Some(service) = state.issues.clone() else {
        return issue_internal(&request_id.0);
    };
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    let result = issue_job(state, move || {
        service.create(&owner, &repository, &actor, &fields[1], &fields[2])
    })
    .await;
    match result {
        Ok(issue) => issue_redirect(&path.owner, &path.repository, issue.number),
        Err(error) => issue_mutation_error(error, &request_id.0),
    }
}

async fn edit_issue(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<IssuePath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "title", "body"]) {
        Ok(fields) => fields,
        Err(()) => return issue_bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    mutate(state, request_id, path, move |service, path| {
        service.edit(
            &path.owner,
            &path.repository,
            path.number,
            &actor,
            &fields[1],
            &fields[2],
        )
    })
    .await
}

async fn comment_issue(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<IssuePath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "body"]) {
        Ok(fields) => fields,
        Err(()) => return issue_bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    mutate(state, request_id, path, move |service, path| {
        service
            .comment(
                &path.owner,
                &path.repository,
                path.number,
                &actor,
                &fields[1],
            )
            .map(|_| ())
    })
    .await
}

async fn change_state(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<IssuePath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "state"]) {
        Ok(fields) => fields,
        Err(()) => return issue_bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    mutate(state, request_id, path, move |service, path| {
        service.set_state(
            &path.owner,
            &path.repository,
            path.number,
            &actor,
            &fields[1],
        )
    })
    .await
}

async fn change_label(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<IssuePath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "label", "operation"]) {
        Ok(fields) => fields,
        Err(()) => return issue_bad_request(&request_id.0),
    };
    let present = match operation(&fields[2]) {
        Ok(present) => present,
        Err(()) => return issue_bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    mutate(state, request_id, path, move |service, path| {
        service.set_label(
            &path.owner,
            &path.repository,
            path.number,
            &actor,
            &fields[1],
            present,
        )
    })
    .await
}

async fn change_assignee(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<IssuePath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "assignee", "operation"]) {
        Ok(fields) => fields,
        Err(()) => return issue_bad_request(&request_id.0),
    };
    let present = match operation(&fields[2]) {
        Ok(present) => present,
        Err(()) => return issue_bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    mutate(state, request_id, path, move |service, path| {
        service.set_assignee(
            &path.owner,
            &path.repository,
            path.number,
            &actor,
            &fields[1],
            present,
        )
    })
    .await
}

async fn mutate(
    state: WebState,
    request_id: RequestId,
    path: IssuePath,
    operation: impl FnOnce(IssueService, &IssuePath) -> Result<(), IssueError> + Send + 'static,
) -> Response {
    let Some(service) = state.issues.clone() else {
        return issue_internal(&request_id.0);
    };
    let redirect_owner = path.owner.clone();
    let redirect_repository = path.repository.clone();
    let redirect_number = path.number;
    let result = issue_job(state, move || operation(service, &path)).await;
    match result {
        Ok(()) => issue_redirect(&redirect_owner, &redirect_repository, redirect_number),
        Err(error) => issue_mutation_error(error, &request_id.0),
    }
}

async fn issue_job<T: Send + 'static>(
    state: WebState,
    operation: impl FnOnce() -> Result<T, IssueError> + Send + 'static,
) -> Result<T, IssueError> {
    let permit = state.jobs.acquire_owned().await.map_err(|_| {
        IssueError::Store(StoreError::Integrity(
            "issue worker pool is unavailable".to_owned(),
        ))
    })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation()
    })
    .await
    .map_err(|_| IssueError::Store(StoreError::Integrity("issue worker failed".to_owned())))?
}

fn operation(value: &str) -> Result<bool, ()> {
    match value {
        "add" => Ok(true),
        "remove" => Ok(false),
        _ => Err(()),
    }
}

fn render_issue(request_id: &str, headers: &HeaderMap, detail: &IssueDetail) -> Response {
    let csrf = cookie(headers, CSRF_COOKIE).unwrap_or_default();
    render(
        StatusCode::OK,
        &IssueTemplate {
            request_id,
            signed_in: !csrf.is_empty(),
            owner: &detail.repository.owner,
            repository: &detail.repository.slug,
            number: detail.issue.number,
            title: &detail.issue.title,
            body: &detail.issue.body,
            body_html: markdown::render(&detail.issue.body),
            state: &detail.issue.state,
            author: &detail.issue.author,
            created_at: detail.issue.created_at,
            updated_at: detail.issue.updated_at,
            labels: &detail.labels,
            assignees: &detail.assignees,
            comments: detail
                .comments
                .iter()
                .map(|comment| CommentView {
                    id: &comment.id,
                    author: &comment.author,
                    body_html: markdown::render(&comment.body),
                    created_at: comment.created_at,
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
            csrf: &csrf,
            can_comment: detail.can_comment && !csrf.is_empty(),
            can_edit: detail.can_edit && !csrf.is_empty(),
            can_maintain: detail.can_maintain && !csrf.is_empty(),
            is_open: detail.issue.state == "open",
        },
    )
}

fn issue_read_error(error: IssueError, request_id: &str) -> Response {
    match error {
        IssueError::Store(
            StoreError::RepositoryNotFound(_, _)
            | StoreError::IssueNotFound(_, _, _)
            | StoreError::IssueDenied
            | StoreError::IssueHidden,
        )
        | IssueError::Auth(_)
        | IssueError::RepositoryName(_)
        | IssueError::Number => render_error(
            StatusCode::NOT_FOUND,
            request_id,
            "Not found",
            "The issue was not found.",
        ),
        _ => issue_internal(request_id),
    }
}

fn issue_mutation_error(error: IssueError, request_id: &str) -> Response {
    match error {
        IssueError::Auth(_)
        | IssueError::RepositoryName(_)
        | IssueError::Number
        | IssueError::Title
        | IssueError::Body
        | IssueError::State
        | IssueError::Label => issue_bad_request(request_id),
        IssueError::Store(StoreError::IssueDenied) => render_error(
            StatusCode::FORBIDDEN,
            request_id,
            "Forbidden",
            "The issue change is not authorized.",
        ),
        IssueError::Store(
            StoreError::IssueState(_)
            | StoreError::IssueLabelState
            | StoreError::IssueAssigneeState,
        ) => render_error(
            StatusCode::CONFLICT,
            request_id,
            "Issue conflict",
            "The issue already has the requested state.",
        ),
        IssueError::Store(
            StoreError::RepositoryNotFound(_, _)
            | StoreError::IssueNotFound(_, _, _)
            | StoreError::IssueAssigneeNotFound(_)
            | StoreError::IssueHidden,
        ) => render_error(
            StatusCode::NOT_FOUND,
            request_id,
            "Not found",
            "The issue or account was not found.",
        ),
        _ => issue_internal(request_id),
    }
}

fn issue_bad_request(request_id: &str) -> Response {
    render_error(
        StatusCode::BAD_REQUEST,
        request_id,
        "Issue error",
        "The issue request is not valid.",
    )
}

fn issue_internal(request_id: &str) -> Response {
    render_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        request_id,
        "Issue error",
        "The issue request could not be completed.",
    )
}

fn issue_redirect(owner: &str, repository: &str, number: i64) -> Response {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(
            header::LOCATION,
            format!("/{owner}/{repository}/issues/{number}"),
        )
        .header(header::CACHE_CONTROL, "no-store")
        .body(axum::body::Body::empty())
        .expect("the issue redirect is valid")
}

#[derive(Clone, Deserialize)]
struct RepositoryPath {
    owner: String,
    repository: String,
}

#[derive(Clone, Deserialize)]
struct IssuePath {
    owner: String,
    repository: String,
    number: i64,
}

#[derive(Template)]
#[template(path = "issues.html")]
struct IssueListTemplate<'a> {
    request_id: &'a str,
    signed_in: bool,
    owner: &'a str,
    repository: &'a str,
    issues: Vec<IssueListItem<'a>>,
    csrf: &'a str,
    can_create: bool,
}

struct IssueListItem<'a> {
    number: i64,
    title: &'a str,
    state: &'a str,
    author: &'a str,
    updated_at: i64,
}

#[derive(Template)]
#[template(path = "issue.html")]
struct IssueTemplate<'a> {
    request_id: &'a str,
    signed_in: bool,
    owner: &'a str,
    repository: &'a str,
    number: i64,
    title: &'a str,
    body: &'a str,
    body_html: RenderedMarkdown,
    state: &'a str,
    author: &'a str,
    created_at: i64,
    updated_at: i64,
    labels: &'a [String],
    assignees: &'a [String],
    comments: Vec<CommentView<'a>>,
    timeline: Vec<TimelineView<'a>>,
    csrf: &'a str,
    can_comment: bool,
    can_edit: bool,
    can_maintain: bool,
    is_open: bool,
}

struct CommentView<'a> {
    id: &'a str,
    author: &'a str,
    body_html: RenderedMarkdown,
    created_at: i64,
}

struct TimelineView<'a> {
    sequence: i64,
    kind: &'a str,
    actor: &'a str,
    created_at: i64,
}
