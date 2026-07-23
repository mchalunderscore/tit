use askama::Template;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Path, State};
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
    headers: HeaderMap,
) -> Response {
    let Some(service) = state.pull_requests.clone() else {
        return internal(&request_id.0);
    };
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    let result = job(state, move || {
        service.get(&owner, &repository, path.number, actor.0.as_deref())
    })
    .await;
    match result {
        Ok(detail) => {
            let csrf = cookie(&headers, CSRF_COOKIE).unwrap_or_default();
            let pull_request = &detail.pull_request;
            render(
                StatusCode::OK,
                &PullRequestTemplate {
                    request_id: &request_id.0,
                    owner: &detail.repository.owner,
                    repository: &detail.repository.slug,
                    pull_request,
                    body_html: markdown::render(&pull_request.body),
                    revisions: &detail.revisions,
                    csrf: &csrf,
                    can_revise: detail.can_revise && !csrf.is_empty(),
                },
            )
        }
        Err(error) => read_error(error, &request_id.0),
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
        | PullRequestError::Git(crate::git::repository::GitRepositoryError::MissingReference(_)) => {
            bad_request(request_id)
        }
        _ => internal(request_id),
    }
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

#[derive(Template)]
#[template(path = "pull_requests.html")]
struct PullRequestListTemplate<'a> {
    request_id: &'a str,
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
    owner: &'a str,
    repository: &'a str,
    pull_request: &'a crate::store::PullRequestRecord,
    body_html: RenderedMarkdown,
    revisions: &'a [crate::store::PullRequestRevisionRecord],
    csrf: &'a str,
    can_revise: bool,
}
