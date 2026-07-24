use askama::Template;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::routing::get;
use serde::Deserialize;

use crate::store::StoreError;
use crate::watch::WatchError;

use super::{
    CSRF_COOKIE, RequestActor, RequestId, WebState, authenticate_mutation, cookie,
    parse_named_form, render, render_error,
};

pub(super) fn routes() -> Router<WebState> {
    Router::new().route(
        "/{owner}/{repository}/watch",
        get(watch_page)
            .post(set_watch)
            .layer(DefaultBodyLimit::max(2048)),
    )
}

async fn watch_page(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Extension(actor): Extension<RequestActor>,
    Path(path): Path<RepositoryPath>,
    headers: HeaderMap,
) -> Response {
    let Some(service) = state.watches.clone() else {
        return watch_internal(&request_id.0);
    };
    let owner = path.owner;
    let repository = path.repository;
    let authenticated = actor.0.is_some();
    let result = watch_job(state, move || {
        service.get(&owner, &repository, actor.0.as_deref())
    })
    .await;
    match result {
        Ok((record, watch)) => {
            let csrf = cookie(&headers, CSRF_COOKIE).unwrap_or_default();
            let watching = watch.is_some();
            render(
                StatusCode::OK,
                &WatchTemplate {
                    request_id: &request_id.0,
                    signed_in: authenticated,
                    owner: &record.owner,
                    repository: &record.slug,
                    csrf: &csrf,
                    can_change: authenticated && !csrf.is_empty(),
                    watching,
                },
            )
        }
        Err(error) => watch_error(error, &request_id.0),
    }
}

async fn set_watch(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<RepositoryPath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "state"]) {
        Ok(fields) => fields,
        Err(()) => return watch_bad_request(&request_id.0),
    };
    let watching = match fields[1].as_str() {
        "watch" => true,
        "unwatch" => false,
        _ => return watch_bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    let Some(service) = state.watches.clone() else {
        return watch_internal(&request_id.0);
    };
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    let result = watch_job(state, move || {
        service.set(&owner, &repository, &actor, watching)
    })
    .await;
    match result {
        Ok(_) => Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(
                header::LOCATION,
                format!("/{}/{}/watch", path.owner, path.repository),
            )
            .header(header::CACHE_CONTROL, "no-store")
            .body(axum::body::Body::empty())
            .expect("the watch redirect is valid"),
        Err(error) => watch_error(error, &request_id.0),
    }
}

async fn watch_job<T: Send + 'static>(
    state: WebState,
    operation: impl FnOnce() -> Result<T, WatchError> + Send + 'static,
) -> Result<T, WatchError> {
    let permit = state.jobs.acquire_owned().await.map_err(|_| {
        WatchError::Store(StoreError::Integrity(
            "watch worker pool is unavailable".to_owned(),
        ))
    })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation()
    })
    .await
    .map_err(|_| WatchError::Store(StoreError::Integrity("watch worker failed".to_owned())))?
}

fn watch_error(error: WatchError, request_id: &str) -> Response {
    match error {
        WatchError::Auth(_)
        | WatchError::RepositoryName(_)
        | WatchError::Store(StoreError::RepositoryNotFound(_, _) | StoreError::WatchDenied) => {
            render_error(
                StatusCode::NOT_FOUND,
                request_id,
                "Not found",
                "The repository was not found.",
            )
        }
        _ => watch_internal(request_id),
    }
}

fn watch_bad_request(request_id: &str) -> Response {
    render_error(
        StatusCode::BAD_REQUEST,
        request_id,
        "Watch error",
        "The watch request is not valid.",
    )
}

fn watch_internal(request_id: &str) -> Response {
    render_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        request_id,
        "Watch error",
        "The watch request could not be completed.",
    )
}

#[derive(Deserialize)]
struct RepositoryPath {
    owner: String,
    repository: String,
}

#[derive(Template)]
#[template(path = "watch.html")]
struct WatchTemplate<'a> {
    request_id: &'a str,
    signed_in: bool,
    owner: &'a str,
    repository: &'a str,
    csrf: &'a str,
    can_change: bool,
    watching: bool,
}
