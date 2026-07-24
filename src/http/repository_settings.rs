use askama::Template;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Extension, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use serde::Deserialize;

use crate::repository::{RepositoryService, RepositoryServiceError};
use crate::store::{RepositoryCollaboratorRecord, StoreError};

use super::{
    RequestActor, RequestId, WebState, authenticate_mutation, parse_named_form, render,
    render_error_with_auth,
};

const MAX_SETTINGS_REQUEST_BYTES: usize = 4 * 1024;

pub(super) fn routes() -> Router<WebState> {
    Router::new()
        .route("/{owner}/{repository}/settings", get(settings))
        .route(
            "/{owner}/{repository}/settings/general",
            post(update_general),
        )
        .route(
            "/{owner}/{repository}/settings/collaborators",
            post(update_collaborator),
        )
        .route(
            "/{owner}/{repository}/settings/default-branch",
            post(update_default_branch),
        )
        .route("/{owner}/{repository}/settings/rename", post(rename))
        .route("/{owner}/{repository}/settings/archive", post(archive))
        .route("/{owner}/{repository}/settings/unarchive", post(unarchive))
        .layer(DefaultBodyLimit::max(MAX_SETTINGS_REQUEST_BYTES))
}

async fn settings(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Extension(actor): Extension<RequestActor>,
    Path(path): Path<RepositoryPath>,
    headers: HeaderMap,
) -> Response {
    let Some(actor) = actor.0 else {
        return denied(&request_id.0, false);
    };
    if state.repositories.is_none() {
        return internal(&request_id.0);
    }
    let is_owner = actor == path.owner;
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    match job(state, move |service| {
        service.settings(&owner, &repository, &actor)
    })
    .await
    {
        Ok(settings) => {
            let csrf = super::cookie(&headers, super::CSRF_COOKIE).unwrap_or_default();
            render(
                StatusCode::OK,
                &RepositorySettingsTemplate {
                    request_id: &request_id.0,
                    signed_in: true,
                    owner: &settings.repository.owner,
                    repository: &settings.repository.slug,
                    description: &settings.description,
                    visibility: &settings.repository.visibility,
                    collaborators: &settings.collaborators,
                    default_branch: &settings.default_branch,
                    branches: &settings.branches,
                    is_owner,
                    csrf: &csrf,
                },
            )
        }
        Err(RepositoryServiceError::Store(StoreError::PullRequestDenied)) => {
            denied(&request_id.0, true)
        }
        Err(RepositoryServiceError::Store(StoreError::RepositoryNotFound(_, _))) => {
            not_found(&request_id.0, true)
        }
        Err(_) => internal(&request_id.0),
    }
}

async fn rename(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<RepositoryPath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "new-name"]) {
        Ok(fields) => fields,
        Err(()) => return bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    let new_name = fields[1].clone();
    match job(state, move |service| {
        service.rename_for_owner(&owner, &repository, &new_name, &actor)
    })
    .await
    {
        Ok(()) => Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(
                header::LOCATION,
                format!("/{}/{}/settings", path.owner, fields[1]),
            )
            .body(Body::empty())
            .expect("the repository rename redirect is valid"),
        Err(RepositoryServiceError::Store(StoreError::PullRequestDenied)) => {
            denied(&request_id.0, true)
        }
        Err(
            RepositoryServiceError::RepositoryName(_)
            | RepositoryServiceError::Store(StoreError::RepositoryExists(_, _)),
        ) => bad_request(&request_id.0),
        Err(RepositoryServiceError::Store(StoreError::RepositoryNotFound(_, _))) => {
            not_found(&request_id.0, true)
        }
        Err(_) => internal(&request_id.0),
    }
}

async fn update_general(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<RepositoryPath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "description", "visibility"]) {
        Ok(fields) => fields,
        Err(()) => return bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    let result = job(state, move |service| {
        service.update_settings(&owner, &repository, &actor, &fields[1], &fields[2])
    })
    .await;
    mutation_result(result, &request_id.0, &path)
}

async fn update_collaborator(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<RepositoryPath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "username", "role", "action"]) {
        Ok(fields) => fields,
        Err(()) => return bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    let role = match fields[3].as_str() {
        "set" => Some(fields[2].clone()),
        "remove" => None,
        _ => return bad_request(&request_id.0),
    };
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    let username = fields[1].clone();
    let result = job(state, move |service| {
        service.update_collaborator(&owner, &repository, &actor, &username, role.as_deref())
    })
    .await;
    mutation_result(result, &request_id.0, &path)
}

async fn update_default_branch(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<RepositoryPath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "default-branch"]) {
        Ok(fields) => fields,
        Err(()) => return bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    let result = job(state, move |service| {
        service.update_default_branch(&owner, &repository, &actor, &fields[1])
    })
    .await;
    mutation_result(result, &request_id.0, &path)
}

async fn archive(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<RepositoryPath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "confirm"]) {
        Ok(fields) => fields,
        Err(()) => return bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    if fields[1] != "yes" {
        return redirect(&path);
    }
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    match job(state, move |service| {
        service.archive_for_actor(&owner, &repository, &actor)
    })
    .await
    {
        Ok(()) => Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, "/")
            .body(Body::empty())
            .expect("the archive redirect is valid"),
        Err(RepositoryServiceError::Store(StoreError::PullRequestDenied)) => {
            denied(&request_id.0, true)
        }
        Err(_) => internal(&request_id.0),
    }
}

async fn unarchive(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Path(path): Path<RepositoryPath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fields = match parse_named_form(&headers, &body, &["csrf", "confirm"]) {
        Ok(fields) => fields,
        Err(()) => return bad_request(&request_id.0),
    };
    let actor =
        match authenticate_mutation(state.clone(), &headers, &fields[0], &request_id.0).await {
            Ok(actor) => actor,
            Err(response) => return response,
        };
    if fields[1] != "yes" {
        return Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, "/")
            .body(Body::empty())
            .expect("the unarchive cancellation redirect is valid");
    }
    let owner = path.owner.clone();
    let repository = path.repository.clone();
    match job(state, move |service| {
        service.unarchive_for_owner(&owner, &repository, &actor)
    })
    .await
    {
        Ok(()) => Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(
                header::LOCATION,
                format!("/{}/{}", path.owner, path.repository),
            )
            .body(Body::empty())
            .expect("the unarchive redirect is valid"),
        Err(RepositoryServiceError::Store(StoreError::PullRequestDenied)) => {
            denied(&request_id.0, true)
        }
        Err(RepositoryServiceError::Store(StoreError::RepositoryNotFound(_, _))) => {
            not_found(&request_id.0, true)
        }
        Err(_) => bad_request(&request_id.0),
    }
}

async fn job<T: Send + 'static>(
    state: WebState,
    operation: impl FnOnce(RepositoryService) -> Result<T, RepositoryServiceError> + Send + 'static,
) -> Result<T, RepositoryServiceError> {
    let service = state.repositories.clone().ok_or_else(|| {
        RepositoryServiceError::Store(StoreError::Integrity(
            "repository service is unavailable".to_owned(),
        ))
    })?;
    let permit = state.jobs.acquire_owned().await.map_err(|_| {
        RepositoryServiceError::Store(StoreError::Integrity("Web work queue is closed".to_owned()))
    })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation(service)
    })
    .await
    .map_err(|_| {
        RepositoryServiceError::Store(StoreError::Integrity("Web task stopped".to_owned()))
    })?
}

fn mutation_result(
    result: Result<(), RepositoryServiceError>,
    request_id: &str,
    path: &RepositoryPath,
) -> Response {
    match result {
        Ok(()) => redirect(path),
        Err(RepositoryServiceError::Store(StoreError::PullRequestDenied)) => {
            denied(request_id, true)
        }
        Err(
            RepositoryServiceError::Description
            | RepositoryServiceError::Auth(_)
            | RepositoryServiceError::Git(_)
            | RepositoryServiceError::Store(
                StoreError::InvalidRepositoryVisibility
                | StoreError::InvalidCollaboratorRole
                | StoreError::CollaboratorNotFound(_)
                | StoreError::OwnerCollaborator,
            ),
        ) => bad_request(request_id),
        Err(_) => internal(request_id),
    }
}

fn redirect(path: &RepositoryPath) -> Response {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(
            header::LOCATION,
            format!("/{}/{}/settings", path.owner, path.repository),
        )
        .body(Body::empty())
        .expect("the repository settings redirect is valid")
}

fn denied(request_id: &str, signed_in: bool) -> Response {
    render_error_with_auth(
        StatusCode::FORBIDDEN,
        request_id,
        "Settings denied",
        "You cannot change this repository.",
        signed_in,
    )
}

fn not_found(request_id: &str, signed_in: bool) -> Response {
    render_error_with_auth(
        StatusCode::NOT_FOUND,
        request_id,
        "Repository not found",
        "The repository does not exist.",
        signed_in,
    )
}

fn bad_request(request_id: &str) -> Response {
    render_error_with_auth(
        StatusCode::BAD_REQUEST,
        request_id,
        "Settings error",
        "The repository settings are not valid.",
        true,
    )
}

fn internal(request_id: &str) -> Response {
    render_error_with_auth(
        StatusCode::INTERNAL_SERVER_ERROR,
        request_id,
        "Settings error",
        "The repository settings could not be read.",
        true,
    )
}

#[derive(Deserialize)]
struct RepositoryPath {
    owner: String,
    repository: String,
}

#[derive(Template)]
#[template(path = "repository-settings.html")]
struct RepositorySettingsTemplate<'a> {
    request_id: &'a str,
    signed_in: bool,
    owner: &'a str,
    repository: &'a str,
    description: &'a str,
    visibility: &'a str,
    collaborators: &'a [RepositoryCollaboratorRecord],
    default_branch: &'a str,
    branches: &'a [String],
    is_owner: bool,
    csrf: &'a str,
}
