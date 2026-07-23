use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Extension, OriginalUri, Path as AxumPath, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use gix::bstr::ByteSlice;
use gix::hash::ObjectId;
use gix::objs::tree::EntryKind;
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::{Semaphore, mpsc};
use tokio_stream::wrappers::ReceiverStream;

use crate::auth::validate_username;
use crate::domain::repository::validate_slug;
use crate::git::packetline::MAX_REQUEST_BYTES;
use crate::git::read::{
    BlameHunk, CommitInfo, DiffFile, ReadCancellation, ReadError, ReadLimits,
    RepositoryReadService, TreeEntryInfo,
};
use crate::git::upload_pack::{ProtocolVersion, UploadPack};
use crate::store::{DATABASE_FILE, RepositoryRecord, Store, StoreError};

use super::{PublicWebConfig, RequestId, WebState, render_error};

const MAX_HISTORY_COMMITS: usize = 10_000;
const MAX_SUMMARY_COMMITS: usize = 50;

#[derive(Clone)]
pub(super) struct PublicWeb {
    database: PathBuf,
    repositories: PathBuf,
    http_clone_base: String,
    ssh_clone_base: String,
    jobs: Arc<Semaphore>,
}

impl PublicWeb {
    pub(super) fn open(
        config: PublicWebConfig,
        jobs: Arc<Semaphore>,
    ) -> Result<Self, PublicWebError> {
        let repositories = fs::canonicalize(config.instance_dir.join("repositories"))
            .map_err(PublicWebError::RepositoryDirectory)?;
        if !repositories.is_dir() {
            return Err(PublicWebError::InvalidRepositoryDirectory);
        }
        let database = config.instance_dir.join(DATABASE_FILE);
        Store::open(&database)?;
        let http_clone_base = clone_base(&config.http_clone_base)?;
        let ssh_clone_base = clone_base(&config.ssh_clone_base)?;
        Ok(Self {
            database,
            repositories,
            http_clone_base,
            ssh_clone_base,
            jobs,
        })
    }

    async fn read<T, F>(
        &self,
        owner: String,
        repository: String,
        operation: F,
    ) -> Result<T, RouteError>
    where
        T: Send + 'static,
        F: FnOnce(RepositoryRecord, RepositoryReadService) -> Result<T, RouteError>
            + Send
            + 'static,
    {
        let permit = self
            .jobs
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| RouteError::Unavailable)?;
        let web = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let (repository, path) = web.resolve_repository(&owner, &repository)?;
            let limits = ReadLimits {
                max_history_commits: MAX_HISTORY_COMMITS,
                ..ReadLimits::default()
            };
            let service = RepositoryReadService::open(&path, limits)?;
            operation(repository, service)
        })
        .await
        .map_err(|_| RouteError::Internal)?
    }

    async fn path_job<T, F>(
        &self,
        owner: String,
        repository: String,
        operation: F,
    ) -> Result<T, RouteError>
    where
        T: Send + 'static,
        F: FnOnce(RepositoryRecord, PathBuf) -> Result<T, RouteError> + Send + 'static,
    {
        let permit = self
            .jobs
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| RouteError::Unavailable)?;
        let web = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let (record, path) = web.resolve_repository(&owner, &repository)?;
            operation(record, path)
        })
        .await
        .map_err(|_| RouteError::Internal)?
    }

    fn resolve_repository(
        &self,
        owner: &str,
        repository: &str,
    ) -> Result<(RepositoryRecord, PathBuf), RouteError> {
        if validate_username(owner).is_err() || validate_slug(repository).is_err() {
            return Err(RouteError::NotFound);
        }
        let store = Store::open(&self.database)?;
        let record = store.public_repository(owner, repository)?;
        let candidate = self.repositories.join(format!("{}.git", record.id));
        let path = fs::canonicalize(&candidate).map_err(|_| RouteError::Internal)?;
        if path.parent() != Some(self.repositories.as_path()) || !path.is_dir() {
            return Err(RouteError::Internal);
        }
        Ok((record, path))
    }

    fn clone_urls(&self, owner: &str, repository: &str) -> (String, String) {
        (
            format!("{}/{owner}/{repository}", self.http_clone_base),
            format!("{}/{owner}/{repository}", self.ssh_clone_base),
        )
    }

    async fn archive(
        &self,
        owner: String,
        repository: String,
        id: ObjectId,
    ) -> Result<Body, RouteError> {
        let path = self
            .path_job(owner, repository, move |record, path| {
                require_id_format(id, &record)?;
                let service = RepositoryReadService::open(&path, ReadLimits::default())?;
                let cancellation = ReadCancellation::default();
                service.commit(id, &cancellation)?;
                Ok(path)
            })
            .await?;
        let permit = self
            .jobs
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| RouteError::Unavailable)?;
        let (sender, receiver) = mpsc::channel(8);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let result =
                RepositoryReadService::open(&path, ReadLimits::default()).and_then(|service| {
                    let cancellation = ReadCancellation::default();
                    service
                        .archive(id, &cancellation, &mut ChannelWriter { sender: &sender })
                        .map(|_| ())
                });
            if let Err(error) = result {
                let _ = sender.blocking_send(Err(std::io::Error::other(error.to_string())));
            }
        });
        Ok(Body::from_stream(ReceiverStream::new(receiver)))
    }
}

pub(super) fn routes() -> Router<WebState> {
    Router::new()
        .route("/{owner}/{repository}/info/refs", get(info_refs))
        .route(
            "/{owner}/{repository}/git-upload-pack",
            post(git_upload_pack).layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES)),
        )
        .route("/{owner}/{repository}/refs", get(refs))
        .route("/{owner}/{repository}/commit/{commit}", get(commit))
        .route("/{owner}/{repository}/diff/{old}/{new}", get(diff))
        .route("/{owner}/{repository}/tree/{commit}", get(tree_root))
        .route("/{owner}/{repository}/tree/{commit}/{*path}", get(tree))
        .route("/{owner}/{repository}/blob/{commit}/{*path}", get(blob))
        .route("/{owner}/{repository}/raw/{commit}/{*path}", get(raw))
        .route("/{owner}/{repository}/blame/{commit}/{*path}", get(blame))
        .route("/{owner}/{repository}/archive/{archive}", get(archive))
        .route("/{owner}/{repository}", get(summary))
}

async fn summary(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(path): AxumPath<RepositoryPath>,
) -> Response {
    if let Some(repository) = path.repository.strip_suffix(".git")
        && validate_username(&path.owner).is_ok()
        && validate_slug(repository).is_ok()
    {
        return redirect(format!("/{}/{repository}", path.owner));
    }
    let Some(web) = state.public else {
        return route_error(RouteError::NotFound, &request_id.0);
    };
    let clone_urls = web.clone_urls(&path.owner, &path.repository);
    let result = web
        .read(path.owner, path.repository, move |record, service| {
            let cancellation = ReadCancellation::default();
            let references = service.references(&cancellation)?;
            let head = references
                .iter()
                .find(|reference| reference.name == b"HEAD")
                .map(|reference| reference.target);
            let (history, readme) = match head {
                Some(head) => (
                    service.history(head, &cancellation)?,
                    service.readme(head, &cancellation)?,
                ),
                None => (Vec::new(), None),
            };
            Ok(RepositoryPage::summary(
                record,
                clone_urls,
                head,
                history,
                readme.map(|readme| (readme.path, readme.blob.data)),
            ))
        })
        .await;
    render_page(result, &request_id.0)
}

async fn refs(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(path): AxumPath<RepositoryPath>,
) -> Response {
    let Some(web) = state.public else {
        return route_error(RouteError::NotFound, &request_id.0);
    };
    let result = web
        .read(path.owner, path.repository, |record, service| {
            let cancellation = ReadCancellation::default();
            let references = service.references(&cancellation)?;
            Ok(RepositoryPage::refs(record, references))
        })
        .await;
    render_page(result, &request_id.0)
}

async fn commit(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(path): AxumPath<CommitPath>,
) -> Response {
    let Some(web) = state.public else {
        return route_error(RouteError::NotFound, &request_id.0);
    };
    let id = match parse_id(&path.commit) {
        Ok(id) => id,
        Err(error) => return route_error(error, &request_id.0),
    };
    let result = web
        .read(path.owner, path.repository, move |record, service| {
            require_id_format(id, &record)?;
            let cancellation = ReadCancellation::default();
            let commit = service.commit(id, &cancellation)?;
            Ok(RepositoryPage::commit(record, commit))
        })
        .await;
    render_page(result, &request_id.0)
}

async fn diff(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(path): AxumPath<DiffPath>,
) -> Response {
    let Some(web) = state.public else {
        return route_error(RouteError::NotFound, &request_id.0);
    };
    let (old, new) = match (parse_id(&path.old), parse_id(&path.new)) {
        (Ok(old), Ok(new)) => (old, new),
        _ => return route_error(RouteError::NotFound, &request_id.0),
    };
    let result = web
        .read(path.owner, path.repository, move |record, service| {
            require_id_format(old, &record)?;
            require_id_format(new, &record)?;
            let cancellation = ReadCancellation::default();
            let files = service.diff(old, new, &cancellation)?;
            Ok(RepositoryPage::diff(record, old, new, files))
        })
        .await;
    render_page(result, &request_id.0)
}

async fn tree_root(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(path): AxumPath<CommitPath>,
) -> Response {
    tree_response(state, request_id, path, Vec::new()).await
}

async fn tree(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let (path, git_path) = match content_route(uri.path(), "tree") {
        Ok(route) => route,
        Err(error) => return route_error(error, &request_id.0),
    };
    tree_response(state, request_id, path, git_path).await
}

async fn tree_response(
    state: WebState,
    request_id: RequestId,
    path: CommitPath,
    git_path: Vec<u8>,
) -> Response {
    let Some(web) = state.public else {
        return route_error(RouteError::NotFound, &request_id.0);
    };
    let id = match parse_id(&path.commit) {
        Ok(id) => id,
        Err(error) => return route_error(error, &request_id.0),
    };
    let result = web
        .read(path.owner, path.repository, move |record, service| {
            require_id_format(id, &record)?;
            let cancellation = ReadCancellation::default();
            let entries = service.tree(id, &git_path, &cancellation)?;
            Ok(RepositoryPage::tree(record, id, git_path, entries))
        })
        .await;
    render_page(result, &request_id.0)
}

async fn blob(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let (path, git_path) = match content_route(uri.path(), "blob") {
        Ok(route) => route,
        Err(error) => return route_error(error, &request_id.0),
    };
    let Some(web) = state.public else {
        return route_error(RouteError::NotFound, &request_id.0);
    };
    let id = match parse_id(&path.commit) {
        Ok(id) => id,
        Err(error) => return route_error(error, &request_id.0),
    };
    let result = web
        .read(path.owner, path.repository, move |record, service| {
            require_id_format(id, &record)?;
            let cancellation = ReadCancellation::default();
            let blob = service.blob(id, &git_path, &cancellation)?;
            Ok(RepositoryPage::blob(record, id, git_path, blob.data))
        })
        .await;
    render_page(result, &request_id.0)
}

async fn raw(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let (path, git_path) = match content_route(uri.path(), "raw") {
        Ok(route) => route,
        Err(error) => return route_error(error, &request_id.0),
    };
    let Some(web) = state.public else {
        return route_error(RouteError::NotFound, &request_id.0);
    };
    let id = match parse_id(&path.commit) {
        Ok(id) => id,
        Err(error) => return route_error(error, &request_id.0),
    };
    let result = web
        .read(path.owner, path.repository, move |record, service| {
            require_id_format(id, &record)?;
            let cancellation = ReadCancellation::default();
            let mut content = Vec::new();
            service.raw(id, &git_path, &cancellation, &mut content)?;
            Ok(content)
        })
        .await;
    match result {
        Ok(content) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
            .body(Body::from(content))
            .expect("the raw response is valid"),
        Err(error) => route_error(error, &request_id.0),
    }
}

async fn blame(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let (path, git_path) = match content_route(uri.path(), "blame") {
        Ok(route) => route,
        Err(error) => return route_error(error, &request_id.0),
    };
    let Some(web) = state.public else {
        return route_error(RouteError::NotFound, &request_id.0);
    };
    let id = match parse_id(&path.commit) {
        Ok(id) => id,
        Err(error) => return route_error(error, &request_id.0),
    };
    let result = web
        .read(path.owner, path.repository, move |record, service| {
            require_id_format(id, &record)?;
            let cancellation = ReadCancellation::default();
            let blob = service.blob(id, &git_path, &cancellation)?;
            let hunks = service.blame(id, &git_path, &cancellation)?;
            Ok(RepositoryPage::blame(
                record, id, git_path, blob.data, hunks,
            ))
        })
        .await;
    render_page(result, &request_id.0)
}

async fn archive(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(path): AxumPath<ArchivePath>,
) -> Response {
    let Some(commit) = path.archive.strip_suffix(".tar") else {
        return route_error(RouteError::NotFound, &request_id.0);
    };
    let id = match parse_id(commit) {
        Ok(id) => id,
        Err(error) => return route_error(error, &request_id.0),
    };
    let Some(web) = state.public else {
        return route_error(RouteError::NotFound, &request_id.0);
    };
    let result = web.archive(path.owner, path.repository, id).await;
    match result {
        Ok(body) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/x-tar")
            .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
            .header(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=repository.tar"),
            )
            .body(body)
            .expect("the archive response is valid"),
        Err(error) => route_error(error, &request_id.0),
    }
}

async fn info_refs(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(mut path): AxumPath<RepositoryPath>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    if uri.query() != Some("service=git-upload-pack") {
        return plain_error(StatusCode::BAD_REQUEST, "Invalid Git service query.\n");
    }
    path.repository = path
        .repository
        .strip_suffix(".git")
        .unwrap_or(&path.repository)
        .to_owned();
    let Some(web) = state.public else {
        return route_error(RouteError::NotFound, &request_id.0);
    };
    let version = match protocol_version(&headers) {
        Ok(version) => version,
        Err(()) => return plain_error(StatusCode::BAD_REQUEST, "Invalid Git protocol version.\n"),
    };
    let result = web
        .path_job(path.owner, path.repository, move |_record, path| {
            UploadPack::open(&path)
                .and_then(|service| service.advertisement(version, true))
                .map_err(|_| RouteError::Internal)
        })
        .await;
    match result {
        Ok(body) => git_response("application/x-git-upload-pack-advertisement", body),
        Err(RouteError::NotFound) => plain_error(StatusCode::NOT_FOUND, "Repository not found.\n"),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "Git service failed.\n"),
    }
}

async fn git_upload_pack(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    AxumPath(mut path): AxumPath<RepositoryPath>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/x-git-upload-pack-request")
    {
        return plain_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Invalid content type.\n",
        );
    }
    path.repository = path
        .repository
        .strip_suffix(".git")
        .unwrap_or(&path.repository)
        .to_owned();
    let Some(web) = state.public else {
        return route_error(RouteError::NotFound, &request_id.0);
    };
    let version = match protocol_version(&headers) {
        Ok(version) => version,
        Err(()) => return plain_error(StatusCode::BAD_REQUEST, "Invalid Git protocol version.\n"),
    };
    let result = web
        .path_job(path.owner, path.repository, move |_record, path| {
            UploadPack::open(&path)
                .and_then(|service| service.respond(version, &body))
                .map_err(|_| RouteError::InvalidRequest)
        })
        .await;
    match result {
        Ok(body) => git_response("application/x-git-upload-pack-result", body),
        Err(RouteError::NotFound) => plain_error(StatusCode::NOT_FOUND, "Repository not found.\n"),
        Err(RouteError::InvalidRequest) => {
            plain_error(StatusCode::BAD_REQUEST, "Invalid Git request.\n")
        }
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "Git service failed.\n"),
    }
}

fn render_page(result: Result<RepositoryPage, RouteError>, request_id: &str) -> Response {
    match result {
        Ok(mut page) => {
            page.request_id = request_id.to_owned();
            match page.render() {
                Ok(body) => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                    .header(header::CACHE_CONTROL, "no-store")
                    .body(Body::from(body))
                    .expect("the repository HTML response is valid"),
                Err(_) => route_error(RouteError::Internal, request_id),
            }
        }
        Err(error) => route_error(error, request_id),
    }
}

fn route_error(error: RouteError, request_id: &str) -> Response {
    match error {
        RouteError::NotFound => render_error(
            StatusCode::NOT_FOUND,
            request_id,
            "Repository content not found",
            "The requested repository content does not exist.",
        ),
        RouteError::Unavailable => render_error(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            "Repository service unavailable",
            "The repository service cannot complete this request now.",
        ),
        RouteError::Internal => render_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            request_id,
            "Repository service error",
            "The repository service cannot complete this request.",
        ),
        RouteError::InvalidRequest => render_error(
            StatusCode::BAD_REQUEST,
            request_id,
            "Invalid repository request",
            "The repository request is not valid.",
        ),
    }
}

fn redirect(location: String) -> Response {
    Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header(header::LOCATION, location)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::empty())
        .expect("the canonical repository redirect is valid")
}

fn git_response(content_type: &'static str, body: Vec<u8>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CACHE_CONTROL,
            "no-cache, max-age=0, must-revalidate",
        )
        .header(header::PRAGMA, "no-cache")
        .body(Body::from(body))
        .expect("the Git HTTP response is valid")
}

fn plain_error(status: StatusCode, message: &'static str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(message))
        .expect("the plain HTTP error response is valid")
}

fn protocol_version(headers: &HeaderMap) -> Result<ProtocolVersion, ()> {
    match headers
        .get("git-protocol")
        .and_then(|value| value.to_str().ok())
    {
        Some("version=2") => Ok(ProtocolVersion::V2),
        None | Some("version=0") => Ok(ProtocolVersion::V0),
        Some("version=1") => Ok(ProtocolVersion::V1),
        Some(_) => Err(()),
    }
}

fn parse_id(value: &str) -> Result<ObjectId, RouteError> {
    if !matches!(value.len(), 40 | 64)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(RouteError::NotFound);
    }
    ObjectId::from_hex(value.as_bytes()).map_err(|_| RouteError::NotFound)
}

fn require_id_format(id: ObjectId, repository: &RepositoryRecord) -> Result<(), RouteError> {
    let expected = match repository.object_format.as_str() {
        "sha1" => gix::hash::Kind::Sha1,
        "sha256" => gix::hash::Kind::Sha256,
        _ => return Err(RouteError::Internal),
    };
    if id.kind() == expected {
        Ok(())
    } else {
        Err(RouteError::NotFound)
    }
}

fn content_route(path: &str, expected_route: &str) -> Result<(CommitPath, Vec<u8>), RouteError> {
    let mut components = path.splitn(6, '/');
    if components.next() != Some("") {
        return Err(RouteError::NotFound);
    }
    let owner = components.next().ok_or(RouteError::NotFound)?;
    let repository = components.next().ok_or(RouteError::NotFound)?;
    let route = components.next().ok_or(RouteError::NotFound)?;
    let commit = components.next().ok_or(RouteError::NotFound)?;
    let encoded_path = components.next().ok_or(RouteError::NotFound)?;
    if route != expected_route || encoded_path.is_empty() {
        return Err(RouteError::NotFound);
    }
    Ok((
        CommitPath {
            owner: owner.to_owned(),
            repository: repository.to_owned(),
            commit: commit.to_owned(),
        },
        decode_path(encoded_path)?,
    ))
}

fn decode_path(value: &str) -> Result<Vec<u8>, RouteError> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(RouteError::NotFound);
            }
            let high = hex_value(bytes[index + 1]).ok_or(RouteError::NotFound)?;
            let low = hex_value(bytes[index + 2]).ok_or(RouteError::NotFound)?;
            output.push((high << 4) | low);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    Ok(output)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_path(path: &[u8]) -> String {
    let mut output = String::new();
    for byte in path {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(byte) {
            output.push(char::from(*byte));
        } else {
            output.push('%');
            output.push(char::from(b"0123456789ABCDEF"[usize::from(byte >> 4)]));
            output.push(char::from(b"0123456789ABCDEF"[usize::from(byte & 0x0f)]));
        }
    }
    output
}

fn clone_base(value: &str) -> Result<String, PublicWebError> {
    let value = value.trim_end_matches('/');
    if value.is_empty() || value.contains(['\r', '\n']) {
        return Err(PublicWebError::CloneBase);
    }
    Ok(value.to_owned())
}

fn display_bytes(value: &[u8]) -> String {
    value.as_bstr().to_str_lossy().into_owned()
}

struct ChannelWriter<'a> {
    sender: &'a mpsc::Sender<Result<Bytes, std::io::Error>>,
}

impl Write for ChannelWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.sender
            .blocking_send(Ok(Bytes::copy_from_slice(buffer)))
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "HTTP client closed")
            })?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn message_summary(message: &[u8]) -> String {
    display_bytes(message)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned()
}

#[derive(Deserialize)]
struct RepositoryPath {
    owner: String,
    repository: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct CommitPath {
    owner: String,
    repository: String,
    commit: String,
}

#[derive(Deserialize)]
struct DiffPath {
    owner: String,
    repository: String,
    old: String,
    new: String,
}

#[derive(Deserialize)]
struct ArchivePath {
    owner: String,
    repository: String,
    archive: String,
}

#[derive(Template)]
#[template(path = "repository.html")]
struct RepositoryPage {
    request_id: String,
    owner: String,
    repository: String,
    object_format: String,
    created_at: i64,
    page_title: String,
    page_kind: &'static str,
    commit_id: String,
    secondary_id: String,
    path: String,
    encoded_path: String,
    http_clone_url: String,
    ssh_clone_url: String,
    has_head: bool,
    has_readme: bool,
    readme_path: String,
    readme_content: String,
    readme_binary: bool,
    history: Vec<CommitView>,
    entries: Vec<TreeView>,
    blob_content: String,
    blob_binary: bool,
    commit: CommitView,
    diffs: Vec<DiffView>,
    refs: Vec<RefView>,
    blame: Vec<BlameView>,
}

impl RepositoryPage {
    fn base(record: RepositoryRecord, page_kind: &'static str, title: String) -> Self {
        Self {
            request_id: String::new(),
            owner: record.owner,
            repository: record.slug,
            object_format: record.object_format,
            created_at: record.created_at,
            page_title: title,
            page_kind,
            commit_id: String::new(),
            secondary_id: String::new(),
            path: String::new(),
            encoded_path: String::new(),
            http_clone_url: String::new(),
            ssh_clone_url: String::new(),
            has_head: false,
            has_readme: false,
            readme_path: String::new(),
            readme_content: String::new(),
            readme_binary: false,
            history: Vec::new(),
            entries: Vec::new(),
            blob_content: String::new(),
            blob_binary: false,
            commit: CommitView::default(),
            diffs: Vec::new(),
            refs: Vec::new(),
            blame: Vec::new(),
        }
    }

    fn summary(
        record: RepositoryRecord,
        clone_urls: (String, String),
        head: Option<ObjectId>,
        history: Vec<CommitInfo>,
        readme: Option<(Vec<u8>, Vec<u8>)>,
    ) -> Self {
        let title = format!("{}/{}", record.owner, record.slug);
        let mut page = Self::base(record, "summary", title);
        page.http_clone_url = clone_urls.0;
        page.ssh_clone_url = clone_urls.1;
        page.has_head = head.is_some();
        page.commit_id = head.map(|id| id.to_string()).unwrap_or_default();
        page.history = history
            .into_iter()
            .take(MAX_SUMMARY_COMMITS)
            .map(CommitView::from)
            .collect();
        if let Some((path, data)) = readme {
            page.has_readme = true;
            page.readme_path = display_bytes(&path);
            if let Ok(content) = std::str::from_utf8(&data)
                && !data.contains(&0)
            {
                page.readme_content = content.to_owned();
            } else {
                page.readme_binary = true;
            }
        }
        page
    }

    fn refs(record: RepositoryRecord, references: Vec<crate::git::read::RefInfo>) -> Self {
        let mut page = Self::base(record, "refs", "Refs".to_owned());
        page.refs = references
            .into_iter()
            .map(|reference| {
                let href = reference.peeled.unwrap_or(reference.target).to_string();
                RefView {
                    name: display_bytes(&reference.name),
                    target: reference.target.to_string(),
                    href,
                    peeled: reference
                        .peeled
                        .map(|id| id.to_string())
                        .unwrap_or_default(),
                    symbolic: reference
                        .symbolic_target
                        .map(|target| display_bytes(&target))
                        .unwrap_or_default(),
                }
            })
            .collect();
        page
    }

    fn commit(record: RepositoryRecord, commit: CommitInfo) -> Self {
        let mut page = Self::base(record, "commit", "Commit".to_owned());
        page.has_head = true;
        page.commit_id = commit.id.to_string();
        page.commit = CommitView::from(commit);
        page
    }

    fn diff(record: RepositoryRecord, old: ObjectId, new: ObjectId, files: Vec<DiffFile>) -> Self {
        let mut page = Self::base(record, "diff", "Diff".to_owned());
        page.has_head = true;
        page.commit_id = new.to_string();
        page.secondary_id = old.to_string();
        page.diffs = files.into_iter().map(DiffView::from).collect();
        page
    }

    fn tree(
        record: RepositoryRecord,
        commit: ObjectId,
        path: Vec<u8>,
        entries: Vec<TreeEntryInfo>,
    ) -> Self {
        let mut page = Self::base(record, "tree", "Tree".to_owned());
        page.has_head = true;
        page.commit_id = commit.to_string();
        page.path = display_bytes(&path);
        page.encoded_path = encode_path(&path);
        page.entries = entries
            .into_iter()
            .map(|entry| TreeView::new(commit, &path, entry))
            .collect();
        page
    }

    fn blob(record: RepositoryRecord, commit: ObjectId, path: Vec<u8>, data: Vec<u8>) -> Self {
        let mut page = Self::base(record, "blob", "Blob".to_owned());
        page.has_head = true;
        page.commit_id = commit.to_string();
        page.path = display_bytes(&path);
        page.encoded_path = encode_path(&path);
        if let Ok(content) = std::str::from_utf8(&data)
            && !data.contains(&0)
        {
            page.blob_content = content.to_owned();
        } else {
            page.blob_binary = true;
        }
        page
    }

    fn blame(
        record: RepositoryRecord,
        commit: ObjectId,
        path: Vec<u8>,
        data: Vec<u8>,
        hunks: Vec<BlameHunk>,
    ) -> Self {
        let mut page = Self::base(record, "blame", "Blame".to_owned());
        page.has_head = true;
        page.commit_id = commit.to_string();
        page.path = display_bytes(&path);
        page.encoded_path = encode_path(&path);
        if let Ok(content) = std::str::from_utf8(&data)
            && !data.contains(&0)
        {
            let lines: Vec<&str> = content.lines().collect();
            page.blame = hunks
                .into_iter()
                .map(|hunk| BlameView::new(hunk, &lines))
                .collect();
        } else {
            page.blob_binary = true;
        }
        page
    }
}

#[derive(Default)]
struct CommitView {
    id: String,
    tree: String,
    parents: Vec<String>,
    author_name: String,
    author_email: String,
    committed_at: i64,
    summary: String,
    message: String,
}

impl From<CommitInfo> for CommitView {
    fn from(commit: CommitInfo) -> Self {
        Self {
            id: commit.id.to_string(),
            tree: commit.tree.to_string(),
            parents: commit
                .parents
                .into_iter()
                .map(|id| id.to_string())
                .collect(),
            author_name: display_bytes(&commit.author_name),
            author_email: display_bytes(&commit.author_email),
            committed_at: commit.committed_at,
            summary: message_summary(&commit.message),
            message: display_bytes(&commit.message),
        }
    }
}

struct TreeView {
    name: String,
    id: String,
    mode: String,
    kind: &'static str,
    href: String,
}

impl TreeView {
    fn new(commit: ObjectId, parent: &[u8], entry: TreeEntryInfo) -> Self {
        let mut path = parent.to_vec();
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(&entry.name);
        let (kind, href) = match entry.kind {
            EntryKind::Tree => ("tree", format!("tree/{commit}/{}", encode_path(&path))),
            EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link => {
                ("blob", format!("blob/{commit}/{}", encode_path(&path)))
            }
            EntryKind::Commit => ("commit", format!("commit/{}", entry.id)),
        };
        Self {
            name: display_bytes(&entry.name),
            id: entry.id.to_string(),
            mode: format!("{:06o}", entry.mode),
            kind,
            href,
        }
    }
}

struct DiffView {
    path: String,
    old_id: String,
    new_id: String,
    old_mode: String,
    new_mode: String,
    binary: bool,
    hunks: String,
}

impl From<DiffFile> for DiffView {
    fn from(file: DiffFile) -> Self {
        Self {
            path: display_bytes(&file.path),
            old_id: file.old_id.map(|id| id.to_string()).unwrap_or_default(),
            new_id: file.new_id.map(|id| id.to_string()).unwrap_or_default(),
            old_mode: file
                .old_mode
                .map(|mode| format!("{mode:06o}"))
                .unwrap_or_default(),
            new_mode: file
                .new_mode
                .map(|mode| format!("{mode:06o}"))
                .unwrap_or_default(),
            binary: file.binary,
            hunks: display_bytes(&file.hunks),
        }
    }
}

struct RefView {
    name: String,
    target: String,
    href: String,
    peeled: String,
    symbolic: String,
}

struct BlameView {
    start_line: u32,
    source_start_line: u32,
    line_count: u32,
    end_line: u32,
    commit_id: String,
    source_path: String,
    content: String,
}

impl BlameView {
    fn new(hunk: BlameHunk, lines: &[&str]) -> Self {
        let start = usize::try_from(hunk.start_line.saturating_sub(1)).unwrap_or(usize::MAX);
        let count = usize::try_from(hunk.line_count).unwrap_or(usize::MAX);
        let content = lines
            .get(start..start.saturating_add(count))
            .unwrap_or_default()
            .join("\n");
        Self {
            start_line: hunk.start_line,
            source_start_line: hunk.source_start_line,
            line_count: hunk.line_count,
            end_line: hunk
                .source_start_line
                .saturating_add(hunk.line_count.saturating_sub(1)),
            commit_id: hunk.commit_id.to_string(),
            source_path: hunk
                .source_path
                .map(|path| display_bytes(&path))
                .unwrap_or_default(),
            content,
        }
    }
}

#[derive(Debug)]
enum RouteError {
    NotFound,
    InvalidRequest,
    Unavailable,
    Internal,
}

impl From<ReadError> for RouteError {
    fn from(error: ReadError) -> Self {
        match error {
            ReadError::InvalidPath
            | ReadError::ObjectNotFound(_)
            | ReadError::PathNotFound(_)
            | ReadError::NotTree(_)
            | ReadError::NotBlob(_)
            | ReadError::WrongObjectKind { .. } => Self::NotFound,
            ReadError::Limit(_) | ReadError::Cancelled | ReadError::Deadline => Self::Unavailable,
            _ => Self::Internal,
        }
    }
}

impl From<StoreError> for RouteError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::RepositoryNotFound(_, _) => Self::NotFound,
            _ => Self::Internal,
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum PublicWebError {
    #[error("cannot open the repository directory: {0}")]
    RepositoryDirectory(std::io::Error),
    #[error("the repository directory is not a directory")]
    InvalidRepositoryDirectory,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("clone URL base is not valid")]
    CloneBase,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_arbitrary_git_path_bytes() {
        let path = b"directory/non-\xff name";
        let encoded = encode_path(path);
        assert_eq!(encoded, "directory/non-%FF%20name");
        assert_eq!(decode_path(&encoded).expect("decode a Git path"), path);
    }

    #[test]
    fn rejects_malformed_percent_encoded_paths() {
        for path in ["%", "%0", "%GG"] {
            assert!(matches!(decode_path(path), Err(RouteError::NotFound)));
        }
    }

    #[test]
    fn extracts_paths_when_the_repository_matches_a_route_name() {
        assert_eq!(
            content_route("/alice/blob/blob/abc/file.txt", "blob")
                .expect("extract the exact route prefix"),
            (
                CommitPath {
                    owner: "alice".to_owned(),
                    repository: "blob".to_owned(),
                    commit: "abc".to_owned(),
                },
                b"file.txt".to_vec()
            )
        );
    }
}
