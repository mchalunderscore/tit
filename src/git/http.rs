use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::Response;
use axum::routing::{get, post};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::packetline::MAX_REQUEST_BYTES;
use super::transport::GitRepositories;
use super::upload_pack::{ProtocolVersion, UploadPack};

pub(crate) struct RunningGitHttpServer {
    address: SocketAddr,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<std::io::Result<()>>,
}

impl RunningGitHttpServer {
    pub(crate) async fn start(
        address: SocketAddr,
        repositories: GitRepositories,
    ) -> Result<Self, GitHttpError> {
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let router = Router::new()
            .route("/{owner}/{repository}/info/refs", get(info_refs))
            .route("/{owner}/{repository}/git-upload-pack", post(upload_pack))
            .with_state(Arc::new(repositories));
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
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

    pub(crate) async fn shutdown(self) -> Result<(), GitHttpError> {
        let _ = self.shutdown.send(());
        self.task.await.map_err(|_| GitHttpError::Join)??;
        Ok(())
    }
}

async fn info_refs(
    State(repositories): State<Arc<GitRepositories>>,
    Path((owner, repository)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if uri.query() != Some("service=git-upload-pack") {
        return plain_response(StatusCode::BAD_REQUEST, "invalid Git service query\n");
    }
    let Ok(path) = repositories.resolve(&owner, &repository) else {
        return plain_response(StatusCode::NOT_FOUND, "repository not found\n");
    };
    let Ok(version) = protocol_version(&headers) else {
        return plain_response(StatusCode::BAD_REQUEST, "invalid Git protocol version\n");
    };
    let Ok(permit) = repositories.blocking_permit().await else {
        return plain_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Git service is not available\n",
        );
    };
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        UploadPack::open(&path).and_then(|service| service.advertisement(version, true))
    })
    .await;
    match result {
        Ok(Ok(body)) => git_response(
            StatusCode::OK,
            "application/x-git-upload-pack-advertisement",
            body,
        ),
        Ok(Err(_)) | Err(_) => {
            plain_response(StatusCode::INTERNAL_SERVER_ERROR, "repository is damaged\n")
        }
    }
}

async fn upload_pack(
    State(repositories): State<Arc<GitRepositories>>,
    Path((owner, repository)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/x-git-upload-pack-request")
    {
        return plain_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid content type\n");
    }
    if body.len() > MAX_REQUEST_BYTES {
        return plain_response(StatusCode::PAYLOAD_TOO_LARGE, "Git request is too large\n");
    }
    let Ok(path) = repositories.resolve(&owner, &repository) else {
        return plain_response(StatusCode::NOT_FOUND, "repository not found\n");
    };
    let Ok(version) = protocol_version(&headers) else {
        return plain_response(StatusCode::BAD_REQUEST, "invalid Git protocol version\n");
    };
    let request = body.to_vec();
    let Ok(permit) = repositories.blocking_permit().await else {
        return plain_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Git service is not available\n",
        );
    };
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        UploadPack::open(&path).and_then(|service| service.respond(version, &request))
    })
    .await;
    match result {
        Ok(Ok(body)) => git_response(StatusCode::OK, "application/x-git-upload-pack-result", body),
        Ok(Err(_)) => plain_response(StatusCode::BAD_REQUEST, "invalid Git request\n"),
        Err(_) => plain_response(StatusCode::INTERNAL_SERVER_ERROR, "Git service failed\n"),
    }
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

fn git_response(status: StatusCode, content_type: &'static str, body: Vec<u8>) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CACHE_CONTROL,
            "no-cache, max-age=0, must-revalidate",
        )
        .header(header::PRAGMA, "no-cache")
        .body(Body::from(body))
        .expect("the static Git HTTP response is valid")
}

fn plain_response(status: StatusCode, message: &'static str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(message))
        .expect("the static error response is valid")
}

#[derive(Debug, Error)]
pub(crate) enum GitHttpError {
    #[error("Git HTTP listener error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Git HTTP server task failed")]
    Join,
}
