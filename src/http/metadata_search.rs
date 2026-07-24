use askama::Template;
use axum::Router;
use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use serde::Deserialize;

use crate::search::{MetadataSearchError, MetadataSearchResult};
use crate::store::StoreError;

use super::{RequestActor, RequestId, WebState, render, render_error};

pub(super) fn routes() -> Router<WebState> {
    Router::new().route("/search", get(search))
}

async fn search(
    State(state): State<WebState>,
    Extension(request_id): Extension<RequestId>,
    Extension(actor): Extension<RequestActor>,
    Query(query): Query<SearchQuery>,
) -> Response {
    let signed_in = actor.0.is_some();
    let Some(value) = query.q else {
        return search_page(&request_id.0, "", None, signed_in);
    };
    let Some(service) = state.search.clone() else {
        return search_internal(&request_id.0);
    };
    let value_for_search = value.clone();
    let result = search_job(state, move || {
        service.search(actor.0.as_deref(), &value_for_search)
    })
    .await;
    match result {
        Ok(outcome) => search_page(&request_id.0, &value, Some(outcome), signed_in),
        Err(MetadataSearchError::InvalidQuery | MetadataSearchError::Auth(_)) => render_error(
            StatusCode::BAD_REQUEST,
            &request_id.0,
            "Search error",
            "The repository search query is not valid.",
        ),
        Err(_) => search_internal(&request_id.0),
    }
}

async fn search_job<T: Send + 'static>(
    state: WebState,
    operation: impl FnOnce() -> Result<T, MetadataSearchError> + Send + 'static,
) -> Result<T, MetadataSearchError> {
    let permit = state.jobs.acquire_owned().await.map_err(|_| {
        MetadataSearchError::Store(StoreError::Integrity(
            "search worker pool is unavailable".to_owned(),
        ))
    })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation()
    })
    .await
    .map_err(|_| {
        MetadataSearchError::Store(StoreError::Integrity("search worker failed".to_owned()))
    })?
}

fn search_page(
    request_id: &str,
    query: &str,
    outcome: Option<crate::search::MetadataSearchOutcome>,
    signed_in: bool,
) -> Response {
    let searched = outcome.is_some();
    let (rows_scanned, bytes_scanned, truncated, results) = outcome.map_or_else(
        || (0, 0, false, Vec::new()),
        |outcome| {
            debug_assert_eq!(outcome.query, query.trim());
            (
                outcome.rows_scanned,
                outcome.bytes_scanned,
                outcome.truncated,
                outcome.results,
            )
        },
    );
    render(
        StatusCode::OK,
        &MetadataSearchTemplate {
            request_id,
            signed_in,
            query,
            searched,
            rows_scanned,
            bytes_scanned,
            truncated,
            results: results.iter().map(result_view).collect(),
        },
    )
}

fn result_view(result: &MetadataSearchResult) -> MetadataSearchResultView<'_> {
    MetadataSearchResultView {
        kind: result.kind,
        url: &result.url,
        title: &result.title,
        summary: &result.summary,
        stable_id: &result.stable_id,
    }
}

fn search_internal(request_id: &str) -> Response {
    render_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        request_id,
        "Search error",
        "The repository search could not be completed.",
    )
}

#[derive(Deserialize)]
struct SearchQuery {
    q: Option<String>,
}

struct MetadataSearchResultView<'a> {
    kind: &'static str,
    url: &'a str,
    title: &'a str,
    summary: &'a str,
    stable_id: &'a str,
}

#[derive(Template)]
#[template(path = "metadata-search.html")]
struct MetadataSearchTemplate<'a> {
    request_id: &'a str,
    signed_in: bool,
    query: &'a str,
    searched: bool,
    rows_scanned: usize,
    bytes_scanned: usize,
    truncated: bool,
    results: Vec<MetadataSearchResultView<'a>>,
}
