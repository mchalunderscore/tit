use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::auth::{AuthError, validate_username};
use crate::store::{MetadataSearchCandidate, Store, StoreError};

pub(crate) const MAX_QUERY_BYTES: usize = 256;
pub(crate) const MAX_SCAN_ROWS: usize = 10_000;
pub(crate) const MAX_SCAN_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_RESULTS: usize = 100;
pub(crate) const MAX_DURATION: Duration = Duration::from_millis(500);

#[derive(Clone)]
pub(crate) struct MetadataSearchService {
    database: PathBuf,
}

impl MetadataSearchService {
    pub(crate) fn new(database: &Path) -> Self {
        Self {
            database: database.to_owned(),
        }
    }

    pub(crate) fn search(
        &self,
        actor: Option<&str>,
        query: &str,
    ) -> Result<MetadataSearchOutcome, MetadataSearchError> {
        if let Some(actor) = actor {
            validate_username(actor)?;
        }
        let query = query.trim();
        if query.is_empty() || query.len() > MAX_QUERY_BYTES || query.chars().any(char::is_control)
        {
            return Err(MetadataSearchError::InvalidQuery);
        }
        let started = Instant::now();
        let store = Store::open(&self.database)?;
        let needle = query.to_lowercase();
        let mut bytes_scanned = 0_usize;
        let mut rows_scanned = 0_usize;
        let mut seen = BTreeSet::new();
        let mut results = Vec::new();
        let mut candidate_error = None;
        let truncated =
            store.visit_metadata_search_candidates(actor, MAX_SCAN_ROWS, |candidate| {
                if started.elapsed() >= MAX_DURATION {
                    return false;
                }
                let Some(bytes) = candidate.title.len().checked_add(candidate.body.len()) else {
                    candidate_error = Some(MetadataSearchError::Limit);
                    return false;
                };
                if bytes_scanned.saturating_add(bytes) > MAX_SCAN_BYTES {
                    return false;
                }
                bytes_scanned += bytes;
                rows_scanned += 1;
                let (Ok(title), Ok(body)) = (
                    std::str::from_utf8(&candidate.title),
                    std::str::from_utf8(&candidate.body),
                ) else {
                    candidate_error = Some(MetadataSearchError::StoredCandidate);
                    return false;
                };
                if !title.to_lowercase().contains(&needle) && !body.to_lowercase().contains(&needle)
                {
                    return true;
                }
                let Ok(result) = result_from_candidate(candidate) else {
                    candidate_error = Some(MetadataSearchError::StoredCandidate);
                    return false;
                };
                if !seen.insert(result.url.clone()) {
                    return true;
                }
                if results.len() == MAX_RESULTS {
                    return false;
                }
                results.push(result);
                true
            })?;
        if let Some(error) = candidate_error {
            return Err(error);
        }

        Ok(MetadataSearchOutcome {
            query: query.to_owned(),
            rows_scanned,
            bytes_scanned,
            truncated,
            results,
        })
    }
}

fn result_from_candidate(
    candidate: MetadataSearchCandidate,
) -> Result<MetadataSearchResult, MetadataSearchError> {
    let title =
        String::from_utf8(candidate.title).map_err(|_| MetadataSearchError::StoredCandidate)?;
    let body =
        String::from_utf8(candidate.body).map_err(|_| MetadataSearchError::StoredCandidate)?;
    if candidate.kind != "repository" {
        return Err(MetadataSearchError::StoredCandidate);
    }
    let (kind, url) = (
        "Repository",
        format!("/{}/{}", candidate.owner, candidate.repository),
    );
    let summary = body
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(160)
        .collect();
    Ok(MetadataSearchResult {
        kind,
        url,
        title,
        summary,
        stable_id: candidate.record_id,
    })
}

pub(crate) struct MetadataSearchOutcome {
    pub(crate) query: String,
    pub(crate) rows_scanned: usize,
    pub(crate) bytes_scanned: usize,
    pub(crate) truncated: bool,
    pub(crate) results: Vec<MetadataSearchResult>,
}

pub(crate) struct MetadataSearchResult {
    pub(crate) kind: &'static str,
    pub(crate) url: String,
    pub(crate) title: String,
    pub(crate) summary: String,
    pub(crate) stable_id: String,
}

#[derive(Debug, Error)]
pub(crate) enum MetadataSearchError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("metadata search query is not valid")]
    InvalidQuery,
    #[error("metadata search reached an arithmetic limit")]
    Limit,
    #[error("stored metadata search candidate is not valid")]
    StoredCandidate,
}
