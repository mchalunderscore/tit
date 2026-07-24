use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::auth::{AuthError, validate_username};
use crate::domain::repository::{RepositoryNameError, validate_slug};
use crate::store::{
    IssueChange, IssueDetail, IssueRecord, NewIssue, RecordPage, RepositoryRecord, Store,
    StoreError,
};

pub(crate) const MAX_TITLE_BYTES: usize = 200;
pub(crate) const MAX_BODY_BYTES: usize = 256 * 1024;
pub(crate) const PAGE_SIZE: usize = 50;

#[derive(Clone)]
pub(crate) struct IssueService {
    database: PathBuf,
}

impl IssueService {
    pub(crate) fn new(database: &Path) -> Self {
        Self {
            database: database.to_owned(),
        }
    }

    pub(crate) fn create(
        &self,
        owner: &str,
        repository: &str,
        actor: &str,
        title: &str,
        body: &str,
    ) -> Result<IssueRecord, IssueError> {
        validate_context(owner, repository, Some(actor))?;
        validate_title(title)?;
        validate_body(body, true)?;
        let mut store = Store::open(&self.database)?;
        store
            .create_issue(&NewIssue {
                owner,
                repository,
                actor,
                title,
                body,
                created_at: timestamp()?,
            })
            .map_err(Into::into)
    }

    pub(crate) fn list(
        &self,
        owner: &str,
        repository: &str,
        actor: Option<&str>,
    ) -> Result<(RepositoryRecord, Vec<IssueRecord>), IssueError> {
        validate_context(owner, repository, actor)?;
        Store::open(&self.database)?
            .issues(owner, repository, actor)
            .map_err(Into::into)
    }

    pub(crate) fn list_page(
        &self,
        owner: &str,
        repository: &str,
        actor: Option<&str>,
        state: &str,
        page: usize,
    ) -> Result<(RepositoryRecord, RecordPage<IssueRecord>), IssueError> {
        validate_context(owner, repository, actor)?;
        validate_list(state, page)?;
        let result = Store::open(&self.database)?
            .issue_page(owner, repository, actor, state, page, PAGE_SIZE)
            .map_err(IssueError::from)?;
        if page > 1 && result.1.items.is_empty() {
            return Err(IssueError::State);
        }
        Ok(result)
    }

    pub(crate) fn get_page(
        &self,
        owner: &str,
        repository: &str,
        number: i64,
        actor: Option<&str>,
        comments_page: usize,
        timeline_page: usize,
    ) -> Result<IssueDetail, IssueError> {
        validate_context(owner, repository, actor)?;
        validate_number(number)?;
        validate_page(comments_page)?;
        validate_page(timeline_page)?;
        let detail = Store::open(&self.database)?
            .issue_detail(
                owner,
                repository,
                number,
                actor,
                comments_page,
                timeline_page,
                PAGE_SIZE,
            )
            .map_err(IssueError::from)?;
        if (comments_page > 1 && detail.comments.is_empty())
            || (timeline_page > 1 && detail.timeline.is_empty())
        {
            return Err(IssueError::Number);
        }
        Ok(detail)
    }

    pub(crate) fn edit(
        &self,
        owner: &str,
        repository: &str,
        number: i64,
        actor: &str,
        title: &str,
        body: &str,
    ) -> Result<(), IssueError> {
        validate_context(owner, repository, Some(actor))?;
        validate_number(number)?;
        validate_title(title)?;
        validate_body(body, true)?;
        Store::open(&self.database)?
            .edit_issue(
                &IssueChange {
                    owner,
                    repository,
                    number,
                    actor,
                    changed_at: timestamp()?,
                },
                title,
                body,
            )
            .map_err(Into::into)
    }

    pub(crate) fn comment(
        &self,
        owner: &str,
        repository: &str,
        number: i64,
        actor: &str,
        body: &str,
    ) -> Result<String, IssueError> {
        validate_context(owner, repository, Some(actor))?;
        validate_number(number)?;
        validate_body(body, false)?;
        Store::open(&self.database)?
            .comment_issue(owner, repository, number, actor, body, timestamp()?)
            .map_err(Into::into)
    }

    pub(crate) fn set_state(
        &self,
        owner: &str,
        repository: &str,
        number: i64,
        actor: &str,
        state: &str,
    ) -> Result<(), IssueError> {
        validate_context(owner, repository, Some(actor))?;
        validate_number(number)?;
        if !matches!(state, "open" | "closed") {
            return Err(IssueError::State);
        }
        Store::open(&self.database)?
            .set_issue_state(owner, repository, number, actor, state, timestamp()?)
            .map_err(Into::into)
    }
}

fn validate_context(owner: &str, repository: &str, actor: Option<&str>) -> Result<(), IssueError> {
    validate_username(owner)?;
    validate_slug(repository)?;
    if let Some(actor) = actor {
        validate_username(actor)?;
    }
    Ok(())
}

fn validate_number(number: i64) -> Result<(), IssueError> {
    if number < 1 {
        return Err(IssueError::Number);
    }
    Ok(())
}

fn validate_list(state: &str, page: usize) -> Result<(), IssueError> {
    if !matches!(state, "all" | "open" | "closed") || page == 0 || page > 10_000 {
        return Err(IssueError::State);
    }
    Ok(())
}

fn validate_page(page: usize) -> Result<(), IssueError> {
    if page == 0 || page > 10_000 {
        return Err(IssueError::Number);
    }
    Ok(())
}

fn validate_title(title: &str) -> Result<(), IssueError> {
    if title.is_empty()
        || title.len() > MAX_TITLE_BYTES
        || title.trim() != title
        || title.chars().any(char::is_control)
    {
        return Err(IssueError::Title);
    }
    Ok(())
}

fn validate_body(body: &str, empty_ok: bool) -> Result<(), IssueError> {
    if body.len() > MAX_BODY_BYTES
        || (!empty_ok && body.trim().is_empty())
        || body
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(IssueError::Body);
    }
    Ok(())
}

fn timestamp() -> Result<i64, IssueError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| IssueError::Clock)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| IssueError::Clock)
}

#[derive(Debug, Error)]
pub(crate) enum IssueError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    RepositoryName(#[from] RepositoryNameError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("issue number is not valid")]
    Number,
    #[error("issue title is not valid")]
    Title,
    #[error("issue body is not valid")]
    Body,
    #[error("issue state is not valid")]
    State,
    #[error("system time is not valid")]
    Clock,
}
