use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum StoreError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("cannot read migration path {path}: {source}")]
    MigrationFilesystem {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("database schema version {0} is newer than this executable")]
    NewerSchema(i64),
    #[error("database schema version is {actual}, expected {expected}")]
    SchemaVersion { expected: i64, actual: i64 },
    #[error("database integrity check failed: {0}")]
    Integrity(String),
    #[error("SQLite setting {name} is {actual}, expected {expected}")]
    Setting {
        name: &'static str,
        expected: &'static str,
        actual: String,
    },
    #[error("Git operation intent {0} is not in the required state")]
    IntentState(String),
    #[error("the instance already has an administrator")]
    AlreadyInitialized,
    #[error("account does not exist or is not active: {0}")]
    AccountNotFound(String),
    #[error("username is not available: {0}")]
    UsernameUnavailable(String),
    #[error("namespace does not exist or is not active: {0}")]
    NamespaceNotFound(String),
    #[error("namespace is not available: {0}")]
    NamespaceUnavailable(String),
    #[error("organization access is not authorized")]
    OrganizationDenied,
    #[error("organization member does not exist: {0}")]
    OrganizationMemberNotFound(String),
    #[error("an organization must have at least one owner")]
    LastOrganizationOwner,
    #[error("organization role is not valid")]
    InvalidOrganizationRole,
    #[error("signup invitation is invalid, expired, or already used")]
    InvalidInvitation,
    #[error("recovery credential is invalid")]
    InvalidRecovery,
    #[error("SSH public key already exists")]
    KeyExists,
    #[error("active SSH public key does not exist")]
    KeyNotFound,
    #[error("an account must have at least one active SSH public key")]
    LastKey,
    #[error("login identity does not exist or is not active")]
    LoginIdentity,
    #[error("too many login challenges are active")]
    LoginNonceLimit,
    #[error("login challenge is invalid, expired, or already used")]
    InvalidLoginChallenge,
    #[error("SSH login approval is invalid, expired, or already used")]
    InvalidLoginApproval,
    #[error("SSH login approval is waiting for SSH authentication")]
    LoginApprovalPending,
    #[error("Web session is invalid or expired")]
    InvalidSession,
    #[error("repository does not exist: {0}/{1}")]
    RepositoryNotFound(String, String),
    #[error("repository already exists: {0}/{1}")]
    RepositoryExists(String, String),
    #[error("repository ID already exists")]
    RepositoryIdentifierCollision,
    #[error("repository is already archived: {0}/{1}")]
    RepositoryArchived(String, String),
    #[error("repository visibility is not valid")]
    InvalidRepositoryVisibility,
    #[error("repository default branch is not valid")]
    InvalidDefaultBranch,
    #[error("repository default-branch intent {0} is not in the required state")]
    DefaultBranchIntentState(String),
    #[error("collaborator role is not valid")]
    InvalidCollaboratorRole,
    #[error("repository owner cannot be a collaborator")]
    OwnerCollaborator,
    #[error("collaborator account does not exist or is not active: {0}")]
    CollaboratorNotFound(String),
    #[error("repository event page limit is too large")]
    EventLimit,
    #[error("stored Git reference event is malformed")]
    EventPayload,
    #[error("audit event page limit is too large")]
    AuditLimit,
    #[error("issue does not exist: {0}/{1}#{2}")]
    IssueNotFound(String, String, i64),
    #[error("issue access is not authorized")]
    IssueDenied,
    #[error("issue is hidden by repository access policy")]
    IssueHidden,
    #[error("issue state is already {0}")]
    IssueState(String),
    #[error("pull request does not exist: {0}/{1}#{2}")]
    PullRequestNotFound(String, String, i64),
    #[error("pull-request access is not authorized")]
    PullRequestDenied,
    #[error("pull request is hidden by repository access policy")]
    PullRequestHidden,
    #[error("pull request is not open")]
    PullRequestState,
    #[error("pull-request revision does not exist")]
    PullRequestRevisionNotFound,
    #[error("pull-request review anchor does not match its revision")]
    PullRequestReviewAnchor,
    #[error("pull-request ref intent {0} is not in the required state")]
    PullRequestIntentState(String),
    #[error("repository watch access is not authorized")]
    WatchDenied,
    #[error("feed token is invalid or revoked")]
    FeedTokenNotFound,
    #[error("an account cannot have more than one active feed token")]
    FeedTokenLimit,
    #[error("feed token scope is not valid")]
    InvalidFeedScope,
}
