pub mod app;

pub(crate) mod account;
pub(crate) mod admin;
pub(crate) mod auth;
pub(crate) mod backup;
pub(crate) mod bootstrap;
pub(crate) mod cli;
pub(crate) mod codec;
pub(crate) mod config;
pub(crate) mod control;
pub(crate) mod diagnostics;
pub(crate) mod domain;
pub(crate) mod feed;
pub(crate) mod feed_token;
pub(crate) mod git;
pub(crate) mod http;
pub(crate) mod instance;
pub(crate) mod issue;
pub(crate) mod maintenance;
pub(crate) mod markdown;
pub(crate) mod organization;
pub(crate) mod policy;
pub(crate) mod pull_request;
pub(crate) mod rate_limit;
pub(crate) mod repair;
pub(crate) mod repository;
pub(crate) mod search;
pub(crate) mod serve;
pub(crate) mod session;
pub(crate) mod ssh;
pub(crate) mod store;
pub(crate) mod system;
pub(crate) mod telemetry;
pub(crate) mod watch;

#[cfg(test)]
#[path = "../tests/account_lifecycle.rs"]
mod account_lifecycle_tests;
#[cfg(test)]
#[path = "../tests/auth.rs"]
mod auth_tests;
#[cfg(test)]
#[path = "../tests/git_http.rs"]
mod git_http_tests;
#[cfg(test)]
#[path = "../tests/git_push_ssh.rs"]
mod git_push_ssh_tests;
#[cfg(test)]
#[path = "../tests/git_reads.rs"]
mod git_reads_tests;
#[cfg(test)]
#[path = "../tests/git_repository.rs"]
mod git_repository_tests;
#[cfg(test)]
#[path = "../tests/git_ssh.rs"]
mod git_ssh_tests;
#[cfg(test)]
#[path = "../tests/metadata_search.rs"]
mod metadata_search_tests;
#[cfg(test)]
#[path = "../tests/organizations.rs"]
mod organization_tests;
#[cfg(test)]
#[path = "../tests/public_routes.rs"]
mod public_routes_tests;
#[cfg(test)]
#[path = "../tests/pull_requests.rs"]
mod pull_requests_tests;
#[cfg(test)]
#[path = "../tests/repository_policy.rs"]
mod repository_policy_tests;
#[cfg(test)]
#[path = "../tests/sqlite.rs"]
mod sqlite_tests;
#[cfg(test)]
#[path = "../tests/sqlite_workload.rs"]
mod sqlite_workload_tests;
#[cfg(test)]
#[path = "../tests/ssh.rs"]
mod ssh_tests;
#[cfg(test)]
#[path = "../tests/process.rs"]
mod test_process;
#[cfg(test)]
#[path = "../tests/web_session.rs"]
mod web_session_tests;
#[cfg(test)]
#[path = "../tests/web_shell.rs"]
mod web_shell_tests;
