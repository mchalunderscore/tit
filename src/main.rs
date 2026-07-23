mod admin;
#[allow(
    dead_code,
    reason = "the bootstrap command uses only part of the authentication API"
)]
mod auth;
mod bootstrap;
mod cli;
mod config;
mod domain;
mod feed;
#[allow(dead_code, reason = "the server uses only part of the shared Git API")]
mod git;
#[allow(dead_code, reason = "the server uses only part of the shared HTTP API")]
mod http;
mod instance;
mod markdown;
mod serve;
#[allow(dead_code, reason = "the server uses only part of the shared SSH API")]
mod ssh;
mod store;

use std::process::ExitCode;
use std::{io, io::Write};

use clap::Parser;

use crate::cli::{AdminCommand, Cli, Command, ObjectFormat, RepositoryCommand, SetupCommand};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            return ExitCode::from(u8::try_from(code).unwrap_or(2));
        }
    };

    match config::load(&cli) {
        Ok(config) => match cli.command {
            None => ExitCode::SUCCESS,
            Some(Command::Serve) => match serve::run(&config).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("tit: {error}");
                    ExitCode::FAILURE
                }
            },
            Some(Command::Doctor) => match store::doctor(&config.instance_dir) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("tit: {error}");
                    ExitCode::FAILURE
                }
            },
            Some(Command::Setup {
                command:
                    SetupCommand::Admin {
                        username,
                        ssh_public_key,
                    },
            }) => match bootstrap::setup_administrator(
                &config.instance_dir,
                &username,
                &ssh_public_key,
            ) {
                Ok(recovery_code) => {
                    let mut output = io::stdout().lock();
                    match writeln!(output, "Recovery code: {recovery_code}") {
                        Ok(()) => ExitCode::SUCCESS,
                        Err(error) => {
                            eprintln!("tit: cannot write the recovery code: {error}");
                            ExitCode::FAILURE
                        }
                    }
                }
                Err(error) => {
                    eprintln!("tit: {error}");
                    ExitCode::FAILURE
                }
            },
            Some(Command::Admin {
                command: AdminCommand::Repository { command },
            }) => run_repository_command(&config.instance_dir, command),
        },
        Err(error) => {
            eprintln!("tit: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_repository_command(instance_dir: &std::path::Path, command: RepositoryCommand) -> ExitCode {
    let result = match command {
        RepositoryCommand::Create {
            owner,
            slug,
            object_format,
        } => admin::create_repository(
            instance_dir,
            &owner,
            &slug,
            match object_format {
                ObjectFormat::Sha1 => gix::hash::Kind::Sha1,
                ObjectFormat::Sha256 => gix::hash::Kind::Sha256,
            },
        ),
        RepositoryCommand::Import {
            owner,
            slug,
            source,
        } => admin::import_repository(instance_dir, &owner, &slug, &source),
        RepositoryCommand::Rename {
            owner,
            old_slug,
            new_slug,
        } => admin::rename_repository(instance_dir, &owner, &old_slug, &new_slug),
        RepositoryCommand::Archive { owner, slug } => {
            admin::archive_repository(instance_dir, &owner, &slug)
        }
        RepositoryCommand::Inspect { owner, slug } => {
            admin::inspect_repository(instance_dir, &owner, &slug)
        }
    };

    match result {
        Ok(repository) => {
            let path = match admin::repository_path(instance_dir, &repository) {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("tit: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let archived_at = repository
                .archived_at
                .map_or_else(|| "-".to_owned(), |value| value.to_string());
            let mut output = io::stdout().lock();
            let written = writeln!(output, "id={}", repository.id)
                .and_then(|()| writeln!(output, "owner={}", repository.owner))
                .and_then(|()| writeln!(output, "slug={}", repository.slug))
                .and_then(|()| writeln!(output, "visibility={}", repository.visibility))
                .and_then(|()| writeln!(output, "state={}", repository.state))
                .and_then(|()| writeln!(output, "object-format={}", repository.object_format))
                .and_then(|()| writeln!(output, "created-at={}", repository.created_at))
                .and_then(|()| writeln!(output, "archived-at={archived_at}"))
                .and_then(|()| writeln!(output, "path={}", path.display()));
            match written {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("tit: cannot write repository information: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(error) => {
            eprintln!("tit: {error}");
            ExitCode::FAILURE
        }
    }
}
