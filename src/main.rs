mod account;
mod admin;
#[allow(
    dead_code,
    reason = "the bootstrap command uses only part of the authentication API"
)]
mod auth;
mod backup;
mod bootstrap;
mod cli;
mod config;
mod control;
mod diagnostics;
mod domain;
mod feed;
mod feed_token;
#[allow(dead_code, reason = "the server uses only part of the shared Git API")]
mod git;
#[allow(dead_code, reason = "the server uses only part of the shared HTTP API")]
mod http;
mod instance;
mod issue;
mod maintenance;
mod markdown;
mod policy;
mod pull_request;
mod rate_limit;
mod repair;
mod repository;
mod search;
mod serve;
mod session;
#[allow(dead_code, reason = "the server uses only part of the shared SSH API")]
mod ssh;
mod store;
mod watch;

use std::process::ExitCode;
use std::{io, io::Write};

use clap::Parser;

use crate::cli::{
    AccountCommand, AdminCommand, Cli, CollaboratorRole, Command, InspectCommand, ObjectFormat,
    RepairCommand, RepositoryCommand, RepositoryVisibility, SetupCommand,
};

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

    if let Some(Command::Restore { archive, target }) = &cli.command {
        return run_restore(archive, target);
    }

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
            Some(Command::InviteCode) => {
                match control::request_invitation(&config.instance_dir).await {
                    Ok(code) => match writeln!(io::stdout().lock(), "Signup code: {code}") {
                        Ok(()) => ExitCode::SUCCESS,
                        Err(error) => {
                            eprintln!("tit: cannot write the signup code: {error}");
                            ExitCode::FAILURE
                        }
                    },
                    Err(error) => {
                        eprintln!("tit: {error}");
                        ExitCode::FAILURE
                    }
                }
            }
            Some(Command::Doctor { backups }) => match diagnostics::doctor(&config, &backups) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("tit: {error}");
                    ExitCode::FAILURE
                }
            },
            Some(Command::Inspect { command }) => run_inspect_command(&config, command),
            Some(Command::Dump) => run_dump_command(&config),
            Some(Command::Repair { command }) => {
                let result = match command {
                    RepairCommand::Intents => repair::intents(&config.instance_dir),
                    RepairCommand::Quarantine => repair::quarantine(&config.instance_dir),
                };
                match result {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(error) => {
                        eprintln!("tit: {error}");
                        ExitCode::FAILURE
                    }
                }
            }
            Some(Command::Backup { output }) => run_backup(&config, &output).await,
            Some(Command::Restore { .. }) => {
                unreachable!("the restore command runs before configuration is loaded")
            }
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
            Some(Command::Admin {
                command: AdminCommand::Account { command },
            }) => run_account_command(&config.instance_dir, command),
            Some(Command::Admin {
                command: AdminCommand::Audit { limit },
            }) => run_audit_command(&config.instance_dir, limit),
        },
        Err(error) => {
            eprintln!("tit: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inspect_command(config: &config::Config, command: InspectCommand) -> ExitCode {
    let result = match command {
        InspectCommand::Account { username } => {
            serialize_inspection(diagnostics::inspect_account(config, &username))
        }
        InspectCommand::Repository { owner, slug } => {
            serialize_inspection(diagnostics::inspect_repository(config, &owner, &slug))
        }
        InspectCommand::Intent { id } => {
            serialize_inspection(diagnostics::inspect_intent(config, &id))
        }
    };
    match result {
        Ok(line) => match writeln!(io::stdout().lock(), "{line}") {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("tit: cannot write inspect information: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("tit: {error}");
            ExitCode::FAILURE
        }
    }
}

fn serialize_inspection(
    result: Result<impl serde::Serialize, diagnostics::DiagnosticError>,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(serde_json::to_string(&result?)?)
}

fn run_dump_command(config: &config::Config) -> ExitCode {
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut output = io::stdout().lock();
        let mut output_error = None;
        diagnostics::dump(config, |row| {
            let result = serde_json::to_writer(&mut output, &row)
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
                .and_then(|()| {
                    writeln!(output).map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
                });
            match result {
                Ok(()) => true,
                Err(error) => {
                    output_error = Some(error);
                    false
                }
            }
        })?;
        if let Some(error) = output_error {
            return Err(error);
        }
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tit: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run_backup(config: &config::Config, output: &std::path::Path) -> ExitCode {
    let result = match backup::create_offline(&config.instance_dir, &config.config_path, output) {
        Ok(()) => Ok(()),
        Err(backup::BackupError::Instance(instance::InstanceError::Locked)) => {
            control::request_backup(&config.instance_dir, output)
                .await
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
        }
        Err(error) => Err(Box::new(error) as Box<dyn std::error::Error>),
    };
    match result {
        Ok(()) => match writeln!(
            io::stdout().lock(),
            "Backup: {}\nWarning: This backup contains credentials.",
            output.display()
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("tit: cannot write backup information: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("tit: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_restore(archive: &std::path::Path, target: &std::path::Path) -> ExitCode {
    match backup::restore(archive, target) {
        Ok(()) => match writeln!(
            io::stdout().lock(),
            "Restore: {}\nThe restored instance is not active.",
            target.display()
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("tit: cannot write restore information: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("tit: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_audit_command(instance_dir: &std::path::Path, limit: usize) -> ExitCode {
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let _lock = instance::InstanceLock::acquire(instance_dir)?;
        let database = instance::prepare_database(instance_dir)?;
        let events = store::Store::open(&database)?.audit_events(limit)?;
        let mut output = io::stdout().lock();
        for event in events {
            writeln!(output, "id={}", event.id)?;
            writeln!(output, "action={}", event.action)?;
            writeln!(output, "actor={}", event.actor)?;
            writeln!(output, "target={}", event.target)?;
            writeln!(output, "outcome={}", event.outcome)?;
            writeln!(output, "correlation-id={}", event.correlation_id)?;
            writeln!(output, "created-at={}", event.created_at)?;
            writeln!(output)?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tit: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_account_command(instance_dir: &std::path::Path, command: AccountCommand) -> ExitCode {
    let result = (|| -> Result<Option<String>, Box<dyn std::error::Error>> {
        let _lock = instance::InstanceLock::acquire(instance_dir)?;
        let database = instance::prepare_database(instance_dir)?;
        let accounts = account::AccountService::new(database);
        let correlation_id = format!("{:032x}", rand::random::<u128>());
        match command {
            AccountCommand::KeyAdd {
                username,
                label,
                ssh_public_key,
            } => {
                let fingerprint = accounts.add_key(
                    &username,
                    &label,
                    &ssh_public_key,
                    "admin-cli",
                    &correlation_id,
                )?;
                Ok(Some(fingerprint))
            }
            AccountCommand::KeyRevoke {
                username,
                fingerprint,
            } => {
                accounts.revoke_key(&username, &fingerprint, "admin-cli", &correlation_id)?;
                Ok(None)
            }
            AccountCommand::Suspend { username } => {
                accounts.suspend(&username, true, "admin-cli", &correlation_id)?;
                Ok(None)
            }
            AccountCommand::Resume { username } => {
                accounts.suspend(&username, false, "admin-cli", &correlation_id)?;
                Ok(None)
            }
        }
    })();
    match result {
        Ok(Some(fingerprint)) => match writeln!(io::stdout().lock(), "fingerprint={fingerprint}") {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("tit: cannot write account information: {error}");
                ExitCode::FAILURE
            }
        },
        Ok(None) => ExitCode::SUCCESS,
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
        RepositoryCommand::Visibility {
            owner,
            slug,
            visibility,
        } => admin::set_repository_visibility(
            instance_dir,
            &owner,
            &slug,
            match visibility {
                RepositoryVisibility::Public => "public",
                RepositoryVisibility::Private => "private",
            },
        ),
        RepositoryCommand::CollaboratorSet {
            owner,
            slug,
            username,
            role,
        } => admin::set_repository_collaborator(
            instance_dir,
            &owner,
            &slug,
            &username,
            match role {
                CollaboratorRole::Maintainer => "maintainer",
                CollaboratorRole::Writer => "writer",
                CollaboratorRole::Reader => "reader",
            },
        ),
        RepositoryCommand::CollaboratorRemove {
            owner,
            slug,
            username,
        } => admin::remove_repository_collaborator(instance_dir, &owner, &slug, &username),
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
