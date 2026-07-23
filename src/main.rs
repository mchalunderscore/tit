#[allow(
    dead_code,
    reason = "the bootstrap command uses only part of the authentication API"
)]
mod auth;
mod bootstrap;
mod cli;
mod config;
#[allow(dead_code, reason = "M1C proves Git reads before the CLI serves them")]
mod git;
mod instance;
#[allow(dead_code, reason = "M1B proves the SSH server before M2 calls it")]
mod ssh;
mod store;

use std::process::ExitCode;
use std::{io, io::Write};

use clap::Parser;

use crate::cli::{Cli, Command, SetupCommand};

fn main() -> ExitCode {
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
        },
        Err(error) => {
            eprintln!("tit: {error}");
            ExitCode::FAILURE
        }
    }
}
