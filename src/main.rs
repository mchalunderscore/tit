mod cli;
mod config;
mod store;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};

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
        },
        Err(error) => {
            eprintln!("tit: {error}");
            ExitCode::FAILURE
        }
    }
}
