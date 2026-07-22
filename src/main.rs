mod cli;
mod config;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::Cli;

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
        Ok(_config) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tit: {error}");
            ExitCode::FAILURE
        }
    }
}
