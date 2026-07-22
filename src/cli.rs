use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use url::Url;

#[derive(Debug, Parser)]
#[command(
    name = "tit",
    version,
    about = "A small self-hosted collaborative development environment",
    arg_required_else_help = true
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<Command>,

    /// Read configuration from FILE
    #[arg(long, value_name = "FILE", conflicts_with = "user")]
    pub(crate) config: Option<PathBuf>,

    /// Read configuration from the XDG data directory
    #[arg(long)]
    pub(crate) user: bool,

    /// Override the canonical public URL
    #[arg(long, value_name = "URL")]
    pub(crate) public_url: Option<Url>,

    /// Override the HTTP listener address
    #[arg(long, value_name = "ADDRESS")]
    pub(crate) http_listen: Option<SocketAddr>,

    /// Override the SSH listener address
    #[arg(long, value_name = "ADDRESS")]
    pub(crate) ssh_listen: Option<SocketAddr>,

    /// Override the advertised SSH hostname
    #[arg(long, value_name = "HOST")]
    pub(crate) ssh_public_host: Option<String>,

    /// Override the public SSH port
    #[arg(long, value_name = "PORT")]
    pub(crate) ssh_public_port: Option<u16>,
}

#[derive(Clone, Copy, Debug, Subcommand)]
pub(crate) enum Command {
    /// Check the instance database
    Doctor,
}
