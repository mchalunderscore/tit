use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
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

#[derive(Clone, Debug, Subcommand)]
pub(crate) enum Command {
    /// Start the HTTP and SSH servers
    Serve,
    /// Create a single-use signup invitation
    InviteCode,
    /// Check the instance without changing it
    Doctor {
        /// Also check the manifest and checksums in FILE
        #[arg(long = "backup", value_name = "FILE")]
        backups: Vec<PathBuf>,
    },
    /// Show one typed instance record as JSON
    Inspect {
        #[command(subcommand)]
        command: InspectCommand,
    },
    /// Write all SQLite rows as deterministic JSON Lines
    Dump,
    /// Run an explicit repair operation
    Repair {
        #[command(subcommand)]
        command: RepairCommand,
    },
    /// Create a backup archive
    Backup {
        /// Write the backup archive to FILE
        output: PathBuf,
    },
    /// Restore a backup archive to an empty instance directory
    Restore {
        /// Read the backup archive from FILE
        archive: PathBuf,
        /// Restore the instance into DIRECTORY
        target: PathBuf,
    },
    /// Set up an uninitialized instance
    Setup {
        #[command(subcommand)]
        command: SetupCommand,
    },
    /// Run an offline administrator command
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
}

#[derive(Clone, Debug, Subcommand)]
pub(crate) enum RepairCommand {
    /// Recover incomplete Git and pull-request ref intents
    Intents,
    /// Remove quarantine debris after all intents are complete
    Quarantine,
}

#[derive(Clone, Debug, Subcommand)]
pub(crate) enum InspectCommand {
    /// Show an account and its SSH key metadata
    Account { username: String },
    /// Show a repository record after Git validation
    Repository { owner: String, slug: String },
    /// Show a Git operation intent
    Intent { id: String },
}

#[derive(Clone, Debug, Subcommand)]
pub(crate) enum AdminCommand {
    /// Show recent audit events
    Audit {
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Administer repositories
    Repository {
        #[command(subcommand)]
        command: RepositoryCommand,
    },
    /// Administer accounts
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
}

#[derive(Clone, Debug, Subcommand)]
pub(crate) enum AccountCommand {
    /// Add an SSH public key
    KeyAdd {
        username: String,
        label: String,
        ssh_public_key: String,
    },
    /// Revoke an SSH public key
    KeyRevoke {
        username: String,
        fingerprint: String,
    },
    /// Suspend an account
    Suspend { username: String },
    /// Restore a suspended account
    Resume { username: String },
}

#[derive(Clone, Debug, Subcommand)]
pub(crate) enum RepositoryCommand {
    /// Create an empty repository
    Create {
        owner: String,
        slug: String,
        #[arg(long, value_enum, default_value_t = ObjectFormat::Sha1)]
        object_format: ObjectFormat,
    },
    /// Import a bare repository
    Import {
        owner: String,
        slug: String,
        source: PathBuf,
    },
    /// Rename a repository
    Rename {
        owner: String,
        old_slug: String,
        new_slug: String,
    },
    /// Archive a repository
    Archive { owner: String, slug: String },
    /// Set repository visibility
    Visibility {
        owner: String,
        slug: String,
        visibility: RepositoryVisibility,
    },
    /// Set a collaborator role
    CollaboratorSet {
        owner: String,
        slug: String,
        username: String,
        role: CollaboratorRole,
    },
    /// Remove a collaborator
    CollaboratorRemove {
        owner: String,
        slug: String,
        username: String,
    },
    /// Inspect a repository
    Inspect { owner: String, slug: String },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum RepositoryVisibility {
    Public,
    Private,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum CollaboratorRole {
    Maintainer,
    Writer,
    Reader,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum ObjectFormat {
    #[default]
    Sha1,
    Sha256,
}

#[derive(Clone, Debug, Subcommand)]
pub(crate) enum SetupCommand {
    /// Create the initial administrator
    Admin {
        /// Use USERNAME for the administrator
        username: String,
        /// Use KEY as the administrator SSH public key
        ssh_public_key: String,
    },
}
