use std::collections::HashSet;
use std::env;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;
use url::{Host, Url};

use crate::cli::Cli;

const CONFIG_VERSION: u32 = 1;
const SYSTEM_CONFIG_PATH: &str = "/srv/tit/config.toml";

#[derive(Debug)]
pub(crate) struct Config {
    pub(crate) config_path: PathBuf,
    pub(crate) public_url: Url,
    pub(crate) instance_dir: PathBuf,
    pub(crate) http_listen: SocketAddr,
    pub(crate) ssh_listen: SocketAddr,
    pub(crate) ssh_public_host: Host<String>,
    pub(crate) ssh_public_port: u16,
    pub(crate) signup_policy: SignupPolicy,
    pub(crate) max_request_bytes: u64,
    pub(crate) max_connections: u32,
    pub(crate) trusted_addresses: Vec<IpAddr>,
}

impl Config {
    fn validate(&self, path: &Path) -> Result<(), ConfigError> {
        validate_clean_absolute_path(&self.instance_dir, false)?;
        if path.parent() != Some(self.instance_dir.as_path()) {
            return Err(ConfigError::ConfigOutsideInstance);
        }
        validate_public_url(&self.public_url)?;
        if self.http_listen.port() == 0 {
            return Err(ConfigError::ZeroListenerPort("http.listen"));
        }
        if self.ssh_listen.port() == 0 {
            return Err(ConfigError::ZeroListenerPort("ssh.listen"));
        }
        let advertised_address = match &self.ssh_public_host {
            Host::Ipv4(address) => Some(IpAddr::V4(*address)),
            Host::Ipv6(address) => Some(IpAddr::V6(*address)),
            Host::Domain(_) => None,
        };
        if let Some(address) = advertised_address
            && (address.is_unspecified() || address.is_multicast())
        {
            return Err(ConfigError::InvalidSshPublicAddress(address));
        }
        if self.ssh_public_port == 0 {
            return Err(ConfigError::ZeroSshPort);
        }
        if self.max_request_bytes == 0 {
            return Err(ConfigError::ZeroLimit("max_request_bytes"));
        }
        if self.max_connections == 0 {
            return Err(ConfigError::ZeroLimit("max_connections"));
        }
        if self.signup_policy != SignupPolicy::Invite {
            return Err(ConfigError::UnsupportedSignupPolicy);
        }

        let mut addresses = HashSet::new();
        for address in &self.trusted_addresses {
            if address.is_unspecified() || address.is_multicast() {
                return Err(ConfigError::InvalidTrustedAddress(*address));
            }
            if !addresses.insert(address) {
                return Err(ConfigError::DuplicateTrustedAddress(*address));
            }
        }
        self.clone_urls("owner", "repository")?;
        Ok(())
    }

    pub(crate) fn clone_urls(
        &self,
        owner: &str,
        repository: &str,
    ) -> Result<(Url, Url), ConfigError> {
        let mut http = self.public_url.clone();
        http.path_segments_mut()
            .map_err(|()| ConfigError::CloneUrlBase)?
            .extend([owner, repository]);

        let ssh_origin = if self.ssh_public_port == 22 {
            format!("ssh://{}/", self.ssh_public_host)
        } else {
            format!("ssh://{}:{}/", self.ssh_public_host, self.ssh_public_port)
        };
        let mut ssh = Url::parse(&ssh_origin).map_err(ConfigError::CloneUrl)?;
        ssh.path_segments_mut()
            .map_err(|()| ConfigError::CloneUrlBase)?
            .extend([owner, repository]);
        Ok((http, ssh))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SignupPolicy {
    Invite,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    version: u32,
    public_url: Url,
    #[serde(default)]
    http: HttpConfig,
    #[serde(default)]
    ssh: SshConfig,
    #[serde(default)]
    signup: SignupConfig,
    #[serde(default)]
    limits: LimitsConfig,
    #[serde(default)]
    proxy: ProxyConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct HttpConfig {
    listen: SocketAddr,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:3000"
                .parse()
                .expect("the default HTTP address is valid"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SshConfig {
    listen: SocketAddr,
    public_host: Option<String>,
    public_port: u16,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:2222"
                .parse()
                .expect("the default SSH address is valid"),
            public_host: None,
            public_port: 2222,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SignupConfig {
    policy: SignupPolicy,
}

impl Default for SignupConfig {
    fn default() -> Self {
        Self {
            policy: SignupPolicy::Invite,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct LimitsConfig {
    max_request_bytes: u64,
    max_connections: u32,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_request_bytes: 1_048_576,
            max_connections: 1_024,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ProxyConfig {
    trusted_addresses: Vec<IpAddr>,
}

#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    #[error("cannot determine the user data directory")]
    UserDataDirectory,
    #[error("configuration path must be absolute: {0}")]
    RelativeConfigPath(PathBuf),
    #[error("configuration path must not contain '.' or '..': {0}")]
    UncleanConfigPath(PathBuf),
    #[error("cannot read configuration {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot parse configuration {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("configuration version {0} is not supported")]
    UnsupportedVersion(u32),
    #[error("instance directory must be absolute: {0}")]
    RelativeInstanceDirectory(PathBuf),
    #[error("instance directory must not contain '.' or '..': {0}")]
    UncleanInstanceDirectory(PathBuf),
    #[error("configuration file must be directly inside the instance directory")]
    ConfigOutsideInstance,
    #[error("public URL must not contain credentials, a query, or a fragment")]
    PublicUrlComponents,
    #[error("public URL path must be '/'")]
    PublicUrlPath,
    #[error("public URL must contain a hostname")]
    PublicUrlHost,
    #[error("public URL must use HTTPS unless its host is loopback")]
    InsecurePublicUrl,
    #[error("public SSH port must not be zero")]
    ZeroSshPort,
    #[error("public SSH hostname is not valid: {value}")]
    InvalidSshPublicHost {
        value: String,
        source: url::ParseError,
    },
    #[error("public SSH hostname must not be an unspecified or multicast address: {0}")]
    InvalidSshPublicAddress(IpAddr),
    #[error("listener port {0} must not be zero")]
    ZeroListenerPort(&'static str),
    #[error("configuration limit {0} must not be zero")]
    ZeroLimit(&'static str),
    #[error("signup policy is not supported")]
    UnsupportedSignupPolicy,
    #[error("trusted proxy address is not a unicast address: {0}")]
    InvalidTrustedAddress(IpAddr),
    #[error("trusted proxy address occurs more than once: {0}")]
    DuplicateTrustedAddress(IpAddr),
    #[error("advertised endpoint cannot be a base URL")]
    CloneUrlBase,
    #[error("cannot generate an SSH clone URL: {0}")]
    CloneUrl(url::ParseError),
}

pub(crate) fn load(cli: &Cli) -> Result<Config, ConfigError> {
    let path = config_path(cli)?;
    validate_clean_absolute_path(&path, true)?;

    let contents = fs::read_to_string(&path).map_err(|source| ConfigError::Read {
        path: path.clone(),
        source,
    })?;
    let file: ConfigFile = toml::from_str(&contents).map_err(|source| ConfigError::Parse {
        path: path.clone(),
        source,
    })?;

    if file.version != CONFIG_VERSION {
        return Err(ConfigError::UnsupportedVersion(file.version));
    }

    let instance_dir = path
        .parent()
        .expect("an absolute file has a parent")
        .to_owned();
    let public_url = cli.public_url.clone().unwrap_or(file.public_url);
    let http_listen = cli.http_listen.unwrap_or(file.http.listen);
    let ssh_listen = cli.ssh_listen.unwrap_or(file.ssh.listen);
    let ssh_public_host = cli
        .ssh_public_host
        .as_deref()
        .or(file.ssh.public_host.as_deref())
        .or_else(|| public_url.host_str())
        .ok_or(ConfigError::PublicUrlHost)?;
    let ssh_public_host =
        Host::parse(ssh_public_host).map_err(|source| ConfigError::InvalidSshPublicHost {
            value: ssh_public_host.to_owned(),
            source,
        })?;
    let ssh_public_port = cli.ssh_public_port.unwrap_or(file.ssh.public_port);

    let config = Config {
        config_path: path.clone(),
        public_url,
        instance_dir,
        http_listen,
        ssh_listen,
        ssh_public_host,
        ssh_public_port,
        signup_policy: file.signup.policy,
        max_request_bytes: file.limits.max_request_bytes,
        max_connections: file.limits.max_connections,
        trusted_addresses: file.proxy.trusted_addresses,
    };
    config.validate(&path)?;
    Ok(config)
}

fn config_path(cli: &Cli) -> Result<PathBuf, ConfigError> {
    if let Some(path) = &cli.config {
        return Ok(path.clone());
    }
    if cli.user {
        return user_config_path();
    }
    Ok(PathBuf::from(SYSTEM_CONFIG_PATH))
}

fn user_config_path() -> Result<PathBuf, ConfigError> {
    if let Some(path) = env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
        let path = PathBuf::from(path);
        if path.is_absolute() {
            return Ok(path.join("tit/config.toml"));
        }
        return Err(ConfigError::UserDataDirectory);
    }

    let home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or(ConfigError::UserDataDirectory)?;
    Ok(home.join(".local/share/tit/config.toml"))
}

fn validate_clean_absolute_path(path: &Path, config: bool) -> Result<(), ConfigError> {
    if !path.is_absolute() {
        return if config {
            Err(ConfigError::RelativeConfigPath(path.to_owned()))
        } else {
            Err(ConfigError::RelativeInstanceDirectory(path.to_owned()))
        };
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return if config {
            Err(ConfigError::UncleanConfigPath(path.to_owned()))
        } else {
            Err(ConfigError::UncleanInstanceDirectory(path.to_owned()))
        };
    }
    Ok(())
}

fn validate_public_url(url: &Url) -> Result<(), ConfigError> {
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ConfigError::PublicUrlComponents);
    }
    if url.path() != "/" {
        return Err(ConfigError::PublicUrlPath);
    }

    let loopback = match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(ConfigError::InsecurePublicUrl);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use clap::Parser;
    use tempfile::TempDir;

    use super::*;

    fn write_config(contents: &str) -> (TempDir, PathBuf) {
        let directory = TempDir::new().expect("create a temporary directory");
        let path = directory.path().join("config.toml");
        fs::write(&path, contents).expect("write the configuration");
        (directory, path)
    }

    fn cli(path: &Path) -> Cli {
        Cli::try_parse_from(["tit", "--config", path.to_str().expect("a UTF-8 path")])
            .expect("parse CLI options")
    }

    #[test]
    fn loads_defaults_and_explicit_security_policy() {
        let (_directory, path) = write_config(
            r#"
version = 1
public_url = "https://tit.example/"

[signup]
policy = "invite"

[proxy]
trusted_addresses = []
"#,
        );

        let config = load(&cli(&path)).expect("load the configuration");

        assert_eq!(config.public_url.as_str(), "https://tit.example/");
        assert_eq!(config.instance_dir, path.parent().expect("a parent"));
        assert_eq!(config.http_listen.to_string(), "127.0.0.1:3000");
        assert_eq!(config.ssh_listen.to_string(), "0.0.0.0:2222");
        assert_eq!(
            config.ssh_public_host,
            Host::Domain("tit.example".to_owned())
        );
        assert_eq!(config.ssh_public_port, 2222);
        assert_eq!(config.signup_policy, SignupPolicy::Invite);
        assert_eq!(config.max_request_bytes, 1_048_576);
        assert_eq!(config.max_connections, 1_024);
        assert!(config.trusted_addresses.is_empty());
    }

    #[test]
    fn rejects_unknown_fields() {
        let (_directory, path) =
            write_config("version = 1\npublic_url = \"https://tit.example/\"\nunknown = true\n");

        assert!(matches!(load(&cli(&path)), Err(ConfigError::Parse { .. })));
    }

    #[test]
    fn rejects_unsupported_versions() {
        let (_directory, path) =
            write_config("version = 2\npublic_url = \"https://tit.example/\"\n");

        assert!(matches!(
            load(&cli(&path)),
            Err(ConfigError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn rejects_remote_plain_http() {
        let (_directory, path) =
            write_config("version = 1\npublic_url = \"http://tit.example/\"\n");

        assert!(matches!(
            load(&cli(&path)),
            Err(ConfigError::InsecurePublicUrl)
        ));
    }

    #[test]
    fn permits_loopback_plain_http() {
        let (_directory, path) =
            write_config("version = 1\npublic_url = \"http://127.0.0.1:3000/\"\n");

        load(&cli(&path)).expect("permit a loopback development URL");
    }

    #[test]
    fn applies_cli_overrides() {
        let (_directory, path) =
            write_config("version = 1\npublic_url = \"https://tit.example/\"\n");
        let options = Cli::try_parse_from([
            "tit",
            "--config",
            path.to_str().expect("a UTF-8 path"),
            "--public-url",
            "https://code.example/",
            "--http-listen",
            "127.0.0.1:4000",
            "--ssh-listen",
            "127.0.0.1:4001",
            "--ssh-public-host",
            "ssh.example",
            "--ssh-public-port",
            "4002",
        ])
        .expect("parse CLI overrides");

        let config = load(&options).expect("load the overridden configuration");

        assert_eq!(config.public_url.as_str(), "https://code.example/");
        assert_eq!(config.http_listen.to_string(), "127.0.0.1:4000");
        assert_eq!(config.ssh_listen.to_string(), "127.0.0.1:4001");
        assert_eq!(
            config.ssh_public_host,
            Host::Domain("ssh.example".to_owned())
        );
        assert_eq!(config.ssh_public_port, 4002);
        let (http, ssh) = config
            .clone_urls("alice", "project")
            .expect("generate clone URLs");
        assert_eq!(http.as_str(), "https://code.example/alice/project");
        assert_eq!(ssh.as_str(), "ssh://ssh.example:4002/alice/project");
    }

    #[test]
    fn accepts_an_onion_ssh_hostname() {
        let hostname = format!("{}.onion", "a".repeat(56));
        let (_directory, path) = write_config(&format!(
            "version = 1\npublic_url = \"https://tit.example/\"\n[ssh]\npublic_host = \"{hostname}\"\n"
        ));

        let config = load(&cli(&path)).expect("load the onion SSH hostname");

        assert_eq!(config.ssh_public_host, Host::Domain(hostname.to_owned()));
    }

    #[test]
    fn rejects_an_invalid_ssh_hostname() {
        let (_directory, path) = write_config(
            "version = 1\npublic_url = \"https://tit.example/\"\n[ssh]\npublic_host = \"bad host\"\n",
        );

        assert!(matches!(
            load(&cli(&path)),
            Err(ConfigError::InvalidSshPublicHost { .. })
        ));
    }

    #[test]
    fn rejects_an_unspecified_ssh_address() {
        let (_directory, path) = write_config(
            "version = 1\npublic_url = \"https://tit.example/\"\n[ssh]\npublic_host = \"0.0.0.0\"\n",
        );

        assert!(matches!(
            load(&cli(&path)),
            Err(ConfigError::InvalidSshPublicAddress(address)) if address.is_unspecified()
        ));
    }

    #[test]
    fn omits_the_standard_ssh_port_from_clone_urls() {
        let (_directory, path) = write_config(
            "version = 1\npublic_url = \"https://tit.example/\"\n[ssh]\npublic_port = 22\n",
        );
        let config = load(&cli(&path)).expect("load the configuration");

        let (_http, ssh) = config
            .clone_urls("alice", "project")
            .expect("generate clone URLs");

        assert_eq!(ssh.as_str(), "ssh://tit.example/alice/project");
    }

    #[test]
    fn rejects_zero_limits() {
        let (_directory, path) = write_config(
            r#"
version = 1
public_url = "https://tit.example/"

[limits]
max_request_bytes = 0
max_connections = 1
"#,
        );

        assert!(matches!(
            load(&cli(&path)),
            Err(ConfigError::ZeroLimit("max_request_bytes"))
        ));
    }

    #[test]
    fn rejects_an_unspecified_trusted_proxy() {
        let (_directory, path) = write_config(
            r#"
version = 1
public_url = "https://tit.example/"

[proxy]
trusted_addresses = ["0.0.0.0"]
"#,
        );

        assert!(matches!(
            load(&cli(&path)),
            Err(ConfigError::InvalidTrustedAddress(address)) if address.is_unspecified()
        ));
    }
}
