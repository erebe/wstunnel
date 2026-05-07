use clap::Parser;
use config::{Config, Environment, File as ConfigFile, FileFormat};
use serde::Deserialize;
use std::io;
use std::path::Path;
use std::str::FromStr;
use tracing::warn;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::Directive;
use wstunnel::LocalProtocol;
use wstunnel::config::{Client, Server};
use wstunnel::executor::DefaultTokioExecutor;
use wstunnel::{run_client, run_server};

#[cfg(feature = "jemalloc")]
use tikv_jemallocator::Jemalloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

/// Use Websocket or HTTP2 protocol to tunnel {TCP,UDP} traffic
/// wsTunnelClient <---> wsTunnelServer <---> RemoteHost
#[derive(clap::Parser, Debug)]
#[command(author, version, about, verbatim_doc_comment, long_about = None)]
pub struct Wstunnel {
    #[command(subcommand)]
    commands: Option<Commands>,

    /// Path to config file (supports YAML, TOML, JSON formats)
    /// Config file can contain 'client' and/or 'server' sections
    /// CLI arguments take precedence over config file values
    /// File format is auto-detected from extension (.yaml/.yml, .toml, .json)
    #[arg(long, global = true, value_name = "FILE_PATH", verbatim_doc_comment)]
    config: Option<std::path::PathBuf>,

    /// Disable color output in logs
    #[arg(long, global = true, verbatim_doc_comment, env = "NO_COLOR")]
    no_color: Option<String>,

    /// *WARNING* The flag does nothing, you need to set the env variable *WARNING*
    /// Control the number of threads that will be used.
    /// By default, it is equal the number of cpus
    #[arg(
        long,
        global = true,
        value_name = "INT",
        verbatim_doc_comment,
        env = "TOKIO_WORKER_THREADS"
    )]
    nb_worker_threads: Option<u32>,

    /// Control the log verbosity. i.e: TRACE, DEBUG, INFO, WARN, ERROR, OFF
    /// for more details: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#example-syntax
    #[arg(
        long,
        global = true,
        value_name = "LOG_LEVEL",
        verbatim_doc_comment,
        env = "RUST_LOG",
        default_value = "INFO"
    )]
    log_lvl: String,
}

#[derive(clap::Subcommand, Debug)]
pub enum Commands {
    Client(Box<Client>),
    Server(Box<Server>),
}

#[derive(Debug, Deserialize)]
struct WstunnelConfig {
    /// Optional mode selector - if specified, determines whether to run as client or server
    /// Can be "client" or "server"
    #[serde(default)]
    mode: Option<String>,

    /// Control the log verbosity. i.e: TRACE, DEBUG, INFO, WARN, ERROR, OFF
    #[serde(default)]
    log_lvl: Option<String>,

    /// Disable color output in logs
    #[serde(default)]
    no_color: Option<bool>,

    #[serde(default)]
    client: Option<Client>,
    #[serde(default)]
    server: Option<Server>,
}

fn load_config_file(path: &Path) -> anyhow::Result<WstunnelConfig> {
    // Detect file format from extension
    let format = match path.extension().and_then(|s| s.to_str()) {
        Some("yaml") | Some("yml") => FileFormat::Yaml,
        Some("toml") => FileFormat::Toml,
        Some("json") => FileFormat::Json,
        _ => {
            // Default to YAML if no extension or unknown
            FileFormat::Yaml
        }
    };

    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Config file path contains non-UTF8 characters: {}", path.display()))?;
    let config = Config::builder()
        .add_source(ConfigFile::new(path_str, format))
        // Add environment variables with prefix WSTUNNEL_
        // Separator is __ (double underscore) for nested fields
        // Example: WSTUNNEL_MODE=client, WSTUNNEL_CLIENT__REMOTE_ADDR=ws://localhost:8080
        .add_source(Environment::with_prefix("WSTUNNEL").separator("__").try_parsing(true))
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to load config file '{}': {}", path.display(), e))?;

    let wstunnel_config: WstunnelConfig = config
        .try_deserialize()
        .map_err(|e| anyhow::anyhow!("Failed to parse config file '{}': {}", path.display(), e))?;

    Ok(wstunnel_config)
}

fn load_config_from_env() -> anyhow::Result<WstunnelConfig> {
    // Load configuration only from environment variables
    let config = Config::builder()
        .add_source(Environment::with_prefix("WSTUNNEL").separator("__").try_parsing(true))
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to load config from environment: {}", e))?;

    let wstunnel_config: WstunnelConfig = config
        .try_deserialize()
        .map_err(|e| anyhow::anyhow!("Failed to parse config from environment: {}", e))?;

    Ok(wstunnel_config)
}

fn merge_client_config(mut cli: Client, cli_has_url: bool, file_config: Option<Client>) -> (Client, bool) {
    let Some(file) = file_config else {
        return (cli, false);
    };

    // If config file has a client section, consider remote_addr as "provided"
    let config_has_remote_addr = true;

    // Merge config: CLI args take precedence over config file values.
    // For boolean flags (which default to false and have no "unset" state in clap),
    // we use OR semantics: enabling a flag in either source enables it. A flag set
    // in the config file cannot be overridden to false from the CLI.
    // For numeric/string fields compared against their clap defaults, there is a
    // known limitation: if the user explicitly passes the default value on the CLI
    // (e.g. --connection-min-idle 0), the config file value still takes precedence.
    // Fixing this properly would require tracking clap value sources, which needs a
    // larger refactor separating the CLI arg struct from the config struct.
    if cli.local_to_remote.is_empty() {
        cli.local_to_remote = file.local_to_remote;
    }
    if cli.remote_to_local.is_empty() {
        cli.remote_to_local = file.remote_to_local;
    }
    if cli.socket_so_mark.is_none() {
        cli.socket_so_mark = file.socket_so_mark;
    }
    if cli.connection_min_idle == 0 {
        cli.connection_min_idle = file.connection_min_idle;
    }
    if cli.connection_retry_max_backoff == std::time::Duration::from_secs(300) {
        cli.connection_retry_max_backoff = file.connection_retry_max_backoff;
    }
    if cli.reverse_tunnel_connection_retry_max_backoff == std::time::Duration::from_secs(1) {
        cli.reverse_tunnel_connection_retry_max_backoff = file.reverse_tunnel_connection_retry_max_backoff;
    }
    if cli.tls_sni_override.is_none() {
        cli.tls_sni_override = file.tls_sni_override;
    }
    cli.tls_sni_disable = cli.tls_sni_disable || file.tls_sni_disable;
    cli.tls_ech_enable = cli.tls_ech_enable || file.tls_ech_enable;
    cli.tls_verify_certificate = cli.tls_verify_certificate || file.tls_verify_certificate;
    if cli.http_proxy.is_none() {
        cli.http_proxy = file.http_proxy;
    }
    if cli.http_proxy_login.is_none() {
        cli.http_proxy_login = file.http_proxy_login;
    }
    if cli.http_proxy_password.is_none() {
        cli.http_proxy_password = file.http_proxy_password;
    }
    if cli.http_upgrade_path_prefix == wstunnel::config::DEFAULT_CLIENT_UPGRADE_PATH_PREFIX {
        cli.http_upgrade_path_prefix = file.http_upgrade_path_prefix;
    }
    if cli.http_upgrade_credentials.is_none() {
        cli.http_upgrade_credentials = file.http_upgrade_credentials;
    }
    if cli.websocket_ping_frequency == Some(std::time::Duration::from_secs(30)) {
        cli.websocket_ping_frequency = file.websocket_ping_frequency;
    }
    cli.websocket_mask_frame = cli.websocket_mask_frame || file.websocket_mask_frame;
    if cli.http_headers.is_empty() {
        cli.http_headers = file.http_headers;
    }
    if cli.http_headers_file.is_none() {
        cli.http_headers_file = file.http_headers_file;
    }
    // Only use config remote_addr if CLI didn't provide one
    if !cli_has_url {
        cli.remote_addr = file.remote_addr;
    }
    if cli.tls_certificate.is_none() {
        cli.tls_certificate = file.tls_certificate;
    }
    if cli.tls_private_key.is_none() {
        cli.tls_private_key = file.tls_private_key;
    }
    if cli.dns_resolver.is_empty() {
        cli.dns_resolver = file.dns_resolver;
    }
    cli.dns_resolver_prefer_ipv4 = cli.dns_resolver_prefer_ipv4 || file.dns_resolver_prefer_ipv4;

    (cli, config_has_remote_addr)
}

fn merge_server_config(mut cli: Server, cli_has_url: bool, file_config: Option<Server>) -> (Server, bool) {
    let Some(file) = file_config else {
        return (cli, false);
    };

    // If config file has a server section, consider remote_addr as "provided"
    let config_has_remote_addr = true;

    // Merge config: same semantics as merge_client_config (see comment there).
    if !cli_has_url {
        cli.remote_addr = file.remote_addr;
    }
    if cli.socket_so_mark.is_none() {
        cli.socket_so_mark = file.socket_so_mark;
    }
    if cli.websocket_ping_frequency == Some(std::time::Duration::from_secs(30)) {
        cli.websocket_ping_frequency = file.websocket_ping_frequency;
    }
    cli.websocket_mask_frame = cli.websocket_mask_frame || file.websocket_mask_frame;
    if cli.dns_resolver.is_empty() {
        cli.dns_resolver = file.dns_resolver;
    }
    cli.dns_resolver_prefer_ipv4 = cli.dns_resolver_prefer_ipv4 || file.dns_resolver_prefer_ipv4;
    if cli.restrict_to.is_none() {
        cli.restrict_to = file.restrict_to;
    }
    if cli.restrict_http_upgrade_path_prefix.is_none() {
        cli.restrict_http_upgrade_path_prefix = file.restrict_http_upgrade_path_prefix;
    }
    if cli.restrict_config.is_none() {
        cli.restrict_config = file.restrict_config;
    }
    if cli.tls_certificate.is_none() {
        cli.tls_certificate = file.tls_certificate;
    }
    if cli.tls_private_key.is_none() {
        cli.tls_private_key = file.tls_private_key;
    }
    if cli.tls_client_ca_certs.is_none() {
        cli.tls_client_ca_certs = file.tls_client_ca_certs;
    }
    if cli.http_proxy.is_none() {
        cli.http_proxy = file.http_proxy;
    }
    if cli.http_proxy_login.is_none() {
        cli.http_proxy_login = file.http_proxy_login;
    }
    if cli.http_proxy_password.is_none() {
        cli.http_proxy_password = file.http_proxy_password;
    }
    if cli.remote_to_local_server_idle_timeout == std::time::Duration::from_secs(180) {
        cli.remote_to_local_server_idle_timeout = file.remote_to_local_server_idle_timeout;
    }

    (cli, config_has_remote_addr)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = Wstunnel::parse();

    // Load config file if provided, otherwise try environment variables
    let config_file = if let Some(config_path) = &args.config {
        match load_config_file(config_path) {
            Ok(config) => Some(config),
            Err(e) => {
                eprintln!("Error: Failed to load config file '{}': {}", config_path.display(), e);
                std::process::exit(1);
            }
        }
    } else {
        // Try to load from environment variables only
        match load_config_from_env() {
            Ok(config) => {
                // Only use env config if it has actual configuration
                if config.client.is_some() || config.server.is_some() || config.mode.is_some() {
                    Some(config)
                } else {
                    None
                }
            }
            Err(_) => None, // Ignore errors when no config file is specified
        }
    };

    // Merge global options from config file (CLI takes precedence)
    if let Some(ref config) = config_file {
        // Merge log_lvl if not set via CLI
        if args.log_lvl == "INFO" {
            if let Some(ref log_lvl) = config.log_lvl {
                args.log_lvl = log_lvl.clone();
            }
        }

        // Merge no_color if not set via CLI
        if args.no_color.is_none() {
            if let Some(true) = config.no_color {
                args.no_color = Some("1".to_string());
            }
        }
    }

    // If no subcommand is provided, try to determine mode from config file
    if args.commands.is_none() {
        if let Some(ref config) = config_file {
            // Check if mode is explicitly set
            let mode = config.mode.as_deref();

            // Determine which config to use based on mode or availability
            match mode {
                Some("client") => {
                    if let Some(client_config) = &config.client {
                        args.commands = Some(Commands::Client(Box::new(client_config.clone())));
                    } else {
                        anyhow::bail!("Config file specifies mode='client' but no client configuration found");
                    }
                }
                Some("server") => {
                    if let Some(server_config) = &config.server {
                        args.commands = Some(Commands::Server(Box::new(server_config.clone())));
                    } else {
                        anyhow::bail!("Config file specifies mode='server' but no server configuration found");
                    }
                }
                Some(other) => {
                    anyhow::bail!("Invalid mode '{}' in config file. Must be 'client' or 'server'", other);
                }
                None => {
                    // No explicit mode, try to infer from available sections
                    if config.client.is_some() && config.server.is_none() {
                        args.commands = Some(Commands::Client(Box::new(config.client.as_ref().unwrap().clone())));
                    } else if config.server.is_some() && config.client.is_none() {
                        args.commands = Some(Commands::Server(Box::new(config.server.as_ref().unwrap().clone())));
                    } else if config.client.is_some() && config.server.is_some() {
                        anyhow::bail!(
                            "Config file contains both client and server sections. Please specify mode in config file or use subcommand (client/server)"
                        );
                    } else {
                        anyhow::bail!("Config file does not contain client or server configuration");
                    }
                }
            }
        }
    }

    // Merge config file with CLI args if both are present
    // Track if remote_addr was explicitly provided in config or CLI
    let mut _client_config_has_url = false;
    let mut _server_config_has_url = false;

    if let Some(ref config) = config_file {
        if let Some(ref mut commands) = args.commands {
            match commands {
                Commands::Client(client) => {
                    // Check if CLI provided the URL (Option::is_some())
                    let cli_provided_url = client.remote_addr.is_some();

                    let (merged, has_url) =
                        merge_client_config((**client).clone(), cli_provided_url, config.client.clone());
                    **client = merged;
                    _client_config_has_url = has_url || cli_provided_url;
                }
                Commands::Server(server) => {
                    // Check if CLI provided the URL (Option::is_some())
                    let cli_provided_url = server.remote_addr.is_some();

                    let (merged, has_url) =
                        merge_server_config((**server).clone(), cli_provided_url, config.server.clone());
                    **server = merged;
                    _server_config_has_url = has_url || cli_provided_url;
                }
            }
        }
    } else if let Some(ref commands) = args.commands {
        // No config file, check if CLI provided URL
        match commands {
            Commands::Client(client) => {
                _client_config_has_url = client.remote_addr.is_some();
            }
            Commands::Server(server) => {
                _server_config_has_url = server.remote_addr.is_some();
            }
        }
    }

    let Some(commands) = args.commands else {
        anyhow::bail!(
            "No command specified. Use 'client' or 'server' subcommand, or provide a config file with --config"
        );
    };

    // Validate that remote_addr was explicitly provided
    match &commands {
        Commands::Client(client) => {
            if client.remote_addr.is_none() {
                anyhow::bail!(
                    "Server URL not specified. Please provide it via:\n\
                     - Command line: wstunnel client <URL>\n\
                     - Config file: Set 'client.remote_addr' in your config file"
                );
            }
        }
        Commands::Server(server) => {
            if server.remote_addr.is_none() {
                anyhow::bail!(
                    "Server bind address not specified. Please provide it via:\n\
                     - Command line: wstunnel server <URL>\n\
                     - Config file: Set 'server.remote_addr' in your config file"
                );
            }
        }
    }

    // Setup logging
    let mut env_filter = EnvFilter::builder().parse(&args.log_lvl).expect("Invalid log level");
    if !(args.log_lvl.contains("h2::") || args.log_lvl.contains("h2=")) {
        env_filter = env_filter.add_directive(Directive::from_str("h2::codec=off").expect("Invalid log directive"));
    }
    let logger = tracing_subscriber::fmt()
        .with_ansi(args.no_color.is_none())
        .with_env_filter(env_filter);

    // stdio tunnel capture stdio, so need to log into stderr
    if let Commands::Client(ref client_args) = commands {
        if client_args
            .local_to_remote
            .iter()
            .filter(|x| matches!(x.local_protocol, LocalProtocol::Stdio { .. }))
            .count()
            > 0
        {
            logger.with_writer(io::stderr).init();
        } else {
            logger.init()
        }
    } else {
        logger.init();
    };

    if let Err(err) = fdlimit::raise_fd_limit() {
        warn!("Failed to set soft filelimit to hard file limit: {}", err)
    }

    match commands {
        Commands::Client(args) => {
            run_client(*args, DefaultTokioExecutor::default())
                .await
                .unwrap_or_else(|err| {
                    panic!("Cannot start wstunnel client: {err:?}");
                });
        }
        Commands::Server(args) => {
            run_server(*args, DefaultTokioExecutor::default())
                .await
                .unwrap_or_else(|err| {
                    panic!("Cannot start wstunnel server: {err:?}");
                });
        }
    }

    Ok(())
}
