use clap::Parser;
use serde_json::Value as JValue;
use std::path::{Path, PathBuf};
use std::time::Duration;
use wstunnel::executor::DefaultTokioExecutor;
use wstunnel::{run_client, run_server};

/// Run tunnels managed by a configuration file (TOML or YAML)
#[derive(clap::Args, Debug, Clone)]
pub struct RunArgs {
    /// Path to the configuration file (TOML or YAML)
    #[arg(long, value_name = "CONFIG_PATH", default_value = "config.yaml")]
    pub config: PathBuf,
}

#[allow(dead_code)]
#[derive(serde::Deserialize, Debug)]
pub struct Config {
    #[serde(default = "Config::default_log_lvl")]
    pub log_lvl: String,
    #[serde(default)]
    pub no_color: bool,
    pub nb_worker_threads: Option<u32>,
    pub tunnels: Vec<JValue>,

    #[serde(default, skip)]
    pub use_stdio: bool,
    #[serde(default, skip)]
    pub display_args: Vec<String>,
}

pub type ParsedArgs = (crate::Wstunnel, Option<Config>, Vec<crate::Wstunnel>);

impl Config {
    const RESTART_DELAY: Duration = Duration::from_secs(5);

    fn default_log_lvl() -> String {
        "INFO".to_string()
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path_ref = path.as_ref();
        let content = std::fs::read_to_string(path_ref)
            .map_err(|e| anyhow::anyhow!("Failed to read config file {path_ref:?}: {e}"))?;
        Self::from_str(&content, path_ref)
    }

    pub fn from_str<P: AsRef<Path>>(content: &str, path: P) -> anyhow::Result<Self> {
        let path_ref = path.as_ref();
        let ext = path_ref.extension().and_then(|s| s.to_str()).unwrap_or("");
        if ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml") {
            serde_yaml::from_str(content)
                .map_err(|e| anyhow::anyhow!("Failed to parse YAML config file {path_ref:?}: {e}"))
        } else if ext.eq_ignore_ascii_case("toml") {
            toml::from_str(content).map_err(|e| anyhow::anyhow!("Failed to parse TOML config file {path_ref:?}: {e}"))
        } else {
            toml::from_str(content).or_else(|toml_err| {
                serde_yaml::from_str(content)
                    .map_err(|_| anyhow::anyhow!("Failed to parse config file {path_ref:?}: {toml_err}"))
            })
        }
    }

    fn parse_config_line(line: &str) -> Vec<String> {
        let mut args = Vec::new();
        let mut current = String::new();
        let mut in_double_quote = false;
        let mut in_single_quote = false;
        let mut escaped = false;

        for c in line.chars() {
            if escaped {
                current.push(c);
                escaped = false;
            } else if c == '\\' && !in_single_quote {
                escaped = true;
            } else if c == '"' && !in_single_quote {
                in_double_quote = !in_double_quote;
            } else if c == '\'' && !in_double_quote {
                in_single_quote = !in_single_quote;
            } else if c.is_whitespace() && !in_double_quote && !in_single_quote {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            } else {
                current.push(c);
            }
        }
        if !current.is_empty() {
            args.push(current);
        }
        args
    }

    fn format_flag(key: &str) -> String {
        let key = key.replace('_', "-");
        if key.is_empty() || key.starts_with('-') {
            key
        } else if key.len() == 1 {
            format!("-{key}")
        } else {
            format!("--{key}")
        }
    }

    fn append_flag_value(key: &str, value: &JValue, args: &mut Vec<String>) {
        let flag = Self::format_flag(key);
        match value {
            JValue::Bool(b) => {
                if *b && !flag.is_empty() {
                    args.push(flag);
                }
            }
            JValue::String(s) => {
                if !flag.is_empty() {
                    args.push(flag);
                }
                args.push(s.clone());
            }
            JValue::Number(n) => {
                if !flag.is_empty() {
                    args.push(flag);
                }
                args.push(n.to_string());
            }
            JValue::Array(list) => {
                for item in list {
                    Self::append_flag_value(key, item, args);
                }
            }
            _ => {}
        }
    }

    /// Converts a tunnel JSON/YAML/TOML value to command line arguments.
    ///
    /// Supports:
    /// 1. Flat object format: `client = "ws://..."` or `server = "ws://..."` with sibling options.
    /// 2. Raw string command: `"client -L ... ws://..."`.
    pub fn json_to_args(val: &JValue, args: &mut Vec<String>) {
        match val {
            JValue::String(s) => {
                args.extend(Self::parse_config_line(s));
            }
            JValue::Object(map) => {
                let subcmd_entry = map
                    .get("client")
                    .and_then(|v| v.as_str().map(|s| ("client", s)))
                    .or_else(|| map.get("server").and_then(|v| v.as_str().map(|s| ("server", s))));

                if let Some((subcmd, target_url)) = subcmd_entry {
                    args.push(subcmd.to_string());
                    args.push(target_url.to_string());

                    for (key, value) in map {
                        if key == "client" || key == "server" {
                            continue;
                        }
                        Self::append_flag_value(key, value, args);
                    }
                }
            }
            _ => {}
        }
    }

    pub fn parse_args() -> anyhow::Result<Option<ParsedArgs>> {
        // Parse CLI arguments
        let mut args = crate::Wstunnel::parse();
        let mut run_config: Option<Self> = None;
        let mut run_tunnels = Vec::new();
        if let crate::Commands::Run(run_args) = &args.commands {
            let mut config = Self::from_file(&run_args.config)?;

            if (args.log_lvl.is_empty() || args.log_lvl == "INFO") && !config.log_lvl.is_empty() {
                args.log_lvl = config.log_lvl.clone();
            }
            if !args.no_color {
                args.no_color = config.no_color;
            }
            if args.nb_worker_threads.is_none() {
                args.nb_worker_threads = config.nb_worker_threads;
            }

            // Pre-validate all tunnel configurations and build full argv for each tunnel
            let mut use_stdio = 0i32;
            for (i, tunnel_val) in std::mem::take(&mut config.tunnels).into_iter().enumerate() {
                let index = i + 1;

                let mut tunnel_args = Vec::new();
                Self::json_to_args(&tunnel_val, &mut tunnel_args);

                config.display_args.push(tunnel_args.join(" "));
                let has_wstunnel = tunnel_args.first().map(|s| s.as_str()) == Some("wstunnel");
                if !has_wstunnel {
                    tunnel_args.insert(0, "wstunnel".to_string());
                }

                let parsed_args = crate::Wstunnel::try_parse_from(&tunnel_args)
                    .map_err(|e| anyhow::anyhow!("Failed to parse arguments for tunnel #{index}: {e}"))?;
                match &parsed_args.commands {
                    crate::Commands::Client(client_args) => {
                        if client_args
                            .local_to_remote
                            .iter()
                            .any(|x| matches!(x.local_protocol, wstunnel::LocalProtocol::Stdio { .. }))
                        {
                            use_stdio += 1;
                        }
                    }
                    crate::Commands::Server(_) => (),
                    crate::Commands::Run(_) => {
                        return Err(anyhow::anyhow!(
                            "Tunnel #{index} specifies a nested 'run' subcommand, which is not supported"
                        ));
                    }
                }

                run_tunnels.push(parsed_args);
            }

            if use_stdio > 1 {
                return Err(anyhow::anyhow!("Multiple tunnels use stdio, which is not supported."));
            }

            config.use_stdio = use_stdio > 0;
            run_config = Some(config);
        }

        Ok(Some((args, run_config, run_tunnels)))
    }

    async fn wait_for_shutdown_signal() {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigint = signal(SignalKind::interrupt()).ok();
            let mut sigterm = signal(SignalKind::terminate()).ok();
            tokio::select! {
                _ = async {
                    if let Some(sig) = &mut sigint {
                        sig.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    tracing::info!("Received SIGINT shutdown signal.");
                }
                _ = async {
                    if let Some(sig) = &mut sigterm {
                        sig.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    tracing::info!("Received SIGTERM shutdown signal.");
                }
            }
        }
        #[cfg(not(unix))]
        {
            if tokio::signal::ctrl_c().await.is_ok() {
                tracing::info!("Received Ctrl+C shutdown signal.");
            }
        }
    }

    pub async fn run(self, tunnels: Vec<crate::Wstunnel>) -> anyhow::Result<()> {
        if tunnels.is_empty() {
            tracing::warn!("No tunnels specified in config file.");
            return Ok(());
        }

        let mut join_set = tokio::task::JoinSet::new();

        for (i, wstunnel_args) in tunnels.into_iter().enumerate() {
            let index = i + 1;

            let display_args = self.display_args[i].clone();
            join_set.spawn(async move {
                tracing::info!(tunnel = index, args = display_args, "Starting tunnel");
                loop {
                    let res = match &wstunnel_args.commands {
                        crate::Commands::Client(client_args) => {
                            run_client((**client_args).clone(), DefaultTokioExecutor::default()).await
                        }
                        crate::Commands::Server(server_args) => {
                            run_server((**server_args).clone(), DefaultTokioExecutor::default()).await
                        }
                        crate::Commands::Run(_) => {
                            tracing::error!(tunnel = index, "Nested run commands are not supported");
                            return;
                        }
                    };

                    match res {
                        Ok(_) => {
                            tracing::info!(
                                tunnel = index,
                                "Tunnel exited normally. Restarting in {}s...",
                                Self::RESTART_DELAY.as_secs()
                            );
                            tokio::time::sleep(Self::RESTART_DELAY).await;
                        }
                        Err(e) => {
                            tracing::error!(
                                tunnel = index,
                                "Tunnel exited with error: {e:?}. Restarting in {}s...",
                                Self::RESTART_DELAY.as_secs()
                            );
                            tokio::time::sleep(Self::RESTART_DELAY).await;
                        }
                    }
                }
            });
        }

        // Wait for shutdown signal
        Self::wait_for_shutdown_signal().await;

        tracing::info!("Stopping all tunnels...");
        join_set.shutdown().await;
        tracing::info!("All tunnels stopped. Exiting.");

        Ok(())
    }
}
