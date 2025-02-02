use clap::Parser;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use opentelemetry::global;
use tracing::warn;
use tracing_subscriber::filter::Directive;
use tracing_subscriber::EnvFilter;
use wstunnel::config::{Client, Server};
use wstunnel::LocalProtocol;
use wstunnel::{run_client, run_server};
use wstunnel::metrics;

/// Use Websocket or HTTP2 protocol to tunnel {TCP,UDP} traffic
/// wsTunnelClient <---> wsTunnelServer <---> RemoteHost
#[derive(clap::Parser, Debug)]
#[command(author, version, about, verbatim_doc_comment, long_about = None)]
pub struct Wstunnel {
    #[command(subcommand)]
    commands: Commands,

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

    /// Set the listen address for the prometheus metrics exporter.
    #[arg(
        long,
        global = true,
        verbatim_doc_comment,
        default_value = None,
    )]
    metrics_provider_address: Option<SocketAddr>,

    /// Allow metrics to take up unbounded space (OOM risk!).
    #[arg(
        long,
        global = true,
        verbatim_doc_comment,
        default_value = "false",
    )]
    metrics_unbounded: bool,
}

#[derive(clap::Subcommand, Debug)]
pub enum Commands {
    Client(Box<Client>),
    Server(Box<Server>),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Wstunnel::parse();

    // Setup logging
    let mut env_filter = EnvFilter::builder().parse(&args.log_lvl).expect("Invalid log level");
    if !(args.log_lvl.contains("h2::") || args.log_lvl.contains("h2=")) {
        env_filter = env_filter.add_directive(Directive::from_str("h2::codec=off").expect("Invalid log directive"));
    }
    let logger = tracing_subscriber::fmt()
        .with_ansi(args.no_color.is_none())
        .with_env_filter(env_filter);

    // stdio tunnel capture stdio, so need to log into stderr
    if let Commands::Client(args) = &args.commands {
        if args
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

    if let Some(addr) = args.metrics_provider_address {
        match metrics::setup_metrics_provider(&addr).await {
            Ok(provider) => {
                let _ = global::set_meter_provider(provider);
            }
            Err(err) => {
                panic!("Failed to setup metrics server: {err:?}")
            }
        }
    }

    match args.commands {
        Commands::Client(args) => {
            run_client(*args).await?;
        }
        Commands::Server(args) => {
            run_server(*args).await?;
        }
    }

    Ok(())
}
