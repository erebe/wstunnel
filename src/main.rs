mod embedded_certificate;
mod socks5;
#[cfg(target_family = "unix")]
mod stdio;
mod tcp;
mod tls;
mod tunnel;
mod udp;

use base64::Engine;
use clap::Parser;
use futures_util::{stream, TryStreamExt};
use hyper::header::HOST;
use hyper::http::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt::{Debug, Formatter};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io};

use tokio_rustls::rustls::server::DnsName;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerName};

use tracing::{error, info, Level};

use crate::tunnel::to_host_port;
use tracing_subscriber::EnvFilter;
use url::{Host, Url};

/// Use the websockets protocol to tunnel {TCP,UDP} traffic
/// wsTunnelClient <---> wsTunnelServer <---> RemoteHost
/// Use secure connection (wss://) to bypass proxies
#[derive(clap::Parser, Debug)]
#[command(author, version, about, verbatim_doc_comment, long_about = None)]
struct Wstunnel {
    #[command(subcommand)]
    commands: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    Client(Box<Client>),
    Server(Box<Server>),
}
#[derive(clap::Args, Debug)]
struct Client {
    /// Listen on local and forwards traffic from remote. Can be specified multiple times
    /// examples:
    /// 'tcp://1212:google.com:443'      =>     listen locally on tcp on port 1212 and forward to google.com on port 443
    /// 'udp://1212:1.1.1.1:53'          =>     listen locally on udp on port 1212 and forward to cloudflare dns 1.1.1.1 on port 53
    /// 'udp://1212:1.1.1.1:53?timeout_sec=10'  timeout_sec on udp force close the tunnel after 10sec. Set it to 0 to disable the timeout [default: 30]
    /// 'socks5://[::1]:1212'            =>     listen locally with socks5 on port 1212 and forward dynamically requested tunnel
    /// 'stdio://google.com:443'         =>     listen for data from stdio, mainly for `ssh -o ProxyCommand="wstunnel client -L stdio://%h:%p ws://localhost:8080" my-server`
    /// 'tproxy+tcp://[::1]:1212         =>     listen locally on tcp on port 1212 as a *transparent proxy* and forward dynamically requested tunnel (linux only requires sudo/CAP_NET_ADMIN)
    #[arg(short='L', long, value_name = "{tcp,udp,socks5,stdio}://[BIND:]PORT:HOST:PORT", value_parser = parse_tunnel_arg, verbatim_doc_comment)]
    local_to_remote: Vec<LocalToRemote>,

    /// Listen on remote and forwards traffic from local. Can be specified multiple times. Only tcp is supported
    /// examples:
    /// 'tcp://1212:google.com:443'      =>     listen on server for incoming tcp cnx on port 1212 and forward to google.com on port 443 from local machine
    /// 'udp://1212:1.1.1.1:53'          =>     listen on server for incoming udp on port 1212 and forward to cloudflare dns 1.1.1.1 on port 53 from local machine
    #[arg(short='R', long, value_name = "{tcp,udp}://[BIND:]PORT:HOST:PORT", value_parser = parse_tunnel_arg, verbatim_doc_comment)]
    remote_to_local: Vec<LocalToRemote>,

    /// (linux only) Mark network packet with SO_MARK sockoption with the specified value.
    /// You need to use {root, sudo, capabilities} to run wstunnel when using this option
    #[arg(long, value_name = "INT", verbatim_doc_comment)]
    socket_so_mark: Option<i32>,

    /// Client will maintain a pool of open connection to the server, in order to speed up the connection process.
    /// This option set the maximum number of connection that will be kept open.
    /// This is useful if you plan to create/destroy a lot of tunnel (i.e: with socks5 to navigate with a browser)
    /// It will avoid the latency of doing tcp + tls handshake with the server
    #[arg(short = 'c', long, value_name = "INT", default_value = "0", verbatim_doc_comment)]
    connection_min_idle: u32,

    /// Domain name that will be use as SNI during TLS handshake
    /// Warning: If you are behind a CDN (i.e: Cloudflare) you must set this domain also in the http HOST header.
    ///          or it will be flagged as fishy and your request rejected
    #[arg(long, value_name = "DOMAIN_NAME", value_parser = parse_sni_override, verbatim_doc_comment)]
    tls_sni_override: Option<DnsName>,

    /// Enable TLS certificate verification.
    /// Disabled by default. The client will happily connect to any server with self signed certificate.
    #[arg(long, verbatim_doc_comment)]
    tls_verify_certificate: bool,

    /// If set, will use this http proxy to connect to the server
    #[arg(short = 'p', long, value_name = "http://USER:PASS@HOST:PORT", verbatim_doc_comment)]
    http_proxy: Option<Url>,

    /// Use a specific prefix that will show up in the http path during the upgrade request.
    /// Useful if you need to route requests server side but don't have vhosts
    #[arg(long, default_value = "morille", verbatim_doc_comment)]
    http_upgrade_path_prefix: String,

    /// Pass authorization header with basic auth credentials during the upgrade request.
    /// If you need more customization, you can use the http_headers option.
    #[arg(long, value_name = "USER[:PASS]", value_parser = parse_http_credentials, verbatim_doc_comment)]
    http_upgrade_credentials: Option<HeaderValue>,

    /// Frequency at which the client will send websocket ping to the server.
    #[arg(long, value_name = "seconds", default_value = "30", value_parser = parse_duration_sec, verbatim_doc_comment)]
    websocket_ping_frequency_sec: Option<Duration>,

    /// Enable the masking of websocket frames. Default is false
    /// Enable this option only if you use unsecure (non TLS) websocket server and you see some issues. Otherwise, it is just overhead.
    #[arg(long, default_value = "false", verbatim_doc_comment)]
    websocket_mask_frame: bool,

    /// Send custom headers in the upgrade request
    /// Can be specified multiple time
    #[arg(short='H', long, value_name = "HEADER_NAME: HEADER_VALUE", value_parser = parse_http_headers, verbatim_doc_comment)]
    http_headers: Vec<(HeaderName, HeaderValue)>,

    /// Address of the wstunnel server
    /// Example: With TLS wss://wstunnel.example.com or without ws://wstunnel.example.com
    #[arg(value_name = "ws[s]://wstunnel.server.com[:port]", value_parser = parse_server_url, verbatim_doc_comment)]
    remote_addr: Url,
}

#[derive(clap::Args, Debug)]
struct Server {
    /// Address of the wstunnel server to bind to
    /// Example: With TLS wss://0.0.0.0:8080 or without ws://[::]:8080
    #[arg(value_name = "ws[s]://0.0.0.0[:port]", value_parser = parse_server_url, verbatim_doc_comment)]
    remote_addr: Url,

    /// (linux only) Mark network packet with SO_MARK sockoption with the specified value.
    /// You need to use {root, sudo, capabilities} to run wstunnel when using this option
    #[arg(long, value_name = "INT", verbatim_doc_comment)]
    socket_so_mark: Option<i32>,

    /// Frequency at which the server will send websocket ping to client.
    #[arg(long, value_name = "seconds", value_parser = parse_duration_sec, verbatim_doc_comment)]
    websocket_ping_frequency_sec: Option<Duration>,

    /// Enable the masking of websocket frames. Default is false
    /// Enable this option only if you use unsecure (non TLS) websocket server and you see some issues. Otherwise, it is just overhead.
    #[arg(long, default_value = "false", verbatim_doc_comment)]
    websocket_mask_frame: bool,

    /// Server will only accept connection from the specified tunnel information.
    /// Can be specified multiple time
    /// Example: --restrict-to "google.com:443" --restrict-to "localhost:22"
    #[arg(long, value_name = "DEST:PORT", verbatim_doc_comment)]
    restrict_to: Option<Vec<String>>,

    /// Server will only accept connection from if this specific path prefix is used during websocket upgrade.
    /// Useful if you specify in the client a custom path prefix and you want the server to only allow this one.
    /// The path prefix act as a secret to authenticate clients
    /// Disabled by default. Accept all path prefix
    #[arg(long, verbatim_doc_comment)]
    restrict_http_upgrade_path_prefix: Option<String>,

    /// [Optional] Use custom certificate (.crt) instead of the default embedded self signed certificate.
    #[arg(long, value_name = "FILE_PATH", verbatim_doc_comment)]
    tls_certificate: Option<PathBuf>,

    /// [Optional] Use a custom tls key (.key) that the server will use instead of the default embedded one
    #[arg(long, value_name = "FILE_PATH", verbatim_doc_comment)]
    tls_private_key: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum LocalProtocol {
    Tcp,
    Udp { timeout: Option<Duration> },
    Stdio,
    Socks5,
    TProxyTcp,
    ReverseTcp,
    ReverseUdp { timeout: Option<Duration> },
}

#[derive(Clone, Debug)]
pub struct LocalToRemote {
    local_protocol: LocalProtocol,
    local: SocketAddr,
    remote: (Host<String>, u16),
}

fn parse_duration_sec(arg: &str) -> Result<Duration, io::Error> {
    use std::io::Error;

    let Ok(secs) = arg.parse::<u64>() else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("cannot duration of seconds from {}", arg),
        ));
    };

    Ok(Duration::from_secs(secs))
}

fn parse_local_bind(arg: &str) -> Result<(SocketAddr, &str), io::Error> {
    use std::io::Error;

    let (bind, remaining) = if arg.starts_with('[') {
        // ipv6 bind
        let Some((ipv6_str, remaining)) = arg.split_once(']') else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("cannot parse IPv6 bind from {}", arg),
            ));
        };
        let Ok(ipv6_addr) = Ipv6Addr::from_str(&ipv6_str[1..]) else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("cannot parse IPv6 bind from {}", ipv6_str),
            ));
        };

        (IpAddr::V6(ipv6_addr), remaining)
    } else {
        // Maybe ipv4 addr
        let (ipv4_str, remaining) = arg.split_once(':').unwrap_or((arg, ""));

        match Ipv4Addr::from_str(ipv4_str) {
            Ok(ip4_addr) => (IpAddr::V4(ip4_addr), remaining),
            // Must be the port, so we default to ipv4 bind
            Err(_) => (IpAddr::V4(Ipv4Addr::from_str("127.0.0.1").unwrap()), arg),
        }
    };

    let remaining = remaining.trim_start_matches(':');
    let (port_str, remaining) = remaining.split_once([':', '?']).unwrap_or((remaining, ""));

    let Ok(bind_port): Result<u16, _> = port_str.parse() else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("cannot parse bind port from {}", port_str),
        ));
    };

    Ok((SocketAddr::new(bind, bind_port), remaining))
}

#[allow(clippy::type_complexity)]
fn parse_tunnel_dest(remaining: &str) -> Result<(Host<String>, u16, BTreeMap<String, String>), io::Error> {
    use std::io::Error;

    let Ok(remote) = Url::parse(&format!("fake://{}", remaining)) else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("cannot parse remote from {}", remaining),
        ));
    };

    let Some(remote_host) = remote.host() else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("cannot parse remote host from {}", remaining),
        ));
    };

    let Some(remote_port) = remote.port() else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("cannot parse remote port from {}", remaining),
        ));
    };

    let options: BTreeMap<String, String> = remote.query_pairs().into_owned().collect();
    Ok((remote_host.to_owned(), remote_port, options))
}

fn parse_tunnel_arg(arg: &str) -> Result<LocalToRemote, io::Error> {
    use std::io::Error;

    match &arg[..6] {
        "tcp://" => {
            let (local_bind, remaining) = parse_local_bind(&arg[6..])?;
            let (dest_host, dest_port, _options) = parse_tunnel_dest(remaining)?;
            Ok(LocalToRemote {
                local_protocol: LocalProtocol::Tcp,
                local: local_bind,
                remote: (dest_host, dest_port),
            })
        }
        "udp://" => {
            let (local_bind, remaining) = parse_local_bind(&arg[6..])?;
            let (dest_host, dest_port, options) = parse_tunnel_dest(remaining)?;
            let timeout = options
                .get("timeout_sec")
                .and_then(|x| x.parse::<u64>().ok())
                .map(|d| if d == 0 { None } else { Some(Duration::from_secs(d)) })
                .unwrap_or(Some(Duration::from_secs(30)));

            Ok(LocalToRemote {
                local_protocol: LocalProtocol::Udp { timeout },
                local: local_bind,
                remote: (dest_host, dest_port),
            })
        }
        _ => match &arg[..8] {
            "socks5:/" => {
                let (local_bind, remaining) = parse_local_bind(&arg[9..])?;
                let x = format!("0.0.0.0:0?{}", remaining);
                let (dest_host, dest_port, _options) = parse_tunnel_dest(&x)?;
                Ok(LocalToRemote {
                    local_protocol: LocalProtocol::Socks5,
                    local: local_bind,
                    remote: (dest_host, dest_port),
                })
            }
            "stdio://" => {
                let (dest_host, dest_port, _options) = parse_tunnel_dest(&arg[8..])?;
                Ok(LocalToRemote {
                    local_protocol: LocalProtocol::Stdio,
                    local: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(0), 0)),
                    remote: (dest_host, dest_port),
                })
            }
            "tproxy+t" => {
                let (local_bind, remaining) = parse_local_bind(&arg["tproxy+tcp://".len()..])?;
                let x = format!("0.0.0.0:0?{}", remaining);
                let (dest_host, dest_port, _options) = parse_tunnel_dest(&x)?;
                Ok(LocalToRemote {
                    local_protocol: LocalProtocol::TProxyTcp,
                    local: local_bind,
                    remote: (dest_host, dest_port),
                })
            }
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid local protocol for tunnel {}", arg),
            )),
        },
    }
}

fn parse_sni_override(arg: &str) -> Result<DnsName, io::Error> {
    match DnsName::try_from(arg.to_string()) {
        Ok(val) => Ok(val),
        Err(err) => Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("Invalid sni override: {}", err),
        )),
    }
}

fn parse_http_headers(arg: &str) -> Result<(HeaderName, HeaderValue), io::Error> {
    let Some((key, value)) = arg.split_once(':') else {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("cannot parse http header from {}", arg),
        ));
    };

    let value = match HeaderValue::from_str(value.trim()) {
        Ok(value) => value,
        Err(err) => {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("cannot parse http header value from {} due to {:?}", value, err),
            ))
        }
    };

    Ok((HeaderName::from_str(key).unwrap(), value))
}

fn parse_http_credentials(arg: &str) -> Result<HeaderValue, io::Error> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(arg.trim().as_bytes());
    let Ok(header) = HeaderValue::from_str(&format!("Basic {}", encoded)) else {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("cannot parse http credentials {}", arg),
        ));
    };

    Ok(header)
}

fn parse_server_url(arg: &str) -> Result<Url, io::Error> {
    let Ok(url) = Url::parse(arg) else {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("cannot parse server url {}", arg),
        ));
    };

    if url.scheme() != "ws" && url.scheme() != "wss" {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("invalid scheme {}", url.scheme()),
        ));
    }

    if url.host().is_none() {
        return Err(io::Error::new(ErrorKind::InvalidInput, format!("invalid server host {}", arg)));
    }

    Ok(url)
}

#[derive(Clone, Debug)]
pub struct TlsClientConfig {
    pub tls_sni_override: Option<DnsName>,
    pub tls_verify_certificate: bool,
}

#[derive(Clone, Debug)]
pub struct TlsServerConfig {
    pub tls_certificate: Vec<Certificate>,
    pub tls_key: PrivateKey,
}

#[derive(Clone)]
pub struct WsServerConfig {
    pub socket_so_mark: Option<i32>,
    pub bind: SocketAddr,
    pub restrict_to: Option<Vec<String>>,
    pub restrict_http_upgrade_path_prefix: Option<String>,
    pub websocket_ping_frequency: Option<Duration>,
    pub timeout_connect: Duration,
    pub websocket_mask_frame: bool,
    pub tls: Option<TlsServerConfig>,
}

impl Debug for WsServerConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("WsServerConfig")
            .field("socket_so_mark", &self.socket_so_mark)
            .field("bind", &self.bind)
            .field("restrict_to", &self.restrict_to)
            .field("websocket_ping_frequency", &self.websocket_ping_frequency)
            .field("timeout_connect", &self.timeout_connect)
            .field("websocket_mask_frame", &self.websocket_mask_frame)
            .field("tls", &self.tls.is_some())
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct WsClientConfig {
    pub remote_addr: (Host<String>, u16),
    pub socket_so_mark: Option<i32>,
    pub tls: Option<TlsClientConfig>,
    pub http_upgrade_path_prefix: String,
    pub http_upgrade_credentials: Option<HeaderValue>,
    pub http_headers: HashMap<HeaderName, HeaderValue>,
    pub http_header_host: HeaderValue,
    pub timeout_connect: Duration,
    pub websocket_ping_frequency: Duration,
    pub websocket_mask_frame: bool,
    pub http_proxy: Option<Url>,
    cnx_pool: Option<bb8::Pool<WsClientConfig>>,
}

impl WsClientConfig {
    pub fn websocket_scheme(&self) -> &'static str {
        match self.tls {
            None => "ws",
            Some(_) => "wss",
        }
    }

    pub fn cnx_pool(&self) -> &bb8::Pool<WsClientConfig> {
        self.cnx_pool.as_ref().unwrap()
    }

    pub fn websocket_host_url(&self) -> String {
        format!("{}:{}", self.remote_addr.0, self.remote_addr.1)
    }

    pub fn tls_server_name(&self) -> ServerName {
        match self.tls.as_ref().and_then(|tls| tls.tls_sni_override.as_ref()) {
            None => match &self.remote_addr.0 {
                Host::Domain(domain) => ServerName::DnsName(DnsName::try_from(domain.clone()).unwrap()),
                Host::Ipv4(ip) => ServerName::IpAddress(IpAddr::V4(*ip)),
                Host::Ipv6(ip) => ServerName::IpAddress(IpAddr::V6(*ip)),
            },
            Some(sni_override) => ServerName::DnsName(sni_override.clone()),
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Wstunnel::parse();

    // Setup logging
    match &args.commands {
        // Disable logging if there is a stdio tunnel
        Commands::Client(args)
            if args
                .local_to_remote
                .iter()
                .filter(|x| x.local_protocol == LocalProtocol::Stdio)
                .count()
                > 0 => {}
        _ => {
            tracing_subscriber::fmt()
                .with_ansi(true)
                .with_env_filter(
                    EnvFilter::builder()
                        .with_default_directive(Level::INFO.into())
                        .from_env_lossy(),
                )
                .init();
        }
    }

    match args.commands {
        Commands::Client(args) => {
            let tls = match args.remote_addr.scheme() {
                "ws" => None,
                "wss" => Some(TlsClientConfig {
                    tls_sni_override: args.tls_sni_override,
                    tls_verify_certificate: args.tls_verify_certificate,
                }),
                _ => panic!("invalid scheme in server url {}", args.remote_addr.scheme()),
            };

            // Extract host header from http_headers
            let host_header = if let Some((_, host_val)) = args.http_headers.iter().find(|(h, _)| *h == HOST) {
                host_val.clone()
            } else {
                let host = match args.remote_addr.port_or_known_default() {
                    None | Some(80) | Some(443) => args.remote_addr.host().unwrap().to_string(),
                    Some(port) => format!("{}:{}", args.remote_addr.host().unwrap(), port),
                };
                HeaderValue::from_str(&host).unwrap()
            };
            let mut client_config = WsClientConfig {
                remote_addr: (
                    args.remote_addr.host().unwrap().to_owned(),
                    args.remote_addr.port_or_known_default().unwrap(),
                ),
                socket_so_mark: args.socket_so_mark,
                tls,
                http_upgrade_path_prefix: args.http_upgrade_path_prefix,
                http_upgrade_credentials: args.http_upgrade_credentials,
                http_headers: args.http_headers.into_iter().filter(|(k, _)| k != HOST).collect(),
                http_header_host: host_header,
                timeout_connect: Duration::from_secs(10),
                websocket_ping_frequency: args.websocket_ping_frequency_sec.unwrap_or(Duration::from_secs(30)),
                websocket_mask_frame: args.websocket_mask_frame,
                http_proxy: args.http_proxy,
                cnx_pool: None,
            };

            let pool = bb8::Pool::builder()
                .max_size(1000)
                .min_idle(Some(args.connection_min_idle))
                .max_lifetime(Some(Duration::from_secs(30)))
                .retry_connection(true)
                .build(client_config.clone())
                .await
                .unwrap();
            client_config.cnx_pool = Some(pool);
            let client_config = Arc::new(client_config);

            // Start tunnels
            for mut tunnel in args.remote_to_local.into_iter() {
                let client_config = client_config.clone();
                match &tunnel.local_protocol {
                    LocalProtocol::Tcp => {
                        tunnel.local_protocol = LocalProtocol::ReverseTcp;
                        tokio::spawn(async move {
                            let remote = tunnel.remote.clone();
                            let cfg = client_config.clone();
                            let connect_to_dest = || async {
                                tcp::connect(&remote.0, remote.1, cfg.socket_so_mark, cfg.timeout_connect).await
                            };

                            if let Err(err) =
                                tunnel::client::run_reverse_tunnel(client_config, tunnel, connect_to_dest).await
                            {
                                error!("{:?}", err);
                            }
                        });
                    }
                    LocalProtocol::Udp { timeout } => {
                        tunnel.local_protocol = LocalProtocol::ReverseUdp { timeout: *timeout };

                        tokio::spawn(async move {
                            let cfg = client_config.clone();
                            let remote = tunnel.remote.clone();
                            let connect_to_dest =
                                || async { udp::connect(&remote.0, remote.1, cfg.timeout_connect).await };

                            if let Err(err) =
                                tunnel::client::run_reverse_tunnel(client_config, tunnel, connect_to_dest).await
                            {
                                error!("{:?}", err);
                            }
                        });
                    }
                    _ => panic!("Invalid protocol for reverse tunnel"),
                }
            }

            for tunnel in args.local_to_remote.into_iter() {
                let client_config = client_config.clone();

                match &tunnel.local_protocol {
                    LocalProtocol::Tcp => {
                        let remote = tunnel.remote.clone();
                        let server = tcp::run_server(tunnel.local, false)
                            .await
                            .unwrap_or_else(|err| panic!("Cannot start TCP server on {}: {}", tunnel.local, err))
                            .map_err(anyhow::Error::new)
                            .map_ok(move |stream| (stream.into_split(), remote.clone()));

                        tokio::spawn(async move {
                            if let Err(err) = tunnel::client::run_tunnel(client_config, tunnel, server).await {
                                error!("{:?}", err);
                            }
                        });
                    }
                    #[cfg(target_os = "linux")]
                    LocalProtocol::TProxyTcp => {
                        let server = tcp::run_server(tunnel.local, true)
                            .await
                            .unwrap_or_else(|err| panic!("Cannot start TProxy server on {}: {}", tunnel.local, err))
                            .map_err(anyhow::Error::new)
                            .map_ok(move |stream| {
                                // In TProxy mode local destination is the final ip:port destination
                                let dest = to_host_port(stream.local_addr().unwrap());
                                (stream.into_split(), dest)
                            });

                        tokio::spawn(async move {
                            if let Err(err) = tunnel::client::run_tunnel(client_config, tunnel, server).await {
                                error!("{:?}", err);
                            }
                        });
                    }
                    #[cfg(not(target_os = "linux"))]
                    LocalProtocol::TProxyTcp => {
                        panic!("Transparent proxy is not available for non Linux platform")
                    }
                    LocalProtocol::Udp { timeout } => {
                        let remote = tunnel.remote.clone();
                        let server = udp::run_server(tunnel.local, *timeout)
                            .await
                            .unwrap_or_else(|err| panic!("Cannot start UDP server on {}: {}", tunnel.local, err))
                            .map_err(anyhow::Error::new)
                            .map_ok(move |stream| (tokio::io::split(stream), remote.clone()));

                        tokio::spawn(async move {
                            if let Err(err) = tunnel::client::run_tunnel(client_config, tunnel, server).await {
                                error!("{:?}", err);
                            }
                        });
                    }
                    LocalProtocol::Socks5 => {
                        let server = socks5::run_server(tunnel.local)
                            .await
                            .unwrap_or_else(|err| panic!("Cannot start Socks5 server on {}: {}", tunnel.local, err))
                            .map_ok(|(stream, remote_dest)| (stream.into_split(), remote_dest));

                        tokio::spawn(async move {
                            if let Err(err) = tunnel::client::run_tunnel(client_config, tunnel, server).await {
                                error!("{:?}", err);
                            }
                        });
                    }

                    #[cfg(target_family = "unix")]
                    LocalProtocol::Stdio => {
                        let server = stdio::run_server().await.unwrap_or_else(|err| {
                            panic!("Cannot start STDIO server: {}", err);
                        });
                        tokio::spawn(async move {
                            if let Err(err) = tunnel::client::run_tunnel(
                                client_config,
                                tunnel.clone(),
                                stream::once(async move { Ok((server, tunnel.remote)) }),
                            )
                            .await
                            {
                                error!("{:?}", err);
                            }
                        });
                    }
                    #[cfg(not(target_family = "unix"))]
                    LocalProtocol::Stdio => {
                        panic!("stdio is not implemented for non unix platform")
                    }
                    LocalProtocol::ReverseTcp => {}
                    LocalProtocol::ReverseUdp { .. } => {}
                }
            }
        }
        Commands::Server(args) => {
            let tls_config = if args.remote_addr.scheme() == "wss" {
                let tls_certificate = if let Some(cert_path) = args.tls_certificate {
                    tls::load_certificates_from_pem(&cert_path).expect("Cannot load tls certificate")
                } else {
                    embedded_certificate::TLS_CERTIFICATE.clone()
                };

                let tls_key = if let Some(key_path) = args.tls_private_key {
                    tls::load_private_key_from_file(&key_path).expect("Cannot load tls private key")
                } else {
                    embedded_certificate::TLS_PRIVATE_KEY.clone()
                };
                Some(TlsServerConfig {
                    tls_certificate,
                    tls_key,
                })
            } else {
                None
            };

            let server_config = WsServerConfig {
                socket_so_mark: args.socket_so_mark,
                bind: args.remote_addr.socket_addrs(|| Some(8080)).unwrap()[0],
                restrict_to: args.restrict_to,
                restrict_http_upgrade_path_prefix: args.restrict_http_upgrade_path_prefix,
                websocket_ping_frequency: args.websocket_ping_frequency_sec,
                timeout_connect: Duration::from_secs(10),
                websocket_mask_frame: args.websocket_mask_frame,
                tls: tls_config,
            };

            info!("{:?}", server_config);
            tunnel::server::run_server(Arc::new(server_config))
                .await
                .unwrap_or_else(|err| {
                    panic!("Cannot start wstunnel server: {:?}", err);
                });
        }
    }

    tokio::signal::ctrl_c().await.unwrap();
}
