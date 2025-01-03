mod config;
mod embedded_certificate;
mod protocols;
mod restrictions;
#[cfg(test)]
mod test_integrations;
mod tunnel;

use crate::config::{DEFAULT_CLIENT_UPGRADE_PATH_PREFIX, Wstunnel, Commands};
use crate::protocols::dns::DnsResolver;
use crate::protocols::tls;
use crate::restrictions::types::RestrictionsRules;
use crate::tunnel::client::{TlsClientConfig, WsClient, WsClientConfig};
use crate::tunnel::connectors::{Socks5TunnelConnector, TcpTunnelConnector, UdpTunnelConnector};
use crate::tunnel::listeners::{
    new_stdio_listener, HttpProxyTunnelListener, Socks5TunnelListener, TcpTunnelListener, UdpTunnelListener,
};
use crate::tunnel::server::{TlsServerConfig, WsServer, WsServerConfig};
use crate::tunnel::transport::{TransportAddr, TransportScheme};
use crate::tunnel::{to_host_port, LocalProtocol, RemoteAddr};
use anyhow::{anyhow, Context};
use base64::Engine;
use clap::Parser;
use hyper::header::HOST;
use hyper::http::{HeaderName, HeaderValue};
use log::{debug, warn};
use parking_lot::{Mutex, RwLock};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::select;
use tokio_rustls::rustls::pki_types::DnsName;
use tracing::{error, info};
use tracing_subscriber::filter::Directive;
use tracing_subscriber::EnvFilter;
use url::{Host, Url};

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

    match args.commands {
        Commands::Client(args) => {
            let (tls_certificate, tls_key) = if let (Some(cert), Some(key)) =
                (args.tls_certificate.as_ref(), args.tls_private_key.as_ref())
            {
                let tls_certificate =
                    tls::load_certificates_from_pem(cert).expect("Cannot load client TLS certificate (mTLS)");
                let tls_key = tls::load_private_key_from_file(key).expect("Cannot load client TLS private key (mTLS)");
                (Some(tls_certificate), Some(tls_key))
            } else {
                (None, None)
            };

            let http_upgrade_path_prefix = if args.http_upgrade_path_prefix.eq(DEFAULT_CLIENT_UPGRADE_PATH_PREFIX) {
                // When using mTLS and no manual http upgrade path is specified configure the HTTP upgrade path
                // to be the common name (CN) of the client's certificate.
                tls_certificate
                    .as_ref()
                    .and_then(|certs| tls::find_leaf_certificate(certs.as_slice()))
                    .and_then(|leaf_cert| tls::cn_from_certificate(&leaf_cert))
                    .unwrap_or(args.http_upgrade_path_prefix)
            } else {
                args.http_upgrade_path_prefix
            };

            let transport_scheme =
                TransportScheme::from_str(args.remote_addr.scheme()).expect("invalid scheme in server url");
            let tls = match transport_scheme {
                TransportScheme::Ws | TransportScheme::Http => None,
                TransportScheme::Wss | TransportScheme::Https => Some(TlsClientConfig {
                    tls_connector: Arc::new(RwLock::new(
                        tls::tls_connector(
                            args.tls_verify_certificate,
                            transport_scheme.alpn_protocols(),
                            !args.tls_sni_disable,
                            tls_certificate,
                            tls_key,
                        )
                        .expect("Cannot create tls connector"),
                    )),
                    tls_sni_override: args.tls_sni_override,
                    tls_verify_certificate: args.tls_verify_certificate,
                    tls_sni_disabled: args.tls_sni_disable,
                    tls_certificate_path: args.tls_certificate.clone(),
                    tls_key_path: args.tls_private_key.clone(),
                }),
            };

            // Extract host header from http_headers
            let host_header = if let Some((_, host_val)) = args.http_headers.iter().find(|(h, _)| *h == HOST) {
                host_val.clone()
            } else {
                let host = match args.remote_addr.port_or_known_default() {
                    None | Some(80) | Some(443) => args.remote_addr.host().unwrap().to_string(),
                    Some(port) => format!("{}:{}", args.remote_addr.host().unwrap(), port),
                };
                HeaderValue::from_str(&host)?
            };
            if let Some(path) = &args.http_headers_file {
                if !path.exists() {
                    panic!("http headers file does not exists: {}", path.display());
                }
            }

            let http_proxy = mk_http_proxy(args.http_proxy, args.http_proxy_login, args.http_proxy_password)?;
            let client_config = WsClientConfig {
                remote_addr: TransportAddr::new(
                    TransportScheme::from_str(args.remote_addr.scheme()).unwrap(),
                    args.remote_addr.host().unwrap().to_owned(),
                    args.remote_addr.port_or_known_default().unwrap(),
                    tls,
                )
                .unwrap(),
                socket_so_mark: args.socket_so_mark,
                http_upgrade_path_prefix,
                http_upgrade_credentials: args.http_upgrade_credentials,
                http_headers: args.http_headers.into_iter().filter(|(k, _)| k != HOST).collect(),
                http_headers_file: args.http_headers_file,
                http_header_host: host_header,
                timeout_connect: Duration::from_secs(10),
                websocket_ping_frequency: args
                    .websocket_ping_frequency_sec
                    .or(Some(Duration::from_secs(30)))
                    .filter(|d| d.as_secs() > 0),
                websocket_mask_frame: args.websocket_mask_frame,
                dns_resolver: DnsResolver::new_from_urls(
                    &args.dns_resolver,
                    http_proxy.clone(),
                    args.socket_so_mark,
                    !args.dns_resolver_prefer_ipv4,
                )
                .expect("cannot create dns resolver"),
                http_proxy,
            };

            let client =
                WsClient::new(client_config, args.connection_min_idle, args.connection_retry_max_backoff_sec).await?;
            info!("Starting wstunnel client v{}", env!("CARGO_PKG_VERSION"),);

            // Start tunnels
            for tunnel in args.remote_to_local.into_iter() {
                let client = client.clone();
                match &tunnel.local_protocol {
                    LocalProtocol::ReverseTcp { .. } => {
                        tokio::spawn(async move {
                            let cfg = client.config.clone();
                            let tcp_connector = TcpTunnelConnector::new(
                                &tunnel.remote.0,
                                tunnel.remote.1,
                                cfg.socket_so_mark,
                                cfg.timeout_connect,
                                &cfg.dns_resolver,
                            );
                            let (host, port) = to_host_port(tunnel.local);
                            let remote = RemoteAddr {
                                protocol: LocalProtocol::ReverseTcp,
                                host,
                                port,
                            };
                            if let Err(err) = client.run_reverse_tunnel(remote, tcp_connector).await {
                                error!("{:?}", err);
                            }
                        });
                    }
                    LocalProtocol::ReverseUdp { timeout } => {
                        let timeout = *timeout;

                        tokio::spawn(async move {
                            let cfg = client.config.clone();
                            let (host, port) = to_host_port(tunnel.local);
                            let remote = RemoteAddr {
                                protocol: LocalProtocol::ReverseUdp { timeout },
                                host,
                                port,
                            };
                            let udp_connector = UdpTunnelConnector::new(
                                &tunnel.remote.0,
                                tunnel.remote.1,
                                cfg.socket_so_mark,
                                cfg.timeout_connect,
                                &cfg.dns_resolver,
                            );

                            if let Err(err) = client.run_reverse_tunnel(remote.clone(), udp_connector).await {
                                error!("{:?}", err);
                            }
                        });
                    }
                    LocalProtocol::ReverseSocks5 { timeout, credentials } => {
                        let credentials = credentials.clone();
                        let timeout = *timeout;
                        tokio::spawn(async move {
                            let cfg = client.config.clone();
                            let (host, port) = to_host_port(tunnel.local);
                            let remote = RemoteAddr {
                                protocol: LocalProtocol::ReverseSocks5 { timeout, credentials },
                                host,
                                port,
                            };
                            let socks_connector =
                                Socks5TunnelConnector::new(cfg.socket_so_mark, cfg.timeout_connect, &cfg.dns_resolver);

                            if let Err(err) = client.run_reverse_tunnel(remote, socks_connector).await {
                                error!("{:?}", err);
                            }
                        });
                    }
                    LocalProtocol::ReverseHttpProxy { timeout, credentials } => {
                        let credentials = credentials.clone();
                        let timeout = *timeout;
                        tokio::spawn(async move {
                            let cfg = client.config.clone();
                            let (host, port) = to_host_port(tunnel.local);
                            let remote = RemoteAddr {
                                protocol: LocalProtocol::ReverseHttpProxy { timeout, credentials },
                                host,
                                port,
                            };
                            let tcp_connector = TcpTunnelConnector::new(
                                &tunnel.remote.0,
                                tunnel.remote.1,
                                cfg.socket_so_mark,
                                cfg.timeout_connect,
                                &cfg.dns_resolver,
                            );

                            if let Err(err) = client.run_reverse_tunnel(remote, tcp_connector).await {
                                error!("{:?}", err);
                            }
                        });
                    }
                    LocalProtocol::ReverseUnix { path } => {
                        let path = path.clone();
                        tokio::spawn(async move {
                            let cfg = client.config.clone();
                            let tcp_connector = TcpTunnelConnector::new(
                                &tunnel.remote.0,
                                tunnel.remote.1,
                                cfg.socket_so_mark,
                                cfg.timeout_connect,
                                &cfg.dns_resolver,
                            );

                            let (host, port) = to_host_port(tunnel.local);
                            let remote = RemoteAddr {
                                protocol: LocalProtocol::ReverseUnix { path },
                                host,
                                port,
                            };
                            if let Err(err) = client.run_reverse_tunnel(remote, tcp_connector).await {
                                error!("{:?}", err);
                            }
                        });
                    }
                    LocalProtocol::Stdio { .. }
                    | LocalProtocol::TProxyTcp
                    | LocalProtocol::TProxyUdp { .. }
                    | LocalProtocol::Tcp { .. }
                    | LocalProtocol::Udp { .. }
                    | LocalProtocol::Socks5 { .. }
                    | LocalProtocol::HttpProxy { .. } => {}
                    LocalProtocol::Unix { .. } => {
                        panic!("Invalid protocol for reverse tunnel");
                    }
                }
            }

            for tunnel in args.local_to_remote.into_iter() {
                let client = client.clone();

                match &tunnel.local_protocol {
                    LocalProtocol::Tcp { proxy_protocol } => {
                        let server =
                            TcpTunnelListener::new(tunnel.local, tunnel.remote.clone(), *proxy_protocol).await?;
                        tokio::spawn(async move {
                            if let Err(err) = client.run_tunnel(server).await {
                                error!("{:?}", err);
                            }
                        });
                    }
                    #[cfg(target_os = "linux")]
                    LocalProtocol::TProxyTcp => {
                        use crate::tunnel::listeners::TproxyTcpTunnelListener;
                        let server = TproxyTcpTunnelListener::new(tunnel.local, false).await?;

                        tokio::spawn(async move {
                            if let Err(err) = client.run_tunnel(server).await {
                                error!("{:?}", err);
                            }
                        });
                    }
                    #[cfg(unix)]
                    LocalProtocol::Unix { path, proxy_protocol } => {
                        use crate::tunnel::listeners::UnixTunnelListener;
                        let server = UnixTunnelListener::new(path, tunnel.remote.clone(), *proxy_protocol).await?;
                        tokio::spawn(async move {
                            if let Err(err) = client.run_tunnel(server).await {
                                error!("{:?}", err);
                            }
                        });
                    }
                    #[cfg(not(unix))]
                    LocalProtocol::Unix { .. } => {
                        panic!("Unix socket is not available for non Unix platform")
                    }

                    #[cfg(target_os = "linux")]
                    LocalProtocol::TProxyUdp { timeout } => {
                        use crate::tunnel::listeners::new_tproxy_udp;
                        let server = new_tproxy_udp(tunnel.local, *timeout).await?;
                        tokio::spawn(async move {
                            if let Err(err) = client.run_tunnel(server).await {
                                error!("{:?}", err);
                            }
                        });
                    }
                    #[cfg(not(target_os = "linux"))]
                    LocalProtocol::TProxyTcp | LocalProtocol::TProxyUdp { .. } => {
                        panic!("Transparent proxy is not available for non Linux platform")
                    }
                    LocalProtocol::Udp { timeout } => {
                        let server = UdpTunnelListener::new(tunnel.local, tunnel.remote.clone(), *timeout).await?;

                        tokio::spawn(async move {
                            if let Err(err) = client.run_tunnel(server).await {
                                error!("{:?}", err);
                            }
                        });
                    }
                    LocalProtocol::Socks5 { timeout, credentials } => {
                        let server = Socks5TunnelListener::new(tunnel.local, *timeout, credentials.clone()).await?;
                        tokio::spawn(async move {
                            if let Err(err) = client.run_tunnel(server).await {
                                error!("{:?}", err);
                            }
                        });
                    }
                    LocalProtocol::HttpProxy {
                        timeout,
                        credentials,
                        proxy_protocol,
                    } => {
                        let server =
                            HttpProxyTunnelListener::new(tunnel.local, *timeout, credentials.clone(), *proxy_protocol)
                                .await?;
                        tokio::spawn(async move {
                            if let Err(err) = client.run_tunnel(server).await {
                                error!("{:?}", err);
                            }
                        });
                    }

                    LocalProtocol::Stdio { proxy_protocol } => {
                        let (server, mut handle) = new_stdio_listener(tunnel.remote.clone(), *proxy_protocol).await?;
                        tokio::spawn(async move {
                            if let Err(err) = client.run_tunnel(server).await {
                                error!("{:?}", err);
                            }
                        });

                        // We need to wait for either a ctrl+c of that the stdio tunnel is closed
                        // to force exit the program
                        select! {
                           _ = handle.closed() => {},
                           _ = tokio::signal::ctrl_c() => {}
                        }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        std::process::exit(0);
                    }
                    LocalProtocol::ReverseTcp => {}
                    LocalProtocol::ReverseUdp { .. } => {}
                    LocalProtocol::ReverseSocks5 { .. } => {}
                    LocalProtocol::ReverseUnix { .. } => {}
                    LocalProtocol::ReverseHttpProxy { .. } => {}
                }
            }
        }
        Commands::Server(args) => {
            let tls_config = if args.remote_addr.scheme() == "wss" {
                let tls_certificate = if let Some(cert_path) = &args.tls_certificate {
                    tls::load_certificates_from_pem(cert_path).expect("Cannot load tls certificate")
                } else {
                    embedded_certificate::TLS_CERTIFICATE.0.clone()
                };

                let tls_key = if let Some(key_path) = &args.tls_private_key {
                    tls::load_private_key_from_file(key_path).expect("Cannot load tls private key")
                } else {
                    embedded_certificate::TLS_CERTIFICATE.1.clone_key()
                };

                let tls_client_ca_certificates = args.tls_client_ca_certs.as_ref().map(|tls_client_ca| {
                    Mutex::new(
                        tls::load_certificates_from_pem(tls_client_ca)
                            .expect("Cannot load client CA certificate (mTLS)"),
                    )
                });

                Some(TlsServerConfig {
                    tls_certificate: Mutex::new(tls_certificate),
                    tls_key: Mutex::new(tls_key),
                    tls_client_ca_certificates,
                    tls_certificate_path: args.tls_certificate,
                    tls_key_path: args.tls_private_key,
                    tls_client_ca_certs_path: args.tls_client_ca_certs,
                })
            } else {
                None
            };

            let restrictions = if let Some(path) = &args.restrict_config {
                RestrictionsRules::from_config_file(path).expect("Cannot parse restriction file")
            } else {
                let restrict_to: Vec<(String, u16)> = args
                    .restrict_to
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(|x| {
                        let (host, port) = x.rsplit_once(':').expect("Invalid restrict-to format");
                        (
                            host.trim_matches(['[', ']']).to_string(),
                            port.parse::<u16>().expect("Invalid restrict-to port format"),
                        )
                    })
                    .collect();

                let restriction_cfg = RestrictionsRules::from_path_prefix(
                    args.restrict_http_upgrade_path_prefix.as_deref().unwrap_or(&[]),
                    &restrict_to,
                )
                .expect("Cannot convert restriction rules from path-prefix and restric-to");
                restriction_cfg
            };

            let http_proxy = mk_http_proxy(args.http_proxy, args.http_proxy_login, args.http_proxy_password)?;
            let server_config = WsServerConfig {
                socket_so_mark: args.socket_so_mark,
                bind: args.remote_addr.socket_addrs(|| Some(8080))?[0],
                websocket_ping_frequency: args
                    .websocket_ping_frequency_sec
                    .or(Some(Duration::from_secs(30)))
                    .filter(|d| d.as_secs() > 0),
                timeout_connect: Duration::from_secs(10),
                websocket_mask_frame: args.websocket_mask_frame,
                tls: tls_config,
                dns_resolver: DnsResolver::new_from_urls(
                    &args.dns_resolver,
                    None,
                    args.socket_so_mark,
                    !args.dns_resolver_prefer_ipv4,
                )
                .expect("Cannot create DNS resolver"),
                restriction_config: args.restrict_config,
                http_proxy,
            };
            let server = WsServer::new(server_config);

            info!(
                "Starting wstunnel server v{} with config {:?}",
                env!("CARGO_PKG_VERSION"),
                server.config
            );
            debug!("Restriction rules: {:#?}", restrictions);
            server.serve(restrictions).await.unwrap_or_else(|err| {
                panic!("Cannot start wstunnel server: {:?}", err);
            });
        }
    }

    tokio::signal::ctrl_c().await?;
    Ok(())
}

fn mk_http_proxy(
    http_proxy: Option<String>,
    proxy_login: Option<String>,
    proxy_password: Option<String>,
) -> anyhow::Result<Option<Url>> {
    let Some(proxy) = http_proxy else {
        return Ok(None);
    };

    let mut proxy = if proxy.starts_with("http://") {
        Url::parse(&proxy).with_context(|| "Invalid http proxy url")?
    } else {
        Url::parse(&format!("http://{}", proxy)).with_context(|| "Invalid http proxy url")?
    };

    if let Some(login) = proxy_login {
        proxy
            .set_username(login.as_str())
            .map_err(|_| anyhow!("Cannot set http proxy login"))?;
    }

    if let Some(password) = proxy_password {
        proxy
            .set_password(Some(password.as_str()))
            .map_err(|_| anyhow!("Cannot set http proxy password"))?;
    }

    Ok(Some(proxy))
}

#[cfg(test)]
mod test {
    use crate::tunnel::LocalProtocol;
    use crate::{parse_local_bind, parse_tunnel_arg, parse_tunnel_dest, LocalToRemote};
    use collection_macros::btreemap;
    use std::collections::BTreeMap;
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use test_case::test_case;
    use url::Host;

    #[test_case("localhost:443" => (Host::Domain("localhost".to_string()), 443, BTreeMap::new()) ; "with domain")]
    #[test_case("127.0.0.1:443" => (Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 443, BTreeMap::new()) ; "with IPv4")]
    #[test_case("[::1]:8080" => (Host::Ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080, BTreeMap::new()) ; "with IpV6")]
    #[test_case("a:1?timeout_sec=30&b=5" => (Host::Domain("a".to_string()), 1, btreemap! { "b".to_string() => "5".to_string(), "timeout_sec".to_string() => "30".to_string() }) ; "with options")]
    fn test_parse_tunnel_dest(input: &str) -> (Host<String>, u16, BTreeMap<String, String>) {
        parse_tunnel_dest(input).unwrap()
    }

    const LOCALHOST_IP4: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 443);
    const LOCALHOST_IP6: SocketAddrV6 = SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 443, 0, 0);

    #[test_case("domain.com:443" => matches Err(_) ; "with domain")]
    #[test_case("127.0.0.1" => matches Err(_) ; "with no port")]
    #[test_case("127.0.0.1:444444443" => matches Err(_) ; "with too long port")]
    #[test_case("127.0.0.1:443" => matches Ok((SocketAddr::V4(LOCALHOST_IP4), _)) ; "with ipv4")]
    #[test_case("[::1]:443" => matches Ok((SocketAddr::V6(LOCALHOST_IP6), _)) ; "with ipv6")]
    fn test_parse_local_bind(input: &str) -> Result<(SocketAddr, &str), io::Error> {
        parse_local_bind(input)
    }

    #[test_case("domain.com:443" => panics ""; "with no protocol")]
    #[test_case("sdsf://443:domain.com:443" => panics ""; "with invalid protocol")]
    #[test_case("tcp://443:domain.com:4443" =>
        LocalToRemote {
            local_protocol: LocalProtocol::Tcp { proxy_protocol: false },
            local: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 443)),
            remote: (Host::Domain("domain.com".to_string()), 4443),
        }
    ; "with no local bind")]
    #[test_case("udp://[::1]:443:toto.com:4443?timeout_sec=30" =>
        LocalToRemote {
            local_protocol: LocalProtocol::Udp { timeout: Some(std::time::Duration::from_secs(30)) },
            local: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 443, 0, 0)),
            remote: (Host::Domain("toto.com".to_string()), 4443),
        }
    ; "with fully defined tunnel")]
    #[test_case("udp://[::1]:443:[::1]:4443?timeout_sec=30" =>
        LocalToRemote {
            local_protocol: LocalProtocol::Udp { timeout: Some(std::time::Duration::from_secs(30)) },
            local: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 443, 0, 0)),
            remote: (Host::Ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 4443),
        }
    ; "with full ipv6 tunnel")]
    fn test_parse_tunnel_arg(input: &str) -> LocalToRemote {
        parse_tunnel_arg(input).unwrap()
    }
}
