pub mod config;
mod embedded_certificate;
pub mod executor;
mod protocols;
mod restrictions;
mod somark;
#[cfg(test)]
mod test_integrations;
pub mod tunnel;

use crate::config::{ClientCreationRequest, DEFAULT_CLIENT_UPGRADE_PATH_PREFIX, ServerCreationRequest};
use crate::executor::{TokioExecutor, TokioExecutorRef};
use crate::protocols::dns::DnsResolver;
use crate::protocols::tls;
use crate::restrictions::types::RestrictionsRules;
use crate::somark::SoMark;
pub use crate::tunnel::LocalProtocol;
pub use crate::tunnel::client::{Client, ClientConfig, TlsClientConfig};
use crate::tunnel::downstream_listeners::{
    HttpProxyDownstreamListener, Socks5DownstreamListener, TcpDownstreamListener, UdpDownstreamListener,
    new_stdio_listener,
};
use crate::tunnel::server::{Server, ServerConfig, TlsServerConfig};
use crate::tunnel::transport::webtransport::WebTransportEndpoint;
use crate::tunnel::transport::{TransportAddr, TransportScheme};
use crate::tunnel::upstream_connectors::{Socks5UpstreamConnector, TcpUpstreamConnector, UdpUpstreamConnector};
use crate::tunnel::{RemoteAddr, to_host_port};
use anyhow::{Context, anyhow};
use futures_util::future::BoxFuture;
use hyper::header::HOST;
use hyper::http::HeaderValue;
use log::debug;
use parking_lot::{Mutex, RwLock};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::select;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tracing::{error, info};
use url::Url;

pub async fn run_client(args: ClientCreationRequest, executor: impl TokioExecutor) -> anyhow::Result<()> {
    let tunnels = create_client_tunnels(args, executor.ref_clone()).await?;

    // Start all tunnels
    let (tx, rx) = oneshot::channel();
    executor.spawn(async move {
        let _ = JoinSet::from_iter(tunnels).join_all().await;
        let _ = tx.send(());
    });

    // wait for all tunnels to finish
    rx.await?;
    Ok(())
}

pub async fn create_client(
    args: ClientCreationRequest,
    executor: impl TokioExecutorRef,
) -> anyhow::Result<Client<impl TokioExecutorRef>> {
    let (tls_certificate, tls_key) = if let (Some(cert), Some(key)) =
        (args.tls_certificate.as_ref(), args.tls_private_key.as_ref())
    {
        let tls_certificate = tls::load_certificates_from_pem(cert).expect("Cannot load client TLS certificate (mTLS)");
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

    let http_proxy = mk_http_proxy(args.http_proxy, args.http_proxy_login, args.http_proxy_password)?;
    let dns_resolver = DnsResolver::new_from_urls(
        &args.dns_resolver,
        http_proxy.clone(),
        SoMark::new(args.socket_so_mark),
        !args.dns_resolver_prefer_ipv4,
    )
    .expect("cannot create dns resolver");

    let transport_scheme = TransportScheme::from_str(args.remote_addr.scheme()).expect("invalid scheme in server url");
    if transport_scheme.is_webtransport() {
        // QUIC runs over UDP, so an HTTP CONNECT proxy cannot carry it.
        if http_proxy.is_some() {
            return Err(anyhow!(
                "--http-proxy cannot be used with wts:// (webtransport): QUIC runs over UDP and cannot traverse an HTTP CONNECT proxy. Use wss:// or https:// instead."
            ));
        }
        // SNI is mandatory to validate the server certificate over QUIC.
        if args.tls_sni_disable {
            return Err(anyhow!(
                "--tls-sni-disable cannot be used with wts:// (webtransport): the QUIC handshake requires a server name. Use wss:// or https:// instead."
            ));
        }
        if args.tls_ech_enable {
            return Err(anyhow!(
                "--tls-ech-enable cannot be used with wts:// (webtransport): ECH is only wired for the TCP transports. Use wss:// or https:// instead."
            ));
        }
    }

    let tls = match transport_scheme {
        TransportScheme::Ws | TransportScheme::Http => None,
        TransportScheme::Wts | TransportScheme::Wss | TransportScheme::Https => {
            let ech_config = if args.tls_ech_enable {
                #[cfg(not(feature = "aws-lc-rs"))]
                return Err(anyhow!(
                    "Your current build does not support ECH. You need to use aws-lc crypto provider"
                ));

                #[cfg(feature = "aws-lc-rs")]
                dns_resolver
                    .lookup_ech_config(&args.remote_addr.host().unwrap().to_owned())
                    .await?
            } else {
                None
            };

            let tls_connector = tls::tls_connector(
                args.tls_verify_certificate,
                transport_scheme.alpn_protocols(),
                !args.tls_sni_disable,
                ech_config,
                tls_certificate,
                tls_key,
            )
            .expect("Cannot create tls connector");

            Some(TlsClientConfig {
                tls_connector: Arc::new(RwLock::new(tls_connector)),
                tls_sni_override: args.tls_sni_override,
                tls_verify_certificate: args.tls_verify_certificate,
                tls_sni_disabled: args.tls_sni_disable,
                tls_certificate_path: args.tls_certificate.clone(),
                tls_key_path: args.tls_private_key.clone(),
            })
        }
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
    if let Some(path) = &args.http_headers_file
        && !path.exists()
    {
        panic!("http headers file does not exists: {}", path.display());
    }

    let websocket_ping_frequency = args
        .websocket_ping_frequency
        .or(Some(Duration::from_secs(30)))
        .filter(|d| d.as_secs() > 0);

    // Webtransport rides QUIC, so it gets its own endpoint instead of a stream from the TCP
    // pool. Built here rather than in `Client::new` so a broken TLS setup fails at startup.
    let webtransport = if transport_scheme.is_webtransport() {
        let tls = tls
            .as_ref()
            .ok_or_else(|| anyhow!("webtransport requires TLS, which is missing from the configuration"))?;
        let tls_config = tls::quic_client_config(
            tls.tls_verify_certificate,
            tls.tls_certificate_path
                .as_deref()
                .map(tls::load_certificates_from_pem)
                .transpose()
                .with_context(|| "Cannot load client TLS certificate (mTLS)")?,
            tls.tls_key_path
                .as_deref()
                .map(tls::load_private_key_from_file)
                .transpose()
                .with_context(|| "Cannot load client TLS private key (mTLS)")?,
        )
        .with_context(|| "Cannot create the TLS configuration for webtransport")?;

        Some(Arc::new(
            WebTransportEndpoint::new(tls_config, SoMark::new(args.socket_so_mark), websocket_ping_frequency)
                .with_context(|| "Cannot create the webtransport endpoint")?,
        ))
    } else {
        None
    };

    let client_config = ClientConfig {
        remote_addr: TransportAddr::new(
            TransportScheme::from_str(args.remote_addr.scheme()).unwrap(),
            args.remote_addr.host().unwrap().to_owned(),
            args.remote_addr.port_or_known_default().unwrap_or(443),
            tls,
        )
        .unwrap(),
        socket_so_mark: SoMark::new(args.socket_so_mark),
        http_upgrade_path_prefix,
        http_upgrade_credentials: args.http_upgrade_credentials,
        http_headers: args.http_headers.into_iter().filter(|(k, _)| k != HOST).collect(),
        http_headers_file: args.http_headers_file,
        http_header_host: host_header,
        timeout_connect: Duration::from_secs(10),
        websocket_ping_frequency,
        websocket_mask_frame: args.websocket_mask_frame,
        dns_resolver,
        http_proxy,
        webtransport,
    };

    let client = Client::new(
        client_config,
        args.connection_min_idle,
        args.connection_retry_max_backoff,
        args.reverse_tunnel_connection_retry_max_backoff,
        executor,
    )
    .await?;
    info!("Starting wstunnel client v{}", env!("CARGO_PKG_VERSION"),);

    Ok(client)
}

async fn create_client_tunnels(
    mut args: ClientCreationRequest,
    executor: impl TokioExecutorRef,
) -> anyhow::Result<Vec<BoxFuture<'static, ()>>> {
    let remote_to_local = std::mem::take(&mut args.remote_to_local);
    let local_to_remote = std::mem::take(&mut args.local_to_remote);
    let client = create_client(args, executor).await?;

    // Keep track of all spawned tunnels
    let mut tunnels: Vec<BoxFuture<()>> = Vec::with_capacity(remote_to_local.len() + local_to_remote.len());
    macro_rules! spawn_tunnel {
        ( $($s:stmt);* ) => {
            tunnels.push(Box::pin(async move {
                $($s)*
            }));
        }
    }

    // Start tunnels
    for tunnel in remote_to_local.into_iter() {
        let client = client.clone();
        match &tunnel.local_protocol {
            LocalProtocol::ReverseTcp => {
                spawn_tunnel! {
                    let cfg = client.config.clone();
                    let tcp_connector = TcpUpstreamConnector::new(
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
                }
            }
            LocalProtocol::ReverseUdp { timeout } => {
                let timeout = *timeout;
                spawn_tunnel! {
                    let cfg = client.config.clone();
                    let (host, port) = to_host_port(tunnel.local);
                    let remote = RemoteAddr {
                        protocol: LocalProtocol::ReverseUdp { timeout },
                        host,
                        port,
                    };
                    let udp_connector = UdpUpstreamConnector::new(
                        &tunnel.remote.0,
                        tunnel.remote.1,
                        cfg.socket_so_mark,
                        cfg.timeout_connect,
                        &cfg.dns_resolver,
                    );

                    if let Err(err) = client.run_reverse_tunnel(remote.clone(), udp_connector).await {
                        error!("{:?}", err);
                    }
                }
            }
            LocalProtocol::ReverseSocks5 { timeout, credentials } => {
                let credentials = credentials.clone();
                let timeout = *timeout;
                spawn_tunnel! {
                    let cfg = client.config.clone();
                    let (host, port) = to_host_port(tunnel.local);
                    let remote = RemoteAddr {
                        protocol: LocalProtocol::ReverseSocks5 { timeout, credentials },
                        host,
                        port,
                    };
                    let socks_connector =
                        Socks5UpstreamConnector::new(cfg.socket_so_mark, cfg.timeout_connect, &cfg.dns_resolver);

                    if let Err(err) = client.run_reverse_tunnel(remote, socks_connector).await {
                        error!("{:?}", err);
                    }
                }
            }
            LocalProtocol::ReverseHttpProxy { timeout, credentials } => {
                let credentials = credentials.clone();
                let timeout = *timeout;
                spawn_tunnel! {
                    let cfg = client.config.clone();
                    let (host, port) = to_host_port(tunnel.local);
                    let remote = RemoteAddr {
                        protocol: LocalProtocol::ReverseHttpProxy { timeout, credentials },
                        host,
                        port,
                    };
                    let tcp_connector = TcpUpstreamConnector::new(
                        &tunnel.remote.0,
                        tunnel.remote.1,
                        cfg.socket_so_mark,
                        cfg.timeout_connect,
                        &cfg.dns_resolver,
                    );

                    if let Err(err) = client.run_reverse_tunnel(remote, tcp_connector).await {
                        error!("{:?}", err);
                    }
                }
            }
            LocalProtocol::ReverseUnix { path } => {
                let path = path.clone();
                info!("Connecting to unix socket {:?}", tunnel);
                spawn_tunnel! {
                    let cfg = client.config.clone();
                    let tcp_connector = TcpUpstreamConnector::new(
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
                }
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

    for tunnel in local_to_remote.into_iter() {
        let client = client.clone();

        match &tunnel.local_protocol {
            LocalProtocol::Tcp { proxy_protocol } => {
                let server = TcpDownstreamListener::new(tunnel.local, tunnel.remote.clone(), *proxy_protocol).await?;
                spawn_tunnel! {
                    if let Err(err) = client.run_tunnel(server).await {
                        error!("{:?}", err);
                    }
                }
            }
            #[cfg(target_os = "linux")]
            LocalProtocol::TProxyTcp => {
                use crate::tunnel::downstream_listeners::TProxyTcpDownstreamListener;
                let server = TProxyTcpDownstreamListener::new(tunnel.local, false).await?;

                spawn_tunnel! {
                    if let Err(err) = client.run_tunnel(server).await {
                        error!("{:?}", err);
                    }
                }
            }
            #[cfg(unix)]
            LocalProtocol::Unix { path, proxy_protocol } => {
                use crate::tunnel::downstream_listeners::UnixDownstreamListener;
                let server = UnixDownstreamListener::new(path, tunnel.remote.clone(), *proxy_protocol).await?;
                spawn_tunnel! {
                    if let Err(err) = client.run_tunnel(server).await {
                        error!("{:?}", err);
                    }
                }
            }
            #[cfg(not(unix))]
            LocalProtocol::Unix { .. } => {
                panic!("Unix socket is not available for non Unix platform")
            }

            #[cfg(target_os = "linux")]
            LocalProtocol::TProxyUdp { timeout } => {
                use crate::tunnel::downstream_listeners::new_tproxy_udp;
                let server = new_tproxy_udp(tunnel.local, *timeout).await?;
                spawn_tunnel! {
                    if let Err(err) = client.run_tunnel(server).await {
                        error!("{:?}", err);
                    }
                }
            }
            #[cfg(not(target_os = "linux"))]
            LocalProtocol::TProxyTcp | LocalProtocol::TProxyUdp { .. } => {
                panic!("Transparent proxy is not available for non Linux platform")
            }
            LocalProtocol::Udp { timeout } => {
                let server = UdpDownstreamListener::new(tunnel.local, tunnel.remote.clone(), *timeout).await?;
                spawn_tunnel! {
                    if let Err(err) = client.run_tunnel(server).await {
                        error!("{:?}", err);
                    }
                }
            }
            LocalProtocol::Socks5 { timeout, credentials } => {
                let server = Socks5DownstreamListener::new(tunnel.local, *timeout, credentials.clone()).await?;
                spawn_tunnel! {
                    if let Err(err) = client.run_tunnel(server).await {
                        error!("{:?}", err);
                    }
                }
            }
            LocalProtocol::HttpProxy {
                timeout,
                credentials,
                proxy_protocol,
            } => {
                let server =
                    HttpProxyDownstreamListener::new(tunnel.local, *timeout, credentials.clone(), *proxy_protocol)
                        .await?;
                spawn_tunnel! {
                    if let Err(err) = client.run_tunnel(server).await {
                        error!("{:?}", err);
                    }
                }
            }

            LocalProtocol::Stdio { proxy_protocol } => {
                let (server, mut handle) = new_stdio_listener(tunnel.remote.clone(), *proxy_protocol).await?;
                if let Err(err) = client.run_tunnel(server).await {
                    error!("{:?}", err);
                }

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

    Ok(tunnels)
}

pub async fn run_server(args: ServerCreationRequest, executor: impl TokioExecutor) -> anyhow::Result<()> {
    let (tx, rx) = oneshot::channel();
    let exec = executor.ref_clone();
    executor.spawn(async move {
        let ret = run_server_impl(args, exec).await;
        let _ = tx.send(ret);
    });

    rx.await?
}

async fn run_server_impl(args: ServerCreationRequest, executor: impl TokioExecutorRef) -> anyhow::Result<()> {
    // wts:// binds TLS on TCP exactly like wss://, and additionally serves webtransport over UDP.
    let is_webtransport = args.remote_addr.scheme() == "wts";
    let tls_config = if args.remote_addr.scheme() == "wss" || is_webtransport {
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
                tls::load_certificates_from_pem(tls_client_ca).expect("Cannot load client CA certificate (mTLS)"),
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

        RestrictionsRules::from_path_prefix(
            args.restrict_http_upgrade_path_prefix.as_deref().unwrap_or(&[]),
            &restrict_to,
        )
        .expect("Cannot convert restriction rules from path-prefix and restric-to")
    };

    let http_proxy = mk_http_proxy(args.http_proxy, args.http_proxy_login, args.http_proxy_password)?;
    let server_config = ServerConfig {
        socket_so_mark: SoMark::new(args.socket_so_mark),
        bind: args.remote_addr.socket_addrs(|| Some(8080))?[0],
        websocket_ping_frequency: args
            .websocket_ping_frequency
            .or(Some(Duration::from_secs(30)))
            .filter(|d| d.as_secs() > 0),
        timeout_connect: Duration::from_secs(10),
        websocket_mask_frame: args.websocket_mask_frame,
        tls: tls_config,
        dns_resolver: DnsResolver::new_from_urls(
            &args.dns_resolver,
            None,
            SoMark::new(args.socket_so_mark),
            !args.dns_resolver_prefer_ipv4,
        )
        .expect("Cannot create DNS resolver"),
        restriction_config: args.restrict_config,
        http_proxy,
        remote_server_idle_timeout: args.remote_to_local_server_idle_timeout,
        // wts:// on the server means "TLS, and also serve webtransport", so it implies the flag.
        // The TCP listener still runs, serving websocket and http2 as usual.
        enable_webtransport: args.enable_webtransport || is_webtransport,
    };
    let server = Server::new(server_config, executor);

    info!(
        "Starting wstunnel server v{} with config {:?}",
        env!("CARGO_PKG_VERSION"),
        server.config
    );
    debug!("Restriction rules: {restrictions:#?}");
    server.serve(restrictions).await
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
        Url::parse(&format!("http://{proxy}")).with_context(|| "Invalid http proxy url")?
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
