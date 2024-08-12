use anyhow::anyhow;
use futures_util::FutureExt;
use http_body_util::Either;
use std::fmt;
use std::fmt::{Debug, Formatter};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use crate::protocols;
use crate::tunnel::{try_to_sock_addr, LocalProtocol, RemoteAddr};
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{http, Request, Response, StatusCode, Version};
use hyper_util::rt::TokioExecutor;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use socket2::SockRef;

use crate::protocols::dns::DnsResolver;
use crate::protocols::tls;
use crate::restrictions::config_reloader::RestrictionsRulesReloader;
use crate::restrictions::types::{RestrictionConfig, RestrictionsRules};
use crate::tunnel::connectors::{TcpTunnelConnector, TunnelConnector, UdpTunnelConnector};
use crate::tunnel::listeners::{HttpProxyTunnelListener, Socks5TunnelListener, TcpTunnelListener, UdpTunnelListener};
use crate::tunnel::server::handler_http2::http_server_upgrade;
use crate::tunnel::server::handler_websocket::ws_server_upgrade;
use crate::tunnel::server::reverse_tunnel::ReverseTunnelServer;
use crate::tunnel::server::utils::{
    bad_request, extract_path_prefix, extract_tunnel_info, extract_x_forwarded_for, find_mapped_port, validate_tunnel,
};
use crate::tunnel::tls_reloader::TlsReloader;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::select;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, span, warn, Instrument, Level, Span};
use url::Url;

#[derive(Debug)]
pub struct TlsServerConfig {
    pub tls_certificate: Mutex<Vec<CertificateDer<'static>>>,
    pub tls_key: Mutex<PrivateKeyDer<'static>>,
    pub tls_client_ca_certificates: Option<Mutex<Vec<CertificateDer<'static>>>>,
    pub tls_certificate_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub tls_client_ca_certs_path: Option<PathBuf>,
}

pub struct WsServerConfig {
    pub socket_so_mark: Option<u32>,
    pub bind: SocketAddr,
    pub websocket_ping_frequency: Option<Duration>,
    pub timeout_connect: Duration,
    pub websocket_mask_frame: bool,
    pub tls: Option<TlsServerConfig>,
    pub dns_resolver: DnsResolver,
    pub restriction_config: Option<PathBuf>,
    pub http_proxy: Option<Url>,
}

#[derive(Clone)]
pub struct WsServer {
    pub config: Arc<WsServerConfig>,
}

impl WsServer {
    pub fn new(config: WsServerConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    pub(super) async fn handle_tunnel_request(
        &self,
        restrictions: Arc<RestrictionsRules>,
        restrict_path_prefix: Option<String>,
        mut client_addr: SocketAddr,
        req: &Request<Incoming>,
    ) -> Result<
        (
            RemoteAddr,
            Pin<Box<dyn AsyncRead + Send>>,
            Pin<Box<dyn AsyncWrite + Send>>,
            bool,
        ),
        Response<Either<String, BoxBody<Bytes, anyhow::Error>>>,
    > {
        match extract_x_forwarded_for(req) {
            Ok(Some((x_forward_for, x_forward_for_str))) => {
                info!("Request X-Forwarded-For: {:?}", x_forward_for);
                Span::current().record("forwarded_for", x_forward_for_str);
                client_addr.set_ip(x_forward_for);
            }
            Ok(_) => {}
            Err(_err) => return Err(bad_request()),
        };

        let path_prefix = match extract_path_prefix(req) {
            Ok(p) => p,
            Err(_err) => return Err(bad_request()),
        };

        if let Some(restrict_path) = restrict_path_prefix {
            if path_prefix != restrict_path {
                warn!(
                    "Client requested upgrade path '{}' does not match upgrade path restriction '{}' (mTLS, etc.)",
                    path_prefix, restrict_path
                );
                return Err(bad_request());
            }
        }

        let jwt = match extract_tunnel_info(req) {
            Ok(jwt) => jwt,
            Err(_err) => return Err(bad_request()),
        };

        Span::current().record("id", &jwt.claims.id);
        Span::current().record("remote", format!("{}:{}", jwt.claims.r, jwt.claims.rp));
        let remote = match RemoteAddr::try_from(jwt.claims) {
            Ok(remote) => remote,
            Err(err) => {
                warn!("Rejecting connection with bad tunnel info: {} {}", err, req.uri());
                return Err(bad_request());
            }
        };

        let restriction = match validate_tunnel(&remote, path_prefix, &restrictions) {
            Ok(matched_restriction) => {
                info!("Tunnel accepted due to matched restriction: {}", matched_restriction.name);
                matched_restriction
            }
            Err(_err) => return Err(bad_request()),
        };

        let req_protocol = remote.protocol.clone();
        let inject_cookie = req_protocol.is_dynamic_reverse_tunnel();
        let tunnel = match self.exec_tunnel(restriction, remote, client_addr).await {
            Ok(ret) => ret,
            Err(err) => {
                warn!("Rejecting connection with bad upgrade request: {} {}", err, req.uri());
                return Err(bad_request());
            }
        };

        let (remote_addr, local_rx, local_tx) = tunnel;
        info!("connected to {:?} {}:{}", req_protocol, remote_addr.host, remote_addr.port);
        Ok((remote_addr, local_rx, local_tx, inject_cookie))
    }

    async fn exec_tunnel(
        &self,
        restriction: &RestrictionConfig,
        remote: RemoteAddr,
        client_address: SocketAddr,
    ) -> anyhow::Result<(RemoteAddr, Pin<Box<dyn AsyncRead + Send>>, Pin<Box<dyn AsyncWrite + Send>>)> {
        match remote.protocol {
            LocalProtocol::Udp { timeout, .. } => {
                let connector = UdpTunnelConnector::new(
                    &remote.host,
                    remote.port,
                    self.config.socket_so_mark,
                    timeout.unwrap_or(Duration::from_secs(10)),
                    &self.config.dns_resolver,
                );
                let (rx, tx) = match &self.config.http_proxy {
                    None => connector.connect(&None).await?,
                    Some(_) => Err(anyhow!("UDP tunneling is not supported with HTTP proxy"))?,
                };

                Ok((remote, Box::pin(rx), Box::pin(tx)))
            }
            LocalProtocol::Tcp { proxy_protocol } => {
                let connector = TcpTunnelConnector::new(
                    &remote.host,
                    remote.port,
                    self.config.socket_so_mark,
                    Duration::from_secs(10),
                    &self.config.dns_resolver,
                );
                let (rx, mut tx) = match &self.config.http_proxy {
                    None => connector.connect(&None).await?,
                    Some(proxy_url) => connector.connect_with_http_proxy(proxy_url, &None).await?,
                };

                if proxy_protocol {
                    let header = ppp::v2::Builder::with_addresses(
                        ppp::v2::Version::Two | ppp::v2::Command::Proxy,
                        ppp::v2::Protocol::Stream,
                        (client_address, tx.local_addr().unwrap()),
                    )
                    .build()
                    .unwrap();
                    let _ = tx.write_all(&header).await;
                }

                Ok((remote, Box::pin(rx), Box::pin(tx)))
            }
            LocalProtocol::ReverseTcp => {
                static SERVERS: Lazy<ReverseTunnelServer<TcpTunnelListener>> = Lazy::new(ReverseTunnelServer::new);

                let remote_port = find_mapped_port(remote.port, restriction);
                let local_srv = (remote.host, remote_port);
                let bind = try_to_sock_addr(local_srv.clone())?;
                let listening_server = async { TcpTunnelListener::new(bind, local_srv.clone(), false).await };
                let ((local_rx, local_tx), remote) = SERVERS.run_listening_server(bind, listening_server).await?;

                Ok((remote, Box::pin(local_rx), Box::pin(local_tx)))
            }
            LocalProtocol::ReverseUdp { timeout } => {
                static SERVERS: Lazy<ReverseTunnelServer<UdpTunnelListener>> = Lazy::new(ReverseTunnelServer::new);

                let remote_port = find_mapped_port(remote.port, restriction);
                let local_srv = (remote.host, remote_port);
                let bind = try_to_sock_addr(local_srv.clone())?;
                let listening_server = async { UdpTunnelListener::new(bind, local_srv.clone(), timeout).await };
                let ((local_rx, local_tx), remote) = SERVERS.run_listening_server(bind, listening_server).await?;
                Ok((remote, Box::pin(local_rx), Box::pin(local_tx)))
            }
            LocalProtocol::ReverseSocks5 { timeout, credentials } => {
                static SERVERS: Lazy<ReverseTunnelServer<Socks5TunnelListener>> = Lazy::new(ReverseTunnelServer::new);

                let remote_port = find_mapped_port(remote.port, restriction);
                let local_srv = (remote.host, remote_port);
                let bind = try_to_sock_addr(local_srv.clone())?;
                let listening_server = async { Socks5TunnelListener::new(bind, timeout, credentials).await };
                let ((local_rx, local_tx), remote) = SERVERS.run_listening_server(bind, listening_server).await?;

                Ok((remote, Box::pin(local_rx), Box::pin(local_tx)))
            }
            LocalProtocol::ReverseHttpProxy { timeout, credentials } => {
                static SERVERS: Lazy<ReverseTunnelServer<HttpProxyTunnelListener>> =
                    Lazy::new(ReverseTunnelServer::new);

                let remote_port = find_mapped_port(remote.port, restriction);
                let local_srv = (remote.host, remote_port);
                let bind = try_to_sock_addr(local_srv.clone())?;
                let listening_server = async { HttpProxyTunnelListener::new(bind, timeout, credentials, false).await };
                let ((local_rx, local_tx), remote) = SERVERS.run_listening_server(bind, listening_server).await?;

                Ok((remote, Box::pin(local_rx), Box::pin(local_tx)))
            }
            #[cfg(unix)]
            LocalProtocol::ReverseUnix { ref path } => {
                use crate::tunnel::listeners::UnixTunnelListener;
                static SERVERS: Lazy<ReverseTunnelServer<UnixTunnelListener>> = Lazy::new(ReverseTunnelServer::new);

                let remote_port = find_mapped_port(remote.port, restriction);
                let local_srv = (remote.host, remote_port);
                let bind = try_to_sock_addr(local_srv.clone())?;
                let listening_server = async { UnixTunnelListener::new(path, local_srv.clone(), false).await };
                let ((local_rx, local_tx), remote) = SERVERS.run_listening_server(bind, listening_server).await?;

                Ok((remote, Box::pin(local_rx), Box::pin(local_tx)))
            }
            #[cfg(not(unix))]
            LocalProtocol::ReverseUnix { .. } => {
                error!("Received an unsupported target protocol {:?}", remote);
                Err(anyhow::anyhow!("Invalid upgrade request"))
            }
            LocalProtocol::Stdio { .. }
            | LocalProtocol::Socks5 { .. }
            | LocalProtocol::TProxyTcp
            | LocalProtocol::TProxyUdp { .. }
            | LocalProtocol::HttpProxy { .. }
            | LocalProtocol::Unix { .. } => {
                error!("Received an unsupported target protocol {:?}", remote);
                Err(anyhow::anyhow!("Invalid upgrade request"))
            }
        }
    }

    pub async fn serve(self, restrictions: RestrictionsRules) -> anyhow::Result<()> {
        info!("Starting wstunnel server listening on {}", self.config.bind);

        // setup upgrade request handler
        let mk_websocket_upgrade_fn = |server: WsServer,
                                       restrictions: Arc<RestrictionsRules>,
                                       restrict_path: Option<String>,
                                       client_addr: SocketAddr| {
            move |req: Request<Incoming>| {
                ws_server_upgrade(server.clone(), restrictions.clone(), restrict_path.clone(), client_addr, req)
                    .map::<anyhow::Result<_>, _>(Ok)
            }
        };

        let mk_http_upgrade_fn = |server: WsServer,
                                  restrictions: Arc<RestrictionsRules>,
                                  restrict_path: Option<String>,
                                  client_addr: SocketAddr| {
            move |req: Request<Incoming>| {
                http_server_upgrade(server.clone(), restrictions.clone(), restrict_path.clone(), client_addr, req)
                    .map::<anyhow::Result<_>, _>(Ok)
            }
        };

        let mk_auto_upgrade_fn = |server: WsServer,
                                  restrictions: Arc<RestrictionsRules>,
                                  restrict_path: Option<String>,
                                  client_addr: SocketAddr| {
            move |req: Request<Incoming>| {
                let server = server.clone();
                let restrictions = restrictions.clone();
                let restrict_path = restrict_path.clone();
                async move {
                    if fastwebsockets::upgrade::is_upgrade_request(&req) {
                        ws_server_upgrade(server.clone(), restrictions.clone(), restrict_path, client_addr, req)
                            .map::<anyhow::Result<_>, _>(Ok)
                            .await
                    } else if req.version() == Version::HTTP_2 {
                        http_server_upgrade(
                            server.clone(),
                            restrictions.clone(),
                            restrict_path.clone(),
                            client_addr,
                            req,
                        )
                        .map::<anyhow::Result<_>, _>(Ok)
                        .await
                    } else {
                        error!("Invalid protocol version request, got {:?} while expecting either websocket http1 upgrade or http2", req.version());
                        Ok(http::Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Either::Left("Invalid protocol request".to_string()))
                            .unwrap())
                    }
                }
            }
        };

        // Init TLS if needed
        let mut tls_context = if let Some(tls_config) = &self.config.tls {
            let tls_context = TlsContext {
                tls_acceptor: Arc::new(tls::tls_acceptor(
                    tls_config,
                    Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
                )?),
                tls_reloader: TlsReloader::new_for_server(self.config.clone())?,
                tls_config,
            };
            Some(tls_context)
        } else {
            None
        };

        // Bind server and run forever to serve incoming connections.
        let mut restrictions = RestrictionsRulesReloader::new(restrictions, self.config.restriction_config.clone())?;
        let mut await_config_reload = Box::pin(restrictions.reload_notifier());
        let listener = TcpListener::bind(&self.config.bind).await?;

        loop {
            let cnx = select! {
                biased;

                _ = &mut await_config_reload => {
                    drop(await_config_reload);
                    restrictions.reload_restrictions_config();
                    await_config_reload = Box::pin(restrictions.reload_notifier());
                    continue;
                },

                cnx = listener.accept() => { cnx }
            };

            let (stream, peer_addr) = match cnx {
                Ok(ret) => ret,
                Err(err) => {
                    warn!("Error while accepting connection {:?}", err);
                    continue;
                }
            };

            if let Err(err) = protocols::tcp::configure_socket(SockRef::from(&stream), &None) {
                warn!("Error while configuring server socket {:?}", err);
            }

            let span = span!(
                Level::INFO,
                "tunnel",
                id = tracing::field::Empty,
                remote = tracing::field::Empty,
                peer = peer_addr.to_string(),
                forwarded_for = tracing::field::Empty
            );

            info!("Accepting connection");
            let server = self.clone();
            let restrictions = restrictions.restrictions_rules().clone();

            // Check if we need to enable TLS or not
            match tls_context.as_mut() {
                Some(tls) => {
                    // Reload TLS certificate if needed
                    let tls_acceptor = tls.tls_acceptor().clone();
                    let fut = async move {
                        info!("Doing TLS handshake");
                        let tls_stream = match tls_acceptor.accept(stream).await {
                            Ok(tls_stream) => hyper_util::rt::TokioIo::new(tls_stream),
                            Err(err) => {
                                error!("error while accepting TLS connection {}", err);
                                return;
                            }
                        };

                        let tls_ctx = tls_stream.inner().get_ref().1;
                        // extract client certificate common name if any
                        let restrict_path = tls_ctx
                            .peer_certificates()
                            .and_then(tls::find_leaf_certificate)
                            .and_then(|c| tls::cn_from_certificate(&c));
                        match tls_ctx.alpn_protocol() {
                            // http2
                            Some(b"h2") => {
                                let mut conn_builder = http2::Builder::new(TokioExecutor::new());
                                if let Some(ping) = server.config.websocket_ping_frequency {
                                    conn_builder.keep_alive_interval(ping);
                                }

                                let http_upgrade_fn =
                                    mk_http_upgrade_fn(server, restrictions.clone(), restrict_path, peer_addr);
                                let con_fut = conn_builder.serve_connection(tls_stream, service_fn(http_upgrade_fn));
                                if let Err(e) = con_fut.await {
                                    error!("Error while upgrading cnx to http: {:?}", e);
                                }
                            }
                            // websocket
                            _ => {
                                let websocket_upgrade_fn =
                                    mk_websocket_upgrade_fn(server, restrictions.clone(), restrict_path, peer_addr);
                                let conn_fut = http1::Builder::new()
                                    .header_read_timeout(Duration::from_secs(10))
                                    .serve_connection(tls_stream, service_fn(websocket_upgrade_fn))
                                    .with_upgrades();

                                if let Err(e) = conn_fut.await {
                                    error!("Error while upgrading cnx: {:?}", e);
                                }
                            }
                        };
                    }
                    .instrument(span);

                    tokio::spawn(fut);
                    // Normal
                }
                // HTTP without TLS
                None => {
                    let fut = async move {
                        let stream = hyper_util::rt::TokioIo::new(stream);
                        let mut conn_fut = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                        if let Some(ping) = server.config.websocket_ping_frequency {
                            conn_fut.http2().keep_alive_interval(ping);
                        }

                        let websocket_upgrade_fn = mk_auto_upgrade_fn(server, restrictions.clone(), None, peer_addr);
                        let upgradable =
                            conn_fut.serve_connection_with_upgrades(stream, service_fn(websocket_upgrade_fn));

                        if let Err(e) = upgradable.await {
                            error!("Error while upgrading cnx to websocket: {:?}", e);
                        }
                    }
                    .instrument(span);

                    tokio::spawn(fut);
                }
            }
        }
    }
}

impl Debug for WsServerConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("WsServerConfig")
            .field("socket_so_mark", &self.socket_so_mark)
            .field("bind", &self.bind)
            .field("websocket_ping_frequency", &self.websocket_ping_frequency)
            .field("timeout_connect", &self.timeout_connect)
            .field("websocket_mask_frame", &self.websocket_mask_frame)
            .field("restriction_config", &self.restriction_config)
            .field("tls", &self.tls.is_some())
            .field(
                "mTLS",
                &self
                    .tls
                    .as_ref()
                    .map(|x| x.tls_client_ca_certificates.is_some())
                    .unwrap_or(false),
            )
            .finish()
    }
}

struct TlsContext<'a> {
    tls_acceptor: Arc<TlsAcceptor>,
    tls_reloader: TlsReloader,
    tls_config: &'a TlsServerConfig,
}
impl TlsContext<'_> {
    #[inline]
    pub fn tls_acceptor(&mut self) -> &Arc<TlsAcceptor> {
        if self.tls_reloader.should_reload_certificate() {
            match tls::tls_acceptor(self.tls_config, Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()])) {
                Ok(acceptor) => self.tls_acceptor = Arc::new(acceptor),
                Err(err) => error!("Cannot reload TLS certificate {:?}", err),
            };
        }

        &self.tls_acceptor
    }
}
