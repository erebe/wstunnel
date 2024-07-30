use ahash::{HashMap, HashMapExt};
use anyhow::anyhow;
use futures_util::{pin_mut, FutureExt, StreamExt};
use http_body_util::Either;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::future::Future;

use std::net::SocketAddr;
use std::ops::Deref;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use crate::tunnel::RemoteAddr;
use crate::{protocols, LocalProtocol};
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{http, Request, StatusCode, Version};
use hyper_util::rt::TokioExecutor;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use socket2::SockRef;

use crate::protocols::dns::DnsResolver;
use crate::protocols::tls;
use crate::protocols::udp::{UdpStream, UdpStreamWriter};
use crate::restrictions::config_reloader::RestrictionsRulesReloader;
use crate::restrictions::types::{RestrictionConfig, RestrictionsRules};
use crate::tunnel::connectors::{TcpTunnelConnector, TunnelConnector, UdpTunnelConnector};
use crate::tunnel::listeners::{
    new_udp_listener, HttpProxyTunnelListener, Socks5TunnelListener, TcpTunnelListener, TunnelListener,
};
use crate::tunnel::server::handler_http2::http_server_upgrade;
use crate::tunnel::server::handler_websocket::ws_server_upgrade;
use crate::tunnel::server::utils::find_mapped_port;
use crate::tunnel::tls_reloader::TlsReloader;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::select;
use tokio::sync::mpsc;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, span, warn, Instrument, Level, Span};
use url::Host;

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

    pub(super) async fn run_tunnel(
        &self,
        restriction: &RestrictionConfig,
        remote: RemoteAddr,
        client_address: SocketAddr,
    ) -> anyhow::Result<(RemoteAddr, Pin<Box<dyn AsyncRead + Send>>, Pin<Box<dyn AsyncWrite + Send>>)> {
        match remote.protocol {
            LocalProtocol::Udp { timeout, .. } => {
                let (rx, tx) = UdpTunnelConnector::new(
                    &remote.host,
                    remote.port,
                    self.config.socket_so_mark,
                    timeout.unwrap_or(Duration::from_secs(10)),
                    &self.config.dns_resolver,
                )
                .connect(&None)
                .await?;

                Ok((remote, Box::pin(rx), Box::pin(tx)))
            }
            LocalProtocol::Tcp { proxy_protocol } => {
                let (rx, mut tx) = TcpTunnelConnector::new(
                    &remote.host,
                    remote.port,
                    self.config.socket_so_mark,
                    Duration::from_secs(10),
                    &self.config.dns_resolver,
                )
                .connect(&None)
                .await?;

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
                type Item = <TcpTunnelListener as TunnelListener>::OkReturn;
                #[allow(clippy::type_complexity)]
                static SERVERS: Lazy<Mutex<HashMap<(Host<String>, u16), mpsc::Receiver<Item>>>> =
                    Lazy::new(|| Mutex::new(HashMap::with_capacity(0)));

                let remote_port = find_mapped_port(remote.port, restriction);
                let local_srv = (remote.host, remote_port);
                let listening_server = async {
                    let bind = format!("{}:{}", local_srv.0, local_srv.1);
                    TcpTunnelListener::new(bind.parse()?, local_srv.clone(), false).await
                };
                let ((local_rx, local_tx), remote) =
                    run_listening_server(&local_srv, SERVERS.deref(), listening_server).await?;

                Ok((remote, Box::pin(local_rx), Box::pin(local_tx)))
            }
            LocalProtocol::ReverseUdp { timeout } => {
                type Item = ((UdpStream, UdpStreamWriter), RemoteAddr);
                #[allow(clippy::type_complexity)]
                static SERVERS: Lazy<Mutex<HashMap<(Host<String>, u16), mpsc::Receiver<Item>>>> =
                    Lazy::new(|| Mutex::new(HashMap::with_capacity(0)));

                let remote_port = find_mapped_port(remote.port, restriction);
                let local_srv = (remote.host, remote_port);
                let listening_server = async {
                    let bind = format!("{}:{}", local_srv.0, local_srv.1);
                    new_udp_listener(bind.parse()?, local_srv.clone(), timeout).await
                };
                let ((local_rx, local_tx), remote) =
                    run_listening_server(&local_srv, SERVERS.deref(), listening_server).await?;
                Ok((remote, Box::pin(local_rx), Box::pin(local_tx)))
            }
            LocalProtocol::ReverseSocks5 { timeout, credentials } => {
                type Item = <Socks5TunnelListener as TunnelListener>::OkReturn;
                #[allow(clippy::type_complexity)]
                static SERVERS: Lazy<Mutex<HashMap<(Host<String>, u16), mpsc::Receiver<Item>>>> =
                    Lazy::new(|| Mutex::new(HashMap::with_capacity(0)));

                let remote_port = find_mapped_port(remote.port, restriction);
                let local_srv = (remote.host, remote_port);
                let listening_server = async {
                    let bind = format!("{}:{}", local_srv.0, local_srv.1);
                    Socks5TunnelListener::new(bind.parse()?, timeout, credentials).await
                };
                let ((local_rx, local_tx), remote) =
                    run_listening_server(&local_srv, SERVERS.deref(), listening_server).await?;

                Ok((remote, Box::pin(local_rx), Box::pin(local_tx)))
            }
            LocalProtocol::ReverseHttpProxy { timeout, credentials } => {
                type Item = <HttpProxyTunnelListener as TunnelListener>::OkReturn;
                #[allow(clippy::type_complexity)]
                static SERVERS: Lazy<Mutex<HashMap<(Host<String>, u16), mpsc::Receiver<Item>>>> =
                    Lazy::new(|| Mutex::new(HashMap::with_capacity(0)));

                let remote_port = find_mapped_port(remote.port, restriction);
                let local_srv = (remote.host, remote_port);
                let listening_server = async {
                    let bind = format!("{}:{}", local_srv.0, local_srv.1);
                    HttpProxyTunnelListener::new(bind.parse()?, timeout, credentials, false).await
                };
                let ((local_rx, local_tx), remote) =
                    run_listening_server(&local_srv, SERVERS.deref(), listening_server).await?;

                Ok((remote, Box::pin(local_rx), Box::pin(local_tx)))
            }
            #[cfg(unix)]
            LocalProtocol::ReverseUnix { ref path } => {
                use crate::tunnel::listeners::UnixTunnelListener;
                type Item = <UnixTunnelListener as TunnelListener>::OkReturn;
                #[allow(clippy::type_complexity)]
                static SERVERS: Lazy<Mutex<HashMap<(Host<String>, u16), mpsc::Receiver<Item>>>> =
                    Lazy::new(|| Mutex::new(HashMap::with_capacity(0)));

                let remote_port = find_mapped_port(remote.port, restriction);
                let local_srv = (remote.host, remote_port);
                let listening_server = async { UnixTunnelListener::new(path, local_srv.clone(), false).await };
                let ((local_rx, local_tx), remote) =
                    run_listening_server(&local_srv, SERVERS.deref(), listening_server).await?;

                Ok((remote, Box::pin(local_rx), Box::pin(local_tx)))
            }
            #[cfg(not(unix))]
            LocalProtocol::ReverseUnix { .. } => {
                error!("Received an unsupported target protocol {:?}", remote);
                Err(anyhow::anyhow!("Invalid upgrade request"))
            }
            LocalProtocol::Stdio
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

#[allow(clippy::type_complexity)]
async fn run_listening_server<T>(
    local_srv: &(Host, u16),
    servers: &Mutex<
        HashMap<
            (Host<String>, u16),
            mpsc::Receiver<((<T as TunnelListener>::Reader, <T as TunnelListener>::Writer), RemoteAddr)>,
        >,
    >,
    gen_listening_server: impl Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<((<T as TunnelListener>::Reader, <T as TunnelListener>::Writer), RemoteAddr)>
where
    T: TunnelListener + Send + 'static,
{
    let listening_server = servers.lock().remove(local_srv);
    let mut listening_server = if let Some(listening_server) = listening_server {
        listening_server
    } else {
        let listening_server = gen_listening_server.await?;
        let send_timeout = Duration::from_secs(60 * 3);
        let (tx, rx) = mpsc::channel(1);
        let fut = async move {
            pin_mut!(listening_server);
            loop {
                select! {
                    biased;
                    cnx = listening_server.next() => {
                       match cnx {
                            None => break,
                            Some(Err(err)) => {
                                warn!("Error while listening for incoming connections {err:?}");
                                continue;
                            }
                            Some(Ok(cnx)) => {
                                if tx.send_timeout(cnx, send_timeout).await.is_err() {
                                    info!("New reverse connection failed to be picked by client after {}s. Closing reverse tunnel server", send_timeout.as_secs());
                                    break;
                                }
                            }
                        }
                    },

                    _ = tx.closed() => {
                        break;
                    }
                }
            }
            info!("Stopping listening reverse server");
        };

        tokio::spawn(fut.instrument(Span::current()));
        rx
    };

    let cnx = listening_server
        .recv()
        .await
        .ok_or_else(|| anyhow!("listening reverse server stopped"))?;
    servers.lock().insert(local_srv.clone(), listening_server);
    Ok(cnx)
}
