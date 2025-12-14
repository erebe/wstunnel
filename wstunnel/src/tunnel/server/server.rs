use crate::executor::{DefaultTokioExecutor, TokioExecutorRef};
use crate::protocols;
use crate::protocols::dns::DnsResolver;
use crate::protocols::tls;
use crate::protocols::tls::CertificateVars;
use crate::restrictions::config_reloader::RestrictionsRulesReloader;
use crate::restrictions::types::{RestrictionConfig, RestrictionsRules};
use crate::somark::SoMark;
use crate::tunnel::connectors::{TcpTunnelConnector, TunnelConnector, UdpTunnelConnector};
use crate::tunnel::listeners::{HttpProxyTunnelListener, Socks5TunnelListener, TcpTunnelListener, UdpTunnelListener};
use crate::tunnel::server::handler_http2::http_server_upgrade;
use crate::tunnel::server::handler_websocket::ws_server_upgrade;
use crate::tunnel::server::reverse_tunnel::ReverseTunnelServer;
use crate::tunnel::server::utils::{
    HttpResponse, bad_request, extract_authorization, extract_path_prefix, extract_tunnel_info,
    extract_x_forwarded_for, find_mapped_port, validate_tunnel,
};
use crate::tunnel::tls_reloader::TlsReloader;
use crate::tunnel::transport::quic::{QuicTunnelRead, QuicTunnelWrite};
use crate::tunnel::{LocalProtocol, RemoteAddr, try_to_sock_addr};
use ahash::AHasher;
use anyhow::{Context, anyhow};
use arc_swap::ArcSwap;
use bytes::BytesMut;
use http_body_util::Either;
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{Request, StatusCode, Version, http};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use parking_lot::Mutex;
use quinn::Endpoint;
use socket2::SockRef;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{Instrument, Level, Span, debug, error, info, span, warn};
use url::{Host, Url};

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
    pub socket_so_mark: SoMark,
    pub bind: SocketAddr,
    pub websocket_ping_frequency: Option<Duration>,
    pub timeout_connect: Duration,
    pub websocket_mask_frame: bool,
    pub tls: Option<TlsServerConfig>,
    pub dns_resolver: DnsResolver,
    pub restriction_config: Option<PathBuf>,
    pub http_proxy: Option<Url>,
    pub remote_server_idle_timeout: Duration,
    pub quic_listen: Option<SocketAddr>,
    pub quic_max_idle_timeout: Option<Duration>,
    pub quic_keep_alive_interval: Duration,
    pub quic_max_concurrent_bi_streams: u64,
    pub quic_initial_max_data: u64,
    pub quic_initial_max_stream_data: u64,
}

#[derive(Clone)]
pub struct WsServer<E: TokioExecutorRef = DefaultTokioExecutor> {
    pub config: Arc<WsServerConfig>,
    pub executor: E,
}

impl<E: crate::TokioExecutorRef> WsServer<E> {
    pub fn new(config: WsServerConfig, executor: E) -> Self {
        Self {
            config: Arc::new(config),
            executor,
        }
    }

    // Extract and parse tunnel information from HTTP request
    fn parse_tunnel_info<'a, B>(&self, req: &'a Request<B>) -> anyhow::Result<(RemoteAddr, &'a str, Option<&'a str>)> {
        let path_prefix = extract_path_prefix(req.uri().path())?;
        let jwt = extract_tunnel_info(req)?;
        let remote = RemoteAddr::try_from(jwt.claims)?;
        let authorization = extract_authorization(req);
        Ok((remote, path_prefix, authorization))
    }

    pub(super) async fn handle_tunnel_request<B>(
        &self,
        restrictions: Arc<RestrictionsRules>,
        restrict_path_prefix: Option<String>,
        cert_vars: &CertificateVars,
        mut client_addr: SocketAddr,
        req: &Request<B>,
    ) -> Result<
        (
            RemoteAddr,
            Pin<Box<dyn AsyncRead + Send>>,
            Pin<Box<dyn AsyncWrite + Send>>,
            bool,
        ),
        HttpResponse,
    > {
        if let Some((x_forward_for, x_forward_for_str)) = extract_x_forwarded_for(req) {
            info!("Request X-Forwarded-For: {x_forward_for:?}");
            Span::current().record("forwarded_for", x_forward_for_str);
            client_addr.set_ip(x_forward_for);
        };

        let path_prefix = extract_path_prefix(req.uri().path()).map_err(|err| {
            warn!("Rejecting connection with {err}: {}", req.uri());
            bad_request()
        })?;

        if let Some(restrict_path) = restrict_path_prefix
            && path_prefix != restrict_path
        {
            warn!(
                "Client requested upgrade path '{path_prefix}' does not match upgrade path restriction '{restrict_path}' (mTLS, etc.)"
            );
            return Err(bad_request());
        }

        let jwt = extract_tunnel_info(req).map_err(|err| {
            warn!("{}", err);
            bad_request()
        })?;

        Span::current().record("id", &jwt.claims.id);
        Span::current().record("remote", format!("{}:{}", jwt.claims.r, jwt.claims.rp));
        let remote = RemoteAddr::try_from(jwt.claims).map_err(|err| {
            warn!("Rejecting connection with bad tunnel info: {err} {}", req.uri());
            bad_request()
        })?;

        let authorization = extract_authorization(req);
        let restriction =
            validate_tunnel(&remote, path_prefix, authorization, &restrictions, cert_vars).ok_or_else(|| {
                warn!("Rejecting connection with not allowed destination: {remote:?}");
                bad_request()
            })?;
        info!("Tunnel accepted due to matched restriction: {}", restriction.name);

        let req_protocol = remote.protocol.clone();
        let inject_cookie = req_protocol.is_dynamic_reverse_tunnel();
        let tunnel = self
            .exec_tunnel(restriction, remote, client_addr, client_addr.port() as usize)
            .await
            .map_err(|err| {
                warn!("Rejecting connection with bad upgrade request: {err} {}", req.uri());
                bad_request()
            })?;

        let (remote_addr, local_rx, local_tx, _kill_switch) = tunnel;
        info!("connected to {:?} {}:{}", req_protocol, remote_addr.host, remote_addr.port);
        Ok((remote_addr, local_rx, local_tx, inject_cookie))
    }

    async fn exec_tunnel(
        &self,
        restriction: &RestrictionConfig,
        remote: RemoteAddr,
        client_address: SocketAddr,
        conn_id: usize,
    ) -> anyhow::Result<(
        RemoteAddr,
        Pin<Box<dyn AsyncRead + Send>>,
        Pin<Box<dyn AsyncWrite + Send>>,
        Option<Arc<Notify>>,
    )> {
        debug!(
            "exec_tunnel: Starting tunnel setup for protocol: {:?}, host: {:?}, port: {}",
            remote.protocol, remote.host, remote.port
        );
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

                Ok((remote, Box::pin(rx), Box::pin(tx), None))
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
                        (client_address, tx.local_addr()?),
                    )
                    .build()?;
                    let _ = tx.write_all(&header).await;
                }

                Ok((remote, Box::pin(rx), Box::pin(tx), None))
            }
            LocalProtocol::ReverseTcp => {
                static SERVERS: LazyLock<ReverseTunnelServer<TcpTunnelListener>> =
                    LazyLock::new(ReverseTunnelServer::new);

                let remote_port = find_mapped_port(remote.port, restriction);
                let local_srv = (remote.host, remote_port);
                let bind = try_to_sock_addr(local_srv.clone())?;
                info!(
                    "ReverseTcp: Binding reverse tunnel on {:?}, waiting for incoming connection...",
                    bind
                );
                let listening_server = async { TcpTunnelListener::new(bind, local_srv.clone(), false).await };
                let res = SERVERS
                    .run_listening_server(
                        &self.executor,
                        bind,
                        self.config.remote_server_idle_timeout,
                        listening_server,
                        conn_id,
                    )
                    .await?;
                let ((local_rx, local_tx), remote) = res.0;
                let kill_switch = res.1;
                info!("ReverseTcp: Incoming connection accepted on {:?}", bind);

                Ok((remote, Box::pin(local_rx), Box::pin(local_tx), Some(kill_switch)))
            }
            LocalProtocol::ReverseUdp { timeout } => {
                static SERVERS: LazyLock<ReverseTunnelServer<UdpTunnelListener>> =
                    LazyLock::new(ReverseTunnelServer::new);

                let remote_port = find_mapped_port(remote.port, restriction);
                let local_srv = (remote.host, remote_port);
                let bind = try_to_sock_addr(local_srv.clone())?;
                let listening_server = async { UdpTunnelListener::new(bind, local_srv.clone(), timeout).await };
                let res = SERVERS
                    .run_listening_server(
                        &self.executor,
                        bind,
                        self.config.remote_server_idle_timeout,
                        listening_server,
                        conn_id,
                    )
                    .await?;
                let ((local_rx, local_tx), remote) = res.0;
                let kill_switch = res.1;
                Ok((remote, Box::pin(local_rx), Box::pin(local_tx), Some(kill_switch)))
            }
            LocalProtocol::ReverseSocks5 { timeout, credentials } => {
                static SERVERS: LazyLock<ReverseTunnelServer<Socks5TunnelListener>> =
                    LazyLock::new(ReverseTunnelServer::new);

                let remote_port = find_mapped_port(remote.port, restriction);
                let local_srv = (remote.host, remote_port);
                let bind = try_to_sock_addr(local_srv.clone())?;
                let listening_server = async { Socks5TunnelListener::new(bind, timeout, credentials).await };
                let res = SERVERS
                    .run_listening_server(
                        &self.executor,
                        bind,
                        self.config.remote_server_idle_timeout,
                        listening_server,
                        conn_id,
                    )
                    .await?;
                let ((local_rx, local_tx), remote) = res.0;
                let kill_switch = res.1;
                Ok((remote, Box::pin(local_rx), Box::pin(local_tx), Some(kill_switch)))
            }
            LocalProtocol::ReverseHttpProxy { timeout, credentials } => {
                static SERVERS: LazyLock<ReverseTunnelServer<HttpProxyTunnelListener>> =
                    LazyLock::new(ReverseTunnelServer::new);

                let remote_port = find_mapped_port(remote.port, restriction);
                let local_srv = (remote.host, remote_port);
                let bind = try_to_sock_addr(local_srv.clone())?;
                let listening_server = async { HttpProxyTunnelListener::new(bind, timeout, credentials, false).await };
                let res = SERVERS
                    .run_listening_server(
                        &self.executor,
                        bind,
                        self.config.remote_server_idle_timeout,
                        listening_server,
                        conn_id,
                    )
                    .await?;
                let ((local_rx, local_tx), remote) = res.0;
                let kill_switch = res.1;

                Ok((remote, Box::pin(local_rx), Box::pin(local_tx), Some(kill_switch)))
            }
            #[cfg(unix)]
            LocalProtocol::ReverseUnix { ref path } => {
                use crate::tunnel::listeners::UnixTunnelListener;
                static SERVERS: LazyLock<ReverseTunnelServer<UnixTunnelListener>> =
                    LazyLock::new(ReverseTunnelServer::new);

                // we hash the unix socket path to generate a unique host
                let hash = {
                    use std::hash::{Hash, Hasher};
                    let mut hasher = AHasher::default();
                    path.hash(&mut hasher);
                    hasher.finish()
                };

                let local_srv = (Host::Ipv6(Ipv6Addr::from(hash as u128)), 0);
                // Fake bind address for the map lock
                let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), (hash % 65535) as u16));
                let path = path.clone();
                let listening_server = async { UnixTunnelListener::new(path.as_path(), local_srv, false).await };
                let res = SERVERS
                    .run_listening_server(
                        &self.executor,
                        bind,
                        self.config.remote_server_idle_timeout,
                        listening_server,
                        conn_id,
                    )
                    .await?;
                let ((local_rx, local_tx), _remote) = res.0;
                let kill_switch = res.1;

                Ok((remote, Box::pin(local_rx), Box::pin(local_tx), Some(kill_switch)))
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
        let mk_websocket_upgrade_fn = |server: WsServer<_>,
                                       restrictions: Arc<ArcSwap<RestrictionsRules>>,
                                       cert_vars: CertificateVars,
                                       client_addr: SocketAddr| {
            move |req: Request<Incoming>| {
                let server = server.clone();
                let restrictions = restrictions.clone();
                let cert_vars = cert_vars.clone();
                async move {
                    let response = ws_server_upgrade(
                        server,
                        restrictions.load().clone(),
                        None, // restrict_path_prefix is None for TLS
                        &cert_vars,
                        client_addr,
                        req,
                    )
                    .await;
                    Ok::<_, std::convert::Infallible>(response)
                }
                .instrument(mk_span())
            }
        };

        let mk_http_upgrade_fn = |server: WsServer<_>,
                                  restrictions: Arc<ArcSwap<RestrictionsRules>>,
                                  cert_vars: CertificateVars,
                                  client_addr: SocketAddr| {
            move |req: Request<Incoming>| {
                let server = server.clone();
                let restrictions = restrictions.clone();
                let cert_vars = cert_vars.clone();
                async move {
                    let response = http_server_upgrade(
                        server,
                        restrictions.load().clone(),
                        None, // restrict_path_prefix is None for TLS
                        &cert_vars,
                        client_addr,
                        req,
                    )
                    .await;
                    Ok::<_, std::convert::Infallible>(response)
                }
                .instrument(mk_span())
            }
        };

        let mk_auto_upgrade_fn = |server: WsServer<_>,
                                  restrictions: Arc<ArcSwap<RestrictionsRules>>,
                                  cert_vars: CertificateVars,
                                  client_addr: SocketAddr| {
            move |req: Request<Incoming>| {
                let server = server.clone();
                let restrictions = restrictions.clone();
                let cert_vars = cert_vars.clone();
                async move {
                    let cert_vars = cert_vars;
                    if fastwebsockets::upgrade::is_upgrade_request(&req) {
                        let response = ws_server_upgrade(
                            server.clone(),
                            restrictions.load().clone(),
                            None,
                            &cert_vars,
                            client_addr,
                            req,
                        )
                        .await;
                        Ok::<_, std::convert::Infallible>(response)
                    } else if req.version() == Version::HTTP_2 {
                        let response = http_server_upgrade(
                            server.clone(),
                            restrictions.load().clone(),
                            None,
                            &cert_vars,
                            client_addr,
                            req,
                        )
                        .await;
                        Ok::<_, std::convert::Infallible>(response)
                    } else {
                        Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Either::Left("Invalid protocol request".to_string()))
                                .unwrap(),
                        )
                    }
                }
                .instrument(mk_span())
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
        let restrictions = RestrictionsRulesReloader::new(restrictions, self.config.restriction_config.clone())?;

        if let Some(tls_config) = &self.config.tls {
            info!(
                "Configuring QUIC with TLS, client CA certificates: {}",
                tls_config.tls_client_ca_certificates.is_some()
            );
            let server_config = tls::rustls_server_config(tls_config, Some(vec![b"h3".to_vec()]))?;
            info!("Created rustls ServerConfig for QUIC, converting to QuicServerConfig");
            let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(server_config)?,
            ));
            info!("QuicServerConfig created successfully");
            let mut transport = quinn::TransportConfig::default();

            // Configure max idle timeout
            // Use 10 minutes by default to support long-lived reverse tunnels that may
            // wait for incoming connections without data activity
            let idle_timeout = self
                .config
                .quic_max_idle_timeout
                .unwrap_or(std::time::Duration::from_secs(600));
            transport.max_idle_timeout(Some(quinn::IdleTimeout::from(
                quinn::VarInt::from_u64(idle_timeout.as_millis() as u64).unwrap(),
            )));

            // Configure keep-alive interval
            transport.keep_alive_interval(Some(self.config.quic_keep_alive_interval));

            // Configure stream limits
            // Configure stream limits
            transport.max_concurrent_bidi_streams(
                quinn::VarInt::from_u64(self.config.quic_max_concurrent_bi_streams)
                    .expect("QUIC concurrent bidirectional streams limit too large"),
            );
            transport.max_concurrent_uni_streams(0u32.into()); // We don\'t use unidirectional streams

            // Configure flow control limits via TransportConfig
            // Connection-level flow control (total data across all streams)
            transport.receive_window(
                quinn::VarInt::from_u64(self.config.quic_initial_max_data)
                    .expect("QUIC initial max data limit too large"),
            );
            transport.send_window(self.config.quic_initial_max_data);

            // Per-stream flow control
            transport.stream_receive_window(
                quinn::VarInt::from_u64(self.config.quic_initial_max_stream_data)
                    .expect("QUIC initial max stream data limit too large"),
            );

            server_config.transport_config(Arc::new(transport));

            let quic_bind_addr = self.config.quic_listen.unwrap_or(self.config.bind);
            info!("Starting QUIC server listening on UDP {}", quic_bind_addr);
            let endpoint = Endpoint::server(server_config, quic_bind_addr)?;

            let server = self.clone();
            let restrictions = restrictions.clone();
            self.executor.spawn(async move {
                while let Some(conn) = endpoint.accept().await {
                    let server_clone = server.clone();
                    let restrictions = restrictions.clone();
                    server.executor.spawn(async move {
                        let server = server_clone;
                        let connection = match conn.await {
                            Ok(c) => c,
                            Err(e) => {
                                warn!("QUIC connection error: {:?}", e);
                                return;
                            }
                        };
                        let client_addr = connection.remote_address();
                        let conn_id = connection.stable_id();
                        info!("QUIC connection accepted from {} with stable_id: {}", client_addr, conn_id);

                        let span =
                            span!(Level::INFO, "cnx", peer = client_addr.to_string(), cn = tracing::field::Empty);

                        // Try to extract CN from QUIC connection immediately
                        if let Some(_identity) = connection.peer_identity() {
                            debug!("QUIC connection established with peer identity available");
                        } else {
                            debug!("QUIC connection established WITHOUT peer identity");
                        }

                        debug!("QUIC server: Starting stream accept loop for connection stable_id: {}", conn_id);

                        async move {
                            // Loop to accept multiple streams on the same QUIC connection
                            loop {
                                info!("QUIC server: Waiting to accept stream on connection {}", conn_id);
                                let (mut send, mut recv) = match connection.accept_bi().await {
                                    Ok(s) => {
                                        info!("QUIC server: Stream accepted successfully on connection {}", conn_id);
                                        s
                                    }
                                    Err(e) => {
                                        warn!("QUIC stream accept error on connection {}: {:?}", conn_id, e);
                                        return;
                                    }
                                };

                                let server_clone = server.clone();
                                let restrictions_clone = restrictions.clone();
                                let connection_clone = connection.clone();

                                // Spawn a task for each stream to handle it concurrently
                                server.executor.spawn(async move {
                                    let server = server_clone;
                                    let restrictions = restrictions_clone;
                                    let connection = connection_clone;
                                    let mut buf = BytesMut::new();

                                    loop {
                                        let mut header_buf = [httparse::EMPTY_HEADER; 64];
                                        let chunk = match recv.read_chunk(4096, true).await {
                                            Ok(Some(chunk)) => chunk,
                                            Ok(None) => return,
                                            Err(e) => {
                                                warn!("QUIC read error: {:?}", e);
                                                return;
                                            }
                                        };
                                        buf.extend_from_slice(&chunk.bytes);

                                        let parse_result = {
                                            let mut req = httparse::Request::new(&mut header_buf);
                                            match req.parse(&buf) {
                                                Ok(httparse::Status::Complete(size)) => {
                                                    let mut builder = Request::builder()
                                                        .method(req.method.unwrap())
                                                        .uri(req.path.unwrap())
                                                        .version(Version::HTTP_11);

                                                    for h in req.headers {
                                                        builder = builder.header(h.name, h.value);
                                                    }

                                                    let req = builder.body(()).unwrap();
                                                    Ok(Some((req, size)))
                                                }
                                                Ok(httparse::Status::Partial) => Ok(None),
                                                Err(e) => Err(e),
                                            }
                                        };

                                        match parse_result {
                                            Ok(Some((req, size))) => {
                                                info!("QUIC server: HTTP request parsed successfully: {} {}", req.method(), req.uri());

                                                // Extract cert vars from QUIC connection if possible
                                                let cert_vars = if let Some(certs) = connection.peer_identity() {
                                                    debug!("QUIC peer_identity() returned Some, attempting downcast");
                                                    if let Some(certs) =
                                                        certs.downcast_ref::<Vec<
                                                            tokio_rustls::rustls::pki_types::CertificateDer<'static>,
                                                        >>(
                                                        )
                                                    {
                                                        debug!("QUIC certificate downcast succeeded, extracting CN from {} certificates", certs.len());
                                                        let vars = crate::protocols::tls::CertificateVars::from_certificate(certs);
                                                        debug!("QUIC extracted certificate CN: {:?}", vars.cn);
                                                        vars
                                                    } else {
                                                        warn!("QUIC peer_identity() downcast failed - type mismatch. Expected Vec<CertificateDer>");
                                                        crate::protocols::tls::CertificateVars::default()
                                                    }
                                                } else {
                                                    warn!("QUIC peer_identity() returned None - no client certificate available");
                                                    crate::protocols::tls::CertificateVars::default()
                                                };

                                                if let Some(cn) = &cert_vars.cn {
                                                    info!("Extracted certificate CN: {:?}", cn);
                                                    Span::current().record("cn", cn);
                                                } else {
                                                    warn!("No certificate CN found for QUIC connection");
                                                }

                                                let restrictions = restrictions.restrictions_rules().load().clone();

                                                // For reverse tunnels, we need to send HTTP 200 BEFORE waiting for incoming connection
                                                // to avoid deadlock. Parse and validate the tunnel request first.
                                                let (remote, path_prefix, authorization) = match server.parse_tunnel_info(&req) {
                                                    Ok(parsed) => parsed,
                                                    Err(err) => {
                                                        warn!("Rejecting connection with bad tunnel info: {err} {}", req.uri());
                                                        return;
                                                    }
                                                };

                                                let restriction = match crate::tunnel::server::utils::validate_tunnel(
                                                    &remote,
                                                    path_prefix,
                                                    authorization,
                                                    &restrictions,
                                                    &cert_vars,
                                                ) {
                                                    Some(r) => r,
                                                    None => {
                                                        warn!("Rejecting connection with not allowed destination: {:?}", remote);
                                                        return;
                                                    }
                                                };

                                                info!("Tunnel accepted due to matched restriction: {}", restriction.name);

                                                // Call exec_tunnel (may block for reverse tunnels waiting for incoming connection)
                                                // We race against connection closed, to avoid having a zombie task waiting for incoming connection
                                                // if the client disconnected. This is important for reverse tunnel where we wait for incoming connection
                                                let (remote_addr, local_rx, local_tx, kill_switch): (_, _, _, Option<Arc<Notify>>) = tokio::select! {
                                                    res = server.exec_tunnel(restriction, remote, client_addr, conn_id) => {
                                                        match res {
                                                            Ok(r) => {
                                                                info!("exec_tunnel completed successfully");
                                                                r
                                                            }
                                                            Err(err) => {
                                                                warn!("Failed to establish tunnel: {err}");
                                                                return;
                                                            }
                                                        }
                                                    }
                                                    _ = connection.closed() => {
                                                        warn!("QUIC connection closed while waiting for tunnel establishment");
                                                        return;
                                                    }
                                                };

                                                info!("connected to {:?} {}:{}", remote_addr.protocol, remote_addr.host, remote_addr.port);

                                                // Send HTTP 200 AFTER exec_tunnel completes
                                                debug!("QUIC server: Sending HTTP 200 AFTER exec_tunnel");
                                                let response = "HTTP/1.1 200 OK\r\n\r\n";
                                                if let Err(e) = send.write_all(response.as_bytes()).await {
                                                    warn!("QUIC server: Failed to send HTTP response: {:?}", e);
                                                    return;
                                                }
                                                debug!("QUIC server: HTTP 200 sent, starting data propagation");

                                                let extra_bytes = if buf.len() > size {
                                                    Some(buf.split_off(size).freeze())
                                                } else {
                                                    None
                                                };

                                                let tunnel_read = QuicTunnelRead::new(recv).with_pre_read(extra_bytes);
                                                let tunnel_write = QuicTunnelWrite::new(send);

                                                let span = span!(
                                                    Level::INFO,
                                                    "tunnel",
                                                    id = tracing::field::Empty,
                                                    remote = format!("{}:{}", remote_addr.host, remote_addr.port)
                                                );

                                                let (close_tx, close_rx) = tokio::sync::oneshot::channel::<()>();

                                                let kill_switch_1 = kill_switch.clone();
                                                server.executor.spawn(
                                                    async move {
                                                        let kill_signal = async {
                                                            if let Some(k) = kill_switch_1 {
                                                                k.notified().await;
                                                            } else {
                                                                std::future::pending::<()>().await
                                                            }
                                                        };

                                                        tokio::select! {
                                                            _ = crate::tunnel::transport::io::propagate_local_to_remote(
                                                                local_rx,
                                                                tunnel_write,
                                                                close_tx,
                                                                server.config.websocket_ping_frequency,
                                                            ) => {}
                                                            _ = kill_signal => {
                                                                warn!("Session killed by new connection");
                                                            }
                                                        }
                                                    }
                                                    .instrument(span.clone()),
                                                );

                                                let kill_signal = async {
                                                    if let Some(k) = kill_switch {
                                                        k.notified().await;
                                                    } else {
                                                        std::future::pending::<()>().await
                                                    }
                                                };

                                                let _ = crate::tunnel::transport::io::propagate_remote_to_local(
                                                    local_tx,
                                                    tunnel_read,
                                                    close_rx,
                                                    kill_signal,
                                                )
                                                .await;

                                                return;
                                            }
                                            Ok(None) => continue,
                                            Err(e) => {
                                                warn!("Invalid HTTP request: {:?}", e);
                                                return;
                                            }
                                        }
                                    }
                                }); // Close the spawned stream task
                            } // Loop back to accept next stream
                        }
                        .instrument(span)
                        .await;
                    });
                }
            });
        }

        let listener = TcpListener::bind(&self.config.bind)
            .await
            .with_context(|| format!("Failed to bind to socket on {}", self.config.bind))?;

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(ret) => ret,
                Err(err) => {
                    warn!("Error while accepting connection {:?}", err);
                    continue;
                }
            };

            let span = span!(Level::INFO, "cnx", peer = peer_addr.to_string(), cn = tracing::field::Empty);
            info!(parent: &span, "Accepting connection");
            if let Err(err) = protocols::tcp::configure_socket(SockRef::from(&stream), SoMark::new(None)) {
                warn!("Error while configuring server socket {:?}", err);
            }

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
                        // extract client certificate variables
                        let peer_certs = tls_ctx.peer_certificates();
                        info!("TLS peer certificates present: {}", peer_certs.is_some());
                        let cert_vars = peer_certs.map(CertificateVars::from_certificate).unwrap_or_default();
                        if let Some(cn) = &cert_vars.cn {
                            Span::current().record("cn", cn);
                        }
                        info!("Extracted certificate CN: {:?}", cert_vars.cn);
                        match tls_ctx.alpn_protocol() {
                            // http2
                            Some(b"h2") => {
                                let mut conn_builder = http2::Builder::new(TokioExecutor::new());
                                conn_builder.timer(TokioTimer::new());
                                if let Some(ping) = server.config.websocket_ping_frequency {
                                    conn_builder.keep_alive_interval(ping);
                                }

                                let http_upgrade_fn =
                                    mk_http_upgrade_fn(server, restrictions, cert_vars.clone(), peer_addr);
                                let con_fut = conn_builder.serve_connection(tls_stream, service_fn(http_upgrade_fn));
                                if let Err(e) = con_fut.await {
                                    error!("Error while upgrading cnx to http: {:?}", e);
                                }
                            }
                            // websocket
                            _ => {
                                let websocket_upgrade_fn =
                                    mk_websocket_upgrade_fn(server, restrictions, cert_vars.clone(), peer_addr);
                                let conn_fut = http1::Builder::new()
                                    .timer(TokioTimer::new())
                                    // https://github.com/erebe/wstunnel/issues/358
                                    // disabled, to avoid conflict with --connection-min-idle flag, that open idle connections
                                    .header_read_timeout(None)
                                    .serve_connection(tls_stream, service_fn(websocket_upgrade_fn))
                                    .with_upgrades();

                                if let Err(e) = conn_fut.await {
                                    error!("Error while upgrading cnx: {:?}", e);
                                }
                            }
                        };
                    }
                    .instrument(span);

                    self.executor.spawn(fut);
                }
                // HTTP without TLS
                None => {
                    let fut = async move {
                        let stream = hyper_util::rt::TokioIo::new(stream);
                        let mut conn_fut = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                        if let Some(ping) = server.config.websocket_ping_frequency {
                            conn_fut.http2().keep_alive_interval(ping);
                        }

                        let websocket_upgrade_fn =
                            mk_auto_upgrade_fn(server, restrictions, CertificateVars::default(), peer_addr);
                        let upgradable =
                            conn_fut.serve_connection_with_upgrades(stream, service_fn(websocket_upgrade_fn));

                        if let Err(e) = upgradable.await {
                            error!("Error while upgrading cnx to websocket: {:?}", e);
                        }
                    }
                    .instrument(span);

                    self.executor.spawn(fut);
                }
            }
        }
    }
}

fn mk_span() -> Span {
    span!(
        Level::INFO,
        "tunnel",
        id = tracing::field::Empty,
        remote = tracing::field::Empty,
        forwarded_for = tracing::field::Empty
    )
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
            .field("remote_server_idle_timeout", &self.remote_server_idle_timeout)
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
