use crate::executor::TokioExecutorRef;
use crate::protocols::tls;
use crate::restrictions::types::RestrictionsRules;
use crate::tunnel::LocalProtocol;
use crate::tunnel::server::WsServer;
use crate::tunnel::tls_reloader::TlsReloader;
use crate::tunnel::transport;
use crate::tunnel::transport::tunnel_to_jwt_token;
use crate::tunnel::transport::webtransport::{
    WebTransportTunnelRead, WebTransportTunnelReadUdpStream, WebTransportTunnelWrite, WebTransportTunnelWriteUdpStream,
    bind_udp_socket, mk_transport_config, write_jwt_preamble,
};
use anyhow::{Context, anyhow};
use arc_swap::ArcSwap;
use hyper::{Request, StatusCode};
use std::any::Any;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tracing::{Instrument, Level, Span, error, info, span, warn};
use uuid::Uuid;
use web_transport_quinn::quinn::crypto::rustls::QuicServerConfig;
use web_transport_quinn::{Server, quinn};

/// Serve WebTransport (HTTP/3 over QUIC) on the same port as the TCP listener, over UDP.
///
/// This runs alongside [`WsServer::serve`]'s TCP accept loop rather than replacing it, so one
/// server process answers websocket, http2 and webtransport clients.
pub(super) async fn run_webtransport_server(
    server: WsServer<impl TokioExecutorRef>,
    restrictions: Arc<ArcSwap<RestrictionsRules>>,
) -> anyhow::Result<()> {
    let Some(tls_config) = server.config.tls.as_ref() else {
        return Err(anyhow!(
            "webtransport requires TLS: QUIC mandates TLS 1.3, so it cannot be served on a cleartext ws:// or http:// endpoint"
        ));
    };

    let bind = server.config.bind;
    let mut endpoint = Server::new(mk_quic_endpoint(&server, tls_config)?);
    let tls_reloader = TlsReloader::new_for_server(server.config.clone())
        .with_context(|| "Cannot create the tls reloader for webtransport")?;

    info!("Starting wstunnel webtransport server listening on udp://{bind}");

    loop {
        // Same contract as `TlsContext::tls_acceptor` on the TCP path: swap the certificate in
        // between accepts, so a rotated certificate is picked up without a restart.
        if tls_reloader.should_reload_certificate() {
            match mk_quic_server_config(&server, tls_config) {
                Ok(config) => endpoint.set_server_config(Some(config)),
                Err(err) => error!("Cannot reload the webtransport TLS certificate {err:?}"),
            }
        }

        let Some(request) = endpoint.accept().await else {
            warn!("webtransport endpoint closed, stopping to accept connections");
            return Ok(());
        };

        let peer_addr = request.conn().remote_address();
        let span = span!(Level::INFO, "cnx", peer = peer_addr.to_string());
        info!(parent: &span, "Accepting webtransport connection");

        let server = server.clone();
        let restrictions = restrictions.load().clone();
        let session_handler = {
            let server = server.clone();
            async move {
                if let Err(err) = handle_session(server, restrictions, request).await {
                    warn!("{err:?}");
                }
            }
            .instrument(span)
        };
        server.executor.spawn(session_handler);
    }
}

fn mk_quic_server_config(
    server: &WsServer<impl TokioExecutorRef>,
    tls_config: &crate::tunnel::server::TlsServerConfig,
) -> anyhow::Result<quinn::ServerConfig> {
    let tls = tls::quic_server_config(tls_config).with_context(|| "Cannot create the TLS config for webtransport")?;
    let tls = QuicServerConfig::try_from(tls)
        .with_context(|| "Cannot use the TLS config for QUIC, TLS 1.3 with a supported cipher suite is required")?;

    let mut config = quinn::ServerConfig::with_crypto(Arc::new(tls));
    config.transport_config(Arc::new(mk_transport_config(server.config.websocket_ping_frequency)?));

    Ok(config)
}

fn mk_quic_endpoint(
    server: &WsServer<impl TokioExecutorRef>,
    tls_config: &crate::tunnel::server::TlsServerConfig,
) -> anyhow::Result<quinn::Endpoint> {
    let socket = bind_udp_socket(Some(server.config.bind), server.config.socket_so_mark)
        .with_context(|| format!("Failed to bind to udp socket on {}", server.config.bind))?;

    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(mk_quic_server_config(server, tls_config)?),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .with_context(|| format!("Failed to create the QUIC endpoint on {}", server.config.bind))
}

async fn handle_session(
    server: WsServer<impl TokioExecutorRef>,
    restrictions: Arc<RestrictionsRules>,
    request: web_transport_quinn::Request,
) -> anyhow::Result<()> {
    let client_addr = request.conn().remote_address();

    // Unlike the TCP path, the client certificate is readable before we answer the CONNECT, so
    // a request rejected by an mTLS path-prefix restriction gets a real 403 rather than an
    // abrupt connection close.
    let restrict_path = request
        .conn()
        .peer_identity()
        .and_then(|identity: Box<dyn Any>| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
        .and_then(|certs| {
            tls::find_leaf_certificate(certs.as_slice()).and_then(|cert| tls::cn_from_certificate(&cert))
        });

    // Rebuild an http request so the whole validation path is shared with the other transports.
    // Only the uri and headers are read, so the unit body is fine.
    let mut http_request = Request::builder()
        .method("CONNECT")
        .uri(request.url.path())
        .body(())
        .with_context(|| format!("webtransport request has an invalid path: {}", request.url.path()))?;
    *http_request.headers_mut() = request.headers.clone();

    let tunnel = server
        .handle_tunnel_request(restrictions, restrict_path, client_addr, &http_request)
        .await;

    let (remote_addr, local_rx, local_tx, need_preamble) = match tunnel {
        Ok(tunnel) => tunnel,
        Err(response) => {
            let status = response.status();
            warn!("Rejecting webtransport connection from {client_addr} with {status}");
            let _ = request.reject(status).await;
            return Ok(());
        }
    };

    let session = request
        .ok()
        .await
        .with_context(|| format!("Cannot accept the webtransport session from {client_addr}"))?;

    // The tunnel to the destination is already open at this point, so bound the wait for the
    // client's stream. Otherwise a client that completes the CONNECT and then never opens one
    // (while still answering QUIC keep-alives) would hold that tunnel open indefinitely. A well
    // behaved client calls `open_bi` immediately, and it writes the WebTransport stream header
    // eagerly, so this resolves in one round trip.
    let accept = tokio::time::timeout(server.config.timeout_connect, session.accept_bi());
    let (mut send, recv) = match accept.await {
        Ok(stream) => stream.with_context(|| format!("Cannot accept the webtransport stream from {client_addr}"))?,
        Err(_) => {
            let timeout = server.config.timeout_connect;
            session.close(StatusCode::REQUEST_TIMEOUT.as_u16() as u32, b"no stream opened");
            return Err(anyhow!(
                "Client {client_addr} opened a webtransport session but no stream within {timeout:?}"
            ));
        }
    };

    // Dynamic reverse tunnels learn their destination from the server. The CONNECT response
    // cannot carry it (`ConnectResponse` has no header map), so it goes out as a preamble on
    // the stream instead. See `transport::webtransport::write_jwt_preamble`.
    if need_preamble {
        let jwt = tunnel_to_jwt_token(Uuid::from_u128(0), &remote_addr);
        if let Err(err) = write_jwt_preamble(&mut send, &jwt).await {
            session.close(StatusCode::INTERNAL_SERVER_ERROR.as_u16() as u32, b"cannot send tunnel info");
            return Err(err).with_context(|| format!("Cannot send the tunnel jwt to {client_addr}"));
        }
    }

    let (close_tx, close_rx) = oneshot::channel::<()>();
    if matches!(
        remote_addr.protocol,
        LocalProtocol::Udp { .. } | LocalProtocol::TProxyUdp { .. }
    ) {
        server.executor.spawn(
            transport::io::propagate_remote_to_local(
                local_tx,
                WebTransportTunnelReadUdpStream::new(recv, session.clone()),
                close_rx,
            )
            .instrument(Span::current()),
        );
        server.executor.spawn(
            transport::io::propagate_local_to_remote(
                local_rx,
                WebTransportTunnelWriteUdpStream::new(send, session),
                close_tx,
                None,
            )
            .instrument(Span::current()),
        );
    } else {
        server.executor.spawn(
            transport::io::propagate_remote_to_local(
                local_tx,
                WebTransportTunnelRead::new(recv, session.clone()),
                close_rx,
            )
            .instrument(Span::current()),
        );
        server.executor.spawn(
            transport::io::propagate_local_to_remote(
                local_rx,
                WebTransportTunnelWrite::new(send, session),
                close_tx,
                None,
            )
            .instrument(Span::current()),
        );
    }

    Ok(())
}
