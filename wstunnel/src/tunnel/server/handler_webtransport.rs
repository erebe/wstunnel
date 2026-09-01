use crate::executor::TokioExecutorRef;
use crate::protocols::tls;
use crate::restrictions::types::RestrictionsRules;
use crate::tunnel::LocalProtocol;
use crate::tunnel::server::Server;
use crate::tunnel::server::utils::{extract_path_prefix, matches_any_restriction};
use crate::tunnel::tls_reloader::TlsReloader;
use crate::tunnel::transport;
use crate::tunnel::transport::tunnel_to_jwt_token;
use crate::tunnel::transport::webtransport::{
    WebTransportRead, WebTransportUdpRead, WebTransportUdpWrite, WebTransportWrite, bind_udp_socket,
    mk_transport_config, read_jwt_preamble, write_jwt_preamble,
};
use anyhow::{Context, anyhow};
use arc_swap::ArcSwap;
use hyper::header::{AUTHORIZATION, COOKIE, HeaderValue};
use hyper::{Request, StatusCode};
use std::any::Any;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tracing::{Instrument, Level, Span, debug, error, info, span, warn};
use uuid::Uuid;
use web_transport_quinn::quinn;
use web_transport_quinn::quinn::crypto::rustls::QuicServerConfig;

/// Serve WebTransport (HTTP/3 over QUIC) on the same port as the TCP listener, over UDP.
///
/// This runs alongside [`Server::serve`]'s TCP accept loop rather than replacing it, so one
/// server process answers websocket, http2 and webtransport clients.
pub(super) async fn run_webtransport_server(
    server: Server<impl TokioExecutorRef>,
    restrictions: Arc<ArcSwap<RestrictionsRules>>,
) -> anyhow::Result<()> {
    let Some(tls_config) = server.config.tls.as_ref() else {
        return Err(anyhow!(
            "webtransport requires TLS: QUIC mandates TLS 1.3, so it cannot be served on a cleartext ws:// or http:// endpoint"
        ));
    };

    let bind = server.config.bind;
    let mut endpoint = web_transport_quinn::Server::new(mk_quic_endpoint(&server, tls_config)?);
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

        let session_handler = {
            let server = server.clone();
            let restrictions = restrictions.load().clone();
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
    server: &Server<impl TokioExecutorRef>,
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
    server: &Server<impl TokioExecutorRef>,
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
    server: Server<impl TokioExecutorRef>,
    restrictions: Arc<RestrictionsRules>,
    request: web_transport_quinn::Request,
) -> anyhow::Result<()> {
    // Unlike the TCP path, the client certificate is readable before we answer the CONNECT.
    let restrict_path = request
        .conn()
        .peer_identity()
        .and_then(|identity: Box<dyn Any>| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
        .and_then(|certs| {
            tls::find_leaf_certificate(certs.as_slice()).and_then(|cert| tls::cn_from_certificate(&cert))
        });

    // Rebuild an http request so the whole validation path is shared with the other transports.
    // Only the uri and headers are read, so the unit body is fine. The destination is *not* in
    // here: the session is shared by every tunnel the client opens on it, so each stream announces
    // its own destination with a JWT preamble and gets this request with that JWT filled in.
    let session_path = request.url.path().to_string();
    let session_headers = request.headers.clone();

    // The destination only arrives per stream, but the path prefix and the authorization header are
    // known now. Checking them here turns a client that could never open any tunnel away with a
    // real status, instead of accepting its session and resetting every stream it opens.
    //
    // Every rejection answers 400, like `utils::bad_request` does on the TCP path, so a prober
    // cannot tell a bad path from a forbidden one.
    let client_addr = request.conn().remote_address();
    let path_prefix = match extract_path_prefix(&session_path) {
        Ok(path_prefix) => path_prefix,
        Err(err) => {
            warn!("Rejecting webtransport session from {client_addr} with {err}: {session_path}");
            let _ = request.reject(StatusCode::BAD_REQUEST).await;
            return Ok(());
        }
    };

    if let Some(restrict_path) = &restrict_path
        && path_prefix != restrict_path
    {
        warn!(
            "Client requested upgrade path '{path_prefix}' does not match upgrade path restriction '{restrict_path}' (mTLS, etc.)"
        );
        let _ = request.reject(StatusCode::BAD_REQUEST).await;
        return Ok(());
    }

    let allowed = matches_any_restriction(
        path_prefix,
        session_headers.get(AUTHORIZATION).and_then(|auth| auth.to_str().ok()),
        &restrictions,
    );
    if !allowed {
        warn!("Rejecting webtransport session from {client_addr}: no restriction matches path prefix '{path_prefix}'");
        let _ = request.reject(StatusCode::BAD_REQUEST).await;
        return Ok(());
    }

    let session = request
        .ok()
        .await
        .with_context(|| format!("Cannot accept the webtransport session from {client_addr}"))?;

    // One tunnel per stream. Accepting the session commits nothing upstream, so there is no need to
    // bound how long the client takes to open the first one; an idle session costs a QUIC
    // connection, which the keep-alive/idle timeout already reaps.
    loop {
        let (send, recv) = match session.accept_bi().await {
            Ok(stream) => stream,
            Err(err) => {
                debug!("webtransport session with {client_addr} ended: {err}");
                return Ok(());
            }
        };

        let server = server.clone();
        let restrictions = restrictions.clone();
        let session = session.clone();
        let session_path = session_path.clone();
        let session_headers = session_headers.clone();
        let restrict_path = restrict_path.clone();
        let span = span!(Level::INFO, "tunnel", peer = client_addr.to_string());
        server.executor.clone().spawn(
            async move {
                if let Err(err) = wt_server_connect(
                    server,
                    restrictions,
                    session,
                    client_addr,
                    restrict_path,
                    &session_path,
                    session_headers,
                    (send, recv),
                )
                .await
                {
                    warn!("{err:?}");
                }
            }
            .instrument(span),
        );
    }
}

/// Serve one tunnel, carried by one bidirectional stream of a webtransport session.
#[allow(clippy::too_many_arguments)]
async fn wt_server_connect(
    server: Server<impl TokioExecutorRef>,
    restrictions: Arc<RestrictionsRules>,
    session: web_transport_quinn::Session,
    client_addr: SocketAddr,
    restrict_path: Option<String>,
    session_path: &str,
    session_headers: hyper::HeaderMap,
    (mut send, mut recv): (web_transport_quinn::SendStream, web_transport_quinn::RecvStream),
) -> anyhow::Result<()> {
    // The client announces the destination for this stream before anything else, since the
    // session-level CONNECT is shared and cannot carry it.
    let jwt = tokio::time::timeout(server.config.timeout_connect, read_jwt_preamble(&mut recv))
        .await
        .map_err(|_| {
            let timeout = server.config.timeout_connect;
            anyhow!("Client {client_addr} opened a webtransport stream but sent no tunnel jwt within {timeout:?}")
        })?
        .with_context(|| format!("Cannot read the tunnel jwt from {client_addr}"))?;

    let mut http_request = Request::builder()
        .method("CONNECT")
        .uri(session_path)
        .body(())
        .with_context(|| format!("webtransport request has an invalid path: {session_path}"))?;
    *http_request.headers_mut() = session_headers;
    http_request.headers_mut().insert(
        COOKIE,
        HeaderValue::from_str(&jwt).with_context(|| "client sent an invalid tunnel jwt")?,
    );

    let tunnel = server
        .handle_tunnel_request(restrictions, restrict_path, client_addr, &http_request)
        .await;

    let (remote_addr, local_rx, local_tx, need_preamble) = match tunnel {
        Ok(tunnel) => tunnel,
        Err(response) => {
            // The session stays up for the client's other tunnels, so only this stream is
            // refused. There is no per-stream status code, so the http status goes out as the
            // stream reset code.
            let status = response.status();
            warn!("Rejecting webtransport stream from {client_addr} with {status}");
            let _ = send.reset(status.as_u16() as u32);
            return Ok(());
        }
    };

    // Dynamic reverse tunnels learn their destination from the server. The CONNECT response
    // cannot carry it (`ConnectResponse` has no header map), so it goes out as a preamble on
    // the stream instead. See `transport::webtransport::write_jwt_preamble`.
    if need_preamble {
        let jwt = tunnel_to_jwt_token(Uuid::from_u128(0), &remote_addr);
        if let Err(err) = write_jwt_preamble(&mut send, &jwt).await {
            let _ = send.reset(StatusCode::INTERNAL_SERVER_ERROR.as_u16() as u32);
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
                WebTransportUdpRead::new(recv, session.clone()),
                close_rx,
            )
            .instrument(Span::current()),
        );
        server.executor.spawn(
            transport::io::propagate_local_to_remote(
                local_rx,
                WebTransportUdpWrite::new(send, session),
                close_tx,
                None,
            )
            .instrument(Span::current()),
        );
    } else {
        server.executor.spawn(
            transport::io::propagate_remote_to_local(local_tx, WebTransportRead::new(recv, session.clone()), close_rx)
                .instrument(Span::current()),
        );
        server.executor.spawn(
            transport::io::propagate_local_to_remote(local_rx, WebTransportWrite::new(send, session), close_tx, None)
                .instrument(Span::current()),
        );
    }

    Ok(())
}
