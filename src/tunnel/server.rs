use std::cmp::min;
use std::ops::{Deref, Not};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use super::{JwtTunnelConfig, JWT_DECODE};
use crate::udp::MyUdpSocket;
use crate::{tcp, tls, LocalProtocol, WsServerConfig};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{http, Body, Request, Response, StatusCode};
use jsonwebtoken::TokenData;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::oneshot;
use tracing::{error, info, instrument, span, warn, Instrument, Level, Span};
use url::Host;

async fn from_query(
    server_config: &WsServerConfig,
    query: &str,
) -> anyhow::Result<(
    LocalProtocol,
    Host,
    u16,
    Pin<Box<dyn AsyncRead + Send>>,
    Pin<Box<dyn AsyncWrite + Send>>,
)> {
    let jwt: TokenData<JwtTunnelConfig> = match query.split_once('=') {
        Some(("bearer", jwt)) => {
            let (validation, decode_key) = JWT_DECODE.deref();
            match jsonwebtoken::decode(jwt, decode_key, validation) {
                Ok(jwt) => jwt,
                err => {
                    error!("error while decoding jwt for tunnel info {:?}", err);
                    return Err(anyhow::anyhow!("Invalid upgrade request"));
                }
            }
        }
        _err => return Err(anyhow::anyhow!("Invalid upgrade request")),
    };

    Span::current().record("id", jwt.claims.id);
    Span::current().record("remote", format!("{}:{}", jwt.claims.r, jwt.claims.rp));
    if let Some(allowed_dests) = &server_config.restrict_to {
        let requested_dest = format!("{}:{}", jwt.claims.r, jwt.claims.rp);
        if allowed_dests
            .iter()
            .any(|dest| dest == &requested_dest)
            .not()
        {
            warn!(
                "Rejecting connection with not allowed destination: {}",
                requested_dest
            );
            return Err(anyhow::anyhow!("Invalid upgrade request"));
        }
    }

    match jwt.claims.p {
        LocalProtocol::Udp { .. } => {
            let host = Host::parse(&jwt.claims.r)?;
            let cnx = Arc::new(UdpSocket::bind("[::]:0").await?);
            cnx.connect((host.to_string(), jwt.claims.rp)).await?;
            Ok((
                LocalProtocol::Udp { timeout: None },
                host,
                jwt.claims.rp,
                Box::pin(MyUdpSocket::new(cnx.clone())),
                Box::pin(MyUdpSocket::new(cnx)),
            ))
        }
        LocalProtocol::Tcp { .. } => {
            let host = Host::parse(&jwt.claims.r)?;
            let port = jwt.claims.rp;
            let (rx, tx) = tcp::connect(
                &host,
                port,
                &server_config.socket_so_mark,
                Duration::from_secs(10),
            )
            .await?
            .into_split();

            Ok((jwt.claims.p, host, port, Box::pin(rx), Box::pin(tx)))
        }
        _ => Err(anyhow::anyhow!("Invalid upgrade request")),
    }
}

async fn server_upgrade(
    server_config: Arc<WsServerConfig>,
    mut req: Request<Body>,
) -> Result<Response<Body>, anyhow::Error> {
    if let Some(x) = req.headers().get("X-Forwarded-For") {
        info!("Request X-Forwarded-For: {:?}", x);
        Span::current().record("forwarded_for", x.to_str().unwrap_or_default());
    }

    if !req.uri().path().ends_with("/events") {
        warn!(
            "Rejecting connection with bad upgrade request: {}",
            req.uri()
        );
        return Ok(http::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Invalid upgrade request"))
            .unwrap_or_default());
    }

    if let Some(path_prefix) = &server_config.restrict_http_upgrade_path_prefix {
        let path = req.uri().path();
        let min_len = min(path.len(), 1);
        let max_len = min(path.len(), path_prefix.len() + 1);
        if &path[0..min_len] != "/"
            || &path[min_len..max_len] != path_prefix.as_str()
            || !path[max_len..].starts_with('/')
        {
            warn!(
                "Rejecting connection with bad path prefix in upgrade request: {}",
                req.uri()
            );
            return Ok(http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Invalid upgrade request"))
                .unwrap_or_default());
        }
    }

    let (protocol, dest, port, local_rx, local_tx) =
        match from_query(&server_config, req.uri().query().unwrap_or_default()).await {
            Ok(ret) => ret,
            Err(err) => {
                warn!(
                    "Rejecting connection with bad upgrade request: {} {}",
                    err,
                    req.uri()
                );
                return Ok(http::Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from(format!("Invalid upgrade request: {:?}", err)))
                    .unwrap_or_default());
            }
        };

    info!("connected to {:?} {:?} {:?}", protocol, dest, port);
    let (response, fut) = match fastwebsockets::upgrade::upgrade(&mut req) {
        Ok(ret) => ret,
        Err(err) => {
            warn!(
                "Rejecting connection with bad upgrade request: {} {}",
                err,
                req.uri()
            );
            return Ok(http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(format!("Invalid upgrade request: {:?}", err)))
                .unwrap_or_default());
        }
    };

    tokio::spawn(
        async move {
            let (ws_rx, mut ws_tx) = match fut.await {
                Ok(ws) => ws.split(tokio::io::split),
                Err(err) => {
                    error!("Error during http upgrade request: {:?}", err);
                    return;
                }
            };
            let (close_tx, close_rx) = oneshot::channel::<()>();
            let ping_frequency = server_config
                .websocket_ping_frequency
                .unwrap_or(Duration::MAX);
            ws_tx.set_auto_apply_mask(server_config.websocket_mask_frame);

            tokio::task::spawn(
                super::io::propagate_write(local_tx, ws_rx, close_rx).instrument(Span::current()),
            );

            let _ = super::io::propagate_read(local_rx, ws_tx, close_tx, ping_frequency).await;
        }
        .instrument(Span::current()),
    );

    Ok(response)
}

#[instrument(name="tunnel", level="info", skip_all, fields(id=tracing::field::Empty, remote=tracing::field::Empty, peer=tracing::field::Empty, forwarded_for=tracing::field::Empty))]
pub async fn run_server(server_config: Arc<WsServerConfig>) -> anyhow::Result<()> {
    info!(
        "Starting wstunnel server listening on {}",
        server_config.bind
    );

    let config = server_config.clone();
    let upgrade_fn = move |req: Request<Body>| server_upgrade(config.clone(), req);

    let listener = TcpListener::bind(&server_config.bind).await?;
    let tls_acceptor = if let Some(tls) = &server_config.tls {
        Some(tls::tls_acceptor(tls, Some(vec![b"http/1.1".to_vec()]))?)
    } else {
        None
    };

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let _ = stream.set_nodelay(true);

        let span = span!(
            Level::INFO,
            "tunnel",
            id = tracing::field::Empty,
            remote = tracing::field::Empty,
            peer = peer_addr.to_string(),
            forwarded_for = tracing::field::Empty
        );

        info!("Accepting connection");
        let upgrade_fn = upgrade_fn.clone();
        // TLS
        if let Some(tls_acceptor) = &tls_acceptor {
            let tls_acceptor = tls_acceptor.clone();
            let fut = async move {
                info!("Doing TLS handshake");
                let tls_stream = match tls_acceptor.accept(stream).await {
                    Ok(tls_stream) => tls_stream,
                    Err(err) => {
                        error!("error while accepting TLS connection {}", err);
                        return;
                    }
                };
                let conn_fut = Http::new()
                    .http1_only(true)
                    .serve_connection(tls_stream, service_fn(upgrade_fn))
                    .with_upgrades();

                if let Err(e) = conn_fut.await {
                    error!("Error while upgrading cnx to websocket: {:?}", e);
                }
            }
            .instrument(span);

            tokio::spawn(fut);
            // Normal
        } else {
            let conn_fut = Http::new()
                .http1_only(true)
                .serve_connection(stream, service_fn(upgrade_fn))
                .with_upgrades();

            let fut = async move {
                if let Err(e) = conn_fut.await {
                    error!("Error while upgrading cnx to weboscket: {:?}", e);
                }
            }
            .instrument(span);

            tokio::spawn(fut);
        };
    }
}
