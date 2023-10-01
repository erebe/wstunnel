#![allow(unused_imports)]

use std::collections::HashSet;
use std::future::Future;
use std::net::Ipv4Addr;
use std::ops::{Deref, Not};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use crate::{tcp, tls, L4Protocol, LocalToRemote, WsClientConfig, WsServerConfig};
use anyhow::Context;
use fastwebsockets::upgrade::UpgradeFut;
use fastwebsockets::{
    Frame, OpCode, Payload, WebSocket, WebSocketError, WebSocketRead, WebSocketWrite,
};
use futures_util::{pin_mut, StreamExt};
use hyper::header::{AUTHORIZATION, SEC_WEBSOCKET_VERSION, UPGRADE, X_FRAME_OPTIONS};
use hyper::header::{CONNECTION, HOST, SEC_WEBSOCKET_KEY};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{http, Body, Request, Response, StatusCode};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
use once_cell::sync::Lazy;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Interest, ReadHalf, WriteHalf,
};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::select;
use tokio::sync::oneshot;
use tokio::time::error::Elapsed;
use tokio::time::timeout;

use crate::udp::{MyUdpSocket, UdpStream};
use serde::{Deserialize, Serialize};
use tokio_rustls::TlsAcceptor;
use tracing::log::debug;
use tracing::{error, field, info, instrument, trace, warn, Instrument, Span};
use url::quirks::host;
use url::Host;
use uuid::Uuid;

struct SpawnExecutor;

impl<Fut> hyper::rt::Executor<Fut> for SpawnExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    fn execute(&self, fut: Fut) {
        tokio::task::spawn(fut);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtTunnelConfig {
    pub id: String,
    pub p: L4Protocol,
    pub r: String,
    pub rp: u16,
}

static JWT_SECRET: &[u8; 15] = b"champignonfrais";
static JWT_KEY: Lazy<(Header, EncodingKey)> = Lazy::new(|| {
    (
        Header::new(Algorithm::HS256),
        EncodingKey::from_secret(JWT_SECRET),
    )
});
static JWT_DECODE: Lazy<(Validation, DecodingKey)> = Lazy::new(|| {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims = HashSet::with_capacity(0);
    (validation, DecodingKey::from_secret(JWT_SECRET))
});

pub async fn connect(
    request_id: Uuid,
    server_cfg: &WsClientConfig,
    tunnel_cfg: &LocalToRemote,
) -> anyhow::Result<WebSocket<Upgraded>> {
    let (host, port) = &server_cfg.remote_addr;
    let tcp_stream = tcp::connect(
        host,
        *port,
        &tunnel_cfg.socket_so_mark,
        server_cfg.timeout_connect,
    )
    .await?;

    let data = JwtTunnelConfig {
        id: request_id.to_string(),
        p: tunnel_cfg.protocol,
        r: tunnel_cfg.remote.0.to_string(),
        rp: tunnel_cfg.remote.1,
    };
    let (alg, secret) = JWT_KEY.deref();
    let mut req = Request::builder()
        .method("GET")
        .uri(format!(
            "/{}/events?bearer={}",
            &server_cfg.http_upgrade_path_prefix,
            jsonwebtoken::encode(alg, &data, secret).unwrap_or_default(),
        ))
        .header(HOST, server_cfg.remote_addr.0.to_string())
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "upgrade")
        .header(SEC_WEBSOCKET_KEY, fastwebsockets::handshake::generate_key())
        .header(SEC_WEBSOCKET_VERSION, "13")
        .version(hyper::Version::HTTP_11);

    for (k, v) in &server_cfg.http_headers {
        req = req.header(k.clone(), v.clone());
    }
    if let Some(auth) = &server_cfg.http_upgrade_credentials {
        req = req.header(AUTHORIZATION, auth.clone());
    }

    let req = req.body(Body::empty()).with_context(|| {
        format!(
            "failed to build HTTP request to contact the server {:?}",
            server_cfg.remote_addr
        )
    })?;
    debug!("with HTTP upgrade request {:?}", req);

    let ws_handshake = match &server_cfg.tls {
        None => fastwebsockets::handshake::client(&SpawnExecutor, req, tcp_stream).await,
        Some(tls_cfg) => {
            let tls_stream = tls::connect(server_cfg, tls_cfg, tcp_stream).await?;
            fastwebsockets::handshake::client(&SpawnExecutor, req, tls_stream).await
        }
    };

    let (ws, _) = ws_handshake.with_context(|| {
        format!(
            "failed to do websocket handshake with the server {:?}",
            server_cfg.remote_addr
        )
    })?;

    Ok(ws)
}

pub async fn connect_to_server<R, W>(
    request_id: Uuid,
    server_config: &WsClientConfig,
    remote_cfg: &LocalToRemote,
    duplex_stream: (R, W),
) -> anyhow::Result<()>
where
    R: AsyncRead + Send + 'static,
    W: AsyncWrite + Send + 'static,
{
    let mut ws = connect(request_id, server_config, remote_cfg).await?;
    ws.set_auto_apply_mask(server_config.websocket_mask_frame);

    let (ws_rx, ws_tx) = ws.split(tokio::io::split);
    let (local_rx, local_tx) = duplex_stream;
    let (close_tx, close_rx) = oneshot::channel::<()>();

    // Forward local tx to websocket tx
    let ping_frequency = server_config.websocket_ping_frequency;
    tokio::spawn(
        propagate_read(local_rx, ws_tx, close_tx, ping_frequency).instrument(Span::current()),
    );

    // Forward websocket rx to local rx
    let _ = propagate_write(local_tx, ws_rx, close_rx, server_config.timeout_connect).await;

    Ok(())
}

async fn from_query(
    server_config: &WsServerConfig,
    query: &str,
) -> anyhow::Result<(
    L4Protocol,
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
        L4Protocol::Udp { .. } => {
            let host = Host::parse(&jwt.claims.r)?;
            let cnx = Arc::new(UdpSocket::bind("[::]:0").await?);
            cnx.connect((host.to_string(), jwt.claims.rp)).await?;
            Ok((
                L4Protocol::Udp { timeout: None },
                host,
                jwt.claims.rp,
                Box::pin(MyUdpSocket::new(cnx.clone())),
                Box::pin(MyUdpSocket::new(cnx)),
            ))
        }
        L4Protocol::Tcp { .. } => {
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
            .body(Body::from("Invalid upgrade request".to_string()))
            .unwrap_or_default());
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
            let (ws_rx, mut ws_tx) = fut.await.unwrap().split(tokio::io::split);
            let (close_tx, close_rx) = oneshot::channel::<()>();
            let connect_timeout = server_config.timeout_connect;
            let ping_frequency = server_config
                .websocket_ping_frequency
                .unwrap_or(Duration::MAX);
            ws_tx.set_auto_apply_mask(server_config.websocket_mask_frame);

            tokio::task::spawn(
                propagate_write(local_tx, ws_rx, close_rx, connect_timeout)
                    .instrument(Span::current()),
            );

            let _ = propagate_read(local_rx, ws_tx, close_tx, ping_frequency).await;
        }
        .instrument(Span::current()),
    );

    Ok(response)
}

#[instrument(name="tunnel", level="info", skip_all, fields(id=field::Empty, remote=field::Empty, peer=field::Empty, forwarded_for=field::Empty))]
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

        Span::current().record("peer", peer_addr.to_string());
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
            .instrument(Span::current());

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
            .instrument(Span::current());

            tokio::spawn(fut);
        };
    }
}

async fn propagate_read(
    local_rx: impl AsyncRead,
    mut ws_tx: WebSocketWrite<WriteHalf<Upgraded>>,
    mut close_tx: oneshot::Sender<()>,
    ping_frequency: Duration,
) -> Result<(), WebSocketError> {
    let _guard = scopeguard::guard((), |_| {
        info!("Closing local tx ==> websocket tx tunnel");
    });

    let mut buffer = vec![0u8; 8 * 1024];
    pin_mut!(local_rx);
    loop {
        let read = select! {
            biased;

            read_len = local_rx.read(buffer.as_mut_slice()) => read_len,

            _ = close_tx.closed() => break,

            _ = timeout(ping_frequency, futures_util::future::pending::<()>()) => {
                debug!("sending ping to keep websocket connection alive");
                ws_tx.write_frame(Frame::new(true, OpCode::Ping, None, Payload::Borrowed(&[]))).await?;
                continue;
            }
        };

        let read_len = match read {
            Ok(read_len) if read_len > 0 => read_len,
            Ok(_) => break,
            Err(err) => {
                warn!(
                    "error while reading incoming bytes from local tx tunnel {}",
                    err
                );
                break;
            }
        };

        trace!("read {} bytes", read_len);
        match ws_tx
            .write_frame(Frame::binary(Payload::Borrowed(&buffer[..read_len])))
            .await
        {
            Ok(_) => {}
            Err(err) => {
                warn!("error while writing to websocket tx tunnel {}", err);
                break;
            }
        }

        if read_len == buffer.len() {
            buffer.resize(read_len * 2, 0);
        }
    }

    Ok(())
}

async fn propagate_write(
    local_tx: impl AsyncWrite,
    mut ws_rx: WebSocketRead<ReadHalf<Upgraded>>,
    mut close_rx: oneshot::Receiver<()>,
    timeout_connect: Duration,
) -> Result<(), WebSocketError> {
    let _guard = scopeguard::guard((), |_| {
        info!("Closing local rx <== websocket rx tunnel");
    });
    let mut x = |x: Frame<'_>| {
        debug!("frame {:?} {:?}", x.opcode, x.payload);
        futures_util::future::ready(anyhow::Ok(()))
    };

    pin_mut!(local_tx);
    loop {
        let ret = select! {
            biased;
            ret = timeout(timeout_connect, ws_rx.read_frame(&mut x)) => ret,

            _ = &mut close_rx => break,
        };

        let msg = match ret {
            Ok(Ok(msg)) => msg,
            Ok(Err(err)) => {
                error!("error while reading from websocket rx {}", err);
                break;
            }
            Err(err) => {
                trace!("frame {:?}", err);
                // TODO: Check that the connection is not closed (no easy method to know if a tx is closed ...)
                continue;
            }
        };

        trace!("frame {:?} {:?}", msg.opcode, msg.payload);
        let ret = match msg.opcode {
            OpCode::Continuation | OpCode::Text | OpCode::Binary => {
                local_tx.write_all(msg.payload.as_ref()).await
            }
            OpCode::Close => break,
            OpCode::Ping => Ok(()),
            OpCode::Pong => Ok(()),
        };

        match ret {
            Ok(_) => {}
            Err(err) => {
                error!("error while writing bytes to local for rx tunnel {}", err);
                break;
            }
        }
    }

    Ok(())
}
