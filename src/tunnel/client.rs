use super::{to_host_port, JwtTunnelConfig, JWT_HEADER_PREFIX, JWT_KEY};
use crate::{LocalToRemote, WsClientConfig};
use anyhow::{anyhow, Context};

use base64::Engine;
use bytes::Bytes;
use fastwebsockets::WebSocket;
use futures_util::pin_mut;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, COOKIE, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION, UPGRADE};
use hyper::header::{CONNECTION, HOST, SEC_WEBSOCKET_KEY};
use hyper::upgrade::Upgraded;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tokio_stream::{Stream, StreamExt};
use tracing::log::debug;
use tracing::{error, span, Instrument, Level, Span};
use url::{Host, Url};
use uuid::Uuid;

fn tunnel_to_jwt_token(request_id: Uuid, tunnel: &LocalToRemote) -> String {
    let cfg = JwtTunnelConfig::new(request_id, tunnel);
    let (alg, secret) = JWT_KEY.deref();
    jsonwebtoken::encode(alg, &cfg, secret).unwrap_or_default()
}

pub async fn connect(
    request_id: Uuid,
    client_cfg: &WsClientConfig,
    tunnel_cfg: &LocalToRemote,
) -> anyhow::Result<(WebSocket<TokioIo<Upgraded>>, Response<Incoming>)> {
    let mut pooled_cnx = match client_cfg.cnx_pool().get().await {
        Ok(tcp_stream) => tcp_stream,
        Err(err) => Err(anyhow!("failed to get a connection to the server from the pool: {err:?}"))?,
    };

    let mut req = Request::builder()
        .method("GET")
        .uri(format!("/{}/events", &client_cfg.http_upgrade_path_prefix,))
        .header(HOST, &client_cfg.http_header_host)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "upgrade")
        .header(SEC_WEBSOCKET_KEY, fastwebsockets::handshake::generate_key())
        .header(SEC_WEBSOCKET_VERSION, "13")
        .header(
            SEC_WEBSOCKET_PROTOCOL,
            format!("v1, {}{}", JWT_HEADER_PREFIX, tunnel_to_jwt_token(request_id, tunnel_cfg)),
        )
        .version(hyper::Version::HTTP_11);

    for (k, v) in &client_cfg.http_headers {
        req = req.header(k, v);
    }
    if let Some(auth) = &client_cfg.http_upgrade_credentials {
        req = req.header(AUTHORIZATION, auth);
    }

    let req = req.body(Empty::<Bytes>::new()).with_context(|| {
        format!(
            "failed to build HTTP request to contact the server {:?}",
            client_cfg.remote_addr
        )
    })?;
    debug!("with HTTP upgrade request {:?}", req);
    let transport = pooled_cnx.deref_mut().take().unwrap();
    let (ws, response) = fastwebsockets::handshake::client(&TokioExecutor::new(), req, transport)
        .await
        .with_context(|| format!("failed to do websocket handshake with the server {:?}", client_cfg.remote_addr))?;

    Ok((ws, response))
}

async fn connect_to_server<R, W>(
    request_id: Uuid,
    client_cfg: &WsClientConfig,
    remote_cfg: &LocalToRemote,
    duplex_stream: (R, W),
) -> anyhow::Result<()>
where
    R: AsyncRead + Send + 'static,
    W: AsyncWrite + Send + 'static,
{
    let (mut ws, _) = connect(request_id, client_cfg, remote_cfg).await?;
    ws.set_auto_apply_mask(client_cfg.websocket_mask_frame);

    let (ws_rx, ws_tx) = ws.split(tokio::io::split);
    let (local_rx, local_tx) = duplex_stream;
    let (close_tx, close_rx) = oneshot::channel::<()>();

    // Forward local tx to websocket tx
    let ping_frequency = client_cfg.websocket_ping_frequency;
    tokio::spawn(
        super::io::propagate_read(local_rx, ws_tx, close_tx, Some(ping_frequency)).instrument(Span::current()),
    );

    // Forward websocket rx to local rx
    let _ = super::io::propagate_write(local_tx, ws_rx, close_rx).await;

    Ok(())
}

pub async fn run_tunnel<T, R, W>(
    client_config: Arc<WsClientConfig>,
    tunnel_cfg: LocalToRemote,
    incoming_cnx: T,
) -> anyhow::Result<()>
where
    T: Stream<Item = anyhow::Result<((R, W), (Host, u16))>>,
    R: AsyncRead + Send + 'static,
    W: AsyncWrite + Send + 'static,
{
    pin_mut!(incoming_cnx);
    while let Some(Ok((cnx_stream, remote_dest))) = incoming_cnx.next().await {
        let request_id = Uuid::now_v7();
        let span = span!(
            Level::INFO,
            "tunnel",
            id = request_id.to_string(),
            remote = format!("{}:{}", remote_dest.0, remote_dest.1)
        );
        let mut tunnel_cfg = tunnel_cfg.clone();
        tunnel_cfg.remote = remote_dest;
        let client_config = client_config.clone();

        let tunnel = async move {
            let _ = connect_to_server(request_id, &client_config, &tunnel_cfg, cnx_stream)
                .await
                .map_err(|err| error!("{:?}", err));
        }
        .instrument(span);

        tokio::spawn(tunnel);
    }

    Ok(())
}

pub async fn run_reverse_tunnel<F, Fut, T>(
    client_config: Arc<WsClientConfig>,
    mut tunnel_cfg: LocalToRemote,
    connect_to_dest: F,
) -> anyhow::Result<()>
where
    F: Fn((Host, u16)) -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
    T: AsyncRead + AsyncWrite + Send + 'static,
{
    // Invert local with remote
    let remote_ori = tunnel_cfg.remote;
    tunnel_cfg.remote = to_host_port(tunnel_cfg.local);

    loop {
        let client_config = client_config.clone();
        let request_id = Uuid::now_v7();
        let span = span!(
            Level::INFO,
            "tunnel",
            id = request_id.to_string(),
            remote = format!("{}:{}", tunnel_cfg.remote.0, tunnel_cfg.remote.1)
        );
        let _span = span.enter();

        // Correctly configure tunnel cfg
        let (mut ws, response) = connect(request_id, &client_config, &tunnel_cfg)
            .instrument(span.clone())
            .await?;
        ws.set_auto_apply_mask(client_config.websocket_mask_frame);

        // Connect to endpoint
        let remote = response
            .headers()
            .get(COOKIE)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| base64::engine::general_purpose::STANDARD.decode(h).ok())
            .and_then(|h| Url::parse(&String::from_utf8_lossy(&h)).ok())
            .and_then(|url| match (url.host(), url.port_or_known_default()) {
                (Some(h), Some(p)) => Some((h.to_owned(), p)),
                _ => None,
            })
            .unwrap_or(remote_ori.clone());

        let stream = match connect_to_dest(remote.clone()).instrument(span.clone()).await {
            Ok(s) => s,
            Err(err) => {
                error!("Cannot connect to {remote:?}: {err:?}");
                continue;
            }
        };

        let (local_rx, local_tx) = tokio::io::split(stream);
        let (ws_rx, ws_tx) = ws.split(tokio::io::split);
        let (close_tx, close_rx) = oneshot::channel::<()>();

        let tunnel = async move {
            let ping_frequency = client_config.websocket_ping_frequency;
            tokio::spawn(
                super::io::propagate_read(local_rx, ws_tx, close_tx, Some(ping_frequency)).instrument(Span::current()),
            );

            // Forward websocket rx to local rx
            let _ = super::io::propagate_write(local_tx, ws_rx, close_rx).await;
        }
        .instrument(span.clone());
        tokio::spawn(tunnel);
    }
}
