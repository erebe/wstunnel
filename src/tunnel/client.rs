use super::{JwtTunnelConfig, MaybeTlsStream, JWT_KEY};
use crate::{LocalProtocol, LocalToRemote, WsClientConfig};
use anyhow::{anyhow, Context};

use fastwebsockets::WebSocket;
use hyper::header::{AUTHORIZATION, SEC_WEBSOCKET_VERSION, UPGRADE};
use hyper::header::{CONNECTION, HOST, SEC_WEBSOCKET_KEY};
use hyper::upgrade::Upgraded;
use hyper::{Body, Request};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tracing::log::debug;
use tracing::{Instrument, Span};
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

pub async fn connect(
    request_id: Uuid,
    client_cfg: &WsClientConfig,
    tunnel_cfg: &LocalToRemote,
) -> anyhow::Result<WebSocket<Upgraded>> {
    let mut tcp_stream = match client_cfg.cnx_pool().get().await {
        Ok(tcp_stream) => tcp_stream,
        Err(err) => Err(anyhow!(
            "failed to get a connection to the server from the pool: {err:?}"
        ))?,
    };

    let data = JwtTunnelConfig {
        id: request_id.to_string(),
        p: match tunnel_cfg.local_protocol {
            LocalProtocol::Tcp => LocalProtocol::Tcp,
            LocalProtocol::Udp { .. } => tunnel_cfg.local_protocol,
            LocalProtocol::Stdio => LocalProtocol::Tcp,
            LocalProtocol::Socks5 => LocalProtocol::Tcp,
        },
        r: tunnel_cfg.remote.0.to_string(),
        rp: tunnel_cfg.remote.1,
    };
    let (alg, secret) = JWT_KEY.deref();
    let mut req = Request::builder()
        .method("GET")
        .uri(format!(
            "/{}/events?bearer={}",
            &client_cfg.http_upgrade_path_prefix,
            jsonwebtoken::encode(alg, &data, secret).unwrap_or_default(),
        ))
        .header(HOST, &client_cfg.http_header_host)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "upgrade")
        .header(SEC_WEBSOCKET_KEY, fastwebsockets::handshake::generate_key())
        .header(SEC_WEBSOCKET_VERSION, "13")
        .version(hyper::Version::HTTP_11);

    for (k, v) in &client_cfg.http_headers {
        req = req.header(k, v);
    }
    if let Some(auth) = &client_cfg.http_upgrade_credentials {
        req = req.header(AUTHORIZATION, auth);
    }

    let req = req.body(Body::empty()).with_context(|| {
        format!(
            "failed to build HTTP request to contact the server {:?}",
            client_cfg.remote_addr
        )
    })?;
    debug!("with HTTP upgrade request {:?}", req);
    let ws_handshake = match tcp_stream.deref_mut() {
        MaybeTlsStream::Plain(cnx) => {
            fastwebsockets::handshake::client(&SpawnExecutor, req, cnx.take().unwrap()).await
        }
        MaybeTlsStream::Tls(cnx) => {
            fastwebsockets::handshake::client(&SpawnExecutor, req, cnx.take().unwrap()).await
        }
    };

    let (ws, _) = ws_handshake.with_context(|| {
        format!(
            "failed to do websocket handshake with the server {:?}",
            client_cfg.remote_addr
        )
    })?;

    Ok(ws)
}

pub async fn connect_to_server<R, W>(
    request_id: Uuid,
    client_cfg: &WsClientConfig,
    remote_cfg: &LocalToRemote,
    duplex_stream: (R, W),
) -> anyhow::Result<()>
where
    R: AsyncRead + Send + 'static,
    W: AsyncWrite + Send + 'static,
{
    let mut ws = connect(request_id, client_cfg, remote_cfg).await?;
    ws.set_auto_apply_mask(client_cfg.websocket_mask_frame);

    let (ws_rx, ws_tx) = ws.split(tokio::io::split);
    let (local_rx, local_tx) = duplex_stream;
    let (close_tx, close_rx) = oneshot::channel::<()>();

    // Forward local tx to websocket tx
    let ping_frequency = client_cfg.websocket_ping_frequency;
    tokio::spawn(
        super::io::propagate_read(local_rx, ws_tx, close_tx, ping_frequency)
            .instrument(Span::current()),
    );

    // Forward websocket rx to local rx
    let _ = super::io::propagate_write(local_tx, ws_rx, close_rx).await;

    Ok(())
}
