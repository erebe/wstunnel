use super::{JwtTunnelConfig, JWT_KEY};
use crate::{LocalToRemote, WsClientConfig};
use anyhow::{anyhow, Context};

use fastwebsockets::WebSocket;
use futures_util::pin_mut;
use hyper::header::{AUTHORIZATION, SEC_WEBSOCKET_VERSION, UPGRADE};
use hyper::header::{CONNECTION, HOST, SEC_WEBSOCKET_KEY};
use hyper::upgrade::Upgraded;
use hyper::{Body, Request};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tokio_stream::{Stream, StreamExt};
use tracing::log::debug;
use tracing::{error, span, Instrument, Level, Span};
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

fn tunnel_to_jwt_token(request_id: Uuid, tunnel: &LocalToRemote) -> String {
    let cfg = JwtTunnelConfig::new(request_id, tunnel);
    let (alg, secret) = JWT_KEY.deref();
    jsonwebtoken::encode(alg, &cfg, secret).unwrap_or_default()
}

pub async fn connect(
    request_id: Uuid,
    client_cfg: &WsClientConfig,
    tunnel_cfg: &LocalToRemote,
) -> anyhow::Result<WebSocket<Upgraded>> {
    let mut pooled_cnx = match client_cfg.cnx_pool().get().await {
        Ok(tcp_stream) => tcp_stream,
        Err(err) => Err(anyhow!(
            "failed to get a connection to the server from the pool: {err:?}"
        ))?,
    };

    let mut req = Request::builder()
        .method("GET")
        .uri(format!(
            "/{}/events?bearer={}",
            &client_cfg.http_upgrade_path_prefix,
            tunnel_to_jwt_token(request_id, tunnel_cfg)
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
    let transport = pooled_cnx.deref_mut().take().unwrap();
    let (ws, _) = fastwebsockets::handshake::client(&SpawnExecutor, req, transport)
        .await
        .with_context(|| {
            format!(
                "failed to do websocket handshake with the server {:?}",
                client_cfg.remote_addr
            )
        })?;

    Ok(ws)
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
