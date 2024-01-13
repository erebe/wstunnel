use crate::tunnel::transport::{TunnelRead, TunnelWrite};
use crate::tunnel::{tunnel_to_jwt_token, RemoteAddr, JWT_HEADER_PREFIX};
use crate::WsClientConfig;
use anyhow::{anyhow, Context};
use bytes::Bytes;
use fastwebsockets::{Frame, OpCode, Payload, WebSocketRead, WebSocketWrite};
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION, UPGRADE};
use hyper::header::{CONNECTION, HOST, SEC_WEBSOCKET_KEY};
use hyper::upgrade::Upgraded;
use hyper::{Request, Response};
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use log::debug;
use std::ops::DerefMut;
use tokio::io::{AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tracing::trace;
use uuid::Uuid;

impl TunnelWrite for WebSocketWrite<WriteHalf<TokioIo<Upgraded>>> {
    async fn write(&mut self, buf: &[u8]) -> anyhow::Result<()> {
        self.write_frame(Frame::binary(Payload::Borrowed(buf)))
            .await
            .with_context(|| "cannot send ws frame")
    }

    async fn ping(&mut self) -> anyhow::Result<()> {
        self.write_frame(Frame::new(true, OpCode::Ping, None, Payload::BorrowedMut(&mut [])))
            .await
            .with_context(|| "cannot send ws ping")
    }

    async fn close(&mut self) -> anyhow::Result<()> {
        self.write_frame(Frame::close(1000, &[]))
            .await
            .with_context(|| "cannot close websocket cnx")
    }
}

fn frame_reader(x: Frame<'_>) -> futures_util::future::Ready<anyhow::Result<()>> {
    debug!("frame {:?} {:?}", x.opcode, x.payload);
    futures_util::future::ready(anyhow::Ok(()))
}
impl TunnelRead for WebSocketRead<ReadHalf<TokioIo<Upgraded>>> {
    async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin + Send) -> anyhow::Result<()> {
        loop {
            let msg = self
                .read_frame(&mut frame_reader)
                .await
                .with_context(|| "error while reading from websocket")?;

            trace!("receive ws frame {:?} {:?}", msg.opcode, msg.payload);
            match msg.opcode {
                OpCode::Continuation | OpCode::Text | OpCode::Binary => {
                    writer.write_all(msg.payload.as_ref()).await.with_context(|| "")?;
                    return Ok(());
                }
                OpCode::Close => return Err(anyhow!("websocket close")),
                OpCode::Ping => continue,
                OpCode::Pong => continue,
            };
        }
    }
}

pub async fn connect(
    request_id: Uuid,
    client_cfg: &WsClientConfig,
    dest_addr: &RemoteAddr,
) -> anyhow::Result<((impl TunnelRead, impl TunnelWrite), Response<Incoming>)> {
    let mut pooled_cnx = match client_cfg.cnx_pool().get().await {
        Ok(cnx) => Ok(cnx),
        Err(err) => Err(anyhow!("failed to get a connection to the server from the pool: {err:?}")),
    }?;

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
            format!("v1, {}{}", JWT_HEADER_PREFIX, tunnel_to_jwt_token(request_id, dest_addr)),
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
    let (mut ws, response) = fastwebsockets::handshake::client(&TokioExecutor::new(), req, transport)
        .await
        .with_context(|| format!("failed to do websocket handshake with the server {:?}", client_cfg.remote_addr))?;

    ws.set_auto_apply_mask(client_cfg.websocket_mask_frame);

    Ok((ws.split(tokio::io::split), response))
}
