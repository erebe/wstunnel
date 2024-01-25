use crate::tunnel::transport::{headers_from_file, TunnelRead, TunnelWrite, MAX_PACKET_LENGTH};
use crate::tunnel::{tunnel_to_jwt_token, RemoteAddr, JWT_HEADER_PREFIX};
use crate::WsClientConfig;
use anyhow::{anyhow, Context};
use bytes::{Bytes, BytesMut};
use fastwebsockets::{Frame, OpCode, Payload, WebSocketRead, WebSocketWrite};
use http_body_util::Empty;
use hyper::header::{AUTHORIZATION, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION, UPGRADE};
use hyper::header::{CONNECTION, HOST, SEC_WEBSOCKET_KEY};
use hyper::http::response::Parts;
use hyper::upgrade::Upgraded;
use hyper::Request;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use log::debug;
use std::io;
use std::io::ErrorKind;
use std::ops::DerefMut;
use tokio::io::{AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tracing::trace;
use uuid::Uuid;

pub struct WebsocketTunnelWrite {
    inner: WebSocketWrite<WriteHalf<TokioIo<Upgraded>>>,
    buf: BytesMut,
}

impl WebsocketTunnelWrite {
    pub fn new(ws: WebSocketWrite<WriteHalf<TokioIo<Upgraded>>>) -> Self {
        Self {
            inner: ws,
            buf: BytesMut::with_capacity(MAX_PACKET_LENGTH),
        }
    }
}

impl TunnelWrite for WebsocketTunnelWrite {
    fn buf_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }

    async fn write(&mut self) -> Result<(), io::Error> {
        let read_len = self.buf.len();
        let buf = &mut self.buf;

        let ret = self
            .inner
            .write_frame(Frame::binary(Payload::BorrowedMut(&mut buf[..read_len])))
            .await;

        if let Err(err) = ret {
            return Err(io::Error::new(ErrorKind::ConnectionAborted, err));
        }

        // If the buffer has been completely filled with previous read, Grows it !
        // For the buffer to not be a bottleneck when the TCP window scale
        // For udp, the buffer will never grows.
        buf.clear();
        if buf.capacity() == read_len {
            let new_size = buf.capacity() + (buf.capacity() / 4); // grow buffer by 1.25 %
            buf.reserve(new_size);
            trace!(
                "Buffer {} Mb {} {} {}",
                buf.capacity() as f64 / 1024.0 / 1024.0,
                new_size,
                buf.len(),
                buf.capacity()
            )
        }

        Ok(())
    }

    async fn ping(&mut self) -> Result<(), io::Error> {
        if let Err(err) = self
            .inner
            .write_frame(Frame::new(true, OpCode::Ping, None, Payload::BorrowedMut(&mut [])))
            .await
        {
            return Err(io::Error::new(ErrorKind::BrokenPipe, err));
        }

        Ok(())
    }

    async fn close(&mut self) -> Result<(), io::Error> {
        if let Err(err) = self.inner.write_frame(Frame::close(1000, &[])).await {
            return Err(io::Error::new(ErrorKind::BrokenPipe, err));
        }

        Ok(())
    }
}

pub struct WebsocketTunnelRead {
    inner: WebSocketRead<ReadHalf<TokioIo<Upgraded>>>,
}

impl WebsocketTunnelRead {
    pub fn new(ws: WebSocketRead<ReadHalf<TokioIo<Upgraded>>>) -> Self {
        Self { inner: ws }
    }
}

fn frame_reader(_: Frame<'_>) -> futures_util::future::Ready<anyhow::Result<()>> {
    //error!("frame {:?} {:?}", x.opcode, x.payload);
    futures_util::future::ready(anyhow::Ok(()))
}

impl TunnelRead for WebsocketTunnelRead {
    async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
        loop {
            let msg = match self.inner.read_frame(&mut frame_reader).await {
                Ok(msg) => msg,
                Err(err) => return Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
            };

            trace!("receive ws frame {:?} {:?}", msg.opcode, msg.payload);
            match msg.opcode {
                OpCode::Continuation | OpCode::Text | OpCode::Binary => {
                    return match writer.write_all(msg.payload.as_ref()).await {
                        Ok(_) => Ok(()),
                        Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
                    }
                }
                OpCode::Close => return Err(io::Error::new(ErrorKind::NotConnected, "websocket close")),
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
) -> anyhow::Result<(WebsocketTunnelRead, WebsocketTunnelWrite, Parts)> {
    let mut pooled_cnx = match client_cfg.cnx_pool().get().await {
        Ok(cnx) => Ok(cnx),
        Err(err) => Err(anyhow!("failed to get a connection to the server from the pool: {err:?}")),
    }?;

    let mut req = Request::builder()
        .method("GET")
        .uri(format!("/{}/events", &client_cfg.http_upgrade_path_prefix))
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

    let headers = req.headers_mut().unwrap();
    for (k, v) in &client_cfg.http_headers {
        let _ = headers.remove(k);
        headers.append(k, v.clone());
    }

    if let Some(auth) = &client_cfg.http_upgrade_credentials {
        let _ = headers.remove(AUTHORIZATION);
        headers.append(AUTHORIZATION, auth.clone());
    }

    if let Some(headers_file_path) = &client_cfg.http_headers_file {
        for (k, v) in headers_from_file(headers_file_path) {
            let _ = headers.remove(&k);
            headers.append(k, v);
        }
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

    let (ws_rx, ws_tx) = ws.split(tokio::io::split);

    Ok((
        WebsocketTunnelRead::new(ws_rx),
        WebsocketTunnelWrite::new(ws_tx),
        response.into_parts().0,
    ))
}
