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
use std::io;
use std::io::ErrorKind;
use std::ops::DerefMut;
use tokio::io::{AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{debug, trace};
use uuid::Uuid;

// Messages that can be passed from the reader half to the writer half
#[derive(Debug)]
pub enum WebSocketTunnelMessage {
    Ping(u8),
    Pong(u8),
    Close,
}

#[derive(Debug)]
pub struct PingState {
    ping_seq: u8,
    pong_seq: u8,
    max_diff: u8,
}

impl PingState {
    pub const fn new() -> Self {
        Self {
            ping_seq: 0,
            pong_seq: 0,
            // TODO: make this configurable
            max_diff: 3,
        }
    }

    fn is_ok(&self) -> bool {
        self.ping_seq - self.pong_seq <= self.max_diff
    }

    fn ping_inc(&mut self) {
        match self.ping_seq.checked_add(1) {
            Some(ping) => self.ping_seq = ping,
            // We reached the end of the range, so we will just start over from zero.
            None => self.reset(),
        }
    }

    fn set_pong_seq(&mut self, seq: u8) {
        if seq > self.pong_seq && seq <= self.ping_seq {
            self.pong_seq = seq;
        }

        // Try to reset once we reached half the range, since we will potentially
        // miss some pongs if we reach the actual end of the range where we need
        // to forcefully reset.
        if self.ping_seq == self.pong_seq && self.ping_seq > u8::MAX / 2 {
            self.reset();
        }
    }

    fn reset(&mut self) {
        self.ping_seq = 0;
        self.pong_seq = 0;
    }
}

pub struct WebsocketTunnelWrite {
    inner: WebSocketWrite<WriteHalf<TokioIo<Upgraded>>>,
    buf: BytesMut,
    ping_state: PingState,
    receive_from_reader: Receiver<WebSocketTunnelMessage>,
}

impl WebsocketTunnelWrite {
    pub fn new(
        ws: WebSocketWrite<WriteHalf<TokioIo<Upgraded>>>,
        receive_from_reader: Receiver<WebSocketTunnelMessage>,
    ) -> Self {
        Self {
            inner: ws,
            buf: BytesMut::with_capacity(MAX_PACKET_LENGTH),
            ping_state: PingState::new(),
            receive_from_reader,
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
        // For the buffer to not be a bottleneck when the TCP window scale.
        // We clamp it to 32Mb to avoid unbounded growth and as websocket max frame size is 64Mb by default
        // For udp, the buffer will never grow.
        const _32_MB: usize = 32 * 1024 * 1024;
        buf.clear();
        if buf.capacity() == read_len && buf.capacity() < _32_MB {
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
        debug!("{:?}", self.ping_state);
        if !self.ping_state.is_ok() {
            return Err(io::Error::new(ErrorKind::BrokenPipe, "No pong received"));
        }
        self.ping_state.ping_inc();
        debug!("Sending ping({})", self.ping_state.ping_seq);
        if let Err(err) = self
            .inner
            .write_frame(Frame::new(
                true,
                OpCode::Ping,
                None,
                Payload::BorrowedMut(&mut [self.ping_state.ping_seq]),
            ))
            .await
        {
            return Err(io::Error::new(ErrorKind::BrokenPipe, err));
        }

        Ok(())
    }

    async fn handle_message(&mut self) -> Result<(), io::Error> {
        match self.receive_from_reader.try_recv() {
            Ok(WebSocketTunnelMessage::Pong(seq)) => {
                self.ping_state.set_pong_seq(seq);
                Ok(())
            }
            Ok(WebSocketTunnelMessage::Ping(seq)) => {
                debug!("Sending pong({})", seq);
                self.inner
                    .write_frame(Frame::pong(Payload::BorrowedMut(&mut [seq])))
                    .await
                    .map_err(|err| io::Error::new(ErrorKind::BrokenPipe, err))
            }
            Ok(WebSocketTunnelMessage::Close) => {
                debug!("Sending close confirmation");
                self.inner
                    .write_frame(Frame::close(1000, &[]))
                    .await
                    .map_err(|err| io::Error::new(ErrorKind::BrokenPipe, err))
            }
            Err(TryRecvError::Empty) => Ok(()),
            Err(TryRecvError::Disconnected) => Err(io::Error::new(ErrorKind::BrokenPipe, "channel closed")),
        }
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
    send_to_writer: Sender<WebSocketTunnelMessage>,
}

impl WebsocketTunnelRead {
    pub const fn new(
        inner: WebSocketRead<ReadHalf<TokioIo<Upgraded>>>,
        send_to_writer: Sender<WebSocketTunnelMessage>,
    ) -> Self {
        Self { inner, send_to_writer }
    }
}

// Since we disable auto_pong and auto_close, we should never end up here.
// So let's panic so that we don't accidentally end up calling this.
fn frame_reader(_: Frame<'_>) -> futures_util::future::Ready<anyhow::Result<()>> {
    unimplemented!()
}

impl TunnelRead for WebsocketTunnelRead {
    async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
        let msg = match self.inner.read_frame(&mut frame_reader).await {
            Ok(msg) => msg,
            Err(err) => return Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
        };

        trace!("receive ws frame {:?} {:?}", msg.opcode, msg.payload);
        match msg.opcode {
            OpCode::Continuation | OpCode::Text | OpCode::Binary => {
                match writer.write_all(msg.payload.as_ref()).await {
                    Ok(_) => Ok(()),
                    Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
                }
            }
            OpCode::Close => {
                // Sending back the close confirmation is best effort, if we fail, we just close
                // the connection anyway
                _ = self.send_to_writer.send(WebSocketTunnelMessage::Close).await;
                Err(io::Error::new(ErrorKind::NotConnected, "websocket close"))
            }
            OpCode::Ping => {
                let seq = msg.payload[0];
                debug!("Received ping({})", seq);
                self.send_to_writer
                    .send(WebSocketTunnelMessage::Ping(seq))
                    .await
                    .map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err))
            }
            OpCode::Pong => {
                let seq = msg.payload[0];
                debug!("Received pong({})", seq);
                self.send_to_writer
                    .send(WebSocketTunnelMessage::Pong(seq))
                    .await
                    .map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err))
            }
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
        let (host, headers_file) = headers_from_file(headers_file_path);
        for (k, v) in headers_file {
            let _ = headers.remove(&k);
            headers.append(k, v);
        }
        if let Some((host, val)) = host {
            let _ = headers.remove(&host);
            headers.append(host, val);
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
    ws.set_auto_pong(false);
    ws.set_auto_close(false);

    let (ws_rx, ws_tx) = ws.split(tokio::io::split);
    let (ch_tx, ch_rx) = mpsc::channel::<WebSocketTunnelMessage>(32);

    Ok((
        WebsocketTunnelRead::new(ws_rx, ch_tx),
        WebsocketTunnelWrite::new(ws_tx, ch_rx),
        response.into_parts().0,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_state() {
        let mut ping_state = PingState::new();

        // An initial ping state has zeroes and is OK
        assert!(ping_state.is_ok());
        assert_eq!(ping_state.ping_seq, 0);
        assert_eq!(ping_state.pong_seq, 0);

        // Send 3 pings, the ping sequence increases, pong sequence doesn't
        for it in 1..=3 {
            ping_state.ping_inc();
            assert_eq!(ping_state.ping_seq, it);
            assert_eq!(ping_state.pong_seq, 0);
            assert!(ping_state.is_ok());
        }

        // After the fourth ping with no pong received, the ping state is not OK
        ping_state.ping_inc();
        assert_eq!(ping_state.ping_seq, 4);
        assert_eq!(ping_state.pong_seq, 0);
        assert!(!ping_state.is_ok());

        // We received two pongs, the pin state is OK again
        ping_state.set_pong_seq(1);
        assert!(ping_state.is_ok());
        ping_state.set_pong_seq(4);
        assert!(ping_state.is_ok());

        // Advance the ping state beyond the middle of the u8 range,
        // it won't wrap since we didn't receive pongs
        for _ in 5..=130 {
            ping_state.ping_inc();
        }
        assert_eq!(ping_state.ping_seq, 130);
        assert_eq!(ping_state.pong_seq, 4);
        assert!(!ping_state.is_ok());

        // As soon as we do receive a pong, we wrap the sequence numbers around
        ping_state.set_pong_seq(130);
        assert_eq!(ping_state.ping_seq, 0);
        assert_eq!(ping_state.pong_seq, 0);
        assert!(ping_state.is_ok());

        // If we receive pongs for every ping, we wrap at 128, half of the u8 range
        for it in 1..=128 {
            ping_state.ping_inc();
            ping_state.set_pong_seq(it)
        }
        assert_eq!(ping_state.ping_seq, 0);
        assert_eq!(ping_state.pong_seq, 0);
        assert!(ping_state.is_ok());
    }
}
