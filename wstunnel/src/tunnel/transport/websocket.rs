use super::io::{MAX_PACKET_LENGTH, TransportRead, TransportWrite};
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::Client;
use crate::tunnel::client::connection_pool::{L4ReadHalf, L4Stream, L4WriteHalf};
use crate::tunnel::transport::headers_from_file;
use crate::tunnel::transport::jwt::{JWT_HEADER_PREFIX, tunnel_to_jwt_token};
use anyhow::{Context, anyhow};
use bytes::{Bytes, BytesMut};
use fastwebsockets::{CloseCode, Frame, OpCode, Payload, Role, WebSocket, WebSocketRead, WebSocketWrite};
use http_body_util::Empty;
use hyper::Request;
use hyper::header::{AUTHORIZATION, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION, UPGRADE};
use hyper::header::{CONNECTION, HOST, SEC_WEBSOCKET_KEY};
use hyper::http::response::Parts;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use log::debug;
use std::io;
use std::io::ErrorKind;
use std::ops::DerefMut;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_rustls::server::TlsStream;
use tracing::trace;
use uuid::Uuid;

pub struct WebsocketTransportWrite {
    inner: WebSocketWrite<L4WriteHalf>,
    buf: BytesMut,
    pending_operations: Receiver<Frame<'static>>,
    pending_ops_notify: Arc<Notify>,
    in_flight_ping: Arc<AtomicUsize>,
}

impl WebsocketTransportWrite {
    pub fn new(
        ws: WebSocketWrite<L4WriteHalf>,
        (pending_operations, notify): (Receiver<Frame<'static>>, Arc<Notify>),
        in_flight_ping: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            inner: ws,
            buf: BytesMut::with_capacity(MAX_PACKET_LENGTH),
            pending_operations,
            pending_ops_notify: notify,
            in_flight_ping,
        }
    }
}

impl TransportWrite for WebsocketTransportWrite {
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

        // It is needed to call poll_flush to ensure that the data is written to the underlying stream.
        // In case of a TLS stream, it may still be buffered in the TLS layer if not flushed.
        // https://docs.rs/tokio-rustls/latest/tokio_rustls/#why-do-i-need-to-call-poll_flush
        if let Err(err) = self.inner.flush().await {
            return Err(io::Error::new(ErrorKind::ConnectionAborted, err));
        }

        // If the buffer has been completely filled with previous read, Grows it !
        // For the buffer to not be a bottleneck when the TCP window scale.
        // We clamp it to 128KB to avoid unbounded growth and as websocket max frame size is 64Mb by default
        // For udp, the buffer will never grow.
        const _128_KB: usize = 128 * 1024;
        buf.clear();
        if buf.capacity() == read_len && buf.capacity() < _128_KB {
            let new_size = (buf.capacity() + (buf.capacity() / 4)).min(_128_KB); // grow buffer by 1.25 %
            buf.reserve(new_size);
            trace!(
                "Buffer {} KB {} {} {}",
                buf.capacity() as f64 / 1024.0,
                new_size,
                buf.len(),
                buf.capacity()
            )
        }

        Ok(())
    }

    async fn ping(&mut self) -> Result<(), io::Error> {
        if self.in_flight_ping.fetch_add(1, Relaxed) >= 3 {
            return Err(io::Error::new(
                ErrorKind::ConnectionAborted,
                "too many in flight/un-answered pings",
            ));
        }

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

    fn pending_operations_notify(&mut self) -> Arc<Notify> {
        self.pending_ops_notify.clone()
    }

    async fn handle_pending_operations(&mut self) -> Result<(), io::Error> {
        while let Ok(frame) = self.pending_operations.try_recv() {
            debug!("received frame {:?}", frame.opcode);
            match frame.opcode {
                OpCode::Close => {
                    if self.inner.write_frame(frame).await.is_err() {
                        return Err(io::Error::new(ErrorKind::ConnectionAborted, "cannot send close frame"));
                    }
                }
                OpCode::Ping => {
                    debug!("sending pong frame");
                    if self.inner.write_frame(Frame::pong(frame.payload)).await.is_err() {
                        return Err(io::Error::new(ErrorKind::ConnectionAborted, "cannot send pong frame"));
                    }
                }
                OpCode::Pong => {
                    debug!("received pong frame");
                    self.in_flight_ping.store(0, Relaxed);
                }
                OpCode::Continuation | OpCode::Text | OpCode::Binary => unreachable!(),
            }
        }

        Ok(())
    }
}

pub struct WebsocketTransportRead {
    inner: WebSocketRead<L4ReadHalf>,
    pending_operations: Sender<Frame<'static>>,
    notify_pending_ops: Arc<Notify>,
    in_flight_ping: Arc<AtomicUsize>,
}

impl WebsocketTransportRead {
    pub fn new(
        ws: WebSocketRead<L4ReadHalf>,
        in_flight_ping: Arc<AtomicUsize>,
    ) -> (Self, (Receiver<Frame<'static>>, Arc<Notify>)) {
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let notify = Arc::new(Notify::new());
        (
            Self {
                inner: ws,
                pending_operations: tx,
                notify_pending_ops: notify.clone(),
                in_flight_ping,
            },
            (rx, notify),
        )
    }
}

fn frame_reader(_: Frame<'_>) -> futures_util::future::Ready<anyhow::Result<()>> {
    //error!("frame {:?} {:?}", x.opcode, x.payload);
    futures_util::future::ready(anyhow::Ok(()))
}

impl TransportRead for WebsocketTransportRead {
    async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
        loop {
            let msg = match self.inner.read_frame(&mut frame_reader).await {
                Ok(msg) => msg,
                Err(err) => return Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
            };

            trace!("receive ws frame {:?} {:?}", msg.opcode, msg.payload);
            self.in_flight_ping.store(0, Relaxed);
            match msg.opcode {
                OpCode::Continuation | OpCode::Text | OpCode::Binary => {
                    return match writer.write_all(msg.payload.as_ref()).await {
                        Ok(_) => Ok(()),
                        Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
                    };
                }
                OpCode::Close => {
                    let _ = self
                        .pending_operations
                        .send(Frame::close(CloseCode::Normal.into(), &[]))
                        .await;
                    self.notify_pending_ops.notify_waiters();
                    return Err(io::Error::new(ErrorKind::NotConnected, "websocket close"));
                }
                OpCode::Ping => {
                    match self.pending_operations.try_send(Frame::new(
                        true,
                        msg.opcode,
                        None,
                        Payload::Owned(msg.payload.to_owned()),
                    )) {
                        Ok(()) => {
                            self.notify_pending_ops.notify_waiters();
                        }
                        Err(TrySendError::Full(_)) => {
                            // Queue full due to TX write congestion; drop pong to avoid blocking RX
                        }
                        Err(TrySendError::Closed(_)) => {
                            return Err(io::Error::new(ErrorKind::ConnectionAborted, "cannot send ping"));
                        }
                    }
                }
                OpCode::Pong => {
                    match self.pending_operations.try_send(Frame::pong(Payload::Borrowed(&[]))) {
                        Ok(()) => {
                            self.notify_pending_ops.notify_waiters();
                        }
                        Err(TrySendError::Full(_)) => {
                            // Queue full; in_flight_ping is already reset by RX
                        }
                        Err(TrySendError::Closed(_)) => {
                            return Err(io::Error::new(ErrorKind::ConnectionAborted, "cannot send pong"));
                        }
                    }
                }
            };
        }
    }
}

pub async fn connect(
    request_id: Uuid,
    client: &Client<impl crate::TokioExecutorRef>,
    dest_addr: &RemoteAddr,
) -> anyhow::Result<(WebsocketTransportRead, WebsocketTransportWrite, Parts)> {
    let client_cfg = &client.config;
    let mut pooled_cnx = match client.cnx_pool.get().await {
        Ok(cnx) => Ok(cnx),
        Err(err) => Err(anyhow!("failed to get a connection to the server from the pool: {err:?}")),
    }?;

    let mut req = Request::builder()
        .method("GET")
        .uri(format!("/{}/events", client_cfg.http_upgrade_path_prefix))
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

    let headers = match req.headers_mut() {
        Some(h) => h,
        None => {
            return Err(anyhow!(
                "failed to build HTTP request to contact the server {:?}. Most likely path_prefix `{}` or http headers is not valid",
                req.body(Empty::<Bytes>::new()),
                client_cfg.http_upgrade_path_prefix
            ));
        }
    };
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
    debug!("with HTTP upgrade request {req:?}");
    let transport = pooled_cnx.deref_mut().take().unwrap();
    let (ws, response) = fastwebsockets::handshake::client(&TokioExecutor::new(), req, transport)
        .await
        .with_context(|| format!("failed to do websocket handshake with the server {:?}", client_cfg.remote_addr))?;

    let (ws_rx, ws_tx) = mk_websocket_tunnel(ws, Role::Client, client_cfg.websocket_mask_frame)?;
    Ok((ws_rx, ws_tx, response.into_parts().0))
}

pub fn mk_websocket_tunnel(
    ws: WebSocket<TokioIo<Upgraded>>,
    role: Role,
    mask_frame: bool,
) -> anyhow::Result<(WebsocketTransportRead, WebsocketTransportWrite)> {
    let mut ws = match role {
        Role::Client => {
            let stream = ws
                .into_inner()
                .into_inner()
                .downcast::<TokioIo<L4Stream>>()
                .map_err(|_| anyhow!("cannot downcast websocket client stream"))?;
            let transport = L4Stream::from(stream.io.into_inner(), stream.read_buf);
            WebSocket::after_handshake(transport, role)
        }
        Role::Server => {
            let upgraded = ws.into_inner().into_inner();
            match upgraded.downcast::<TokioIo<TlsStream<TcpStream>>>() {
                Ok(stream) => {
                    let transport = L4Stream::from_server_tls(stream.io.into_inner(), stream.read_buf);
                    WebSocket::after_handshake(transport, role)
                }
                Err(upgraded) => {
                    let stream = hyper_util::server::conn::auto::upgrade::downcast::<TokioIo<TcpStream>>(upgraded)
                        .map_err(|_| anyhow!("cannot downcast websocket server stream"))?;
                    let transport = L4Stream::from_tcp(stream.io.into_inner(), stream.read_buf);
                    WebSocket::after_handshake(transport, role)
                }
            }
        }
    };

    ws.set_auto_pong(false);
    ws.set_auto_close(false);
    ws.set_auto_apply_mask(mask_frame);
    let (ws_rx, ws_tx) = ws.split(|x| x.into_split());

    let in_flight_ping = Arc::new(AtomicUsize::new(0));
    let (ws_rx, pending_ops) = WebsocketTransportRead::new(ws_rx, in_flight_ping.clone());
    Ok((ws_rx, WebsocketTransportWrite::new(ws_tx, pending_ops, in_flight_ping)))
}
