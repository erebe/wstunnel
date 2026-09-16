use super::io::{MAX_PACKET_LENGTH, TransportRead, TransportWrite};
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::{Client, ClientConfig};
use crate::tunnel::client::connection_pool::{connect_l4_stream, L4ReadHalf, L4Stream, L4WriteHalf};
use crate::tunnel::transport::headers_from_file;
use crate::tunnel::transport::jwt::{JWT_HEADER_PREFIX, tunnel_to_jwt_token};
use crate::tunnel::transport::{TransportAddr, TransportScheme};
use anyhow::{Context, anyhow};
use bytes::{Bytes, BytesMut};
use either::Either;
use fastwebsockets::{CloseCode, Frame, OpCode, Payload, Role, WebSocket, WebSocketRead, WebSocketWrite};
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper::header::{AUTHORIZATION, HeaderValue, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION, UPGRADE};
use hyper::header::{CONNECTION, HOST, SEC_WEBSOCKET_KEY};
use hyper::http::response::Parts;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use log::{debug, warn};
use std::collections::HashSet;
use std::io;
use std::io::ErrorKind;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_rustls::server::TlsStream;
use tracing::{info, trace};
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

/// Derives the appropriate `Host` header for `target_addr`.
///
/// Honors any explicit `Host` header provided in `client_cfg.http_headers`, otherwise
/// generates the host authority string (including non-default port if applicable).
fn host_header_for(target_addr: &TransportAddr, client_cfg: &ClientConfig) -> HeaderValue {
    if let Some(custom_host) = client_cfg.http_headers.get(&HOST) {
        return custom_host.clone();
    }
    let host_str = match target_addr.port() {
        80 if matches!(target_addr.scheme(), TransportScheme::Ws | TransportScheme::Http) => {
            target_addr.host().to_string()
        }
        443 if matches!(target_addr.scheme(), TransportScheme::Wss | TransportScheme::Https) => {
            target_addr.host().to_string()
        }
        port => format!("{}:{}", target_addr.host(), port),
    };
    HeaderValue::from_str(&host_str).unwrap_or_else(|_| client_cfg.http_header_host.clone())
}

/// Builds the HTTP/1.1 WebSocket upgrade request targeting `target_addr` at `/{path_prefix}/events`.
fn build_upgrade_request(
    client_cfg: &ClientConfig,
    target_addr: &TransportAddr,
    path_prefix: &str,
    request_id: Uuid,
    dest_addr: &RemoteAddr,
) -> anyhow::Result<Request<Empty<Bytes>>> {
    let host_val = host_header_for(target_addr, client_cfg);
    let mut req = Request::builder()
        .method("GET")
        .uri(format!("/{}/events", path_prefix))
        .header(HOST, host_val)
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
                target_addr,
                path_prefix
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
        format!("failed to build HTTP request to contact the server {target_addr:?}")
    })?;
    Ok(req)
}

/// The outcome of a WebSocket handshake attempt.
enum HandshakeOutcome {
    /// Server accepted the upgrade with 101 Switching Protocols.
    Success(Box<WebSocket<TokioIo<Upgraded>>>, Parts),
    /// Server responded with an HTTP 3xx redirection and a `Location` header.
    Redirect { status: hyper::StatusCode, location: String },
}

/// Performs a WebSocket handshake over the given `transport` stream, intercepting HTTP 3xx redirects.
async fn do_websocket_handshake(
    transport: L4Stream,
    req: Request<Empty<Bytes>>,
    executor: &impl crate::TokioExecutorRef,
) -> anyhow::Result<HandshakeOutcome> {
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(transport))
        .await
        .with_context(|| "failed to establish HTTP/1.1 handshake with server")?;

    executor.spawn(async move {
        if let Err(err) = conn.with_upgrades().await {
            debug!("HTTP/1.1 connection driver ended: {err:?}");
        }
    });

    let mut response = sender
        .send_request(req)
        .await
        .with_context(|| "failed to send WebSocket upgrade request")?;

    let status = response.status();
    if status == hyper::StatusCode::SWITCHING_PROTOCOLS {
        let is_upgrade_ws = response
            .headers()
            .get(UPGRADE)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);
        if !is_upgrade_ws {
            return Err(anyhow!(
                "Server responded with 101 Switching Protocols but missing or invalid Upgrade header"
            ));
        }

        let is_conn_upgrade = response
            .headers()
            .get(CONNECTION)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(',').any(|part| part.trim().eq_ignore_ascii_case("upgrade")))
            .unwrap_or(false);
        if !is_conn_upgrade {
            return Err(anyhow!(
                "Server responded with 101 Switching Protocols but missing or invalid Connection header"
            ));
        }

        let upgraded = hyper::upgrade::on(&mut response)
            .await
            .with_context(|| "failed to upgrade HTTP connection to WebSocket")?;
        let ws = WebSocket::after_handshake(TokioIo::new(upgraded), Role::Client);
        Ok(HandshakeOutcome::Success(Box::new(ws), response.into_parts().0))
    } else if status.is_redirection() {
        let location = response
            .headers()
            .get(hyper::header::LOCATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| anyhow!("Redirect status code {status} without valid Location header"))?
            .to_string();
        Ok(HandshakeOutcome::Redirect { status, location })
    } else {
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .map(|c| c.to_bytes())
            .unwrap_or_default();
        let body_str = String::from_utf8_lossy(&body_bytes);
        let detail = if body_str.is_empty() {
            String::new()
        } else {
            format!(": {body_str}")
        };
        Err(anyhow!(
            "WebSocket handshake rejected by server with status {status}{detail}"
        ))
    }
}

async fn do_connect(
    request_id: Uuid,
    client: &Client<impl crate::TokioExecutorRef>,
    dest_addr: &RemoteAddr,
    start_addr: TransportAddr,
    start_path_prefix: String,
    can_use_pool: bool,
) -> anyhow::Result<(WebsocketTransportRead, WebsocketTransportWrite, Parts)> {
    let client_cfg = &client.config;
    let mut current_addr = start_addr;
    let mut current_path_prefix = start_path_prefix;
    let mut visited = HashSet::new();
    let max_redirects = client_cfg.max_redirects;
    let mut redirect_count = 0;

    loop {
        // If permitted and on the first attempt, use an already-pooled connection.
        // Otherwise (for redirected hops or when connecting directly to a cached redirect target),
        // dial directly via connect_l4_stream.
        let transport = if can_use_pool && redirect_count == 0 {
            let mut pooled_cnx = match client.cnx_pool.get().await {
                Ok(cnx) => Ok(cnx),
                Err(err) => Err(anyhow!("failed to get a connection to the server from the pool: {err:?}")),
            }?;
            pooled_cnx
                .take()
                .and_then(Either::left)
                .ok_or_else(|| anyhow!("the connection pool did not return a TCP stream"))?
        } else {
            connect_l4_stream(client_cfg, &current_addr).await?
        };

        let req = build_upgrade_request(
            client_cfg,
            &current_addr,
            &current_path_prefix,
            request_id,
            dest_addr,
        )?;
        debug!("with HTTP upgrade request {req:?}");

        match do_websocket_handshake(transport, req, &client.executor)
            .await
            .with_context(|| format!("failed to do websocket handshake with the server {:?}", current_addr))?
        {
            HandshakeOutcome::Success(ws, parts) => {
                if redirect_count > 0 {
                    client.set_active_target(current_addr, current_path_prefix);
                }
                let (ws_rx, ws_tx) = mk_websocket_tunnel(*ws, Role::Client, client_cfg.websocket_mask_frame)?;
                return Ok((ws_rx, ws_tx, parts));
            }
            HandshakeOutcome::Redirect { status, location } => {
                if redirect_count >= max_redirects {
                    return Err(anyhow!(
                        "too many redirects ({redirect_count}) when connecting to {:?}",
                        client_cfg.remote_addr
                    ));
                }
                redirect_count += 1;
                info!("Server redirected ({status}) to {location}");
                let (next_addr, next_prefix) = current_addr
                    .resolve_redirect(&current_path_prefix, &location, &mut visited)
                    .with_context(|| format!("failed to follow redirect from {current_addr:?} to {location}"))?;

                current_addr = next_addr;
                current_path_prefix = next_prefix;
            }
        }
    }
}

/// Connect to a remote wstunnel server over WebSocket, following HTTP 3xx redirects if encountered.
pub async fn connect(
    request_id: Uuid,
    client: &Client<impl crate::TokioExecutorRef>,
    dest_addr: &RemoteAddr,
) -> anyhow::Result<(WebsocketTransportRead, WebsocketTransportWrite, Parts)> {
    let client_cfg = &client.config;
    let active = client.active_target();
    let is_cached = !active.is_same_target(&client_cfg.remote_addr, &client_cfg.http_upgrade_path_prefix);

    if is_cached {
        match do_connect(
            request_id,
            client,
            dest_addr,
            active.addr.clone(),
            active.path_prefix.clone(),
            false,
        )
        .await
        {
            Ok(res) => Ok(res),
            Err(err) => {
                warn!(
                    "Failed to connect to cached redirect target {:?}: {:?}. Falling back to canonical server URL {:?}",
                    active.addr,
                    err,
                    client_cfg.remote_addr
                );
                client.reset_active_target();
                // When falling back after a cached target failure, establish a fresh L4 connection directly
                // rather than borrowing potentially stale/closed sockets from the connection pool.
                do_connect(
                    request_id,
                    client,
                    dest_addr,
                    client_cfg.remote_addr.clone(),
                    client_cfg.http_upgrade_path_prefix.clone(),
                    false,
                )
                .await
            }
        }
    } else {
        do_connect(
            request_id,
            client,
            dest_addr,
            client_cfg.remote_addr.clone(),
            client_cfg.http_upgrade_path_prefix.clone(),
            true,
        )
        .await
    }
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
