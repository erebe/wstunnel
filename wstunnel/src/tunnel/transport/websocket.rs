use super::io::{MAX_PACKET_LENGTH, TransportRead, TransportWrite};
use super::redirect::{self, HopOutcome};
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::connection_pool::{L4ReadHalf, L4Stream, L4WriteHalf};
use crate::tunnel::client::{Client, ClientConfig};
use crate::tunnel::transport::TransportAddr;
use crate::tunnel::transport::headers_from_file;
use crate::tunnel::transport::jwt::{JWT_HEADER_PREFIX, tunnel_to_jwt_token};
use anyhow::{Context, anyhow};
use bytes::{Bytes, BytesMut};
use fastwebsockets::{CloseCode, Frame, OpCode, Payload, Role, WebSocket, WebSocketRead, WebSocketWrite};
use http_body_util::Empty;
use hyper::HeaderMap;
use hyper::Request;
use hyper::header::{AUTHORIZATION, HeaderName, HeaderValue, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION, UPGRADE};
use hyper::header::{CONNECTION, HOST, SEC_WEBSOCKET_KEY};
use hyper::http::response::Parts;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use log::debug;
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

/// The headers of `--http-headers-file`, read once and reused for every hop of a connection attempt.
///
/// A request is built per hop, so reading the file inside the request builder would re-open and
/// re-parse it for every redirect hop, and an edit mid-chain would change the request between hops.
struct HeadersFile {
    /// The file's `Host` line, if it has one.
    host: Option<(HeaderName, HeaderValue)>,
    /// Every other header in the file.
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl HeadersFile {
    /// Reads `client_cfg.http_headers_file`, if one is configured.
    fn load(client_cfg: &ClientConfig) -> Self {
        match client_cfg.http_headers_file.as_deref().map(headers_from_file) {
            Some((host, headers)) => Self { host, headers },
            None => Self {
                host: None,
                headers: Vec::new(),
            },
        }
    }

    /// Applies the file's headers, `Host` included, to `headers`.
    fn apply(&self, headers: &mut HeaderMap) {
        for (name, value) in &self.headers {
            let _ = headers.remove(name);
            headers.append(name, value.clone());
        }
        if let Some((name, value)) = &self.host {
            let _ = headers.remove(name);
            headers.append(name, value.clone());
        }
    }
}

/// Derives the appropriate `Host` header for `target_addr`.
///
/// On the initial connection attempt (`is_initial == true`), any explicit custom `Host` header
/// provided by the user via `-H "Host: ..."` is honored.
///
/// On subsequent redirected hops (`is_initial == false`) or if no custom host header was configured,
/// the authority is dynamically derived from `target_addr`, eliding the port when it is the
/// default for the scheme.
fn host_header_for(
    target_addr: &TransportAddr,
    client_cfg: &ClientConfig,
    is_initial: bool,
) -> anyhow::Result<HeaderValue> {
    if is_initial && let Some(custom_host) = &client_cfg.custom_http_header_host {
        return Ok(custom_host.clone());
    }
    let authority = target_addr.request_authority();
    HeaderValue::from_str(&authority)
        .with_context(|| format!("cannot build the Host header for the server {target_addr:?}"))
}

/// Builds the HTTP/1.1 WebSocket upgrade request targeting `target_addr` at `/{path_prefix}/events`.
///
/// `headers_file` carries the headers already parsed from `--http-headers-file`, so building a
/// request (once per redirect hop) does not re-read and re-parse the file.
fn build_upgrade_request(
    client_cfg: &ClientConfig,
    headers_file: &HeadersFile,
    target_addr: &TransportAddr,
    path_prefix: &str,
    request_id: Uuid,
    dest_addr: &RemoteAddr,
    is_initial: bool,
) -> anyhow::Result<Request<Empty<Bytes>>> {
    let host_val = host_header_for(target_addr, client_cfg, is_initial)?;
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

    headers_file.apply(headers);

    let req = req
        .body(Empty::<Bytes>::new())
        .with_context(|| format!("failed to build HTTP request to contact the server {target_addr:?}"))?;
    Ok(req)
}

/// Performs a WebSocket handshake over the given `transport` stream, intercepting HTTP 3xx redirects.
async fn do_websocket_handshake(
    transport: L4Stream,
    req: Request<Empty<Bytes>>,
    executor: &impl crate::TokioExecutorRef,
) -> anyhow::Result<HopOutcome<(Box<WebSocket<TokioIo<Upgraded>>>, Parts)>> {
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
        Ok(HopOutcome::Connected((Box::new(ws), response.into_parts().0)))
    } else if status.is_redirection() {
        // The chain logic reads `Location` (and, later, cache directives) from these headers.
        Ok(HopOutcome::Redirect {
            status,
            headers: response.headers().clone(),
        })
    } else {
        // The reply body is never parsed by wstunnel: the status is what matters, and the caller
        // reports it with the server URL. Reading it would make this path wait for a body that a
        // misbehaving server may never finish (there is no timeout around the handshake) and would
        // buffer whatever it does send. Drop it and let the connection go.
        Err(anyhow!("WebSocket handshake rejected by server with status {status}"))
    }
}

/// Connect to a remote wstunnel server over WebSocket, following HTTP 3xx redirects if encountered.
pub async fn connect(
    request_id: Uuid,
    client: &Client<impl crate::TokioExecutorRef>,
    dest_addr: &RemoteAddr,
) -> anyhow::Result<(WebsocketTransportRead, WebsocketTransportWrite, Parts)> {
    let client_cfg = &client.config;
    // Read the headers file once for the whole connection attempt, not once per hop.
    let headers_file = HeadersFile::load(client_cfg);
    let headers_file = &headers_file;

    let (ws, parts) = redirect::connect(client, |transport, addr, path_prefix, is_initial| async move {
        let req =
            build_upgrade_request(client_cfg, headers_file, &addr, &path_prefix, request_id, dest_addr, is_initial)?;
        debug!("with HTTP upgrade request {req:?}");

        do_websocket_handshake(transport, req, &client.executor)
            .await
            .with_context(|| format!("failed to do websocket handshake with the server {addr:?}"))
    })
    .await?;

    let (ws_rx, ws_tx) = mk_websocket_tunnel(*ws, Role::Client, client_cfg.websocket_mask_frame)?;
    Ok((ws_rx, ws_tx, parts))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DnsResolver;
    use crate::SoMark;
    use crate::tunnel::transport::TransportScheme;
    use std::collections::HashMap;
    use std::time::Duration;
    use url::Host;

    fn make_test_cfg(custom_host: Option<&str>) -> ClientConfig {
        ClientConfig {
            remote_addr: TransportAddr::new(
                TransportScheme::Ws,
                Host::Domain("d1.example.com".to_string()),
                8080,
                None,
            )
            .unwrap(),
            socket_so_mark: SoMark::new(None),
            http_upgrade_path_prefix: "v1".to_string(),
            http_upgrade_credentials: None,
            http_headers: HashMap::new(),
            http_headers_file: None,
            custom_http_header_host: custom_host.map(|h| HeaderValue::from_str(h).unwrap()),
            timeout_connect: Duration::from_secs(10),
            websocket_ping_frequency: None,
            websocket_mask_frame: false,
            dns_resolver: DnsResolver::System,
            http_proxy: None,
            webtransport: None,
            max_redirects: 5,
            tls_verify_certificate: false,
        }
    }

    #[test]
    fn test_host_header_custom_on_initial_hop_only() {
        let cfg = make_test_cfg(Some("custom.example.com"));
        let initial_addr = cfg.remote_addr.clone();
        let redirected_addr =
            TransportAddr::new(TransportScheme::Ws, Host::Domain("d2.example.com".to_string()), 9090, None).unwrap();

        // Initial hop must use the custom host header
        let host_initial = host_header_for(&initial_addr, &cfg, true).unwrap();
        assert_eq!(host_initial.to_str().unwrap(), "custom.example.com");

        // Redirected hop must derive host authority dynamically
        let host_redirected = host_header_for(&redirected_addr, &cfg, false).unwrap();
        assert_eq!(host_redirected.to_str().unwrap(), "d2.example.com:9090");
    }

    #[test]
    fn test_host_header_auto_derived_when_no_custom_host() {
        let cfg = make_test_cfg(None);
        let initial_addr = cfg.remote_addr.clone();
        let host_initial = host_header_for(&initial_addr, &cfg, true).unwrap();
        assert_eq!(host_initial.to_str().unwrap(), "d1.example.com:8080");
    }

    #[test]
    fn test_host_header_elides_default_port() {
        let mut cfg = make_test_cfg(None);
        cfg.remote_addr =
            TransportAddr::new(TransportScheme::Ws, Host::Domain("d1.example.com".to_string()), 80, None).unwrap();

        let host_initial = host_header_for(&cfg.remote_addr, &cfg, true).unwrap();
        assert_eq!(host_initial.to_str().unwrap(), "d1.example.com");
    }

    #[test]
    fn test_headers_file_is_parsed_once_and_reused() {
        let path = std::env::temp_dir().join(format!("wstunnel-headers-{}.txt", std::process::id()));
        std::fs::write(&path, "Host: pinned.example.com\nX-Extra: 1\n").unwrap();

        let mut cfg = make_test_cfg(None);
        cfg.http_headers_file = Some(path.clone());

        // Parsed once for the whole connection attempt...
        let headers_file = HeadersFile::load(&cfg);
        // ...and the file is gone before any request is built, so a builder that re-read it per hop
        // would silently send no file headers at all.
        std::fs::remove_file(&path).unwrap();

        let dest = crate::tunnel::RemoteAddr {
            protocol: crate::tunnel::LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Domain("target.invalid".to_string()),
            port: 22,
        };
        let redirected =
            TransportAddr::new(TransportScheme::Ws, Host::Domain("d2.example.com".to_string()), 9090, None).unwrap();

        let initial =
            build_upgrade_request(&cfg, &headers_file, &cfg.remote_addr.clone(), "v1", Uuid::new_v4(), &dest, true)
                .unwrap();
        let second_hop =
            build_upgrade_request(&cfg, &headers_file, &redirected, "v1", Uuid::new_v4(), &dest, false).unwrap();

        for req in [&initial, &second_hop] {
            assert_eq!(
                req.headers().get("x-extra").and_then(|v| v.to_str().ok()),
                Some("1"),
                "file headers must be reused from the parsed copy"
            );
        }
        assert_eq!(
            initial.headers().get(HOST).and_then(|v| v.to_str().ok()),
            Some("pinned.example.com")
        );
    }
}
