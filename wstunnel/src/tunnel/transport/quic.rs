use super::io::{MAX_PACKET_LENGTH, TunnelRead, TunnelWrite};
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::WsClient;
use crate::tunnel::client::quic_cnx_pool::QuicConnection;
use crate::tunnel::transport::jwt::tunnel_to_jwt_token;
use crate::tunnel::transport::{TransportScheme, headers_from_file};
use anyhow::{Context, anyhow};
use bb8::ManageConnection;
use bytes::{Bytes, BytesMut};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, HOST};
use hyper::http::response::Parts;
use hyper::{Request, Response};
use quinn::{RecvStream, SendStream};
use std::future::Future;
use std::io;
use std::io::ErrorKind;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;
use tokio::time::{Duration, timeout};
use tracing::{debug, trace, warn};
use uuid::Uuid;

pub struct QuicTunnelRead {
    inner: RecvStream,
    pre_read: Option<Bytes>,
}

impl QuicTunnelRead {
    pub const fn new(inner: RecvStream) -> Self {
        Self { inner, pre_read: None }
    }

    pub fn with_pre_read(mut self, pre_read: Option<Bytes>) -> Self {
        self.pre_read = pre_read;
        self
    }
}

impl TunnelRead for QuicTunnelRead {
    async fn copy(&mut self, mut writer: impl tokio::io::AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
        if let Some(data) = self.pre_read.take() {
            writer.write_all(&data).await?;
            return Ok(());
        }

        match self.inner.read_chunk(MAX_PACKET_LENGTH, true).await {
            Ok(Some(chunk)) => {
                writer.write_all(&chunk.bytes).await?;
                Ok(())
            }
            Ok(None) => {
                trace!("QUIC stream closed gracefully");
                Err(io::Error::new(ErrorKind::BrokenPipe, "stream closed"))
            }
            Err(e) => {
                trace!("QUIC read error: {:?}", e);
                Err(io::Error::new(ErrorKind::ConnectionAborted, e))
            }
        }
    }
}

pub struct QuicTunnelWrite {
    inner: SendStream,
    buf: BytesMut,
}

impl QuicTunnelWrite {
    pub fn new(inner: SendStream) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(1024 * 1024),
        }
    }
}

impl TunnelWrite for QuicTunnelWrite {
    fn buf_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }

    async fn write(&mut self) -> Result<(), io::Error> {
        let data = self.buf.split().freeze();
        match self.inner.write_chunk(data).await {
            Ok(_) => {
                if self.buf.capacity() < MAX_PACKET_LENGTH {
                    self.buf.reserve(MAX_PACKET_LENGTH);
                }
                Ok(())
            }
            Err(e) => Err(io::Error::new(ErrorKind::ConnectionAborted, e)),
        }
    }

    async fn ping(&mut self) -> Result<(), io::Error> {
        Ok(())
    }

    async fn close(&mut self) -> Result<(), io::Error> {
        match self.inner.finish() {
            Ok(_) => Ok(()),
            Err(e) => Err(io::Error::new(ErrorKind::BrokenPipe, e)),
        }
    }

    fn pending_operations_notify(&mut self) -> Arc<Notify> {
        Arc::new(Notify::new())
    }

    fn handle_pending_operations(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        std::future::ready(Ok(()))
    }
}

pub async fn connect(
    request_id: Uuid,
    client: &WsClient<impl crate::TokioExecutorRef>,
    dest_addr: &RemoteAddr,
    allow_pooling: bool,
) -> anyhow::Result<(QuicTunnelRead, QuicTunnelWrite, Parts)> {
    debug!("QUIC connect: Starting tunnel connection for request {}", request_id);

    // 4. Send HTTP handshake
    let (headers_file, authority) =
        client
            .config
            .http_headers_file
            .as_ref()
            .map_or((None, None), |headers_file_path| {
                let (host, headers) = headers_from_file(headers_file_path);
                let host = if let Some((_, v)) = host {
                    match (client.config.remote_addr.scheme(), client.config.remote_addr.port()) {
                        (TransportScheme::Http, 80) | (TransportScheme::Https, 443) => {
                            Some(v.to_str().unwrap_or("").to_string())
                        }
                        (_, port) => Some(format!("{}:{}", v.to_str().unwrap_or(""), port)),
                    }
                } else {
                    None
                };

                (Some(headers), host)
            });

    let mut req = Request::builder()
        .method("POST")
        .uri(format!(
            "{}://{}/{}/events",
            client.config.remote_addr.scheme(),
            authority
                .as_deref()
                .unwrap_or_else(|| client.config.http_header_host.to_str().unwrap_or("")),
            &client.config.http_upgrade_path_prefix
        ))
        .header(COOKIE, tunnel_to_jwt_token(request_id, dest_addr))
        .header(CONTENT_TYPE, "application/json")
        .header(HOST, client.config.http_header_host.as_bytes())
        .version(hyper::Version::HTTP_11);

    let headers = match req.headers_mut() {
        Some(h) => h,
        None => {
            return Err(anyhow!(
                "failed to build HTTP request. Most likely path_prefix `{}` or http headers is not valid",
                client.config.http_upgrade_path_prefix
            ));
        }
    };

    for (k, v) in &client.config.http_headers {
        let _ = headers.remove(k);
        headers.append(k, v.clone());
    }

    if let Some(auth) = &client.config.http_upgrade_credentials {
        let _ = headers.remove(AUTHORIZATION);
        headers.append(AUTHORIZATION, auth.clone());
    }

    if let Some(headers_file) = headers_file {
        for (k, v) in headers_file {
            let _ = headers.remove(&k);
            headers.append(k, v);
        }
    }

    let req = req.body(()).unwrap();

    // Serialize request
    debug!("QUIC connect: Preparing HTTP request to {} {}", req.method(), req.uri().path());
    let mut buf = BytesMut::new();
    buf.extend_from_slice(format!("{} {} {:?}\r\n", req.method(), req.uri().path(), req.version()).as_bytes());
    for (name, value) in req.headers() {
        buf.extend_from_slice(name.as_str().as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"\r\n");

    let mut attempts = 0;
    loop {
        attempts += 1;
        let handshake_timeout = if dest_addr.protocol.is_reverse_tunnel() {
            Duration::from_secs(3600 * 24 * 365) // 1 year
        } else {
            client.config.quic_handshake_timeout
        };

        // Get a QUIC connection
        // If pooling is allowed, try to get a connection from the pool first.
        // Otherwise, create a new connection to ensure freshness (e.g. for -L forward tunnels).
        // We use two Option variables to extend the lifetime of the connection object
        // so we can borrow it as &quinn::Connection regardless of source.
        let (pooled_guard, new_connection_guard);
        let connection: &quinn::Connection = if allow_pooling {
            debug!("QUIC connect: Getting connection from pool (attempt {})", attempts);
            pooled_guard = Some(
                client
                    .quic_cnx_pool
                    .as_ref()
                    .ok_or_else(|| anyhow!("QUIC connection pool not initialized"))?
                    .get()
                    .await
                    .map_err(|err| anyhow!("failed to get a QUIC connection from the pool: {err:?}"))?,
            );
            debug!("QUIC connect: Successfully got pooled connection");
            pooled_guard
                .as_ref()
                .unwrap()
                .as_ref()
                .ok_or_else(|| anyhow!("pooled connection is None"))?
        } else {
            debug!("QUIC connect: Creating new connection (attempt {})", attempts);
            new_connection_guard = Some(
                QuicConnection::new(client.config.clone())
                    .connect()
                    .await
                    .map_err(|err| anyhow!("failed to connect to QUIC server: {err:?}"))?
                    .ok_or_else(|| anyhow!("failed to connect to QUIC server"))?,
            );
            new_connection_guard.as_ref().unwrap()
        };

        debug!("QUIC connect: Using connection with stable_id: {}", connection.stable_id());

        // Open bi-directional stream on the pooled connection
        debug!("QUIC connect: Opening bidirectional stream");
        let (mut send, mut recv): (SendStream, RecvStream) = match connection.open_bi().await {
            Ok(stream) => {
                debug!("QUIC connect: Bidirectional stream opened successfully (stream_id likely: TBD)");
                stream
            }
            Err(e) => {
                warn!("QUIC connect: Failed to open bidirectional stream: {:?}", e);
                // If we failed to open a stream, the connection might be dead.
                // Invalidate it and retry if it's the first attempt.
                if attempts == 1 {
                    warn!(
                        "QUIC connect: Connection {} failed to open stream. Closing and retrying.",
                        connection.stable_id()
                    );

                    connection.close(quinn::VarInt::from_u32(0), b"stale connection");
                    continue;
                }
                return Err(e).context("failed to open QUIC stream");
            }
        };

        debug!("QUIC connect: Sending HTTP request ({} bytes)", buf.len());
        match timeout(handshake_timeout, send.write_all(&buf)).await {
            Ok(Ok(())) => {
                debug!("QUIC connect: HTTP request sent successfully");
            }
            Ok(Err(e)) => {
                if attempts == 1 {
                    warn!(
                        "QUIC connect: Failed to send request on connection {}. Closing and retrying.",
                        connection.stable_id()
                    );

                    connection.close(quinn::VarInt::from_u32(0), b"stale connection");
                    continue;
                }
                return Err(e).context("failed to send HTTP request");
            }
            Err(_) => {
                if attempts == 1 {
                    warn!(
                        "QUIC connect: Timed out sending request on connection {}. Closing and retrying.",
                        connection.stable_id()
                    );

                    connection.close(quinn::VarInt::from_u32(0), b"stale connection");
                    continue;
                }
                return Err(anyhow!("QUIC handshake write timed out"));
            }
        }

        // 5. Read response
        debug!("QUIC connect: Waiting for server response with timeout");
        let mut resp_buf = BytesMut::with_capacity(4096);

        // Read enough for headers
        let handshake_result = async {
            loop {
                let mut header_buf = [httparse::EMPTY_HEADER; 64];
                debug!("QUIC connect: Reading response chunk");
                let chunk = recv
                    .read_chunk(4096, true)
                    .await?
                    .ok_or_else(|| anyhow!("Connection closed during handshake"))?;
                debug!("QUIC connect: Received {} bytes", chunk.bytes.len());
                resp_buf.extend_from_slice(&chunk.bytes);

                let (size, parts) = {
                    let mut resp = httparse::Response::new(&mut header_buf);
                    match resp.parse(&resp_buf) {
                        Ok(httparse::Status::Complete(size)) => {
                            // Parse complete
                            debug!("QUIC connect: Received complete HTTP response, status: {:?}", resp.code);
                            if resp.code.unwrap_or(0) != 200 {
                                warn!("QUIC handshake failed: status {:?}", resp.code);
                                return Err(anyhow!("QUIC handshake failed: status {:?}", resp.code));
                            }

                            let mut parts = Response::builder()
                                .status(resp.code.unwrap())
                                .version(hyper::Version::HTTP_11)
                                .body(())
                                .unwrap()
                                .into_parts()
                                .0;

                            for h in resp.headers {
                                parts.headers.append(
                                    hyper::header::HeaderName::from_str(h.name).unwrap(),
                                    hyper::header::HeaderValue::from_bytes(h.value).unwrap(),
                                );
                            }
                            (size, parts)
                        }
                        Ok(httparse::Status::Partial) => {
                            debug!("QUIC connect: Partial response, waiting for more data");
                            continue;
                        }
                        Err(e) => {
                            warn!("QUIC connect: Failed to parse HTTP response: {:?}", e);
                            return Err(anyhow!("Failed to parse response: {:?}", e));
                        }
                    }
                };

                return Ok((recv, size, parts));
            }
        };

        match timeout(handshake_timeout, handshake_result).await {
            Ok(Ok((recv, size, parts))) => {
                let extra_bytes = if resp_buf.len() > size {
                    Some(resp_buf.split_off(size).freeze())
                } else {
                    None
                };

                debug!("QUIC connect: Tunnel established successfully");
                return Ok((
                    QuicTunnelRead::new(recv).with_pre_read(extra_bytes),
                    QuicTunnelWrite::new(send),
                    parts,
                ));
            }
            Ok(Err(e)) => {
                if attempts == 1 {
                    warn!(
                        "QUIC connect: Handshake failed on connection {}: {:?}. Closing and retrying.",
                        connection.stable_id(),
                        e
                    );

                    connection.close(quinn::VarInt::from_u32(0), b"stale connection");
                    continue;
                }
                return Err(e);
            }
            Err(_) => {
                // Timeout
                if attempts == 1 {
                    warn!(
                        "QUIC connect: Handshake timed out on connection {}. Closing and retrying.",
                        connection.stable_id()
                    );

                    connection.close(quinn::VarInt::from_u32(0), b"stale connection");
                    continue;
                }
                return Err(anyhow!("QUIC handshake timed out"));
            }
        }
    }
}
