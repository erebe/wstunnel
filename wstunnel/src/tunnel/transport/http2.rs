use super::io::{MAX_PACKET_LENGTH, TransportRead, TransportWrite};
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::connection_pool::connect_l4_stream;
use crate::tunnel::client::{Client, ClientConfig};
use crate::tunnel::transport::jwt::tunnel_to_jwt_token;
use crate::tunnel::transport::{TransportAddr, TransportScheme, headers_from_file};
use anyhow::{Context, anyhow};
use bytes::{Bytes, BytesMut};
use either::Either;
use http_body_util::{BodyExt, BodyStream, StreamBody};
use hyper::Request;
use hyper::body::{Frame, Incoming};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE};
use hyper::http::response::Parts;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use log::{debug, error, info, warn};
use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};
use tokio::task::AbortHandle;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

pub struct Http2TransportRead {
    inner: BodyStream<Incoming>,
    cnx_poller: Option<AbortHandle>,
}

impl Http2TransportRead {
    pub const fn new(inner: BodyStream<Incoming>, cnx_poller: Option<AbortHandle>) -> Self {
        Self { inner, cnx_poller }
    }
}

impl Drop for Http2TransportRead {
    fn drop(&mut self) {
        if let Some(t) = self.cnx_poller.as_ref() {
            t.abort()
        }
    }
}

impl TransportRead for Http2TransportRead {
    async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
        loop {
            match self.inner.next().await {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => {
                        return match writer.write_all(data.as_ref()).await {
                            Ok(_) => Ok(()),
                            Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
                        };
                    }
                    Err(err) => {
                        warn!("{err:?}");
                        continue;
                    }
                },
                Some(Err(err)) => {
                    return Err(io::Error::new(ErrorKind::ConnectionAborted, err));
                }
                None => return Err(io::Error::new(ErrorKind::BrokenPipe, "closed")),
            }
        }
    }
}

pub struct Http2TransportWrite {
    inner: mpsc::Sender<Bytes>,
    buf: BytesMut,
}

impl Http2TransportWrite {
    pub fn new(inner: mpsc::Sender<Bytes>) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(MAX_PACKET_LENGTH * 20), // ~ 1Mb
        }
    }
}

impl TransportWrite for Http2TransportWrite {
    fn buf_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }

    async fn write(&mut self) -> Result<(), io::Error> {
        let data = self.buf.split().freeze();
        let ret = match self.inner.send(data).await {
            Ok(_) => Ok(()),
            Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
        };

        if self.buf.capacity() < MAX_PACKET_LENGTH {
            //info!("read {} Kb {} Kb", self.buf.capacity() / 1024, old_capa / 1024);
            self.buf.reserve(MAX_PACKET_LENGTH)
        }

        ret
    }

    async fn ping(&mut self) -> Result<(), io::Error> {
        Ok(())
    }

    async fn close(&mut self) -> Result<(), io::Error> {
        Ok(())
    }

    fn pending_operations_notify(&mut self) -> Arc<Notify> {
        Arc::new(Notify::new())
    }

    fn handle_pending_operations(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        std::future::ready(Ok(()))
    }
}

/// Derives the HTTP/2 authority string (`host` or `host:port`) for `target_addr`.
///
/// On the initial connection, honors any host override from `--http-headers-file` or `--http-headers`.
/// For subsequent redirected hops, uses `target_addr.authority()`.
fn authority_for(
    target_addr: &TransportAddr,
    client_cfg: &ClientConfig,
    headers_file_host: Option<&str>,
    is_initial: bool,
) -> String {
    if is_initial {
        if let Some(host) = headers_file_host {
            return host.to_string();
        }
        if let Some(custom_host) = client_cfg.http_headers.get(&hyper::header::HOST)
            && let Ok(s) = custom_host.to_str()
        {
            return s.to_string();
        }
        if let Ok(s) = client_cfg.http_header_host.to_str()
            && !s.is_empty()
        {
            return s.to_string();
        }
    }
    target_addr.authority()
}

async fn do_connect(
    request_id: Uuid,
    client: &Client<impl crate::TokioExecutorRef>,
    dest_addr: &RemoteAddr,
    start_addr: TransportAddr,
    start_path_prefix: String,
    can_use_pool: bool,
) -> anyhow::Result<(Http2TransportRead, Http2TransportWrite, Parts)> {
    let client_cfg = &client.config;
    let mut current_addr = start_addr;
    let mut current_path_prefix = start_path_prefix;
    let mut visited = HashSet::new();
    let max_redirects = client_cfg.max_redirects;
    let mut redirect_count = 0;

    // In HTTP/2, the HOST header is not used directly; authority is set in the request URI.
    let (headers_file, headers_file_host) =
        client_cfg
            .http_headers_file
            .as_ref()
            .map_or((None, None), |headers_file_path| {
                let (host, headers) = headers_from_file(headers_file_path);
                let host = if let Some((_, v)) = host {
                    match (client_cfg.remote_addr.scheme(), client_cfg.remote_addr.port()) {
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

    loop {
        // If permitted and on attempt 0, take an already-pooled connection.
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

        let authority = authority_for(
            &current_addr,
            client_cfg,
            headers_file_host.as_deref(),
            can_use_pool && redirect_count == 0,
        );

        let uri_scheme = match current_addr.scheme() {
            TransportScheme::Https | TransportScheme::Wss => "https",
            _ => "http",
        };

        let mut req = Request::builder()
            .method("POST")
            .uri(format!("{uri_scheme}://{authority}/{current_path_prefix}/events"))
            .header(COOKIE, tunnel_to_jwt_token(request_id, dest_addr))
            .header(CONTENT_TYPE, "application/json")
            .version(hyper::Version::HTTP_2);

        let headers = match req.headers_mut() {
            Some(h) => h,
            None => {
                return Err(anyhow!(
                    "failed to build HTTP request to contact the server {:?}. Most likely path_prefix `{}` or http headers is not valid",
                    current_addr,
                    current_path_prefix
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

        if let Some(ref headers_file) = headers_file {
            for (k, v) in headers_file {
                let _ = headers.remove(k);
                headers.append(k, v.clone());
            }
        }

        let (tx, rx) = mpsc::channel::<Bytes>(1024);
        let body = StreamBody::new(ReceiverStream::new(rx).map(|s| -> anyhow::Result<Frame<Bytes>> { Ok(Frame::data(s)) }));
        let req = req.body(body).with_context(|| {
            format!("failed to build HTTP request to contact the server {current_addr:?}")
        })?;
        debug!("with HTTP upgrade request {req:?}");

        let (mut request_sender, cnx) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .adaptive_window(true)
            .keep_alive_interval(client_cfg.websocket_ping_frequency)
            .keep_alive_timeout(Duration::from_secs(10))
            .keep_alive_while_idle(false)
            .handshake(TokioIo::new(transport))
            .await
            .with_context(|| format!("failed to do http2 handshake with the server {current_addr:?}"))?;

        let cnx_poller = client.executor.spawn(async move {
            if let Err(err) = cnx.await {
                error!("{err:?}")
            }
        });

        let response = request_sender
            .send_request(req)
            .await
            .with_context(|| format!("failed to send http2 request with the server {current_addr:?}"))?;

        let status = response.status();
        if status.is_success() {
            if redirect_count > 0 {
                client.set_active_target(current_addr, current_path_prefix);
            }
            let (parts, body) = response.into_parts();
            return Ok((
                Http2TransportRead::new(BodyStream::new(body), Some(cnx_poller)),
                Http2TransportWrite::new(tx),
                parts,
            ));
        } else if status.is_redirection() {
            cnx_poller.abort();
            if redirect_count >= max_redirects {
                return Err(anyhow!(
                    "too many redirects ({redirect_count}) when connecting to {:?}",
                    client_cfg.remote_addr
                ));
            }
            redirect_count += 1;
            let location = response
                .headers()
                .get(hyper::header::LOCATION)
                .and_then(|h| h.to_str().ok())
                .ok_or_else(|| anyhow!("Redirect status code {status} without valid Location header"))?
                .to_string();
            info!("Server redirected ({status}) to {location}");

            let (next_addr, next_prefix) = current_addr
                .resolve_redirect(&current_path_prefix, &location, &mut visited)
                .with_context(|| format!("failed to follow redirect from {current_addr:?} to {location}"))?;

            current_addr = next_addr;
            current_path_prefix = next_prefix;
        } else {
            cnx_poller.abort();
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
            return Err(anyhow!(
                "Http2 server rejected the connection with status {status}{detail}"
            ));
        }
    }
}

/// Connect to a remote wstunnel server over HTTP/2, following HTTP 3xx redirects if encountered.
pub async fn connect(
    request_id: Uuid,
    client: &Client<impl crate::TokioExecutorRef>,
    dest_addr: &RemoteAddr,
) -> anyhow::Result<(Http2TransportRead, Http2TransportWrite, Parts)> {
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
