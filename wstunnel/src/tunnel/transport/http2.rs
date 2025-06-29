use super::io::{MAX_PACKET_LENGTH, TunnelRead, TunnelWrite};
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::WsClient;
use crate::tunnel::transport::jwt::tunnel_to_jwt_token;
use crate::tunnel::transport::{TransportScheme, headers_from_file};
use anyhow::{Context, anyhow};
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, BodyStream, StreamBody};
use hyper::Request;
use hyper::body::{Frame, Incoming};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE};
use hyper::http::response::Parts;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use log::{debug, error, warn};
use std::future::Future;
use std::io;
use std::io::ErrorKind;
use std::ops::DerefMut;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};
use tokio::task::AbortHandle;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

pub struct Http2TunnelRead {
    inner: BodyStream<Incoming>,
    cnx_poller: Option<AbortHandle>,
}

impl Http2TunnelRead {
    pub const fn new(inner: BodyStream<Incoming>, cnx_poller: Option<AbortHandle>) -> Self {
        Self { inner, cnx_poller }
    }
}

impl Drop for Http2TunnelRead {
    fn drop(&mut self) {
        if let Some(t) = self.cnx_poller.as_ref() {
            t.abort()
        }
    }
}

impl TunnelRead for Http2TunnelRead {
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

pub struct Http2TunnelWrite {
    inner: mpsc::Sender<Bytes>,
    buf: BytesMut,
}

impl Http2TunnelWrite {
    pub fn new(inner: mpsc::Sender<Bytes>) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(MAX_PACKET_LENGTH * 20), // ~ 1Mb
        }
    }
}

impl TunnelWrite for Http2TunnelWrite {
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

pub async fn connect(
    request_id: Uuid,
    client: &WsClient<impl crate::TokioExecutorRef>,
    dest_addr: &RemoteAddr,
) -> anyhow::Result<(Http2TunnelRead, Http2TunnelWrite, Parts)> {
    let mut pooled_cnx = match client.cnx_pool.get().await {
        Ok(cnx) => Ok(cnx),
        Err(err) => Err(anyhow!("failed to get a connection to the server from the pool: {err:?}")),
    }?;

    // In http2 HOST header does not exist, it is explicitly set in the authority from the request uri
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
        .version(hyper::Version::HTTP_2);

    let headers = match req.headers_mut() {
        Some(h) => h,
        None => {
            return Err(anyhow!(
                "failed to build HTTP request to contact the server {:?}. Most likely path_prefix `{}` or http headers is not valid",
                req,
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

    let (tx, rx) = mpsc::channel::<Bytes>(1024);
    let body = StreamBody::new(ReceiverStream::new(rx).map(|s| -> anyhow::Result<Frame<Bytes>> { Ok(Frame::data(s)) }));
    let req = req.body(body).with_context(|| {
        format!(
            "failed to build HTTP request to contact the server {:?}",
            client.config.remote_addr
        )
    })?;
    debug!("with HTTP upgrade request {req:?}");
    let transport = pooled_cnx.deref_mut().take().unwrap();
    let (mut request_sender, cnx) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .adaptive_window(true)
        .keep_alive_interval(client.config.websocket_ping_frequency)
        .keep_alive_timeout(Duration::from_secs(10))
        .keep_alive_while_idle(false)
        .handshake(TokioIo::new(transport))
        .await
        .with_context(|| format!("failed to do http2 handshake with the server {:?}", client.config.remote_addr))?;
    let cnx_poller = client.executor.spawn(async move {
        if let Err(err) = cnx.await {
            error!("{err:?}")
        }
    });

    let response = request_sender
        .send_request(req)
        .await
        .with_context(|| format!("failed to send http2 request with the server {:?}", client.config.remote_addr))?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Http2 server rejected the connection: {:?}: {:?}",
            response.status(),
            String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec()).unwrap_or_default()
        ));
    }

    let (parts, body) = response.into_parts();
    Ok((
        Http2TunnelRead::new(BodyStream::new(body), Some(cnx_poller)),
        Http2TunnelWrite::new(tx),
        parts,
    ))
}
