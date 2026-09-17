use super::io::{MAX_PACKET_LENGTH, TransportRead, TransportWrite};
use super::redirect::{self, HopOutcome};
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::{Client, ClientConfig};
use crate::tunnel::transport::jwt::tunnel_to_jwt_token;
use crate::tunnel::transport::{TransportAddr, TransportScheme, headers_from_file};
use anyhow::{Context, anyhow};
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyStream, StreamBody};
use hyper::Request;
use hyper::body::{Frame, Incoming};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE};
use hyper::http::response::Parts;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use log::{debug, error, warn};
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
/// A host override from `--http-headers-file` or `-H "Host: ..."` is honored while the hop is on the
/// same host as the configured server (`keep_pinned_host`), matching what curl does with an explicit
/// `Host` override. Once a redirect changes the host, the authority is derived from `target_addr`
/// instead, eliding the port when it is the default for the scheme.
fn authority_for(
    target_addr: &TransportAddr,
    client_cfg: &ClientConfig,
    headers_file_host: Option<&str>,
    keep_pinned_host: bool,
) -> String {
    if keep_pinned_host {
        if let Some(host) = headers_file_host {
            return host.to_string();
        }
        if let Some(custom_host) = &client_cfg.custom_http_header_host
            && let Ok(s) = custom_host.to_str()
        {
            return s.to_string();
        }
    }
    target_addr.request_authority()
}

/// Connect to a remote wstunnel server over HTTP/2, following HTTP 3xx redirects if encountered.
pub async fn connect(
    request_id: Uuid,
    client: &Client<impl crate::TokioExecutorRef>,
    dest_addr: &RemoteAddr,
) -> anyhow::Result<(Http2TransportRead, Http2TransportWrite, Parts)> {
    let client_cfg = &client.config;

    // In HTTP/2, the HOST header is not used directly; authority is set in the request URI. Parse the
    // headers file once for the whole attempt rather than once per hop.
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
    let (headers_file, headers_file_host) = (&headers_file, &headers_file_host);

    redirect::connect(client, |transport, addr, path_prefix, policy| async move {
        let authority = authority_for(
            &addr,
            client_cfg,
            headers_file_host.as_deref(),
            policy.keep_pinned_host,
        );

        let uri_scheme = match addr.scheme() {
            TransportScheme::Https | TransportScheme::Wss => "https",
            _ => "http",
        };

        let mut req = Request::builder()
            .method("POST")
            .uri(format!("{uri_scheme}://{authority}/{path_prefix}/events"))
            .header(COOKIE, tunnel_to_jwt_token(request_id, dest_addr))
            .header(CONTENT_TYPE, "application/json")
            .version(hyper::Version::HTTP_2);

        let headers = match req.headers_mut() {
            Some(h) => h,
            None => {
                return Err(anyhow!(
                    "failed to build HTTP request to contact the server {:?}. Most likely path_prefix `{}` or http headers is not valid",
                    addr,
                    path_prefix
                ));
            }
        };

        for (k, v) in &client_cfg.http_headers {
            if !policy.allows_header(k) {
                continue;
            }
            let _ = headers.remove(k);
            headers.append(k, v.clone());
        }

        if policy.keep_credentials
            && let Some(auth) = &client_cfg.http_upgrade_credentials
        {
            let _ = headers.remove(AUTHORIZATION);
            headers.append(AUTHORIZATION, auth.clone());
        }

        if let Some(headers_file) = headers_file {
            for (k, v) in headers_file {
                if !policy.allows_header(k) {
                    continue;
                }
                let _ = headers.remove(k);
                headers.append(k, v.clone());
            }
        }

        let (tx, rx) = mpsc::channel::<Bytes>(1024);
        let body =
            StreamBody::new(ReceiverStream::new(rx).map(|s| -> anyhow::Result<Frame<Bytes>> { Ok(Frame::data(s)) }));
        let req = req
            .body(body)
            .with_context(|| format!("failed to build HTTP request to contact the server {addr:?}"))?;
        debug!("with HTTP upgrade request {req:?}");

        let (mut request_sender, cnx) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .adaptive_window(true)
            .keep_alive_interval(client_cfg.websocket_ping_frequency)
            .keep_alive_timeout(Duration::from_secs(10))
            .keep_alive_while_idle(false)
            .handshake(TokioIo::new(transport))
            .await
            .with_context(|| format!("failed to do http2 handshake with the server {addr:?}"))?;

        let cnx_poller = client.executor.spawn(async move {
            if let Err(err) = cnx.await {
                error!("{err:?}")
            }
        });

        let response = match request_sender.send_request(req).await {
            Ok(response) => response,
            Err(err) => {
                // Abort the connection poller like the branches below do: a failed request can leave
                // the connection open (the server may have reset the stream, not the connection), and
                // then the task would keep polling it detached.
                cnx_poller.abort();
                return Err(err).with_context(|| format!("failed to send http2 request with the server {addr:?}"));
            }
        };

        let status = response.status();
        if status.is_success() {
            let (parts, body) = response.into_parts();
            Ok(HopOutcome::Connected((
                Http2TransportRead::new(BodyStream::new(body), Some(cnx_poller)),
                Http2TransportWrite::new(tx),
                parts,
            )))
        } else if status.is_redirection() {
            cnx_poller.abort();
            Ok(HopOutcome::Redirect {
                status,
                headers: response.headers().clone(),
            })
        } else {
            cnx_poller.abort();
            // The reply body is never parsed by wstunnel: the status is what matters. Reading it
            // would stall on a body the server may never finish and buffer whatever it does send;
            // it was also racy, since the connection poller is aborted just above.
            Err(anyhow!("Http2 server rejected the connection with status {status}"))
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DnsResolver;
    use crate::SoMark;
    use hyper::header::HeaderValue;
    use std::collections::HashMap;
    use std::time::Duration;
    use url::Host;

    fn make_test_cfg(custom_host: Option<&str>) -> ClientConfig {
        ClientConfig {
            remote_addr: TransportAddr::new(
                TransportScheme::Http,
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
            forward_credentials_on_redirect: false,
            tls_verify_certificate: false,
        }
    }

    #[test]
    fn test_authority_pinned_while_host_is_unchanged() {
        let cfg = make_test_cfg(Some("custom.example.com"));

        // The configured host uses the pinned authority
        assert_eq!(authority_for(&cfg.remote_addr, &cfg, None, true), "custom.example.com");

        // Same host on another port is still the service the pin was meant for
        let other_port =
            TransportAddr::new(TransportScheme::Http, Host::Domain("d1.example.com".to_string()), 9090, None).unwrap();
        assert_eq!(authority_for(&other_port, &cfg, None, true), "custom.example.com");

        // Another host derives the authority from the address being dialed
        let other_host =
            TransportAddr::new(TransportScheme::Http, Host::Domain("d2.example.com".to_string()), 9090, None).unwrap();
        assert_eq!(authority_for(&other_host, &cfg, None, false), "d2.example.com:9090");
    }

    #[test]
    fn test_authority_auto_derived_when_no_custom_host() {
        let cfg = make_test_cfg(None);
        let initial_addr = cfg.remote_addr.clone();
        let auth_initial = authority_for(&initial_addr, &cfg, None, true);
        assert_eq!(auth_initial, "d1.example.com:8080");
    }

    #[test]
    fn test_authority_elides_default_port() {
        let mut cfg = make_test_cfg(None);
        cfg.remote_addr =
            TransportAddr::new(TransportScheme::Http, Host::Domain("d1.example.com".to_string()), 80, None).unwrap();

        // Default port is elided, matching what wstunnel sent before redirection support
        assert_eq!(authority_for(&cfg.remote_addr, &cfg, None, true), "d1.example.com");
        // A redirected hop follows the same rule
        assert_eq!(authority_for(&cfg.remote_addr, &cfg, None, false), "d1.example.com");
    }
}
