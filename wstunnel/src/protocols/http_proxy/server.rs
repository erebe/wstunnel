use anyhow::Context;
use bytes::Bytes;
use log::{debug, error};
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine;
use futures_util::{Stream, future, stream};
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioTimer;
use parking_lot::Mutex;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::task::JoinSet;
use tracing::log::info;
use url::{Host, Url};

#[allow(clippy::type_complexity)]
pub struct HttpProxyListener {
    listener: Pin<Box<dyn Stream<Item = anyhow::Result<(TcpStream, (Host, u16))>> + Send>>,
}

impl Stream for HttpProxyListener {
    type Item = anyhow::Result<(TcpStream, (Host, u16))>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
        unsafe { self.map_unchecked_mut(|x| &mut x.listener) }.poll_next(cx)
    }
}

fn handle_http_connect_request(
    credentials: &Option<String>,
    dest: &Mutex<Option<(Host, u16)>>,
    req: Request<Incoming>,
) -> impl Future<Output = Result<Response<Empty<Bytes>>, &'static str>> {
    let ok_response = |forward_to: Option<(Host, u16)>| -> Result<Response<Empty<Bytes>>, _> {
        *dest.lock() = forward_to;
        Ok(Response::builder().status(200).body(Empty::new()).unwrap())
    };
    fn err_response() -> Result<Response<Empty<Bytes>>, &'static str> {
        info!("Un-authorized connection to http proxy");
        Ok(Response::builder().status(401).body(Empty::new()).unwrap())
    }

    if req.method() != hyper::Method::CONNECT {
        return future::ready(err_response());
    }

    debug!("HTTP Proxy CONNECT request to {}", req.uri());
    let forward_to = Host::parse(req.uri().host().unwrap_or_default())
        .ok()
        .map(|h| (h, req.uri().port_u16().unwrap_or(443)));

    let header = req
        .headers()
        .get(hyper::header::PROXY_AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    if !verify_credentials(credentials, &header) {
        return future::ready(err_response());
    }

    future::ready(ok_response(forward_to))
}

fn verify_credentials(credentials: &Option<String>, header_value: &Option<&str>) -> bool {
    const PROXY_AUTHORIZATION_PREFIX: &str = "Basic ";

    // no creds set, that's ok
    let Some(token) = credentials else {
        return true;
    };

    // creds set, and no auth provided, that's forbidden
    let Some(header_value) = header_value else {
        return false;
    };

    let auth = header_value.trim();
    auth.starts_with(PROXY_AUTHORIZATION_PREFIX) && &auth[PROXY_AUTHORIZATION_PREFIX.len()..] == token
}

pub async fn run_server(
    bind: SocketAddr,
    timeout: Option<Duration>,
    credentials: Option<(String, String)>,
) -> Result<HttpProxyListener, anyhow::Error> {
    info!("Starting http proxy server listening cnx on {bind} with credentials {credentials:?}");

    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("Cannot create TCP server {bind:?}"))?;

    let http1 = {
        let mut builder = http1::Builder::new();
        builder
            .timer(TokioTimer::new())
            .header_read_timeout(timeout)
            .keep_alive(false);
        builder
    };
    let auth_header =
        credentials.map(|(user, pass)| base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}")));
    let tasks = JoinSet::<Option<(TcpStream, Option<(Host, u16)>)>>::new();

    let proxy_cfg = Arc::new((auth_header, http1));
    let listener = stream::unfold((listener, tasks, proxy_cfg), |(listener, mut tasks, proxy_cfg)| async {
        loop {
            let (mut stream, forward_to) = select! {
                biased;

                cnx = tasks.join_next(), if !tasks.is_empty() => {
                    match cnx {
                        Some(Ok(Some((stream, Some(f))))) => (stream, Some(f)),
                        Some(Ok(Some((_, None)))) => {
                            // Bad request or UnAuthorized request
                            continue
                        },
                        None | Some(Ok(None)) => continue,
                        Some(Err(err)) => {
                            error!("Error while joinning tasks {err:?}");
                            continue
                        },
                    }
                },

                stream = listener.accept() => {
                    match stream {
                        Ok((stream, _)) => (stream, None),
                        Err(err) => {
                            error!("Error while accepting connection {err:?}");
                            continue;
                        }
                    }
                }
            };

            if let Some(forward_to) = forward_to {
                return Some((Ok((stream, forward_to)), (listener, tasks, proxy_cfg)));
            }

            let handle_new_cnx = {
                let proxy_cfg = proxy_cfg.clone();
                async move {
                    // We need to know if the http request if a CONNECT method or a regular one.
                    // HTTP CONNECT requires doing a handshake with client (which is easier)
                    // While for regular method, we need to replay the request as if it was done by the client.
                    // Non HTTP CONNECT method only works for non TLS connection/request.
                    let forward_to = {
                        // Get a pick at data to analyze http request
                        let mut request_buf = [0; 512];
                        let buf_size = stream.peek(&mut request_buf).await.ok()?;

                        // Parse http request. If no creds/auth is expected don't bother with headers
                        let mut headers = {
                            let headers_len = if proxy_cfg.0.is_some() { 32 } else { 0 };
                            vec![httparse::EMPTY_HEADER; headers_len]
                        };
                        let mut http_parser = httparse::Request::new(&mut headers);
                        let _ = http_parser.parse(&request_buf[..buf_size]);
                        if http_parser.method == Some(hyper::Method::CONNECT.as_str()) {
                            None
                        } else {
                            handle_regular_http_request(&http_parser, &proxy_cfg.0)
                        }
                    };

                    // Handle regular http request. Meaning we need to forward it directly as is
                    return if forward_to.is_some() {
                        Some((stream, forward_to))
                    } else {
                        // Handle HTTP CONNECT request
                        let http1 = &proxy_cfg.1;
                        let auth_header = &proxy_cfg.0;
                        let forward_to = Mutex::new(None);
                        let conn_fut = http1.serve_connection(
                            hyper_util::rt::TokioIo::new(&mut stream),
                            service_fn(|req| handle_http_connect_request(auth_header, &forward_to, req)),
                        );

                        match conn_fut.await {
                            Ok(_) => Some((stream, forward_to.into_inner())),
                            Err(err) => {
                                info!("Error while serving connection: {err}");
                                None
                            }
                        }
                    };
                }
            };
            tasks.spawn(handle_new_cnx);
        }
    });

    Ok(HttpProxyListener {
        listener: Box::pin(listener),
    })
}

fn handle_regular_http_request(http_parser: &httparse::Request, auth_header: &Option<String>) -> Option<(Host, u16)> {
    const DEFAULT_HTTP_PORT: u16 = 80;

    let header = http_parser.headers.iter().find_map(|h| {
        if h.name == hyper::header::PROXY_AUTHORIZATION {
            Some(String::from_utf8_lossy(h.value))
        } else {
            None
        }
    });

    if !verify_credentials(auth_header, &header.as_deref()) {
        return None;
    }

    let url = Url::parse(http_parser.path.unwrap_or("")).ok()?;
    let host = url.host().unwrap_or(Host::Ipv4(Ipv4Addr::UNSPECIFIED)).to_owned();
    let port = url.port_or_known_default().unwrap_or(DEFAULT_HTTP_PORT);

    Some((host, port))
}

//#[cfg(test)]
//mod tests {
//    use super::*;
//    use tracing::level_filters::LevelFilter;
//
//    #[tokio::test]
//    async fn test_run_server() {
//        tracing_subscriber::fmt()
//            .with_ansi(true)
//            .with_max_level(LevelFilter::TRACE)
//            .init();
//        let x = run_server("127.0.0.1:1212".parse().unwrap(), None, None).await;
//    }
//}
