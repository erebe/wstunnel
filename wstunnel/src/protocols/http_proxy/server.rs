use anyhow::Context;
use bytes::Bytes;
use log::{debug, error};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use crate::protocols::tcp;
use crate::somark::SoMark;
use base64::Engine;
use futures_util::{Stream, future, stream};
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioTimer;
use parking_lot::Mutex;
use socket2::SockRef;
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
    let ok_response = |forward_to: (Host, u16)| -> Result<Response<Empty<Bytes>>, _> {
        *dest.lock() = Some(forward_to);
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

    let Some(forward_to) = forward_to else {
        return future::ready(err_response());
    };

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

async fn handle_new_connection(
    proxy_cfg: Arc<(Option<String>, http1::Builder)>,
    mut stream: TcpStream,
) -> Option<(TcpStream, (Host, u16))> {
    // We need to know if the http request if a CONNECT method or a regular one.
    // HTTP CONNECT requires doing a handshake with client (which is easier)
    // While for regular method, we need to replay the request as if it was done by the client.
    // Non HTTP CONNECT method only works for non TLS connection/request.

    // to drop the request_buf early when not needed anymore
    {
        // Get a pick at data to analyze http request
        const CONNECT_METHOD: &[u8] = b"CONNECT ";
        let mut request_buf = [0; 512];

        // it is possible that the data is not yet available to us.
        // ideally, we should delay and retry the call until we have read enough bytes, or deadline elapsed.
        // But in practice and for the case of wstunnel, it is an edge case not worth handling.
        // So we parse what we have and reject the request if not enough bytes already.
        let buf_size = stream.peek(&mut request_buf).await.ok()?;

        if request_buf[..CONNECT_METHOD.len()] != *CONNECT_METHOD {
            // If no creds/auth is expected don't bother with headers
            let mut headers = {
                let headers_len = if proxy_cfg.0.is_some() { 32 } else { 0 };
                vec![httparse::EMPTY_HEADER; headers_len]
            };
            let mut http_parser = httparse::Request::new(&mut headers);
            let _ = http_parser.parse(&request_buf[..buf_size]);

            // if it is not an HTTP CONNECT request handle it directly
            return handle_regular_http_request(&http_parser, &proxy_cfg.0).map(|x| (stream, x));
        }
    }

    // Handle HTTP CONNECT request
    let (auth_header, http1) = proxy_cfg.as_ref();
    let forward_to = Mutex::new(None);
    let conn_fut = http1.serve_connection(
        hyper_util::rt::TokioIo::new(&mut stream),
        service_fn(|req| handle_http_connect_request(auth_header, &forward_to, req)),
    );

    match conn_fut.await {
        Ok(_) => forward_to.into_inner().map(|forward_to| (stream, forward_to)),
        Err(err) => {
            info!("Error while serving connection: {err}");
            None
        }
    }
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
    let tasks = JoinSet::<Option<(TcpStream, (Host, u16))>>::new();

    let proxy_cfg = Arc::new((auth_header, http1));
    let listener = stream::unfold((listener, tasks, proxy_cfg), |(listener, mut tasks, proxy_cfg)| async {
        loop {
            let (stream, forward_to) = select! {
                biased;

                cnx = tasks.join_next(), if !tasks.is_empty() => {
                    match cnx {
                        Some(Ok(Some((stream, f)))) => (stream, Some(f)),
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

            // We have a new connection to forward
            if let Some(forward_to) = forward_to {
                let _ = tcp::configure_socket(SockRef::from(&stream), SoMark::new(None));
                return Some((Ok((stream, forward_to)), (listener, tasks, proxy_cfg)));
            }

            // New incoming connection, parse and route the http request
            //let task = tokio::time::timeout(Duration::from_secs(10), handle_new_connection(proxy_cfg.clone(), stream));
            let task = handle_new_connection(proxy_cfg.clone(), stream);
            tasks.spawn(task);
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
    let host = url.host()?.to_owned();
    let port = url.port_or_known_default().unwrap_or(DEFAULT_HTTP_PORT);

    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::{fixture, rstest};
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    #[fixture]
    async fn connected_client() -> (TcpStream, TcpStream) {
        let server = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let client = TcpStream::connect(server.local_addr().unwrap()).await.unwrap();
        let (stream, _) = server.accept().await.unwrap();
        (client, stream)
    }

    #[rstest]
    // No host available, it should fail
    #[case("GET / HTTP/1.1\r\n\r\n", None, None)]
    // Partial request should fail
    #[case("GET ", None, None)]
    // Url is too long, it should fail. Limit is 512 bytes for the whole request
    #[case(String::from_iter(["GET google.com/".to_string(), "a".repeat(512), "  HTTP/1.1\r\n\r\n".to_string()]), None, None)]
    #[case("GET http://google.com/ HTTP/1.1\r\n\r\n", None, Some((Host::Domain("google.com".to_string()), 80)))]
    #[case("GET http://google.com/ HTTP/1.1\r\nProxy-Authorization: Basic toto\r\n\r\n", Some("toto"), Some((Host::Domain("google.com".to_string()), 80)))]
    #[case(
        "GET http://google.com/ HTTP/1.1\r\nProxy-Authorization: Basic toto\r\n\r\n",
        Some("tata"),
        None
    )]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    #[awt]
    async fn test_handle_new_connection(
        #[future] connected_client: (TcpStream, TcpStream),
        #[case] input: impl AsRef<[u8]>,
        #[case] auth: Option<&str>,
        #[case] expected_result: Option<(Host, u16)>,
    ) {
        let (mut client, stream) = connected_client;
        let auth_header = auth.map(|x| x.to_string());
        let proxy_cfg = Arc::new((auth_header, http1::Builder::new()));

        client.write_all(input.as_ref()).await.unwrap();

        let ret = handle_new_connection(proxy_cfg.clone(), stream).await;
        assert_eq!(ret.map(|(_, x)| x), expected_result);
    }

    #[rstest]
    // No host available, it should fail
    #[case("CONNECT / HTTP/1.0\r\n\r\n", None, None)]
    #[case("CONNECT google.com:80 HTTP/1.1\r\n\r\n", None, Some((Host::Domain("google.com".to_string()), 80)))]
    #[case("CONNECT google.com HTTP/1.1\r\n\r\n", None, Some((Host::Domain("google.com".to_string()), 443)))]
    #[case("CONNECT google.com HTTP/1.1\r\nProxy-Authorization: Basic toto\r\n\r\n", Some("toto"), Some((Host::Domain("google.com".to_string()), 443)))]
    #[case(
        "CONNECT google.com HTTP/1.0\r\nProxy-Authorization: Basic toto\r\n\r\n",
        Some("tata"),
        None
    )]
    #[timeout(Duration::from_secs(10))]
    #[tokio::test]
    #[awt]
    async fn test_handle_new_connect_connection(
        #[future] connected_client: (TcpStream, TcpStream),
        #[case] input: impl AsRef<[u8]>,
        #[case] auth: Option<&str>,
        #[case] expected_result: Option<(Host, u16)>,
    ) {
        let (mut client, stream) = connected_client;
        let auth_header = auth.map(|x| x.to_string());
        let proxy_cfg = Arc::new((auth_header, http1::Builder::new()));

        client.write_all(input.as_ref()).await.unwrap();

        let ret = handle_new_connection(proxy_cfg.clone(), stream).await;
        assert_eq!(ret.map(|(_, x)| x), expected_result);

        let mut buf = Vec::with_capacity(1024);
        client.read_to_end(&mut buf).await.unwrap();
        if expected_result.is_some() {
            assert_eq!(String::from_utf8_lossy(&buf)[..17], *"HTTP/1.1 200 OK\r\n");
        } else {
            assert_eq!(String::from_utf8_lossy(&buf)[..27], *"HTTP/1.0 401 Unauthorized\r\n");
        }
    }
}
