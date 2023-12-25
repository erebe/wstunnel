use ahash::{HashMap, HashMapExt};
use anyhow::anyhow;
use base64::Engine;
use futures_util::{pin_mut, FutureExt, Stream, StreamExt};
use std::cmp::min;
use std::fmt::Debug;
use std::future::Future;
use std::ops::{Deref, Not};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use super::{JwtTunnelConfig, JWT_DECODE};
use crate::{socks5, tcp, tls, udp, LocalProtocol, WsServerConfig};
use hyper::body::Incoming;
use hyper::header::COOKIE;
use hyper::http::HeaderValue;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{http, Request, Response, StatusCode};
use jsonwebtoken::TokenData;
use once_cell::sync::Lazy;
use parking_lot::Mutex;

use crate::udp::UdpStream;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, span, warn, Instrument, Level, Span};
use url::Host;

async fn run_tunnel(
    server_config: &WsServerConfig,
    jwt: TokenData<JwtTunnelConfig>,
) -> anyhow::Result<(
    LocalProtocol,
    Host,
    u16,
    Pin<Box<dyn AsyncRead + Send>>,
    Pin<Box<dyn AsyncWrite + Send>>,
)> {
    match jwt.claims.p {
        LocalProtocol::Udp { timeout, .. } => {
            let host = Host::parse(&jwt.claims.r)?;
            let cnx = udp::connect(
                &host,
                jwt.claims.rp,
                timeout.unwrap_or(Duration::from_secs(10)),
                &server_config.dns_resolver,
            )
            .await?;
            Ok((
                LocalProtocol::Udp { timeout: None },
                host,
                jwt.claims.rp,
                Box::pin(cnx.clone()),
                Box::pin(cnx),
            ))
        }
        LocalProtocol::Tcp => {
            let host = Host::parse(&jwt.claims.r)?;
            let port = jwt.claims.rp;
            let (rx, tx) = tcp::connect(
                &host,
                port,
                server_config.socket_so_mark,
                Duration::from_secs(10),
                &server_config.dns_resolver,
            )
            .await?
            .into_split();

            Ok((jwt.claims.p, host, port, Box::pin(rx), Box::pin(tx)))
        }
        LocalProtocol::ReverseTcp => {
            #[allow(clippy::type_complexity)]
            static SERVERS: Lazy<Mutex<HashMap<(Host<String>, u16), mpsc::Receiver<TcpStream>>>> =
                Lazy::new(|| Mutex::new(HashMap::with_capacity(0)));

            let local_srv = (Host::parse(&jwt.claims.r)?, jwt.claims.rp);
            let bind = format!("{}:{}", local_srv.0, local_srv.1);
            let listening_server = tcp::run_server(bind.parse()?, false);
            let tcp = run_listening_server(&local_srv, SERVERS.deref(), listening_server).await?;
            let (local_rx, local_tx) = tcp.into_split();

            Ok((jwt.claims.p, local_srv.0, local_srv.1, Box::pin(local_rx), Box::pin(local_tx)))
        }
        LocalProtocol::ReverseUdp { timeout } => {
            #[allow(clippy::type_complexity)]
            static SERVERS: Lazy<Mutex<HashMap<(Host<String>, u16), mpsc::Receiver<UdpStream>>>> =
                Lazy::new(|| Mutex::new(HashMap::with_capacity(0)));

            let local_srv = (Host::parse(&jwt.claims.r)?, jwt.claims.rp);
            let bind = format!("{}:{}", local_srv.0, local_srv.1);
            let listening_server =
                udp::run_server(bind.parse()?, timeout, |_| Ok(()), |send_socket| Ok(send_socket.clone()));
            let udp = run_listening_server(&local_srv, SERVERS.deref(), listening_server).await?;
            let (local_rx, local_tx) = tokio::io::split(udp);

            Ok((jwt.claims.p, local_srv.0, local_srv.1, Box::pin(local_rx), Box::pin(local_tx)))
        }
        LocalProtocol::ReverseSocks5 => {
            #[allow(clippy::type_complexity)]
            static SERVERS: Lazy<Mutex<HashMap<(Host<String>, u16), mpsc::Receiver<(TcpStream, (Host, u16))>>>> =
                Lazy::new(|| Mutex::new(HashMap::with_capacity(0)));

            let local_srv = (Host::parse(&jwt.claims.r)?, jwt.claims.rp);
            let bind = format!("{}:{}", local_srv.0, local_srv.1);
            let listening_server = socks5::run_server(bind.parse()?);
            let (tcp, local_srv) = run_listening_server(&local_srv, SERVERS.deref(), listening_server).await?;
            let (local_rx, local_tx) = tokio::io::split(tcp);

            Ok((jwt.claims.p, local_srv.0, local_srv.1, Box::pin(local_rx), Box::pin(local_tx)))
        }
        _ => Err(anyhow::anyhow!("Invalid upgrade request")),
    }
}

#[allow(clippy::type_complexity)]
async fn run_listening_server<T, Fut, FutOut, E>(
    local_srv: &(Host, u16),
    servers: &Mutex<HashMap<(Host<String>, u16), mpsc::Receiver<T>>>,
    gen_listening_server: Fut,
) -> anyhow::Result<T>
where
    Fut: Future<Output = anyhow::Result<FutOut>>,
    FutOut: Stream<Item = Result<T, E>> + Send + 'static,
    E: Debug + Send,
    T: Send + 'static,
{
    let listening_server = servers.lock().remove(local_srv);
    let mut listening_server = if let Some(listening_server) = listening_server {
        listening_server
    } else {
        let listening_server = gen_listening_server.await?;
        let (tx, rx) = mpsc::channel::<T>(1);
        let fut = async move {
            pin_mut!(listening_server);
            loop {
                select! {
                    biased;
                    cnx = listening_server.next() => {
                       match cnx {
                            None => break,
                            Some(Err(err)) => {
                                warn!("Error while listening for incoming connections {err:?}");
                                break;
                            }
                            Some(Ok(cnx)) => {
                                if tx.send_timeout(cnx, Duration::from_secs(30)).await.is_err() {
                                    break;
                                }
                            }
                        }
                    },

                    _ = tx.closed() => {
                        break;
                    }
                }
            }
            info!("Stopping listening server");
        };

        tokio::spawn(fut.instrument(Span::current()));
        rx
    };

    let cnx = listening_server
        .recv()
        .await
        .ok_or_else(|| anyhow!("listening server stopped"))?;
    servers.lock().insert(local_srv.clone(), listening_server);
    Ok(cnx)
}

#[inline]
fn extract_x_forwarded_for(req: &Request<Incoming>) -> Result<Option<&str>, Response<String>> {
    let Some(x_forward_for) = req.headers().get("X-Forwarded-For") else {
        return Ok(None);
    };

    Ok(Some(x_forward_for.to_str().unwrap_or_default()))
}

#[inline]
fn validate_url(
    req: &Request<Incoming>,
    path_restriction_prefix: &Option<Vec<String>>,
) -> Result<(), Response<String>> {
    if !req.uri().path().ends_with("/events") {
        warn!("Rejecting connection with bad upgrade request: {}", req.uri());
        return Err(http::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("Invalid upgrade request".into())
            .unwrap());
    }

    if let Some(paths_prefix) = &path_restriction_prefix {
        let path = req.uri().path();
        let min_len = min(path.len(), 1);
        let mut max_len = 0;
        if &path[0..min_len] != "/"
            || !paths_prefix.iter().any(|p| {
                max_len = min(path.len(), p.len() + 1);
                p == &path[min_len..max_len]
            })
            || !path[max_len..].starts_with('/')
        {
            warn!("Rejecting connection with bad path prefix in upgrade request: {}", req.uri());
            return Err(http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Invalid upgrade request".to_string())
                .unwrap());
        }
    }

    Ok(())
}

#[inline]
fn extract_tunnel_info(req: &Request<Incoming>) -> Result<TokenData<JwtTunnelConfig>, Response<String>> {
    let jwt: TokenData<JwtTunnelConfig> = match req.uri().query().unwrap_or_default().split_once('=') {
        Some(("bearer", jwt)) => {
            let (validation, decode_key) = JWT_DECODE.deref();
            match jsonwebtoken::decode(jwt, decode_key, validation) {
                Ok(jwt) => jwt,
                err => {
                    error!("error while decoding jwt for tunnel info {:?}", err);
                    return Err(http::Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body("Invalid upgrade request".to_string())
                        .unwrap());
                }
            }
        }
        err => {
            error!("Missing jwt tunnel config from request {:?}", err);
            return Err(http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Invalid upgrade request".to_string())
                .unwrap());
        }
    };

    Ok(jwt)
}

#[inline]
fn validate_destination(
    _req: &Request<Incoming>,
    jwt: &TokenData<JwtTunnelConfig>,
    destination_restriction: &Option<Vec<String>>,
) -> Result<(), Response<String>> {
    let Some(allowed_dests) = &destination_restriction else {
        return Ok(());
    };

    let requested_dest = format!("{}:{}", jwt.claims.r, jwt.claims.rp);
    if allowed_dests.iter().any(|dest| dest == &requested_dest).not() {
        warn!("Rejecting connection with not allowed destination: {}", requested_dest);
        return Err(http::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("Invalid upgrade request".to_string())
            .unwrap());
    }

    Ok(())
}

async fn server_upgrade(server_config: Arc<WsServerConfig>, mut req: Request<Incoming>) -> Response<String> {
    if !fastwebsockets::upgrade::is_upgrade_request(&req) {
        warn!("Rejecting connection with bad upgrade request: {}", req.uri());
        return http::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("Invalid upgrade request".to_string())
            .unwrap();
    }

    match extract_x_forwarded_for(&req) {
        Ok(Some(x_forward_for)) => {
            info!("Request X-Forwarded-For: {:?}", x_forward_for);
            Span::current().record("forwarded_for", x_forward_for);
        }
        Ok(_) => {}
        Err(err) => return err,
    }

    if let Err(err) = validate_url(&req, &server_config.restrict_http_upgrade_path_prefix) {
        return err;
    }

    let jwt = match extract_tunnel_info(&req) {
        Ok(jwt) => jwt,
        Err(err) => return err,
    };

    Span::current().record("id", &jwt.claims.id);
    Span::current().record("remote", format!("{}:{}", jwt.claims.r, jwt.claims.rp));

    if let Err(err) = validate_destination(&req, &jwt, &server_config.restrict_to) {
        return err;
    }

    let tunnel = match run_tunnel(&server_config, jwt).await {
        Ok(ret) => ret,
        Err(err) => {
            warn!("Rejecting connection with bad upgrade request: {} {}", err, req.uri());
            return http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Invalid upgrade request".to_string())
                .unwrap();
        }
    };

    let (protocol, dest, port, local_rx, local_tx) = tunnel;
    info!("connected to {:?} {:?} {:?}", protocol, dest, port);
    let (mut response, fut) = match fastwebsockets::upgrade::upgrade(&mut req) {
        Ok(ret) => ret,
        Err(err) => {
            warn!("Rejecting connection with bad upgrade request: {} {}", err, req.uri());
            return http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(format!("Invalid upgrade request: {:?}", err))
                .unwrap();
        }
    };

    tokio::spawn(
        async move {
            let (ws_rx, mut ws_tx) = match fut.await {
                Ok(ws) => ws.split(tokio::io::split),
                Err(err) => {
                    error!("Error during http upgrade request: {:?}", err);
                    return;
                }
            };
            let (close_tx, close_rx) = oneshot::channel::<()>();
            ws_tx.set_auto_apply_mask(server_config.websocket_mask_frame);

            tokio::task::spawn(super::io::propagate_write(local_tx, ws_rx, close_rx).instrument(Span::current()));

            let _ = super::io::propagate_read(local_rx, ws_tx, close_tx, None).await;
        }
        .instrument(Span::current()),
    );

    if protocol == LocalProtocol::ReverseSocks5 {
        let Ok(header_val) = HeaderValue::from_str(
            &base64::engine::general_purpose::STANDARD.encode(format!("fake://{}:{}", dest, port)),
        ) else {
            error!("Bad headervalue for reverse socks5: {} {}", dest, port);
            return http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Invalid upgrade request".to_string())
                .unwrap();
        };
        response.headers_mut().insert(COOKIE, header_val);
    }

    Response::from_parts(response.into_parts().0, "".to_string())
}

pub async fn run_server(server_config: Arc<WsServerConfig>) -> anyhow::Result<()> {
    info!("Starting wstunnel server listening on {}", server_config.bind);

    let config = server_config.clone();
    let upgrade_fn = move |req: Request<Incoming>| server_upgrade(config.clone(), req).map::<anyhow::Result<_>, _>(Ok);

    let listener = TcpListener::bind(&server_config.bind).await?;
    let tls_acceptor = if let Some(tls) = &server_config.tls {
        Some(tls::tls_acceptor(tls, Some(vec![b"http/1.1".to_vec()]))?)
    } else {
        None
    };

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let _ = stream.set_nodelay(true);

        let span = span!(
            Level::INFO,
            "tunnel",
            id = tracing::field::Empty,
            remote = tracing::field::Empty,
            peer = peer_addr.to_string(),
            forwarded_for = tracing::field::Empty
        );

        info!("Accepting connection");
        let upgrade_fn = upgrade_fn.clone();
        // TLS
        if let Some(tls_acceptor) = &tls_acceptor {
            let tls_acceptor = tls_acceptor.clone();
            let fut = async move {
                info!("Doing TLS handshake");
                let tls_stream = match tls_acceptor.accept(stream).await {
                    Ok(tls_stream) => hyper_util::rt::TokioIo::new(tls_stream),
                    Err(err) => {
                        error!("error while accepting TLS connection {}", err);
                        return;
                    }
                };

                let conn_fut = http1::Builder::new()
                    .serve_connection(tls_stream, service_fn(upgrade_fn))
                    .with_upgrades();

                if let Err(e) = conn_fut.await {
                    error!("Error while upgrading cnx to websocket: {:?}", e);
                }
            }
            .instrument(span);

            tokio::spawn(fut);
            // Normal
        } else {
            let stream = hyper_util::rt::TokioIo::new(stream);
            let conn_fut = http1::Builder::new()
                .serve_connection(stream, service_fn(upgrade_fn))
                .with_upgrades();

            let fut = async move {
                if let Err(e) = conn_fut.await {
                    error!("Error while upgrading cnx to websocket: {:?}", e);
                }
            }
            .instrument(span);

            tokio::spawn(fut);
        };
    }
}
