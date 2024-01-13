use super::{tunnel_to_jwt_token, JwtTunnelConfig, RemoteAddr, JWT_DECODE, JWT_HEADER_PREFIX};
use crate::WsClientConfig;
use anyhow::{anyhow, Context};

use bytes::Bytes;
use fastwebsockets::WebSocket;
use futures_util::pin_mut;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, COOKIE, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION, UPGRADE};
use hyper::header::{CONNECTION, HOST, SEC_WEBSOCKET_KEY};
use hyper::upgrade::Upgraded;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use jsonwebtoken::TokenData;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tokio_stream::{Stream, StreamExt};
use tracing::log::debug;
use tracing::{error, span, Instrument, Level, Span};
use url::Host;
use uuid::Uuid;

async fn connect(
    request_id: Uuid,
    client_cfg: &WsClientConfig,
    dest_addr: &RemoteAddr,
) -> anyhow::Result<(WebSocket<TokioIo<Upgraded>>, Response<Incoming>)> {
    let mut pooled_cnx = match client_cfg.cnx_pool().get().await {
        Ok(cnx) => Ok(cnx),
        Err(err) => Err(anyhow!("failed to get a connection to the server from the pool: {err:?}")),
    }?;

    let mut req = Request::builder()
        .method("GET")
        .uri(format!("/{}/events", &client_cfg.http_upgrade_path_prefix,))
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

    for (k, v) in &client_cfg.http_headers {
        req = req.header(k, v);
    }
    if let Some(auth) = &client_cfg.http_upgrade_credentials {
        req = req.header(AUTHORIZATION, auth);
    }

    let req = req.body(Empty::<Bytes>::new()).with_context(|| {
        format!(
            "failed to build HTTP request to contact the server {:?}",
            client_cfg.remote_addr
        )
    })?;
    debug!("with HTTP upgrade request {:?}", req);
    let transport = pooled_cnx.deref_mut().take().unwrap();
    let (ws, response) = fastwebsockets::handshake::client(&TokioExecutor::new(), req, transport)
        .await
        .with_context(|| format!("failed to do websocket handshake with the server {:?}", client_cfg.remote_addr))?;

    Ok((ws, response))
}

//async fn connect_http2(
//    request_id: Uuid,
//    client_cfg: &WsClientConfig,
//    dest_addr: &RemoteAddr,
//) -> anyhow::Result<BodyStream<Incoming>> {
//    let mut pooled_cnx = match client_cfg.cnx_pool().get().await {
//        Ok(cnx) => Ok(cnx),
//        Err(err) => Err(anyhow!("failed to get a connection to the server from the pool: {err:?}")),
//    }?;
//
//    let mut req = Request::builder()
//        .method("GET")
//        .uri(format!("/{}/events", &client_cfg.http_upgrade_path_prefix))
//        .header(HOST, &client_cfg.http_header_host)
//        .header(COOKIE, tunnel_to_jwt_token(request_id, dest_addr))
//        .version(hyper::Version::HTTP_2);
//
//    for (k, v) in &client_cfg.http_headers {
//        req = req.header(k, v);
//    }
//    if let Some(auth) = &client_cfg.http_upgrade_credentials {
//        req = req.header(AUTHORIZATION, auth);
//    }
//
//    let x: Vec<u8> = vec![];
//    //let bosy = StreamBody::new(stream::iter(vec![anyhow::Result::Ok(hyper::body::Frame::data(x.as_slice()))]));
//    let req = req.body(Empty::<Bytes>::new()).with_context(|| {
//        format!(
//            "failed to build HTTP request to contact the server {:?}",
//            client_cfg.remote_addr
//        )
//    })?;
//    debug!("with HTTP upgrade request {:?}", req);
//    let transport = pooled_cnx.deref_mut().take().unwrap();
//    let (mut request_sender, cnx) = hyper::client::conn::http2::Builder::new(TokioExecutor::new()).handshake(TokioIo::new(transport)).await
//        .with_context(|| format!("failed to do http2 handshake with the server {:?}", client_cfg.remote_addr))?;
//    tokio::spawn(cnx);
//
//    let response = request_sender.send_request(req)
//        .await
//        .with_context(|| format!("failed to send http2 request with the server {:?}", client_cfg.remote_addr))?;
//
//    // TODO: verify response is ok
//    Ok(BodyStream::new(response.into_body()))
//}

async fn connect_to_server<R, W>(
    request_id: Uuid,
    client_cfg: &WsClientConfig,
    remote_cfg: &RemoteAddr,
    duplex_stream: (R, W),
) -> anyhow::Result<()>
where
    R: AsyncRead + Send + 'static,
    W: AsyncWrite + Send + 'static,
{
    let (mut ws, _) = connect(request_id, client_cfg, remote_cfg).await?;
    ws.set_auto_apply_mask(client_cfg.websocket_mask_frame);

    let (ws_rx, ws_tx) = ws.split(tokio::io::split);
    let (local_rx, local_tx) = duplex_stream;
    let (close_tx, close_rx) = oneshot::channel::<()>();

    // Forward local tx to websocket tx
    let ping_frequency = client_cfg.websocket_ping_frequency;
    tokio::spawn(
        super::transport::io::propagate_local_to_remote(local_rx, ws_tx, close_tx, Some(ping_frequency))
            .instrument(Span::current()),
    );

    // Forward websocket rx to local rx
    let _ = super::transport::io::propagate_remote_to_local(local_tx, ws_rx, close_rx).await;

    Ok(())
}

pub async fn run_tunnel<T, R, W>(client_config: Arc<WsClientConfig>, incoming_cnx: T) -> anyhow::Result<()>
where
    T: Stream<Item = anyhow::Result<((R, W), RemoteAddr)>>,
    R: AsyncRead + Send + 'static,
    W: AsyncWrite + Send + 'static,
{
    pin_mut!(incoming_cnx);
    while let Some(Ok((cnx_stream, remote_addr))) = incoming_cnx.next().await {
        let request_id = Uuid::now_v7();
        let span = span!(
            Level::INFO,
            "tunnel",
            id = request_id.to_string(),
            remote = format!("{}:{}", remote_addr.host, remote_addr.port)
        );
        let client_config = client_config.clone();

        let tunnel = async move {
            let _ = connect_to_server(request_id, &client_config, &remote_addr, cnx_stream)
                .await
                .map_err(|err| error!("{:?}", err));
        }
        .instrument(span);

        tokio::spawn(tunnel);
    }

    Ok(())
}

pub async fn run_reverse_tunnel<F, Fut, T>(
    client_config: Arc<WsClientConfig>,
    remote_addr: RemoteAddr,
    connect_to_dest: F,
) -> anyhow::Result<()>
where
    F: Fn(Option<RemoteAddr>) -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
    T: AsyncRead + AsyncWrite + Send + 'static,
{
    loop {
        let client_config = client_config.clone();
        let request_id = Uuid::now_v7();
        let span = span!(
            Level::INFO,
            "tunnel",
            id = request_id.to_string(),
            remote = format!("{}:{}", remote_addr.host, remote_addr.port)
        );
        let _span = span.enter();

        // Correctly configure tunnel cfg
        let (mut ws, response) = connect(request_id, &client_config, &remote_addr)
            .instrument(span.clone())
            .await?;
        ws.set_auto_apply_mask(client_config.websocket_mask_frame);

        // Connect to endpoint
        let remote = response
            .headers()
            .get(COOKIE)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| {
                let (validation, decode_key) = JWT_DECODE.deref();
                let jwt: Option<TokenData<JwtTunnelConfig>> = jsonwebtoken::decode(h, decode_key, validation).ok();
                jwt
            })
            .map(|jwt| RemoteAddr {
                protocol: jwt.claims.p,
                host: Host::parse(&jwt.claims.r).unwrap_or_else(|_| Host::Domain(String::new())),
                port: jwt.claims.rp,
            });

        let stream = match connect_to_dest(remote).instrument(span.clone()).await {
            Ok(s) => s,
            Err(err) => {
                error!("Cannot connect to xxxx: {err:?}");
                continue;
            }
        };

        let (local_rx, local_tx) = tokio::io::split(stream);
        let (ws_rx, ws_tx) = ws.split(tokio::io::split);
        let (close_tx, close_rx) = oneshot::channel::<()>();

        let tunnel = async move {
            let ping_frequency = client_config.websocket_ping_frequency;
            tokio::spawn(
                super::transport::io::propagate_local_to_remote(local_rx, ws_tx, close_tx, Some(ping_frequency))
                    .instrument(Span::current()),
            );

            // Forward websocket rx to local rx
            let _ = super::transport::io::propagate_remote_to_local(local_tx, ws_rx, close_rx).await;
        }
        .instrument(span.clone());
        tokio::spawn(tunnel);
    }
}
