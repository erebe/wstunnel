use super::{JwtTunnelConfig, RemoteAddr, TransportScheme, JWT_DECODE};
use crate::tunnel::transport::{TunnelReader, TunnelWriter};
use crate::{tunnel, WsClientConfig};
use futures_util::pin_mut;
use hyper::header::COOKIE;
use jsonwebtoken::TokenData;
use log::debug;
use std::future::Future;
use std::ops::Deref;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tokio_stream::{Stream, StreamExt};
use tracing::{error, span, Instrument, Level, Span};
use url::Host;
use uuid::Uuid;

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
    // Connect to server with the correct protocol
    let (ws_rx, ws_tx, response) = match client_cfg.remote_addr.scheme() {
        TransportScheme::Ws | TransportScheme::Wss => {
            tunnel::transport::websocket::connect(request_id, client_cfg, remote_cfg)
                .await
                .map(|(r, w, response)| (TunnelReader::Websocket(r), TunnelWriter::Websocket(w), response))?
        }
        TransportScheme::Http | TransportScheme::Https => {
            tunnel::transport::http2::connect(request_id, client_cfg, remote_cfg)
                .await
                .map(|(r, w, response)| (TunnelReader::Http2(r), TunnelWriter::Http2(w), response))?
        }
    };

    debug!("Server response: {:?}", response);
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
    client_cfg: Arc<WsClientConfig>,
    remote_addr: RemoteAddr,
    connect_to_dest: F,
) -> anyhow::Result<()>
where
    F: Fn(Option<RemoteAddr>) -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
    T: AsyncRead + AsyncWrite + Send + 'static,
{
    loop {
        let client_config = client_cfg.clone();
        let request_id = Uuid::now_v7();
        let span = span!(
            Level::INFO,
            "tunnel",
            id = request_id.to_string(),
            remote = format!("{}:{}", remote_addr.host, remote_addr.port)
        );
        let _span = span.enter();
        // Correctly configure tunnel cfg
        let (ws_rx, ws_tx, response) = match client_cfg.remote_addr.scheme() {
            TransportScheme::Ws | TransportScheme::Wss => {
                tunnel::transport::websocket::connect(request_id, &client_cfg, &remote_addr)
                    .instrument(span.clone())
                    .await
                    .map(|(r, w, response)| (TunnelReader::Websocket(r), TunnelWriter::Websocket(w), response))?
            }
            TransportScheme::Http | TransportScheme::Https => {
                tunnel::transport::http2::connect(request_id, &client_cfg, &remote_addr)
                    .instrument(span.clone())
                    .await
                    .map(|(r, w, response)| (TunnelReader::Http2(r), TunnelWriter::Http2(w), response))?
            }
        };

        // Connect to endpoint
        debug!("Server response: {:?}", response);
        let remote = response
            .headers
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
