use crate::tunnel;
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::WsClientConfig;
use crate::tunnel::client::cnx_pool::WsConnection;
use crate::tunnel::connectors::TunnelConnector;
use crate::tunnel::listeners::TunnelListener;
use crate::tunnel::tls_reloader::TlsReloader;
use crate::tunnel::transport::io::{TunnelReader, TunnelWriter};
use crate::tunnel::transport::{TransportScheme, jwt_token_to_tunnel};
use anyhow::Context;
use futures_util::pin_mut;
use hyper::header::COOKIE;
use log::debug;
use std::cmp::min;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tracing::{Instrument, Level, Span, error, event, span};
use url::Host;
use uuid::Uuid;

#[derive(Clone)]
pub struct WsClient {
    pub config: Arc<WsClientConfig>,
    pub cnx_pool: bb8::Pool<WsConnection>,
    reverse_reconnect_max_delay: Duration,
    _tls_reloader: Arc<TlsReloader>,
}

impl WsClient {
    pub async fn new(
        config: WsClientConfig,
        connection_min_idle: u32,
        connection_retry_max_backoff_sec: Duration,
        reverse_reconnect_max_delay: Duration,
    ) -> anyhow::Result<Self> {
        let config = Arc::new(config);
        let cnx = WsConnection::new(config.clone());
        let tls_reloader = TlsReloader::new_for_client(config.clone()).with_context(|| "Cannot create tls reloader")?;
        let cnx_pool = bb8::Pool::builder()
            .max_size(1000)
            .min_idle(Some(connection_min_idle))
            .max_lifetime(Some(Duration::from_secs(30)))
            .connection_timeout(connection_retry_max_backoff_sec)
            .retry_connection(true)
            .build(cnx)
            .await?;

        Ok(Self {
            config,
            cnx_pool,
            reverse_reconnect_max_delay,
            _tls_reloader: Arc::new(tls_reloader),
        })
    }
}

impl WsClient {
    async fn connect_to_server<R, W>(
        &self,
        request_id: Uuid,
        remote_cfg: &RemoteAddr,
        duplex_stream: (R, W),
    ) -> anyhow::Result<()>
    where
        R: AsyncRead + Send + 'static,
        W: AsyncWrite + Send + 'static,
    {
        // Connect to server with the correct protocol
        let (ws_rx, ws_tx, response) = match self.config.remote_addr.scheme() {
            TransportScheme::Ws | TransportScheme::Wss => {
                tunnel::transport::websocket::connect(request_id, self, remote_cfg)
                    .await
                    .map(|(r, w, response)| (TunnelReader::Websocket(r), TunnelWriter::Websocket(w), response))?
            }
            TransportScheme::Http | TransportScheme::Https => {
                tunnel::transport::http2::connect(request_id, self, remote_cfg)
                    .await
                    .map(|(r, w, response)| (TunnelReader::Http2(r), TunnelWriter::Http2(w), response))?
            }
        };

        debug!("Server response: {:?}", response);
        let (local_rx, local_tx) = duplex_stream;
        let (close_tx, close_rx) = oneshot::channel::<()>();

        // Forward local tx to websocket tx
        let ping_frequency = self.config.websocket_ping_frequency;
        tokio::spawn(
            super::super::transport::io::propagate_local_to_remote(local_rx, ws_tx, close_tx, ping_frequency)
                .instrument(Span::current()),
        );

        // Forward websocket rx to local rx
        let _ = super::super::transport::io::propagate_remote_to_local(local_tx, ws_rx, close_rx).await;

        Ok(())
    }

    pub async fn run_tunnel(self, tunnel_listener: impl TunnelListener) -> anyhow::Result<()> {
        pin_mut!(tunnel_listener);
        while let Some(cnx) = tunnel_listener.next().await {
            let (cnx_stream, remote_addr) = match cnx {
                Ok((cnx_stream, remote_addr)) => (cnx_stream, remote_addr),
                Err(err) => {
                    error!("Error accepting connection: {:?}", err);
                    continue;
                }
            };

            let request_id = Uuid::now_v7();
            let span = span!(
                Level::INFO,
                "tunnel",
                id = request_id.to_string(),
                remote = format!("{}:{}", remote_addr.host, remote_addr.port)
            );
            let client = self.clone();
            let tunnel = async move {
                let _ = client
                    .connect_to_server(request_id, &remote_addr, cnx_stream)
                    .await
                    .map_err(|err| error!("{:?}", err));
            }
            .instrument(span);

            tokio::spawn(tunnel);
        }

        Ok(())
    }

    pub async fn run_reverse_tunnel(
        self,
        remote_addr: RemoteAddr,
        connector: impl TunnelConnector,
    ) -> anyhow::Result<()> {
        const INITIAL_DELAY: Duration = Duration::from_secs(1);
        let mut delay = INITIAL_DELAY;

        loop {
            let client = self.clone();
            let request_id = Uuid::now_v7();
            let span = span!(
                Level::INFO,
                "tunnel",
                id = request_id.to_string(),
                remote = format!("{}:{}", remote_addr.host, remote_addr.port)
            );
            // Correctly configure tunnel cfg
            let (ws_rx, ws_tx, response) = match client.config.remote_addr.scheme() {
                TransportScheme::Ws | TransportScheme::Wss => {
                    match tunnel::transport::websocket::connect(request_id, &client, &remote_addr)
                        .instrument(span.clone())
                        .await
                    {
                        Ok((r, w, response)) => (TunnelReader::Websocket(r), TunnelWriter::Websocket(w), response),
                        Err(err) => {
                            event!(parent: &span, Level::ERROR, "Retrying in {:?}, cannot connect to remote server: {:?}", delay, err);
                            tokio::time::sleep(delay).await;
                            delay = min(delay * 2, self.reverse_reconnect_max_delay);
                            continue;
                        }
                    }
                }
                TransportScheme::Http | TransportScheme::Https => {
                    match tunnel::transport::http2::connect(request_id, &client, &remote_addr)
                        .instrument(span.clone())
                        .await
                    {
                        Ok((r, w, response)) => (TunnelReader::Http2(r), TunnelWriter::Http2(w), response),
                        Err(err) => {
                            event!(parent: &span, Level::ERROR, "Retrying in {:?}, cannot connect to remote server: {:?}", delay, err);
                            tokio::time::sleep(delay).await;
                            delay = min(delay * 2, self.reverse_reconnect_max_delay);
                            continue;
                        }
                    }
                }
            };
            delay = INITIAL_DELAY;

            // Connect to endpoint
            event!(parent: &span, Level::DEBUG, "Server response: {:?}", response);
            let remote = response
                .headers
                .get(COOKIE)
                .and_then(|h| h.to_str().ok())
                .and_then(|h| jwt_token_to_tunnel(h).ok())
                .map(|jwt| RemoteAddr {
                    protocol: jwt.claims.p,
                    host: Host::parse(&jwt.claims.r).unwrap_or_else(|_| Host::Domain(String::new())),
                    port: jwt.claims.rp,
                });

            let (local_rx, local_tx) = match connector.connect(&remote).instrument(span.clone()).await {
                Ok(s) => s,
                Err(err) => {
                    event!(parent: &span, Level::ERROR, "Cannot connect to {remote:?}: {err:?}");
                    continue;
                }
            };

            let (close_tx, close_rx) = oneshot::channel::<()>();
            let tunnel = async move {
                let ping_frequency = client.config.websocket_ping_frequency;
                tokio::spawn(
                    super::super::transport::io::propagate_local_to_remote(local_rx, ws_tx, close_tx, ping_frequency)
                        .in_current_span(),
                );

                // Forward websocket rx to local rx
                let _ = super::super::transport::io::propagate_remote_to_local(local_tx, ws_rx, close_rx).await;
            }
            .instrument(span.clone());
            tokio::spawn(tunnel);
        }
    }
}
