use crate::executor::{DefaultTokioExecutor, TokioExecutorRef};
use crate::tunnel;
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::WsClientConfig;
use crate::tunnel::client::cnx_pool::WsConnection;
use crate::tunnel::connectors::TunnelConnector;
use crate::tunnel::listeners::TunnelListener;
use crate::tunnel::tls_reloader::TlsReloader;
use crate::tunnel::transport::io::{TunnelRead, TunnelReader, TunnelWrite, TunnelWriter};
use crate::tunnel::transport::{TransportScheme, jwt_token_to_tunnel};
use anyhow::Context;
use futures_util::pin_mut;
use hyper::header::COOKIE;
use log::debug;
use std::cmp::min;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tracing::{Instrument, Level, Span, error, event, span};
use url::Host;
use uuid::Uuid;

#[derive(Clone)]
pub struct WsClient<E: TokioExecutorRef = DefaultTokioExecutor> {
    pub config: Arc<WsClientConfig>,
    pub cnx_pool: bb8::Pool<WsConnection>,
    reverse_tunnel_connection_retry_max_backoff: Duration,
    _tls_reloader: Arc<TlsReloader>,
    pub(crate) executor: E,
}

impl<E: TokioExecutorRef> WsClient<E> {
    pub async fn new(
        config: WsClientConfig,
        connection_min_idle: u32,
        connection_retry_max_backoff: Duration,
        reverse_tunnel_connection_retry_max_backoff: Duration,
        executor: E,
    ) -> anyhow::Result<Self> {
        let config = Arc::new(config);
        let cnx = WsConnection::new(config.clone());
        let tls_reloader = TlsReloader::new_for_client(config.clone()).with_context(|| "Cannot create tls reloader")?;
        let cnx_pool = bb8::Pool::builder()
            .max_size(1000)
            .min_idle(Some(connection_min_idle))
            .max_lifetime(Some(Duration::from_secs(30)))
            .connection_timeout(connection_retry_max_backoff)
            .retry_connection(true)
            .build(cnx)
            .await?;

        Ok(Self {
            config,
            cnx_pool,
            reverse_tunnel_connection_retry_max_backoff,
            _tls_reloader: Arc::new(tls_reloader),
            executor,
        })
    }

    pub async fn connect_to_server<R, W>(
        &self,
        request_id: Uuid,
        remote_cfg: &RemoteAddr,
        duplex_stream: (R, W),
    ) -> anyhow::Result<()>
    where
        R: AsyncRead + Send + 'static,
        W: AsyncWrite + Send + 'static,
    {
        let (local_rx, local_tx) = duplex_stream;

        if self.config.udp_multiplex > 1 && matches!(remote_cfg.protocol, crate::LocalProtocol::Udp { .. }) {
            let n = self.config.udp_multiplex;
            let mut ws_tx_senders = Vec::new();
            let (to_local_tx, mut to_local_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(2048);

            for _ in 0..n {
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

                debug!("Server response (multiplexed): {response:?}");

                let (tx, mut rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(100);
                ws_tx_senders.push(tx);

                let ping_frequency = self.config.websocket_ping_frequency;
                let mut ws_tx = ws_tx;
                
                self.executor.spawn(async move {
                    let frequency = ping_frequency.unwrap_or(Duration::from_secs(3600 * 24));
                    let mut interval = tokio::time::interval(frequency);
                    let notify = ws_tx.pending_operations_notify();
                    let mut has_pending = Box::pin(notify.notified());
                    
                    loop {
                        tokio::select! {
                            biased;
                            _ = &mut has_pending => {
                                has_pending = Box::pin(notify.notified());
                                if ws_tx.handle_pending_operations().await.is_err() {
                                    break;
                                }
                            }
                            data = rx.recv() => {
                                match data {
                                    Some(data) => {
                                        ws_tx.buf_mut().clear();
                                        ws_tx.buf_mut().extend_from_slice(&data);
                                        if ws_tx.write().await.is_err() {
                                            break;
                                        }
                                    }
                                    None => break,
                                }
                            }
                            _ = interval.tick(), if ping_frequency.is_some() => {
                                if ws_tx.ping().await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = ws_tx.close().await;
                }.instrument(Span::current()));

                let mut ws_rx = ws_rx;
                let to_local_tx_clone = to_local_tx.clone();
                self.executor.spawn(async move {
                    struct Wrapper(tokio::sync::mpsc::Sender<bytes::Bytes>);
                    impl AsyncWrite for Wrapper {
                        fn poll_write(
                            self: std::pin::Pin<&mut Self>,
                            _cx: &mut std::task::Context<'_>,
                            buf: &[u8],
                        ) -> std::task::Poll<Result<usize, std::io::Error>> {
                            let data = bytes::Bytes::copy_from_slice(buf);
                            match self.0.try_send(data) {
                                Ok(_) => std::task::Poll::Ready(Ok(buf.len())),
                                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                    std::task::Poll::Ready(Ok(buf.len()))
                                }
                                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                    std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "channel closed")))
                                }
                            }
                        }

                        fn poll_flush(
                            self: std::pin::Pin<&mut Self>,
                            _cx: &mut std::task::Context<'_>,
                        ) -> std::task::Poll<Result<(), std::io::Error>> {
                            std::task::Poll::Ready(Ok(()))
                        }

                        fn poll_shutdown(
                            self: std::pin::Pin<&mut Self>,
                            _cx: &mut std::task::Context<'_>,
                        ) -> std::task::Poll<Result<(), std::io::Error>> {
                            std::task::Poll::Ready(Ok(()))
                        }
                    }
                    let mut wrapper = Wrapper(to_local_tx_clone);
                    let _ = ws_rx.copy(&mut wrapper).await;
                }.instrument(Span::current()));
            }

            drop(to_local_tx);

            let ws_tx_senders_clone = ws_tx_senders.clone();
            self.executor.spawn(async move {
                tokio::pin!(local_rx);
                let mut buf = bytes::BytesMut::with_capacity(65536);
                let mut counter = 0;
                while let Ok(n) = local_rx.read_buf(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let data = buf.split_to(n).freeze();
                    let idx = counter % ws_tx_senders_clone.len();
                    if ws_tx_senders_clone[idx].send(data).await.is_err() {
                        break;
                    }
                    counter += 1;
                }
            }.instrument(Span::current()));

            tokio::pin!(local_tx);
            while let Some(data) = to_local_rx.recv().await {
                if local_tx.write_all(&data).await.is_err() {
                    break;
                }
            }

            Ok(())
        } else {
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

            debug!("Server response: {response:?}");
            let (close_tx, close_rx) = oneshot::channel::<()>();

            // Forward local tx to websocket tx
            let ping_frequency = self.config.websocket_ping_frequency;
            self.executor.spawn(
                super::super::transport::io::propagate_local_to_remote(local_rx, ws_tx, close_tx, ping_frequency)
                    .instrument(Span::current()),
            );

            // Forward websocket rx to local rx
            let _ = super::super::transport::io::propagate_remote_to_local(local_tx, ws_rx, close_rx).await;

            Ok(())
        }
    }

    pub async fn run_tunnel(self, tunnel_listener: impl TunnelListener) -> anyhow::Result<()> {
        pin_mut!(tunnel_listener);
        // everybody who connects to the local socket gets their own tunnel
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

            self.executor.spawn(tunnel);
        }

        Ok(())
    }

    pub async fn run_reverse_tunnel(
        self,
        remote_addr: RemoteAddr,
        connector: impl TunnelConnector,
    ) -> anyhow::Result<()> {
        fn new_reconnect_delay(max_delay: Duration) -> impl FnMut() -> Duration {
            let mut reconnect_delay = Duration::from_secs(1);

            move || -> Duration {
                let delay = reconnect_delay;
                reconnect_delay = min(reconnect_delay * 2, max_delay);
                delay
            }
        }

        let mut reconnect_delay = new_reconnect_delay(self.reverse_tunnel_connection_retry_max_backoff);
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
                            let reconnect_delay = reconnect_delay();
                            event!(parent: &span, Level::ERROR, "Retrying in {:?}, cannot connect to remote server: {:?}", reconnect_delay, err);
                            tokio::time::sleep(reconnect_delay).await;
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
                            let reconnect_delay = reconnect_delay();
                            event!(parent: &span, Level::ERROR, "Retrying in {:?}, cannot connect to remote server: {:?}", reconnect_delay, err);
                            tokio::time::sleep(reconnect_delay).await;
                            continue;
                        }
                    }
                }
            };
            reconnect_delay = new_reconnect_delay(self.reverse_tunnel_connection_retry_max_backoff);

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
            self.executor.spawn({
                let ping_frequency = client.config.websocket_ping_frequency;
                super::super::transport::io::propagate_local_to_remote(local_rx, ws_tx, close_tx, ping_frequency)
                    .instrument(span.clone())
            });

            // Forward websocket rx to local rx
            self.executor.spawn(
                super::super::transport::io::propagate_remote_to_local(local_tx, ws_rx, close_rx)
                    .instrument(span.clone()),
            );
        }
    }
}
