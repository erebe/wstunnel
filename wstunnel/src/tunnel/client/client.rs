use crate::executor::{DefaultTokioExecutor, TokioExecutorRef};
use crate::tunnel;
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::WsClientConfig;
use crate::tunnel::client::cnx_pool::WsConnection;
use crate::tunnel::connectors::TunnelConnector;
use crate::tunnel::listeners::TunnelListener;
use crate::tunnel::tls_reloader::TlsReloader;
use crate::tunnel::transport::io::{
    TunnelReader, TunnelWriter, propagate_local_to_remote, propagate_remote_to_local,
};
use crate::tunnel::transport::{TransportScheme, jwt_token_to_tunnel};
use anyhow::Context;
use bytes::{Bytes, BytesMut};
use futures_util::pin_mut;
use hyper::header::COOKIE;
use log::debug;
use std::cmp::min;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::StreamExt;
use tracing::{Instrument, Level, Span, error, event, span, warn};
use url::Host;
use uuid::Uuid;

/// Max UDP datagram size (theoretical max payload is 65507, rounded up to a power of two).
const MAX_DATAGRAM_SIZE: usize = 64 * 1024;
/// Per-connection / merge channel depth (in datagrams) used by UDP multiplexing.
const UDP_MULTIPLEX_CHANNEL_SIZE: usize = 2048;

/// `AsyncRead` adapter over an mpsc channel of datagrams. Yields exactly one datagram per `poll_read`,
/// preserving UDP message boundaries, and reports EOF (0 bytes) once the channel is closed.
struct DatagramChannelReader(mpsc::Receiver<Bytes>);

impl AsyncRead for DatagramChannelReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.0.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                let len = data.len().min(buf.remaining());
                buf.put_slice(&data[..len]);
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())), // channel closed => EOF
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// `AsyncWrite` adapter over an mpsc channel of datagrams. Each `poll_write` enqueues one datagram.
/// When the channel is full the datagram is dropped (UDP semantics, no head-of-line blocking) and
/// accounted for; a closed channel surfaces as an error so the reader task can shut down.
struct DatagramChannelWriter {
    tx: mpsc::Sender<Bytes>,
    dropped: u64,
}

impl DatagramChannelWriter {
    fn new(tx: mpsc::Sender<Bytes>) -> Self {
        Self { tx, dropped: 0 }
    }
}

impl AsyncWrite for DatagramChannelWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.tx.try_send(Bytes::copy_from_slice(buf)) {
            Ok(()) => std::task::Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped += 1;
                if self.dropped.is_power_of_two() {
                    warn!("udp-multiplex: dropped {} datagrams (local receive buffer full)", self.dropped);
                }
                std::task::Poll::Ready(Ok(buf.len()))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "local udp channel closed",
            ))),
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
            self.connect_to_server_udp_multiplex(request_id, remote_cfg, local_rx, local_tx)
                .await
        } else {
            let (ws_rx, ws_tx, response) = self.connect_transport(request_id, None, remote_cfg).await?;
            debug!("Server response: {response:?}");

            let (close_tx, close_rx) = oneshot::channel::<()>();

            // Forward local tx to websocket tx
            let ping_frequency = self.config.websocket_ping_frequency;
            self.executor.spawn(
                propagate_local_to_remote(local_rx, ws_tx, close_tx, ping_frequency).instrument(Span::current()),
            );

            // Forward websocket rx to local rx
            let _ = propagate_remote_to_local(local_tx, ws_rx, close_rx).await;

            Ok(())
        }
    }

    /// Establish a single tunnel connection to the server using the configured transport.
    /// `flow_id` is `Some` only for UDP multiplexing, where the N sibling connections share it so the
    /// server can route them to a single upstream UDP socket.
    async fn connect_transport(
        &self,
        request_id: Uuid,
        flow_id: Option<Uuid>,
        remote_cfg: &RemoteAddr,
    ) -> anyhow::Result<(TunnelReader, TunnelWriter, hyper::http::response::Parts)> {
        match self.config.remote_addr.scheme() {
            TransportScheme::Ws | TransportScheme::Wss => {
                tunnel::transport::websocket::connect(request_id, flow_id, self, remote_cfg)
                    .await
                    .map(|(r, w, response)| (TunnelReader::Websocket(r), TunnelWriter::Websocket(w), response))
            }
            TransportScheme::Http | TransportScheme::Https => {
                tunnel::transport::http2::connect(request_id, flow_id, self, remote_cfg)
                    .await
                    .map(|(r, w, response)| (TunnelReader::Http2(r), TunnelWriter::Http2(w), response))
            }
        }
    }

    /// Tunnel a single local UDP session over N parallel server connections to bypass per-connection QOS.
    ///
    /// All N connections carry the same `flow_id`, so the server reassembles them onto a single upstream
    /// UDP socket (preserving the destination's 5-tuple, required for stateful protocols like WireGuard).
    ///
    /// Datagram boundaries are preserved end to end: one local datagram becomes one websocket binary
    /// frame becomes one upstream datagram. Both directions reuse the regular `propagate_*` helpers, fed
    /// through small datagram-preserving channel adapters. Under backpressure datagrams are dropped (not
    /// blocked), which matches UDP semantics and avoids head-of-line blocking.
    async fn connect_to_server_udp_multiplex(
        &self,
        request_id: Uuid,
        remote_cfg: &RemoteAddr,
        local_rx: impl AsyncRead + Send + 'static,
        local_tx: impl AsyncWrite + Send + 'static,
    ) -> anyhow::Result<()> {
        let n = self.config.udp_multiplex;
        let flow_id = Some(Uuid::now_v7());
        let ping_frequency = self.config.websocket_ping_frequency;

        let mut ws_tx_senders = Vec::with_capacity(n);
        let (to_local_tx, mut to_local_rx) = mpsc::channel::<Bytes>(UDP_MULTIPLEX_CHANNEL_SIZE);

        for _ in 0..n {
            let (ws_rx, ws_tx, response) = self.connect_transport(request_id, flow_id, remote_cfg).await?;
            debug!("Server response (multiplexed): {response:?}");

            let (close_tx, close_rx) = oneshot::channel::<()>();

            // Write direction: the splitter feeds this per-connection channel; reuse propagate_local_to_remote.
            let (conn_tx, conn_rx) = mpsc::channel::<Bytes>(UDP_MULTIPLEX_CHANNEL_SIZE);
            ws_tx_senders.push(conn_tx);
            self.executor.spawn(
                propagate_local_to_remote(DatagramChannelReader(conn_rx), ws_tx, close_tx, ping_frequency)
                    .instrument(Span::current()),
            );

            // Read direction: merge this connection's datagrams into the shared to_local channel.
            let writer = DatagramChannelWriter::new(to_local_tx.clone());
            self.executor
                .spawn(propagate_remote_to_local(writer, ws_rx, close_rx).instrument(Span::current()));
        }
        // Only the per-connection read tasks should keep the merge channel open.
        drop(to_local_tx);

        // Splitter: read local datagrams and round-robin them across the connections.
        self.executor.spawn(
            async move {
                pin_mut!(local_rx);
                let mut counter: usize = 0;
                let mut dropped: u64 = 0;
                loop {
                    let mut buf = BytesMut::with_capacity(MAX_DATAGRAM_SIZE);
                    match local_rx.read_buf(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(read_len) => {
                            let data = buf.split_to(read_len).freeze();
                            let idx = counter % ws_tx_senders.len();
                            counter = counter.wrapping_add(1);
                            match ws_tx_senders[idx].try_send(data) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    dropped += 1;
                                    if dropped.is_power_of_two() {
                                        warn!("udp-multiplex: dropped {dropped} datagrams (connection send buffer full)");
                                    }
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => break,
                            }
                        }
                    }
                }
            }
            .instrument(Span::current()),
        );

        // Merge: drain the shared channel into the single local writer.
        pin_mut!(local_tx);
        while let Some(data) = to_local_rx.recv().await {
            if local_tx.write_all(&data).await.is_err() {
                break;
            }
        }

        Ok(())
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
                    match tunnel::transport::websocket::connect(request_id, None, &client, &remote_addr)
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
                    match tunnel::transport::http2::connect(request_id, None, &client, &remote_addr)
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
