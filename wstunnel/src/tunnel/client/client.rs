use crate::executor::{DefaultTokioExecutor, TokioExecutorRef};
use crate::tunnel;
use crate::tunnel::client::ClientConfig;
use crate::tunnel::client::connection_pool::L4StreamManager;
use crate::tunnel::downstream_listeners::{DownstreamListener, DownstreamRead, DownstreamWrite};
use crate::tunnel::tls_reloader::TlsReloader;
use crate::tunnel::transport::TransportAddr;
use crate::tunnel::transport::io::{TransportReader, TransportWriter};
use crate::tunnel::transport::{TransportScheme, jwt_token_to_tunnel};
use crate::tunnel::upstream_connectors::UpstreamConnector;
use crate::tunnel::{LocalProtocol, RemoteAddr};
use anyhow::Context;
use arc_swap::ArcSwap;
use futures_util::pin_mut;
use hyper::header::COOKIE;
use log::debug;
use std::cmp::min;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tracing::{Instrument, Level, Span, error, event, span};
use url::Host;
use uuid::Uuid;

/// Represents the currently active remote target for client connections.
#[derive(Clone, Debug)]
pub struct ActiveTarget {
    pub addr: TransportAddr,
    pub path_prefix: String,
}

impl ActiveTarget {
    /// Returns true if this target matches the given address and path prefix.
    pub fn is_same_target(&self, addr: &TransportAddr, path_prefix: &str) -> bool {
        self.addr.is_same_endpoint(addr) && self.path_prefix == path_prefix
    }
}

#[derive(Clone)]
pub struct Client<E: TokioExecutorRef = DefaultTokioExecutor> {
    pub config: Arc<ClientConfig>,
    pub cnx_pool: bb8::Pool<L4StreamManager>,
    pub active_target: Arc<ArcSwap<ActiveTarget>>,
    reverse_tunnel_connection_retry_max_backoff: Duration,
    _tls_reloader: Arc<TlsReloader>,
    pub(crate) executor: E,
}

impl<E: TokioExecutorRef> Client<E> {
    pub async fn new(
        config: ClientConfig,
        connection_min_idle: u32,
        connection_retry_max_backoff: Duration,
        reverse_tunnel_connection_retry_max_backoff: Duration,
        executor: E,
    ) -> anyhow::Result<Self> {
        let active_target = Arc::new(ArcSwap::from_pointee(ActiveTarget {
            addr: config.remote_addr.clone(),
            path_prefix: config.http_upgrade_path_prefix.clone(),
        }));
        let config = Arc::new(config);

        let cnx = L4StreamManager::new(config.clone());
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
            active_target,
            reverse_tunnel_connection_retry_max_backoff,
            _tls_reloader: Arc::new(tls_reloader),
            executor,
        })
    }

    /// Load the current active remote target (lock-free).
    pub fn active_target(&self) -> Arc<ActiveTarget> {
        self.active_target.load_full()
    }

    /// Update the shared active remote target after following a redirect.
    pub fn set_active_target(&self, addr: TransportAddr, path_prefix: String) {
        self.active_target.store(Arc::new(ActiveTarget { addr, path_prefix }));
    }

    /// Reset the active remote target back to the configured canonical server URL.
    pub fn reset_active_target(&self) {
        self.active_target.store(Arc::new(ActiveTarget {
            addr: self.config.remote_addr.clone(),
            path_prefix: self.config.http_upgrade_path_prefix.clone(),
        }));
    }

    pub async fn connect_to_server<R, W>(
        &self,
        request_id: Uuid,
        remote_cfg: &RemoteAddr,
        duplex_stream: (R, W),
    ) -> anyhow::Result<()>
    where
        R: DownstreamRead,
        W: DownstreamWrite,
    {
        // Connect to server with the correct protocol. Capture the result instead of `?`-ing it: on
        // failure we must still acknowledge the local handshake (e.g. send a SOCKS5 error reply)
        // before bubbling the error up.
        let connect_result = match self.config.remote_addr.scheme() {
            TransportScheme::Ws | TransportScheme::Wss => {
                tunnel::transport::websocket::connect(request_id, self, remote_cfg)
                    .await
                    .map(|(r, w, response)| (TransportReader::Websocket(r), TransportWriter::Websocket(w), response))
            }
            TransportScheme::Http | TransportScheme::Https => {
                tunnel::transport::http2::connect(request_id, self, remote_cfg)
                    .await
                    .map(|(r, w, response)| (TransportReader::Http2(r), TransportWriter::Http2(w), response))
            }
            TransportScheme::Wts => tunnel::transport::webtransport::connect(request_id, self, remote_cfg)
                .await
                .map(|(r, w, response)| {
                    if matches!(remote_cfg.protocol, LocalProtocol::Udp { .. } | LocalProtocol::TProxyUdp { .. }) {
                        (
                            TransportReader::WebTransportUdp(Box::new(r.into_udp_stream())),
                            TransportWriter::WebTransportUdp(Box::new(w.into_udp_stream())),
                            response,
                        )
                    } else {
                        (
                            TransportReader::WebTransport(Box::new(r)),
                            TransportWriter::WebTransport(Box::new(w)),
                            response,
                        )
                    }
                }),
        };

        let (local_rx, mut local_tx) = duplex_stream;

        // Acknowledge the tunnel outcome to the local client (no-op for protocols without a
        // handshake). A successful transport connect means the server accepted the request and
        // reached the target, so this is the moment to reply success; otherwise reply failure.
        let (ws_rx, ws_tx, response) = match connect_result {
            Ok(tunnel) => {
                if let Err(err) = local_tx.on_tunnel_ready(Ok(())).await {
                    return Err(anyhow::Error::new(err).context("failed to acknowledge local tunnel handshake"));
                }
                tunnel
            }
            Err(err) => {
                let _ = local_tx.on_tunnel_ready(Err(&err)).await;
                return Err(err);
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

    pub async fn run_tunnel(self, tunnel_listener: impl DownstreamListener) -> anyhow::Result<()> {
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
        connector: impl UpstreamConnector,
    ) -> anyhow::Result<()> {
        fn new_reconnect_delay(max_delay: Duration) -> impl FnMut() -> Duration {
            let mut reconnect_delay = Duration::from_secs(1);

            move || -> Duration {
                let delay = reconnect_delay;
                reconnect_delay = min(reconnect_delay * 2, max_delay);
                delay
            }
        }

        let connector = Arc::new(connector);
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
                        Ok((r, w, response)) => {
                            (TransportReader::Websocket(r), TransportWriter::Websocket(w), response)
                        }
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
                        Ok((r, w, response)) => (TransportReader::Http2(r), TransportWriter::Http2(w), response),
                        Err(err) => {
                            let reconnect_delay = reconnect_delay();
                            event!(parent: &span, Level::ERROR, "Retrying in {:?}, cannot connect to remote server: {:?}", reconnect_delay, err);
                            tokio::time::sleep(reconnect_delay).await;
                            continue;
                        }
                    }
                }
                TransportScheme::Wts => {
                    match tunnel::transport::webtransport::connect(request_id, &client, &remote_addr)
                        .instrument(span.clone())
                        .await
                    {
                        Ok((r, w, response)) => (
                            TransportReader::WebTransport(Box::new(r)),
                            TransportWriter::WebTransport(Box::new(w)),
                            response,
                        ),
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
            let task = {
                let executor = self.executor.clone();
                let connector = connector.clone();
                async move {
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
                            return;
                        }
                    };

                    let (close_tx, close_rx) = oneshot::channel::<()>();
                    executor.spawn({
                        let ping_frequency = client.config.websocket_ping_frequency;
                        super::super::transport::io::propagate_local_to_remote(
                            local_rx,
                            ws_tx,
                            close_tx,
                            ping_frequency,
                        )
                        .instrument(span.clone())
                    });

                    let _ = super::super::transport::io::propagate_remote_to_local(local_tx, ws_rx, close_rx)
                        .instrument(span.clone())
                        .await;
                }
            };

            self.executor.spawn(task);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::transport::TransportScheme;

    #[test]
    fn test_active_target_equality() {
        let addr1 = TransportAddr::Ws {
            scheme: TransportScheme::Ws,
            host: Host::Domain("d1.example.com".to_string()),
            port: 80,
        };
        let addr2 = TransportAddr::Ws {
            scheme: TransportScheme::Ws,
            host: Host::Domain("d2.example.com".to_string()),
            port: 80,
        };
        let target = ActiveTarget {
            addr: addr1.clone(),
            path_prefix: "v1".to_string(),
        };

        assert!(target.is_same_target(&addr1, "v1"));
        assert!(!target.is_same_target(&addr2, "v1"));
        assert!(!target.is_same_target(&addr1, "v2"));
    }
}
