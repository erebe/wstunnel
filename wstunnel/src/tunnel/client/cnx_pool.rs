use crate::protocols;
use crate::protocols::tls;
use crate::tunnel::client::WsClientConfig;
use crate::tunnel::client::l4_transport_stream::TransportStream;
use anyhow::anyhow;
use bb8::ManageConnection;
use bytes::Bytes;
use std::ops::Deref;
use std::sync::Arc;
use tracing::{instrument, warn};

#[derive(Clone)]
pub struct WsConnection(Arc<WsClientConfig>);

impl WsConnection {
    pub fn new(config: Arc<WsClientConfig>) -> Self {
        Self(config)
    }
}

impl Deref for WsConnection {
    type Target = WsClientConfig;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ManageConnection for WsConnection {
    type Connection = Option<TransportStream>;
    type Error = anyhow::Error;

    #[instrument(level = "trace", name = "cnx_server", skip_all)]
    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let timeout = self.timeout_connect;

        let tcp_stream = if let Some(http_proxy) = &self.http_proxy {
            protocols::tcp::connect_with_http_proxy(
                http_proxy,
                self.remote_addr.host(),
                self.remote_addr.port(),
                self.socket_so_mark,
                timeout,
                &self.dns_resolver,
            )
            .await?
        } else {
            protocols::tcp::connect(
                self.remote_addr.host(),
                self.remote_addr.port(),
                self.socket_so_mark,
                timeout,
                &self.dns_resolver,
            )
            .await?
        };

        if self.remote_addr.tls().is_some() {
            // Bound the TLS handshake with the same timeout as the TCP connect,
            // so a peer that accepts the connection but never completes the
            // handshake is dropped instead of held.
            let tls_stream = match tokio::time::timeout(timeout, tls::connect(self, tcp_stream)).await {
                Ok(res) => res?,
                Err(_) => {
                    warn!("Timed out after {timeout:?} doing the TLS handshake with the server");
                    return Err(anyhow!("Timed out doing the TLS handshake with the server"));
                }
            };
            Ok(Some(TransportStream::from_client_tls(tls_stream, Bytes::default())))
        } else {
            Ok(Some(TransportStream::from_tcp(tcp_stream, Bytes::default())))
        }
    }

    async fn is_valid(&self, _conn: &mut Self::Connection) -> Result<(), Self::Error> {
        Ok(())
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        conn.is_none()
    }
}
