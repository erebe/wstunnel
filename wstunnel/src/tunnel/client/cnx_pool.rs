use crate::protocols;
use crate::protocols::tls;
use crate::tunnel::client::WsClientConfig;
use crate::tunnel::client::l4_transport_stream::TransportStream;
use bb8::ManageConnection;
use bytes::Bytes;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::AsyncRead;
use tracing::instrument;

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
            let tls_stream = tls::connect(self, tcp_stream).await?;
            Ok(Some(TransportStream::from_client_tls(tls_stream, Bytes::default())))
        } else {
            Ok(Some(TransportStream::from_tcp(tcp_stream, Bytes::default())))
        }
    }

    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        if let Some(conn) = conn {
            // Check if connection is closed or has unexpected data
            let mut buf = [0u8; 1];
            let mut read_buf = tokio::io::ReadBuf::new(&mut buf);
            let waker = futures_util::task::noop_waker();
            let mut cx = Context::from_waker(&waker);

            match Pin::new(conn).poll_read(&mut cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    if read_buf.filled().is_empty() {
                        return Err(anyhow::anyhow!("connection closed"));
                    } else {
                        return Err(anyhow::anyhow!("connection has unexpected data"));
                    }
                }
                Poll::Ready(Err(e)) => return Err(e.into()),
                Poll::Pending => return Ok(()),
            }
        }
        Err(anyhow::anyhow!("connection is None"))
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        conn.is_none()
    }
}
