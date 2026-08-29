use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncWrite};
use url::Url;

pub use socks5::Socks5UpstreamConnector;
pub use tcp::TcpUpstreamConnector;
pub use udp::UdpUpstreamConnector;

use crate::tunnel::RemoteAddr;

mod socks5;
mod tcp;
mod udp;

pub trait UpstreamConnector {
    type Reader: AsyncRead + Send + 'static;
    type Writer: AsyncWrite + Send + 'static;

    #[allow(async_fn_in_trait)]
    async fn connect(&self, remote: &Option<RemoteAddr>) -> anyhow::Result<(Self::Reader, Self::Writer)>;
    #[allow(async_fn_in_trait)]
    async fn connect_with_http_proxy(
        &self,
        _proxy: &Url,
        _remote: &Option<RemoteAddr>,
    ) -> anyhow::Result<(Self::Reader, Self::Writer)> {
        Err(anyhow!(
            "Requested to use HTTP Proxy to connect but it is not supported with this connector"
        ))
    }
}
