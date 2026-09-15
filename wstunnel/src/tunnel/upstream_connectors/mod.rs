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

pub trait UpstreamConnector: Send + Sync + 'static {
    type Reader: AsyncRead + Send + 'static;
    type Writer: AsyncWrite + Send + 'static;

    fn connect(
        &self,
        remote: &Option<RemoteAddr>,
    ) -> impl Future<Output = anyhow::Result<(Self::Reader, Self::Writer)>> + Send;
    fn connect_with_http_proxy(
        &self,
        _proxy: &Url,
        _remote: &Option<RemoteAddr>,
    ) -> impl Future<Output = anyhow::Result<(Self::Reader, Self::Writer)>> {
        futures_util::future::ready(Err(anyhow!(
            "Requested to use HTTP Proxy to connect but it is not supported with this connector"
        )))
    }
}
