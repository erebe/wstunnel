use tokio::io::{AsyncRead, AsyncWrite};
use url::Url;

pub use sock5::Socks5TunnelConnector;
pub use tcp::TcpTunnelConnector;
pub use udp::UdpTunnelConnector;

use crate::tunnel::RemoteAddr;

mod sock5;
mod tcp;
mod udp;

pub trait TunnelConnector {
    type Reader: AsyncRead + Send + 'static;
    type Writer: AsyncWrite + Send + 'static;

    async fn connect(&self, remote: &Option<RemoteAddr>) -> anyhow::Result<(Self::Reader, Self::Writer)>;
    async fn connect_with_http_proxy(
        &self,
        proxy: &Url,
        remote: &Option<RemoteAddr>,
    ) -> anyhow::Result<(Self::Reader, Self::Writer)>;
}
