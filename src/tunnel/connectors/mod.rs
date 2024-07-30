mod sock5;
mod tcp;
mod udp;

pub use sock5::Socks5TunnelConnector;
pub use tcp::TcpTunnelConnector;
pub use udp::UdpTunnelConnector;

use crate::tunnel::RemoteAddr;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait TunnelConnector {
    type Reader: AsyncRead + Send + 'static;
    type Writer: AsyncWrite + Send + 'static;

    async fn connect(&self, remote: &Option<RemoteAddr>) -> anyhow::Result<(Self::Reader, Self::Writer)>;
}
