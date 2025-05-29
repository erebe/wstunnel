mod tcp;
#[cfg(target_os = "linux")]
mod tproxy;

mod http_proxy;
mod socks5;
mod stdio;
mod udp;
#[cfg(unix)]
mod unix_sock;

#[cfg(target_os = "linux")]
pub use tproxy::TproxyTcpTunnelListener;
#[cfg(target_os = "linux")]
pub use tproxy::new_tproxy_udp;

pub use http_proxy::HttpProxyTunnelListener;
pub use socks5::Socks5TunnelListener;
pub use stdio::new_stdio_listener;
pub use tcp::TcpTunnelListener;
pub use udp::UdpTunnelListener;

#[cfg(unix)]
pub use unix_sock::UnixTunnelListener;

use crate::tunnel::RemoteAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_stream::Stream;

pub trait TunnelListener: Stream<Item = anyhow::Result<((Self::Reader, Self::Writer), RemoteAddr)>> {
    type Reader: AsyncRead + Send + 'static;
    type Writer: AsyncWrite + Send + 'static;
}

impl<T, R, W> TunnelListener for T
where
    T: Stream<Item = anyhow::Result<((R, W), RemoteAddr)>>,
    R: AsyncRead + Send + 'static,
    W: AsyncWrite + Send + 'static,
{
    type Reader = R;
    type Writer = W;
}
