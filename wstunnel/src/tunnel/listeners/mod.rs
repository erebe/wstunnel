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
use std::future::Future;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_stream::Stream;

/// Read half of a local duplex stream that can be forwarded through a tunnel.
pub trait TunnelConnectorRead: AsyncRead + Send + 'static {}
impl<T: AsyncRead + Send + 'static> TunnelConnectorRead for T {}

/// Write half of a local duplex stream that can be forwarded through a tunnel. On top of being
/// writable, it must acknowledge the end-to-end tunnel outcome to the local client once it is known.
///
/// Most local protocols (plain TCP, UDP, unix, stdio, ...) have nothing to acknowledge and rely on
/// the no-op default. SOCKS5 overrides [`TunnelConnectorWrite::on_tunnel_ready`] to defer its
/// `reply_success` / `reply_error` until the tunnel to the remote endpoint (and onward to the
/// target) is confirmed up or has failed.
pub trait TunnelConnectorWrite: AsyncWrite + Send + 'static {
    /// Called exactly once per connection, after the tunnel connection attempt completes and before
    /// any data is forwarded.
    fn on_tunnel_ready(
        &mut self,
        result: Result<(), &anyhow::Error>,
    ) -> impl Future<Output = std::io::Result<()>> + Send {
        let _ = result;
        async { Ok(()) }
    }
}

// Forward local protocols without a post-connect handshake: nothing to acknowledge.
// A blanket `impl<T: AsyncWrite>` is impossible here because it would overlap the SOCKS5 impl, so the
// concrete writer types are enumerated explicitly (tcp/tproxy/http_proxy share `OwnedWriteHalf`,
// udp/tproxy-udp share `UdpStreamWriter`).
impl TunnelConnectorWrite for tokio::net::tcp::OwnedWriteHalf {}
#[cfg(unix)]
impl TunnelConnectorWrite for tokio::net::unix::OwnedWriteHalf {}
impl TunnelConnectorWrite for crate::protocols::udp::UdpStreamWriter {}

pub trait TunnelListener: Stream<Item = anyhow::Result<((Self::Reader, Self::Writer), RemoteAddr)>> {
    type Reader: TunnelConnectorRead;
    type Writer: TunnelConnectorWrite;
}

impl<T, R, W> TunnelListener for T
where
    T: Stream<Item = anyhow::Result<((R, W), RemoteAddr)>>,
    R: TunnelConnectorRead,
    W: TunnelConnectorWrite,
{
    type Reader = R;
    type Writer = W;
}
