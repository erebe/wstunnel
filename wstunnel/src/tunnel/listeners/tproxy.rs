use crate::protocols;
use crate::protocols::udp;
use crate::protocols::udp::{UdpStream, UdpStreamWriter};
use crate::tunnel::{LocalProtocol, RemoteAddr, to_host_port};
use anyhow::{Context, anyhow};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Poll, ready};
use std::time::Duration;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio_stream::Stream;
use tokio_stream::wrappers::TcpListenerStream;

pub struct TproxyTcpTunnelListener {
    listener: TcpListenerStream,
    proxy_protocol: bool,
}

impl TproxyTcpTunnelListener {
    pub async fn new(bind_addr: SocketAddr, proxy_protocol: bool) -> anyhow::Result<Self> {
        let listener = protocols::tcp::run_server(bind_addr, true)
            .await
            .with_context(|| anyhow!("Cannot start TProxy TCP server on {bind_addr}"))?;

        Ok(Self {
            listener,
            proxy_protocol,
        })
    }
}

impl Stream for TproxyTcpTunnelListener {
    type Item = anyhow::Result<((OwnedReadHalf, OwnedWriteHalf), RemoteAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let ret = ready!(Pin::new(&mut this.listener).poll_next(cx));
        let ret = match ret {
            Some(Ok(stream)) => {
                let (host, port) = to_host_port(stream.local_addr().unwrap());
                Some(anyhow::Ok((
                    stream.into_split(),
                    RemoteAddr {
                        protocol: LocalProtocol::Tcp {
                            proxy_protocol: this.proxy_protocol,
                        },
                        host,
                        port,
                    },
                )))
            }
            Some(Err(err)) => Some(Err(anyhow::Error::new(err))),
            None => None,
        };
        Poll::Ready(ret)
    }
}

// TPROXY UDP
pub struct TProxyUdpTunnelListener<S>
where
    S: Stream<Item = io::Result<UdpStream>>,
{
    listener: S,
    timeout: Option<Duration>,
}

pub async fn new_tproxy_udp(
    bind_addr: SocketAddr,
    timeout: Option<Duration>,
) -> anyhow::Result<TProxyUdpTunnelListener<impl Stream<Item = io::Result<UdpStream>>>> {
    let listener = udp::run_server(bind_addr, timeout, udp::configure_tproxy, udp::mk_send_socket_tproxy)
        .await
        .with_context(|| anyhow!("Cannot start TProxy UDP server on {bind_addr}"))?;

    Ok(TProxyUdpTunnelListener { listener, timeout })
}

impl<S> Stream for TProxyUdpTunnelListener<S>
where
    S: Stream<Item = io::Result<UdpStream>>,
{
    type Item = anyhow::Result<((UdpStream, UdpStreamWriter), RemoteAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        let this = unsafe { self.get_unchecked_mut() };
        let ret = ready!(unsafe { Pin::new_unchecked(&mut this.listener) }.poll_next(cx));
        let ret = match ret {
            Some(Ok(stream)) => {
                let (host, port) = to_host_port(stream.local_addr().unwrap());
                let stream_writer = stream.writer();
                Some(anyhow::Ok((
                    (stream, stream_writer),
                    RemoteAddr {
                        protocol: LocalProtocol::Udp { timeout: this.timeout },
                        host,
                        port,
                    },
                )))
            }
            Some(Err(err)) => Some(Err(anyhow::Error::new(err))),
            None => None,
        };
        Poll::Ready(ret)
    }
}
