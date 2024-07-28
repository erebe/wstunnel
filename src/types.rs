use crate::http_proxy::HttpProxyListener;
use crate::socks5::{Socks5Listener, Socks5Stream};
use crate::tunnel::{to_host_port, RemoteAddr};
use crate::udp::{UdpStream, UdpStreamWriter};
use crate::unix_socket::UnixListenerStream;
use crate::LocalProtocol;
use std::io;
use std::pin::Pin;
use std::task::{ready, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::unix;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::Stream;
use url::Host;

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

pub struct TcpTunnelListener {
    listener: TcpListenerStream,
    dest: (Host, u16),
    proxy_protocol: bool,
}

impl TcpTunnelListener {
    pub fn new(listener: TcpListenerStream, dest: (Host, u16), proxy_protocol: bool) -> Self {
        Self {
            listener,
            dest,
            proxy_protocol,
        }
    }
}

impl Stream for TcpTunnelListener {
    type Item = anyhow::Result<((OwnedReadHalf, OwnedWriteHalf), RemoteAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let ret = ready!(Pin::new(&mut this.listener).poll_next(cx));
        let ret = match ret {
            Some(Ok(strean)) => {
                let (host, port) = this.dest.clone();
                Some(anyhow::Ok((
                    strean.into_split(),
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

// TPROXY
pub struct TproxyTcpTunnelListener {
    listener: TcpListenerStream,
    proxy_protocol: bool,
}

impl TproxyTcpTunnelListener {
    pub fn new(listener: TcpListenerStream, proxy_protocol: bool) -> Self {
        Self {
            listener,
            proxy_protocol,
        }
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

// UNIX
pub struct UnixTunnelListener {
    listener: UnixListenerStream,
    dest: (Host, u16),
    proxy_protocol: bool,
}

impl UnixTunnelListener {
    pub fn new(listener: UnixListenerStream, dest: (Host, u16), proxy_protocol: bool) -> Self {
        Self {
            listener,
            dest,
            proxy_protocol,
        }
    }
}
impl Stream for UnixTunnelListener {
    type Item = anyhow::Result<((unix::OwnedReadHalf, unix::OwnedWriteHalf), RemoteAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let ret = ready!(Pin::new(&mut this.listener).poll_next(cx));
        let ret = match ret {
            Some(Ok(stream)) => {
                let stream = stream.into_split();
                let (host, port) = this.dest.clone();
                Some(anyhow::Ok((
                    stream,
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

impl<S> TProxyUdpTunnelListener<S>
where
    S: Stream<Item = io::Result<UdpStream>>,
{
    pub fn new(listener: S, timeout: Option<Duration>) -> Self {
        Self { listener, timeout }
    }
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

pub struct UdpTunnelListener<S>
where
    S: Stream<Item = io::Result<UdpStream>>,
{
    listener: S,
    dest: (Host, u16),
    timeout: Option<Duration>,
}

impl<S> UdpTunnelListener<S>
where
    S: Stream<Item = io::Result<UdpStream>>,
{
    pub fn new(listener: S, dest: (Host, u16), timeout: Option<Duration>) -> Self {
        Self {
            listener,
            dest,
            timeout,
        }
    }
}

impl<S> Stream for UdpTunnelListener<S>
where
    S: Stream<Item = io::Result<UdpStream>>,
{
    type Item = anyhow::Result<((UdpStream, UdpStreamWriter), RemoteAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        let this = unsafe { self.get_unchecked_mut() };
        let ret = ready!(unsafe { Pin::new_unchecked(&mut this.listener) }.poll_next(cx));
        let ret = match ret {
            Some(Ok(stream)) => {
                let (host, port) = this.dest.clone();
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

pub struct Socks5TunnelListener {
    listener: Socks5Listener,
}

impl Socks5TunnelListener {
    pub fn new(listener: Socks5Listener) -> Self {
        Self { listener }
    }
}

impl Stream for Socks5TunnelListener {
    type Item = anyhow::Result<((ReadHalf<Socks5Stream>, WriteHalf<Socks5Stream>), RemoteAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let ret = ready!(Pin::new(&mut this.listener).poll_next(cx));
        let ret = match ret {
            Some(Ok((stream, (host, port)))) => {
                let protocol = stream.local_protocol();
                Some(anyhow::Ok((tokio::io::split(stream), RemoteAddr { protocol, host, port })))
            }
            Some(Err(err)) => Some(Err(err)),
            None => None,
        };
        Poll::Ready(ret)
    }
}

pub struct HttpProxyTunnelListener {
    listener: HttpProxyListener,
    proxy_protocol: bool,
}

impl HttpProxyTunnelListener {
    pub fn new(listener: HttpProxyListener, proxy_protocol: bool) -> Self {
        Self {
            listener,
            proxy_protocol,
        }
    }
}

impl Stream for HttpProxyTunnelListener {
    type Item = anyhow::Result<((OwnedReadHalf, OwnedWriteHalf), RemoteAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let ret = ready!(Pin::new(&mut this.listener).poll_next(cx));
        let ret = match ret {
            Some(Ok((stream, (host, port)))) => {
                let protocol = LocalProtocol::Tcp {
                    proxy_protocol: this.proxy_protocol,
                };
                Some(anyhow::Ok((stream.into_split(), RemoteAddr { protocol, host, port })))
            }
            Some(Err(err)) => Some(Err(err)),
            None => None,
        };
        Poll::Ready(ret)
    }
}

pub struct StdioTunnelListener<R, W>
where
    R: AsyncRead + Send + 'static,
    W: AsyncWrite + Send + 'static,
{
    listener: Option<(R, W)>,
    dest: (Host, u16),
    proxy_protocol: bool,
}

impl<R, W> StdioTunnelListener<R, W>
where
    R: AsyncRead + Send + 'static,
    W: AsyncWrite + Send + 'static,
{
    pub fn new(listener: (R, W), dest: (Host, u16), proxy_protocol: bool) -> Self {
        Self {
            listener: Some(listener),
            proxy_protocol,
            dest,
        }
    }
}

impl<R, W> Stream for StdioTunnelListener<R, W>
where
    R: AsyncRead + Send + 'static,
    W: AsyncWrite + Send + 'static,
{
    type Item = anyhow::Result<((R, W), RemoteAddr)>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        let this = unsafe { self.get_unchecked_mut() };
        let ret = match this.listener.take() {
            None => None,
            Some(stream) => {
                let (host, port) = this.dest.clone();
                Some(Ok((
                    stream,
                    RemoteAddr {
                        protocol: LocalProtocol::Tcp {
                            proxy_protocol: this.proxy_protocol,
                        },
                        host,
                        port,
                    },
                )))
            }
        };

        Poll::Ready(ret)
    }
}
