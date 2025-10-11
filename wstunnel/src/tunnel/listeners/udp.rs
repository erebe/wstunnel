use crate::protocols::udp;
use crate::protocols::udp::{UdpStream, UdpStreamWriter};
use crate::tunnel::{LocalProtocol, RemoteAddr};
use anyhow::{Context, anyhow};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Poll, ready};
use std::time::Duration;
use tokio_stream::Stream;
use url::Host;

pub struct UdpTunnelListener {
    listener: Pin<Box<dyn Stream<Item = io::Result<UdpStream>> + Send>>,
    dest: (Host, u16),
    timeout: Option<Duration>,
}

impl UdpTunnelListener {
    pub async fn new(
        bind_addr: SocketAddr,
        dest: (Host, u16),
        timeout: Option<Duration>,
    ) -> anyhow::Result<UdpTunnelListener> {
        let listener = udp::run_server(bind_addr, timeout, |_| Ok(()), |s| Ok(s.clone()))
            .await
            .with_context(|| anyhow!("Cannot start UDP server on {bind_addr}"))?;

        Ok(UdpTunnelListener {
            listener: Box::pin(listener),
            dest,
            timeout,
        })
    }
}

impl Stream for UdpTunnelListener {
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
