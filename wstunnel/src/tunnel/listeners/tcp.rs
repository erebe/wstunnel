use crate::protocols;
use crate::tunnel::{LocalProtocol, RemoteAddr};
use anyhow::{Context, anyhow};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Poll, ready};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio_stream::Stream;
use tokio_stream::wrappers::TcpListenerStream;
use url::Host;

pub struct TcpTunnelListener {
    listener: TcpListenerStream,
    dest: (Host, u16),
    proxy_protocol: bool,
}

impl TcpTunnelListener {
    pub async fn new(bind_addr: SocketAddr, dest: (Host, u16), proxy_protocol: bool) -> anyhow::Result<Self> {
        let listener = protocols::tcp::run_server(bind_addr, false)
            .await
            .with_context(|| anyhow!("Cannot start TCP server on {bind_addr}"))?;

        Ok(Self {
            listener,
            dest,
            proxy_protocol,
        })
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
