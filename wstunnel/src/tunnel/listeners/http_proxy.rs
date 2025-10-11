use crate::protocols::http_proxy;
use crate::protocols::http_proxy::HttpProxyListener;
use crate::tunnel::{LocalProtocol, RemoteAddr};
use anyhow::{Context, anyhow};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Poll, ready};
use std::time::Duration;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio_stream::Stream;

pub struct HttpProxyTunnelListener {
    listener: HttpProxyListener,
    proxy_protocol: bool,
}

impl HttpProxyTunnelListener {
    pub async fn new(
        bind_addr: SocketAddr,
        timeout: Option<Duration>,
        credentials: Option<(String, String)>,
        proxy_protocol: bool,
    ) -> anyhow::Result<Self> {
        let listener = http_proxy::run_server(bind_addr, timeout, credentials)
            .await
            .with_context(|| anyhow!("Cannot start http proxy server on {bind_addr}"))?;

        Ok(Self {
            listener,
            proxy_protocol,
        })
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
