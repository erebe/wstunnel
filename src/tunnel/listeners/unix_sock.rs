use crate::protocols::unix_sock;
use crate::protocols::unix_sock::UnixListenerStream;
use crate::tunnel::{LocalProtocol, RemoteAddr};
use anyhow::{anyhow, Context};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{ready, Poll};
use tokio::net::unix;
use tokio_stream::Stream;
use url::Host;

pub struct UnixTunnelListener {
    listener: UnixListenerStream,
    dest: (Host, u16),
    proxy_protocol: bool,
    path: PathBuf,
}

impl UnixTunnelListener {
    pub async fn new(path: &Path, dest: (Host, u16), proxy_protocol: bool) -> anyhow::Result<Self> {
        let listener = unix_sock::run_server(path)
            .await
            .with_context(|| anyhow!("Cannot start Unix domain server on {}", path.display()))?;

        Ok(Self {
            listener,
            dest,
            proxy_protocol,
            path: path.to_path_buf(),
        })
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
impl Drop for UnixTunnelListener {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_file(&self.path) {
            log::error!("Cannot remove Unix domain socket file {}: {}", self.path.display(), err);
        }
    }
}
