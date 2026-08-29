use super::{DownstreamRead, DownstreamWrite};
use crate::protocols::stdio;
use crate::tunnel::{LocalProtocol, RemoteAddr};
use anyhow::{Context, anyhow};
use std::pin::Pin;
use std::task::Poll;
use tokio::sync::oneshot;
use tokio_stream::Stream;
use url::Host;

// Stdio has no post-connect handshake: the concrete write half relies on the no-op default.
// `run_server` yields these concrete types, so they can be named for a direct impl (a non-auto
// trait like `TunnelConnectorWrite` does not leak through an `impl AsyncWrite` return type).
#[cfg(unix)]
impl DownstreamWrite for tokio_fd::AsyncFd {}
#[cfg(not(unix))]
impl DownstreamWrite for tokio::io::DuplexStream {}

pub struct StdioDownstreamListener<R, W>
where
    R: DownstreamRead,
    W: DownstreamWrite,
{
    listener: Option<(R, W)>,
    dest: (Host, u16),
    proxy_protocol: bool,
}

pub async fn new_stdio_listener(
    dest: (Host, u16),
    proxy_protocol: bool,
) -> anyhow::Result<(
    StdioDownstreamListener<impl DownstreamRead, impl DownstreamWrite>,
    oneshot::Sender<()>,
)> {
    let (listener, handle) = stdio::run_server()
        .await
        .with_context(|| anyhow!("Cannot start STDIO server"))?;
    Ok((
        StdioDownstreamListener {
            listener: Some(listener),
            proxy_protocol,
            dest,
        },
        handle,
    ))
}

impl<R, W> Stream for StdioDownstreamListener<R, W>
where
    R: DownstreamRead,
    W: DownstreamWrite,
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
