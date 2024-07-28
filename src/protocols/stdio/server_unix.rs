use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::oneshot;
use tokio_fd::AsyncFd;
use tracing::info;

pub struct WsStdin {
    stdin: AsyncFd,
    _receiver: oneshot::Receiver<()>,
}

impl AsyncRead for WsStdin {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        unsafe { self.map_unchecked_mut(|s| &mut s.stdin) }.poll_read(cx, buf)
    }
}

pub async fn run_server() -> Result<((WsStdin, AsyncFd), oneshot::Sender<()>), anyhow::Error> {
    info!("Starting STDIO server");

    let stdin = AsyncFd::try_from(nix::libc::STDIN_FILENO)?;
    let stdout = AsyncFd::try_from(nix::libc::STDOUT_FILENO)?;
    let (tx, rx) = oneshot::channel::<()>();

    Ok(((WsStdin { stdin, _receiver: rx }, stdout), tx))
}
