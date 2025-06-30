use anyhow::Context;
use futures_util::Stream;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::task::Poll;
use tokio::net::{UnixListener, UnixStream};
use tracing::log::info;

pub struct UnixListenerStream {
    inner: UnixListener,
    path_to_delete: bool,
}

impl UnixListenerStream {
    pub const fn new(listener: UnixListener, path_to_delete: bool) -> Self {
        Self {
            inner: listener,
            path_to_delete,
        }
    }
}

impl Drop for UnixListenerStream {
    fn drop(&mut self) {
        if self.path_to_delete {
            let Ok(addr) = &self.inner.local_addr() else {
                return;
            };
            let Some(path) = addr.as_pathname() else {
                return;
            };
            let _ = std::fs::remove_file(path);
        }
    }
}

impl Stream for UnixListenerStream {
    type Item = io::Result<UnixStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<io::Result<UnixStream>>> {
        match self.inner.poll_accept(cx) {
            Poll::Ready(Ok((stream, _))) => Poll::Ready(Some(Ok(stream))),
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub async fn run_server(socket_path: &Path) -> Result<UnixListenerStream, anyhow::Error> {
    info!("Starting Unix socket server listening cnx on {socket_path:?}");

    let path_to_delete = !socket_path.exists();
    let listener =
        UnixListener::bind(socket_path).with_context(|| format!("Cannot create Unix socket server {socket_path:?}"))?;

    Ok(UnixListenerStream::new(listener, path_to_delete))
}
