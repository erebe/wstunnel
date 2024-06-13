#[cfg(unix)]
pub mod server {
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
}

#[cfg(not(unix))]
pub mod server {
    use bytes::BytesMut;
    use log::error;
    use parking_lot::Mutex;
    use scopeguard::guard;
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::{io, thread};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
    use tokio::sync::oneshot;
    use tokio::task::LocalSet;
    use tokio_stream::wrappers::UnboundedReceiverStream;
    use tokio_util::io::StreamReader;
    use tracing::info;

    pub async fn run_server() -> Result<((impl AsyncRead, impl AsyncWrite), oneshot::Sender<()>), anyhow::Error> {
        info!("Starting STDIO server. Press ctrl+c twice to exit");

        crossterm::terminal::enable_raw_mode()?;

        let stdin = io::stdin();
        let (send, recv) = tokio::sync::mpsc::unbounded_channel();
        let (abort_tx, abort_rx) = oneshot::channel::<()>();
        let abort_rx = Arc::new(Mutex::new(abort_rx));
        let abort_rx2 = abort_rx.clone();
        thread::spawn(move || {
            let _restore_terminal = guard((), move |_| {
                let _ = crossterm::terminal::disable_raw_mode();
                abort_rx.lock().close();
            });
            let stdin = stdin;
            let mut stdin = stdin.lock();
            let mut buf = [0u8; 65536];

            loop {
                let n = stdin.read(&mut buf).unwrap_or(0);
                if n == 0 || (n == 1 && buf[0] == 3) {
                    // ctrl+c send char 3
                    break;
                }
                if let Err(err) = send.send(Result::<_, io::Error>::Ok(BytesMut::from(&buf[..n]))) {
                    error!("Failed send inout: {:?}", err);
                    break;
                }
            }
        });
        let stdin = StreamReader::new(UnboundedReceiverStream::new(recv));

        let (stdout, mut recv) = tokio::io::duplex(65536);
        let rt = tokio::runtime::Handle::current();
        thread::spawn(move || {
            let task = async move {
                let _restore_terminal = guard((), move |_| {
                    let _ = crossterm::terminal::disable_raw_mode();
                    abort_rx2.lock().close();
                });
                let mut stdout = io::stdout().lock();
                let mut buf = [0u8; 65536];
                loop {
                    let Ok(n) = recv.read(&mut buf).await else {
                        break;
                    };

                    if n == 0 {
                        break;
                    }

                    if let Err(err) = stdout.write_all(&buf[..n]) {
                        error!("Failed to write to stdout: {:?}", err);
                        break;
                    };
                    let _ = stdout.flush();
                }
            };

            let local = LocalSet::new();
            local.spawn_local(task);

            rt.block_on(local);
        });

        Ok(((stdin, stdout), abort_tx))
    }
}
