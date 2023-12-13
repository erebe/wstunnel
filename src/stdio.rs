#[cfg(unix)]
pub mod server {

    use tokio_fd::AsyncFd;
    pub async fn run_server() -> Result<(AsyncFd, AsyncFd), anyhow::Error> {
        eprintln!("Starting STDIO server");

        let stdin = AsyncFd::try_from(nix::libc::STDIN_FILENO)?;
        let stdout = AsyncFd::try_from(nix::libc::STDOUT_FILENO)?;

        Ok((stdin, stdout))
    }
}

#[cfg(not(unix))]
pub mod server {
    use bytes::BytesMut;
    use std::io::{Read, Write};
    use std::{io, thread};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
    use tokio::task::LocalSet;
    use tokio_stream::wrappers::UnboundedReceiverStream;
    use tokio_util::io::StreamReader;

    pub async fn run_server() -> Result<(impl AsyncRead, impl AsyncWrite), anyhow::Error> {
        eprintln!("Starting STDIO server");

        crossterm::terminal::enable_raw_mode()?;

        let stdin = io::stdin();
        let (send, recv) = tokio::sync::mpsc::unbounded_channel();
        thread::spawn(move || {
            let stdin = stdin;
            let mut stdin = stdin.lock();
            let mut buf = [0u8; 65536];
            loop {
                let n = stdin.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                if let Err(err) = send.send(Result::<_, io::Error>::Ok(BytesMut::from(&buf[..n]))) {
                    eprintln!("Failed send inout: {:?}", err);
                    break;
                }
            }
        });
        let stdin = StreamReader::new(UnboundedReceiverStream::new(recv));

        let (stdout, mut recv) = tokio::io::duplex(65536);
        let rt = tokio::runtime::Handle::current();
        thread::spawn(move || {
            let task = async move {
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
                        eprintln!("Failed to write to stdout: {:?}", err);
                        break;
                    };
                    let _ = stdout.flush();
                }
            };

            let local = LocalSet::new();
            local.spawn_local(task);

            rt.block_on(local);
        });

        Ok((stdin, stdout))
    }
}
