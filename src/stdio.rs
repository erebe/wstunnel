use tokio_fd::AsyncFd;

pub async fn run_server() -> Result<(AsyncFd, AsyncFd), anyhow::Error> {
    eprintln!("Starting STDIO server");

    let stdin = AsyncFd::try_from(libc::STDIN_FILENO)?;
    let stdout = AsyncFd::try_from(libc::STDOUT_FILENO)?;

    Ok((stdin, stdout))
}
