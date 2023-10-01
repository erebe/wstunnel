#![allow(unused_imports)]

use libc::STDIN_FILENO;
use std::os::fd::{AsRawFd, FromRawFd};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::fs::File;
use tokio::io::{stdout, AsyncRead, ReadBuf, Stdout};
use tokio_fd::AsyncFd;
use tracing::info;

pub async fn run_server() -> Result<(AsyncFd, AsyncFd), anyhow::Error> {
    info!("Starting STDIO server");

    let stdin = AsyncFd::try_from(libc::STDIN_FILENO)?;
    let stdout = AsyncFd::try_from(libc::STDOUT_FILENO)?;

    Ok((stdin, stdout))
}
