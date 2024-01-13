use std::future::Future;
use tokio::io::AsyncWrite;

pub mod io;
pub mod websocket;

pub trait TunnelWrite: Send + 'static {
    fn write(&mut self, buf: &[u8]) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn ping(&mut self) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn close(&mut self) -> impl Future<Output = anyhow::Result<()>> + Send;
}

pub trait TunnelRead: Send + 'static {
    fn copy(&mut self, writer: impl AsyncWrite + Unpin + Send) -> impl Future<Output = anyhow::Result<()>> + Send;
}
