use tokio::io::AsyncWrite;

pub mod io;
pub mod websocket;

pub trait TunnelWrite {
    async fn write(&mut self, buf: &[u8]) -> anyhow::Result<()>;
    async fn ping(&mut self) -> anyhow::Result<()>;
    async fn close(&mut self) -> anyhow::Result<()>;
}

pub trait TunnelRead {
    async fn copy(&mut self, writer: impl AsyncWrite + Unpin) -> anyhow::Result<()>;
}
