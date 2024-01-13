use crate::tunnel::transport::{TunnelRead, TunnelWrite};
use anyhow::{anyhow, Context};
use fastwebsockets::{Frame, OpCode, Payload, WebSocketRead, WebSocketWrite};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use log::debug;
use tokio::io::{AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tracing::trace;

impl TunnelWrite for WebSocketWrite<WriteHalf<TokioIo<Upgraded>>> {
    async fn write(&mut self, buf: &[u8]) -> anyhow::Result<()> {
        self.write_frame(Frame::binary(Payload::Borrowed(buf)))
            .await
            .with_context(|| "cannot send ws frame")
    }

    async fn ping(&mut self) -> anyhow::Result<()> {
        self.write_frame(Frame::new(true, OpCode::Ping, None, Payload::BorrowedMut(&mut [])))
            .await
            .with_context(|| "cannot send ws ping")
    }

    async fn close(&mut self) -> anyhow::Result<()> {
        self.write_frame(Frame::close(1000, &[]))
            .await
            .with_context(|| "cannot close websocket cnx")
    }
}

fn frame_reader(x: Frame<'_>) -> futures_util::future::Ready<anyhow::Result<()>> {
    debug!("frame {:?} {:?}", x.opcode, x.payload);
    futures_util::future::ready(anyhow::Ok(()))
}
impl TunnelRead for WebSocketRead<ReadHalf<TokioIo<Upgraded>>> {
    async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin) -> anyhow::Result<()> {
        loop {
            let msg = self
                .read_frame(&mut frame_reader)
                .await
                .with_context(|| "error while reading from websocket")?;

            trace!("receive ws frame {:?} {:?}", msg.opcode, msg.payload);
            match msg.opcode {
                OpCode::Continuation | OpCode::Text | OpCode::Binary => {
                    writer.write_all(msg.payload.as_ref()).await.with_context(|| "")?;
                    return Ok(());
                }
                OpCode::Close => return Err(anyhow!("websocket close")),
                OpCode::Ping => continue,
                OpCode::Pong => continue,
            };
        }
    }
}
