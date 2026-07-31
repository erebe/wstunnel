use crate::protocols::socks5::Socks5WriteHalf;
use fast_socks5::ReplyError;
use std::any::Any;
use std::pin::Pin;
use tokio::io::AsyncWrite;

pub(crate) trait AnyAsyncWrite: AsyncWrite + Send + Unpin {
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T> AnyAsyncWrite for T
where
    T: AsyncWrite + Send + Unpin + Any + 'static,
{
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

pub(crate) async fn send_socks5_reply_if_needed(
    writer: &mut Pin<Box<dyn AnyAsyncWrite>>,
    error: ReplyError,
) -> anyhow::Result<()> {
    let Some(socks5_writer) = writer.as_mut().get_mut().as_any_mut().downcast_mut::<Socks5WriteHalf>() else {
        return Ok(());
    };

    socks5_writer.send_reply_if_needed(error).await
}
