use std::io::{Error, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

pub enum TransportStream {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl AsyncRead for TransportStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(cnx) => Pin::new(cnx).poll_read(cx, buf),
            Self::Tls(cnx) => Pin::new(cnx).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TransportStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Self::Plain(cnx) => Pin::new(cnx).poll_write(cx, buf),
            Self::Tls(cnx) => Pin::new(cnx).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Self::Plain(cnx) => Pin::new(cnx).poll_flush(cx),
            Self::Tls(cnx) => Pin::new(cnx).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Self::Plain(cnx) => Pin::new(cnx).poll_shutdown(cx),
            Self::Tls(cnx) => Pin::new(cnx).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Self::Plain(cnx) => Pin::new(cnx).poll_write_vectored(cx, bufs),
            Self::Tls(cnx) => Pin::new(cnx).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self {
            Self::Plain(cnx) => cnx.is_write_vectored(),
            Self::Tls(cnx) => cnx.is_write_vectored(),
        }
    }
}
