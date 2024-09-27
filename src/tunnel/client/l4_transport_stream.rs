use bytes::{Buf, Bytes};
use std::cmp;
use std::io::{Error, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

pub enum TransportStream {
    Plain(TcpStream, Bytes),
    Tls(tokio_rustls::client::TlsStream<TcpStream>, Bytes),
    TlsSrv(tokio_rustls::server::TlsStream<TcpStream>, Bytes),
}

impl TransportStream {
    pub fn read_buf_mut(&mut self) -> &mut Bytes {
        match self {
            Self::Plain(_, buf) => buf,
            Self::Tls(_, buf) => buf,
            Self::TlsSrv(_, buf) => buf,
        }
    }
}

impl AsyncRead for TransportStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        let read_buf = this.read_buf_mut();
        if !read_buf.is_empty() {
            let copy_len = cmp::min(read_buf.len(), buf.remaining());
            buf.put_slice(&read_buf[..copy_len]);
            read_buf.advance(copy_len);
            return Poll::Ready(Ok(()));
        }

        match this {
            Self::Plain(cnx, _) => Pin::new(cnx).poll_read(cx, buf),
            Self::Tls(cnx, _) => Pin::new(cnx).poll_read(cx, buf),
            Self::TlsSrv(cnx, _) => Pin::new(cnx).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TransportStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Self::Plain(cnx, _) => Pin::new(cnx).poll_write(cx, buf),
            Self::Tls(cnx, _) => Pin::new(cnx).poll_write(cx, buf),
            Self::TlsSrv(cnx, _) => Pin::new(cnx).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Self::Plain(cnx, _) => Pin::new(cnx).poll_flush(cx),
            Self::Tls(cnx, _) => Pin::new(cnx).poll_flush(cx),
            Self::TlsSrv(cnx, _) => Pin::new(cnx).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Self::Plain(cnx, _) => Pin::new(cnx).poll_shutdown(cx),
            Self::Tls(cnx, _) => Pin::new(cnx).poll_shutdown(cx),
            Self::TlsSrv(cnx, _) => Pin::new(cnx).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Self::Plain(cnx, _) => Pin::new(cnx).poll_write_vectored(cx, bufs),
            Self::Tls(cnx, _) => Pin::new(cnx).poll_write_vectored(cx, bufs),
            Self::TlsSrv(cnx, _) => Pin::new(cnx).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self {
            Self::Plain(cnx, _) => cnx.is_write_vectored(),
            Self::Tls(cnx, _) => cnx.is_write_vectored(),
            Self::TlsSrv(cnx, _) => cnx.is_write_vectored(),
        }
    }
}
