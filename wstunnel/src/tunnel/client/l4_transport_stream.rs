use bytes::{Buf, Bytes};
use std::cmp;
use std::io::{Error, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

pub struct TransportStream {
    read: TransportReadHalf,
    write: TransportWriteHalf,
}

impl TransportStream {
    pub fn from_tcp(tcp: TcpStream, read_buf: Bytes) -> Self {
        let (read, write) = tcp.into_split();
        Self {
            read: TransportReadHalf::Plain(read, read_buf),
            write: TransportWriteHalf::Plain(write),
        }
    }

    pub fn from_client_tls(tls: tokio_rustls::client::TlsStream<TcpStream>, read_buf: Bytes) -> Self {
        let (read, write) = tokio::io::split(tls);
        Self {
            read: TransportReadHalf::Tls(read, read_buf),
            write: TransportWriteHalf::Tls(write),
        }
    }

    pub fn from_server_tls(tls: tokio_rustls::server::TlsStream<TcpStream>, read_buf: Bytes) -> Self {
        let (read, write) = tokio::io::split(tls);
        Self {
            read: TransportReadHalf::TlsSrv(read, read_buf),
            write: TransportWriteHalf::TlsSrv(write),
        }
    }

    pub fn from(self, read_buf: Bytes) -> Self {
        let mut read = self.read;
        *read.read_buf_mut() = read_buf;
        Self {
            read,
            write: self.write,
        }
    }

    pub fn into_split(self) -> (TransportReadHalf, TransportWriteHalf) {
        (self.read, self.write)
    }
}

pub enum TransportReadHalf {
    Plain(OwnedReadHalf, Bytes),
    Tls(ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>, Bytes),
    TlsSrv(ReadHalf<tokio_rustls::server::TlsStream<TcpStream>>, Bytes),
}

impl TransportReadHalf {
    fn read_buf_mut(&mut self) -> &mut Bytes {
        match self {
            Self::Plain(_, buf) => buf,
            Self::Tls(_, buf) => buf,
            Self::TlsSrv(_, buf) => buf,
        }
    }
}

pub enum TransportWriteHalf {
    Plain(OwnedWriteHalf),
    Tls(WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>),
    TlsSrv(WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl AsyncRead for TransportStream {
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        unsafe { self.map_unchecked_mut(|s| &mut s.read).poll_read(cx, buf) }
    }
}

impl AsyncWrite for TransportStream {
    #[inline]
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        unsafe { self.map_unchecked_mut(|s| &mut s.write).poll_write(cx, buf) }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        unsafe { self.map_unchecked_mut(|s| &mut s.write).poll_flush(cx) }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        unsafe { self.map_unchecked_mut(|s| &mut s.write).poll_shutdown(cx) }
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        unsafe { self.map_unchecked_mut(|s| &mut s.write).poll_write_vectored(cx, bufs) }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.write.is_write_vectored()
    }
}

impl AsyncRead for TransportReadHalf {
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        let read_buf = this.read_buf_mut();
        if !read_buf.is_empty() {
            let copy_len = cmp::min(read_buf.len(), buf.remaining());
            buf.put_slice(&read_buf[..copy_len]);
            read_buf.advance(copy_len);
            if read_buf.is_empty() {
                read_buf.clear();
            }
            return Poll::Ready(Ok(()));
        }

        match this {
            Self::Plain(cnx, _) => Pin::new(cnx).poll_read(cx, buf),
            Self::Tls(cnx, _) => Pin::new(cnx).poll_read(cx, buf),
            Self::TlsSrv(cnx, _) => Pin::new(cnx).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TransportWriteHalf {
    #[inline]
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Self::Plain(cnx) => Pin::new(cnx).poll_write(cx, buf),
            Self::Tls(cnx) => Pin::new(cnx).poll_write(cx, buf),
            Self::TlsSrv(cnx) => Pin::new(cnx).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Self::Plain(cnx) => Pin::new(cnx).poll_flush(cx),
            Self::Tls(cnx) => Pin::new(cnx).poll_flush(cx),
            Self::TlsSrv(cnx) => Pin::new(cnx).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Self::Plain(cnx) => Pin::new(cnx).poll_shutdown(cx),
            Self::Tls(cnx) => Pin::new(cnx).poll_shutdown(cx),
            Self::TlsSrv(cnx) => Pin::new(cnx).poll_shutdown(cx),
        }
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Self::Plain(cnx) => Pin::new(cnx).poll_write_vectored(cx, bufs),
            Self::Tls(cnx) => Pin::new(cnx).poll_write_vectored(cx, bufs),
            Self::TlsSrv(cnx) => Pin::new(cnx).poll_write_vectored(cx, bufs),
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        match &self {
            Self::Plain(cnx) => cnx.is_write_vectored(),
            Self::Tls(cnx) => cnx.is_write_vectored(),
            Self::TlsSrv(cnx) => cnx.is_write_vectored(),
        }
    }
}
