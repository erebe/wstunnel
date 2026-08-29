use std::io::{Error, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use url::Url;

use crate::protocols;
use crate::protocols::dns::DnsResolver;
use crate::protocols::udp;
use crate::protocols::udp::WsUdpStream;
use crate::somark::SoMark;
use crate::tunnel::upstream_connectors::UpstreamConnector;
use crate::tunnel::{LocalProtocol, RemoteAddr};

pub struct Socks5UpstreamConnector<'a> {
    so_mark: SoMark,
    connect_timeout: Duration,
    dns_resolver: &'a DnsResolver,
}

impl Socks5UpstreamConnector<'_> {
    pub fn new(so_mark: SoMark, connect_timeout: Duration, dns_resolver: &DnsResolver) -> Socks5UpstreamConnector<'_> {
        Socks5UpstreamConnector {
            so_mark,
            connect_timeout,
            dns_resolver,
        }
    }
}

impl UpstreamConnector for Socks5UpstreamConnector<'_> {
    type Reader = Socks5UpstreamReader;
    type Writer = Socks5UpstreamWriter;

    async fn connect(&self, remote: &Option<RemoteAddr>) -> anyhow::Result<(Self::Reader, Self::Writer)> {
        let Some(remote) = remote else {
            return Err(anyhow!("Missing remote destination for reverse socks5"));
        };

        match remote.protocol {
            LocalProtocol::Tcp { proxy_protocol: _ } => {
                let stream = protocols::tcp::connect(
                    &remote.host,
                    remote.port,
                    self.so_mark,
                    self.connect_timeout,
                    self.dns_resolver,
                )
                .await?;
                let (reader, writer) = stream.into_split();
                Ok((Socks5UpstreamReader::Tcp(reader), Socks5UpstreamWriter::Tcp(writer)))
            }
            LocalProtocol::Udp { .. } => {
                let stream =
                    udp::connect(&remote.host, remote.port, self.connect_timeout, self.so_mark, self.dns_resolver)
                        .await?;
                Ok((Socks5UpstreamReader::Udp(stream.clone()), Socks5UpstreamWriter::Udp(stream)))
            }
            _ => Err(anyhow!("Invalid protocol for reverse socks5 {:?}", remote.protocol)),
        }
    }

    async fn connect_with_http_proxy(
        &self,
        proxy: &Url,
        remote: &Option<RemoteAddr>,
    ) -> anyhow::Result<(Self::Reader, Self::Writer)> {
        let Some(remote) = remote else {
            return Err(anyhow!("Missing remote destination for reverse socks5"));
        };

        match remote.protocol {
            LocalProtocol::Tcp { proxy_protocol: _ } => {
                let stream = protocols::tcp::connect_with_http_proxy(
                    proxy,
                    &remote.host,
                    remote.port,
                    self.so_mark,
                    self.connect_timeout,
                    self.dns_resolver,
                )
                .await?;
                let (reader, writer) = stream.into_split();
                Ok((Socks5UpstreamReader::Tcp(reader), Socks5UpstreamWriter::Tcp(writer)))
            }
            _ => Err(anyhow!("Socks5 UDP cannot use http proxy to connect to destination")),
        }
    }
}

pub enum Socks5UpstreamReader {
    Tcp(OwnedReadHalf),
    Udp(WsUdpStream),
}

impl AsyncRead for Socks5UpstreamReader {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Socks5UpstreamReader::Tcp(reader) => Pin::new(reader).poll_read(cx, buf),
            Socks5UpstreamReader::Udp(reader) => Pin::new(reader).poll_read(cx, buf),
        }
    }
}

pub enum Socks5UpstreamWriter {
    Tcp(OwnedWriteHalf),
    Udp(WsUdpStream),
}

impl AsyncWrite for Socks5UpstreamWriter {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Socks5UpstreamWriter::Tcp(writer) => Pin::new(writer).poll_write(cx, buf),
            Socks5UpstreamWriter::Udp(wrtier) => Pin::new(wrtier).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Socks5UpstreamWriter::Tcp(writer) => Pin::new(writer).poll_flush(cx),
            Socks5UpstreamWriter::Udp(wrtier) => Pin::new(wrtier).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Socks5UpstreamWriter::Tcp(writer) => Pin::new(writer).poll_shutdown(cx),
            Socks5UpstreamWriter::Udp(wrtier) => Pin::new(wrtier).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Socks5UpstreamWriter::Tcp(writer) => Pin::new(writer).poll_write_vectored(cx, bufs),
            Socks5UpstreamWriter::Udp(wrtier) => Pin::new(wrtier).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Socks5UpstreamWriter::Tcp(v) => v.is_write_vectored(),
            Socks5UpstreamWriter::Udp(v) => v.is_write_vectored(),
        }
    }
}
