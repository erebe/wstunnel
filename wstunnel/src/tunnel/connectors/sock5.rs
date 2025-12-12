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
use crate::protocols::udp::WsUdpSocket;
use crate::somark::SoMark;
use crate::tunnel::connectors::TunnelConnector;
use crate::tunnel::{LocalProtocol, RemoteAddr};

pub struct Socks5TunnelConnector<'a> {
    so_mark: SoMark,
    connect_timeout: Duration,
    dns_resolver: &'a DnsResolver,
}

impl Socks5TunnelConnector<'_> {
    pub fn new(so_mark: SoMark, connect_timeout: Duration, dns_resolver: &DnsResolver) -> Socks5TunnelConnector<'_> {
        Socks5TunnelConnector {
            so_mark,
            connect_timeout,
            dns_resolver,
        }
    }
}

impl TunnelConnector for Socks5TunnelConnector<'_> {
    type Reader = Socks5Reader;
    type Writer = Socks5Writer;

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
                Ok((Socks5Reader::Tcp(reader), Socks5Writer::Tcp(writer)))
            }
            LocalProtocol::Udp { .. } => {
                let stream =
                    udp::connect(&remote.host, remote.port, self.connect_timeout, self.so_mark, self.dns_resolver)
                        .await?;
                Ok((Socks5Reader::Udp(stream.clone()), Socks5Writer::Udp(stream)))
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
                Ok((Socks5Reader::Tcp(reader), Socks5Writer::Tcp(writer)))
            }
            _ => Err(anyhow!("Socks5 UDP cannot use http proxy to connect to destination")),
        }
    }
}

pub enum Socks5Reader {
    Tcp(OwnedReadHalf),
    Udp(WsUdpSocket),
}

impl AsyncRead for Socks5Reader {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Socks5Reader::Tcp(reader) => Pin::new(reader).poll_read(cx, buf),
            Socks5Reader::Udp(reader) => Pin::new(reader).poll_read(cx, buf),
        }
    }
}

pub enum Socks5Writer {
    Tcp(OwnedWriteHalf),
    Udp(WsUdpSocket),
}

impl AsyncWrite for Socks5Writer {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Socks5Writer::Tcp(writer) => Pin::new(writer).poll_write(cx, buf),
            Socks5Writer::Udp(wrtier) => Pin::new(wrtier).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Socks5Writer::Tcp(writer) => Pin::new(writer).poll_flush(cx),
            Socks5Writer::Udp(wrtier) => Pin::new(wrtier).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Socks5Writer::Tcp(writer) => Pin::new(writer).poll_shutdown(cx),
            Socks5Writer::Udp(wrtier) => Pin::new(wrtier).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Socks5Writer::Tcp(writer) => Pin::new(writer).poll_write_vectored(cx, bufs),
            Socks5Writer::Udp(wrtier) => Pin::new(wrtier).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Socks5Writer::Tcp(v) => v.is_write_vectored(),
            Socks5Writer::Udp(v) => v.is_write_vectored(),
        }
    }
}
