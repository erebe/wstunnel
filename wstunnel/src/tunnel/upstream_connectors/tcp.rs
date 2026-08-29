use std::time::Duration;

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use url::{Host, Url};

use crate::protocols;
use crate::protocols::dns::DnsResolver;
use crate::somark::SoMark;
use crate::tunnel::RemoteAddr;
use crate::tunnel::upstream_connectors::UpstreamConnector;

pub struct TcpUpstreamConnector<'a> {
    host: &'a Host,
    port: u16,
    so_mark: SoMark,
    connect_timeout: Duration,
    dns_resolver: &'a DnsResolver,
}

impl<'a> TcpUpstreamConnector<'a> {
    pub fn new(
        host: &'a Host,
        port: u16,
        so_mark: SoMark,
        connect_timeout: Duration,
        dns_resolver: &'a DnsResolver,
    ) -> TcpUpstreamConnector<'a> {
        TcpUpstreamConnector {
            host,
            port,
            so_mark,
            connect_timeout,
            dns_resolver,
        }
    }
}

impl UpstreamConnector for TcpUpstreamConnector<'_> {
    type Reader = OwnedReadHalf;
    type Writer = OwnedWriteHalf;

    async fn connect(&self, remote: &Option<RemoteAddr>) -> anyhow::Result<(Self::Reader, Self::Writer)> {
        let (host, port) = match remote {
            Some(remote) => (&remote.host, remote.port),
            None => (self.host, self.port),
        };

        let stream = protocols::tcp::connect(host, port, self.so_mark, self.connect_timeout, self.dns_resolver).await?;
        Ok(stream.into_split())
    }

    async fn connect_with_http_proxy(
        &self,
        proxy: &Url,
        remote: &Option<RemoteAddr>,
    ) -> anyhow::Result<(Self::Reader, Self::Writer)> {
        let (host, port) = match remote {
            Some(remote) => (&remote.host, remote.port),
            None => (self.host, self.port),
        };

        let stream = protocols::tcp::connect_with_http_proxy(
            proxy,
            host,
            port,
            self.so_mark,
            self.connect_timeout,
            self.dns_resolver,
        )
        .await?;
        Ok(stream.into_split())
    }
}
