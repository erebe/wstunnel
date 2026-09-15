use std::time::Duration;

use url::Host;

use crate::protocols;
use crate::protocols::dns::DnsResolver;
use crate::protocols::udp::WsUdpStream;
use crate::somark::SoMark;
use crate::tunnel::RemoteAddr;
use crate::tunnel::upstream_connectors::UpstreamConnector;

pub struct UdpUpstreamConnector {
    host: Host,
    port: u16,
    so_mark: SoMark,
    connect_timeout: Duration,
    dns_resolver: DnsResolver,
}

impl UdpUpstreamConnector {
    pub fn new(
        host: Host,
        port: u16,
        so_mark: SoMark,
        connect_timeout: Duration,
        dns_resolver: DnsResolver,
    ) -> UdpUpstreamConnector {
        UdpUpstreamConnector {
            host,
            port,
            so_mark,
            connect_timeout,
            dns_resolver,
        }
    }
}

impl UpstreamConnector for UdpUpstreamConnector {
    type Reader = WsUdpStream;
    type Writer = WsUdpStream;

    async fn connect(&self, _: &Option<RemoteAddr>) -> anyhow::Result<(Self::Reader, Self::Writer)> {
        let stream =
            protocols::udp::connect(&self.host, self.port, self.connect_timeout, self.so_mark, &self.dns_resolver)
                .await?;

        Ok((stream.clone(), stream))
    }
}
