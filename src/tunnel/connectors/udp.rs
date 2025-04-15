use std::time::Duration;

use url::Host;

use crate::protocols;
use crate::protocols::dns::DnsResolver;
use crate::protocols::udp::WsUdpSocket;
use crate::somark::SoMark;
use crate::tunnel::RemoteAddr;
use crate::tunnel::connectors::TunnelConnector;

pub struct UdpTunnelConnector<'a> {
    host: &'a Host,
    port: u16,
    so_mark: SoMark,
    connect_timeout: Duration,
    dns_resolver: &'a DnsResolver,
}

impl<'a> UdpTunnelConnector<'a> {
    pub fn new(
        host: &'a Host,
        port: u16,
        so_mark: SoMark,
        connect_timeout: Duration,
        dns_resolver: &'a DnsResolver,
    ) -> UdpTunnelConnector<'a> {
        UdpTunnelConnector {
            host,
            port,
            so_mark,
            connect_timeout,
            dns_resolver,
        }
    }
}

impl TunnelConnector for UdpTunnelConnector<'_> {
    type Reader = WsUdpSocket;
    type Writer = WsUdpSocket;

    async fn connect(&self, _: &Option<RemoteAddr>) -> anyhow::Result<(Self::Reader, Self::Writer)> {
        let stream =
            protocols::udp::connect(self.host, self.port, self.connect_timeout, self.so_mark, self.dns_resolver)
                .await?;

        Ok((stream.clone(), stream))
    }
}
