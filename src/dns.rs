use hickory_resolver::TokioAsyncResolver;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

#[derive(Clone)]
pub enum DnsResolver {
    System,
    TrustDns(TokioAsyncResolver),
}

impl DnsResolver {
    pub async fn lookup_host(&self, domain: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
        let addrs: Vec<SocketAddr> = match self {
            DnsResolver::System => tokio::net::lookup_host(format!("{}:{}", domain, port)).await?.collect(),
            DnsResolver::TrustDns(dns_resolver) => dns_resolver
                .lookup_ip(domain)
                .await?
                .into_iter()
                .map(|ip| match ip {
                    IpAddr::V4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, port)),
                    IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)),
                })
                .collect(),
        };

        Ok(addrs)
    }
}
