use anyhow::anyhow;
use futures_util::FutureExt;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::{GenericConnector, RuntimeProvider, TokioRuntimeProvider};
use hickory_resolver::proto::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::proto::TokioTime;
use hickory_resolver::{AsyncResolver, TokioHandle};
use log::warn;
use std::future::Future;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use tokio::net::{TcpStream, UdpSocket};
use url::{Host, Url};

#[derive(Clone)]
pub enum DnsResolver {
    System,
    TrustDns(AsyncResolver<GenericConnector<TokioRuntimeProviderWithSoMark>>),
}

impl DnsResolver {
    pub async fn lookup_host(&self, domain: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
        let addrs: Vec<SocketAddr> = match self {
            Self::System => tokio::net::lookup_host(format!("{}:{}", domain, port)).await?.collect(),
            Self::TrustDns(dns_resolver) => dns_resolver
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

    pub fn new_from_urls(resolvers: &[Url], so_mark: Option<u32>) -> anyhow::Result<Self> {
        if resolvers.is_empty() {
            // no dns resolver specified, fall-back to default one
            let Ok((cfg, mut opts)) = hickory_resolver::system_conf::read_system_conf() else {
                warn!("Fall-backing to system dns resolver. You should consider specifying a dns resolver. To avoid performance issue");
                return Ok(Self::System);
            };

            opts.timeout = std::time::Duration::from_secs(1);
            // Windows end-up with too many dns resolvers, which causes a performance issue
            // https://github.com/hickory-dns/hickory-dns/issues/1968
            #[cfg(target_os = "windows")]
            {
                opts.cache_size = 1024;
                opts.num_concurrent_reqs = cfg.name_servers().len();
            }
            return Ok(Self::TrustDns(AsyncResolver::new(
                cfg,
                opts,
                GenericConnector::new(TokioRuntimeProviderWithSoMark::new(so_mark)),
            )));
        };

        // if one is specified as system, use the default one from libc
        if resolvers.iter().any(|r| r.scheme() == "system") {
            return Ok(Self::System);
        }

        // otherwise, use the specified resolvers
        let mut cfg = ResolverConfig::new();
        for resolver in resolvers.iter() {
            let (protocol, port) = match resolver.scheme() {
                "dns" => (hickory_resolver::config::Protocol::Udp, resolver.port().unwrap_or(53)),
                "dns+https" => (hickory_resolver::config::Protocol::Https, resolver.port().unwrap_or(443)),
                "dns+tls" => (hickory_resolver::config::Protocol::Tls, resolver.port().unwrap_or(853)),
                _ => return Err(anyhow!("invalid protocol for dns resolver")),
            };
            let host = resolver
                .host()
                .ok_or_else(|| anyhow!("Invalid dns resolver host: {}", resolver))?;
            let sock = match host {
                Host::Domain(host) => match Host::parse(host) {
                    Ok(Host::Ipv4(ip)) => SocketAddr::V4(SocketAddrV4::new(ip, port)),
                    Ok(Host::Ipv6(ip)) => SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)),
                    Ok(Host::Domain(_)) | Err(_) => {
                        return Err(anyhow!("Dns resolver must be an ip address, got {}", host));
                    }
                },
                Host::Ipv4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, port)),
                Host::Ipv6(ip) => SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)),
            };
            cfg.add_name_server(NameServerConfig::new(sock, protocol))
        }

        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(1);
        Ok(Self::TrustDns(AsyncResolver::new(
            cfg,
            opts,
            GenericConnector::new(TokioRuntimeProviderWithSoMark::new(so_mark)),
        )))
    }
}

#[derive(Clone)]
pub struct TokioRuntimeProviderWithSoMark {
    runtime: TokioRuntimeProvider,
    #[cfg(target_os = "linux")]
    so_mark: Option<u32>,
}

impl TokioRuntimeProviderWithSoMark {
    fn new(so_mark: Option<u32>) -> Self {
        Self {
            runtime: TokioRuntimeProvider::default(),
            #[cfg(target_os = "linux")]
            so_mark,
        }
    }
}

impl RuntimeProvider for TokioRuntimeProviderWithSoMark {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    #[inline]
    fn create_handle(&self) -> Self::Handle {
        self.runtime.create_handle()
    }

    #[inline]
    fn connect_tcp(&self, server_addr: SocketAddr) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>> {
        let socket = TcpStream::connect(server_addr);

        #[cfg(target_os = "linux")]
        let socket = {
            use socket2::SockRef;

            socket.map({
                let so_mark = self.so_mark;
                move |sock| {
                    if let (Ok(sock), Some(so_mark)) = (&sock, so_mark) {
                        SockRef::from(sock).set_mark(so_mark)?;
                    }
                    sock
                }
            })
        };

        Box::pin(socket.map(|s| s.map(AsyncIoTokioAsStd)))
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        let socket = UdpSocket::bind(local_addr);

        #[cfg(target_os = "linux")]
        let socket = {
            use socket2::SockRef;

            socket.map({
                let so_mark = self.so_mark;
                move |sock| {
                    if let (Ok(sock), Some(so_mark)) = (&sock, so_mark) {
                        SockRef::from(sock).set_mark(so_mark)?;
                    }
                    sock
                }
            })
        };

        Box::pin(socket)
    }
}
