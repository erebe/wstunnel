use crate::protocols;
use crate::somark::SoMark;
use anyhow::{Context, anyhow};
use futures_util::{FutureExt, TryFutureExt};
use hickory_resolver::Resolver;
use hickory_resolver::config::{LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::GenericConnector;
use hickory_resolver::proto::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::proto::runtime::{RuntimeProvider, TokioHandle, TokioRuntimeProvider, TokioTime};
use hickory_resolver::proto::xfer::Protocol;
use log::warn;
use std::future::Future;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use url::{Host, Url};

#[cfg(feature = "aws-lc-rs")]
use hickory_resolver::ResolveError;
#[cfg(feature = "aws-lc-rs")]
use tokio_rustls::rustls::client::EchConfig;

// Interleave v4 and v6 addresses as per RFC8305.
// The first address is v6 if we have any v6 addresses.
#[inline]
fn sort_socket_addrs(socket_addrs: &[SocketAddr], prefer_ipv6: bool) -> impl Iterator<Item = &'_ SocketAddr> {
    let mut pick_v6 = !prefer_ipv6;
    let mut v6 = socket_addrs.iter().filter(|s| matches!(s, SocketAddr::V6(_)));
    let mut v4 = socket_addrs.iter().filter(|s| matches!(s, SocketAddr::V4(_)));
    std::iter::from_fn(move || {
        pick_v6 = !pick_v6;
        if pick_v6 {
            v6.next().or_else(|| v4.next())
        } else {
            v4.next().or_else(|| v6.next())
        }
    })
}

#[allow(clippy::large_enum_variant)] // System variant never used mostly
#[derive(Clone, Debug)]
pub enum DnsResolver {
    System,
    TrustDns {
        resolver: Box<Resolver<GenericConnector<TokioRuntimeProviderWithSoMark>>>,
        prefer_ipv6: bool,
    },
}

impl DnsResolver {
    pub async fn lookup_host(&self, domain: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
        let addrs = match self {
            Self::System => tokio::net::lookup_host(format!("{domain}:{port}")).await?.collect(),
            Self::TrustDns { resolver, prefer_ipv6 } => {
                let addrs: Vec<_> = resolver
                    .lookup_ip(domain)
                    .await?
                    .into_iter()
                    .map(|ip| match ip {
                        IpAddr::V4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, port)),
                        IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)),
                    })
                    .collect();
                sort_socket_addrs(&addrs, *prefer_ipv6).copied().collect()
            }
        };

        Ok(addrs)
    }

    #[cfg(feature = "aws-lc-rs")]
    pub async fn lookup_ech_config(&self, domain: &Host) -> Result<Option<EchConfig>, ResolveError> {
        use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
        use hickory_resolver::proto::rr::{RData, RecordType};
        use tokio_rustls::rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
        use tokio_rustls::rustls::pki_types::EchConfigListBytes;

        let resolver = match self {
            DnsResolver::TrustDns { resolver, .. } => resolver,
            _ => {
                return Ok(None);
            }
        };

        let domain = match domain {
            Host::Domain(domain) => domain,
            _ => return Ok(None),
        };

        let lookup = resolver.lookup(domain, RecordType::HTTPS).await?;

        let ech_config = lookup
            .iter()
            .filter_map(|record_data| {
                if let RData::HTTPS(svcb) = record_data {
                    Some(svcb)
                } else {
                    None
                }
            })
            .flat_map(|svcb| {
                svcb.svc_params().iter().filter_map(|sp| {
                    let (SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(e)) = sp else {
                        return None;
                    };

                    EchConfig::new(EchConfigListBytes::from(e.0.as_slice()), ALL_SUPPORTED_SUITES).ok()
                })
            })
            .next();

        Ok(ech_config)
    }

    pub fn new_from_urls(
        resolvers: &[Url],
        proxy: Option<Url>,
        so_mark: SoMark,
        prefer_ipv6: bool,
    ) -> anyhow::Result<Self> {
        fn mk_resolver(
            cfg: ResolverConfig,
            mut opts: ResolverOpts,
            proxy: Option<Url>,
            so_mark: SoMark,
        ) -> Resolver<GenericConnector<TokioRuntimeProviderWithSoMark>> {
            opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
            opts.timeout = Duration::from_secs(1);

            // Windows end-up with too many dns resolvers, which causes a performance issue
            // https://github.com/hickory-dns/hickory-dns/issues/1968
            #[cfg(target_os = "windows")]
            {
                opts.cache_size = 1024;
                opts.num_concurrent_reqs = cfg.name_servers().len();
            }

            let mut builder = Resolver::builder_with_config(
                cfg,
                GenericConnector::new(TokioRuntimeProviderWithSoMark::new(proxy, so_mark)),
            );
            *builder.options_mut() = opts;
            builder.build()
        }

        fn get_sni(resolver: &Url) -> anyhow::Result<String> {
            Ok(resolver
                .query_pairs()
                .find(|(k, _)| k == "sni")
                .with_context(|| "Missing `sni` query parameter for dns over https")?
                .1
                .to_string())
        }

        fn url_to_ns_config(resolver: &Url) -> anyhow::Result<NameServerConfig> {
            let (protocol, port, tls_sni) = match resolver.scheme() {
                "dns" => (Protocol::Udp, resolver.port().unwrap_or(53), None),
                "dns+https" => (Protocol::Https, resolver.port().unwrap_or(443), Some(get_sni(resolver)?)),
                "dns+tls" => (Protocol::Tls, resolver.port().unwrap_or(853), Some(get_sni(resolver)?)),
                _ => return Err(anyhow!("invalid protocol for dns resolver")),
            };
            let host = resolver
                .host()
                .ok_or_else(|| anyhow!("Invalid dns resolver host: {resolver}"))?;
            let sock = match host {
                Host::Domain(host) => match Host::parse(host) {
                    Ok(Host::Ipv4(ip)) => SocketAddr::V4(SocketAddrV4::new(ip, port)),
                    Ok(Host::Ipv6(ip)) => SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)),
                    Ok(Host::Domain(_)) | Err(_) => {
                        return Err(anyhow!("Dns resolver must be an ip address, got {host}"));
                    }
                },
                Host::Ipv4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, port)),
                Host::Ipv6(ip) => SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)),
            };

            let mut ns = NameServerConfig::new(sock, protocol);
            ns.tls_dns_name = tls_sni;

            Ok(ns)
        }

        // no dns resolver specified, fall-back to default one
        if resolvers.is_empty() {
            let Ok((cfg, opts)) = hickory_resolver::system_conf::read_system_conf() else {
                warn!(
                    "Fall-backing to system dns resolver. You should consider specifying a dns resolver. To avoid performance issue"
                );
                return Ok(Self::System);
            };

            return Ok(Self::TrustDns {
                resolver: Box::new(mk_resolver(cfg, opts, proxy, so_mark)),
                prefer_ipv6,
            });
        };

        // if one is specified as system, use the default one from libc
        if resolvers.iter().any(|r| r.scheme() == "system") {
            return Ok(Self::System);
        }

        // otherwise, use the specified resolvers
        let mut cfg = ResolverConfig::new();
        for resolver in resolvers.iter() {
            cfg.add_name_server(url_to_ns_config(resolver)?);
        }

        Ok(Self::TrustDns {
            resolver: Box::new(mk_resolver(cfg, ResolverOpts::default(), proxy, so_mark)),
            prefer_ipv6,
        })
    }
}

#[derive(Clone)]
pub struct TokioRuntimeProviderWithSoMark {
    runtime: TokioRuntimeProvider,
    proxy: Option<Arc<Url>>,
    so_mark: SoMark,
}

impl TokioRuntimeProviderWithSoMark {
    fn new(proxy: Option<Url>, so_mark: SoMark) -> Self {
        Self {
            runtime: TokioRuntimeProvider::default(),
            proxy: proxy.map(Arc::new),
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
    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        _bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>> {
        let so_mark = self.so_mark;
        let proxy = self.proxy.clone();
        let socket = async move {
            let host = match server_addr.ip() {
                IpAddr::V4(addr) => Host::Ipv4(addr),
                IpAddr::V6(addr) => Host::Ipv6(addr),
            };

            if let Some(proxy) = &proxy {
                protocols::tcp::connect_with_http_proxy(
                    proxy,
                    &host,
                    server_addr.port(),
                    so_mark,
                    timeout.unwrap_or(Duration::from_secs(10)),
                    &DnsResolver::System, // not going to be used as host is directly an ip address
                )
                .map_err(std::io::Error::other)
                .map(|s| s.map(AsyncIoTokioAsStd))
                .await
            } else {
                protocols::tcp::connect(
                    &host,
                    server_addr.port(),
                    so_mark,
                    timeout.unwrap_or(Duration::from_secs(10)),
                    &DnsResolver::System, // not going to be used as host is directly an ip address
                )
                .map_err(std::io::Error::other)
                .map(|s| s.map(AsyncIoTokioAsStd))
                .await
            }
        };

        Box::pin(socket)
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        let socket = UdpSocket::bind(local_addr);

        #[cfg(target_os = "linux")]
        let socket = {
            socket.map({
                let so_mark = self.so_mark;
                move |sock| {
                    if let Ok(ref sock) = sock {
                        so_mark.set_mark(socket2::SockRef::from(sock))?;
                    }
                    sock
                }
            })
        };

        Box::pin(socket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_sort_socket_addrs() {
        let addrs = [
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 1)),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 127, 0, 0, 1), 1, 0, 0)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 3), 1)),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 127, 0, 0, 2), 1, 0, 0)),
        ];
        let expected = [
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 127, 0, 0, 1), 1, 0, 0)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1)),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 127, 0, 0, 2), 1, 0, 0)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 1)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 3), 1)),
        ];
        let actual: Vec<_> = sort_socket_addrs(&addrs, true).copied().collect();
        assert_eq!(expected, *actual);
    }
}
