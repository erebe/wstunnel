pub mod client;
pub mod connectors;
pub mod listeners;
pub mod server;
mod tls_reloader;
pub mod transport;

use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use std::time::Duration;
use url::Host;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LocalProtocol {
    Tcp {
        proxy_protocol: bool,
    },
    Udp {
        timeout: Option<Duration>,
    },
    Stdio {
        proxy_protocol: bool,
    },
    Socks5 {
        timeout: Option<Duration>,
        credentials: Option<(String, String)>,
    },
    TProxyTcp,
    TProxyUdp {
        timeout: Option<Duration>,
    },
    HttpProxy {
        timeout: Option<Duration>,
        credentials: Option<(String, String)>,
        proxy_protocol: bool,
    },
    ReverseTcp,
    ReverseUdp {
        timeout: Option<Duration>,
    },
    ReverseSocks5 {
        timeout: Option<Duration>,
        credentials: Option<(String, String)>,
    },
    ReverseHttpProxy {
        timeout: Option<Duration>,
        credentials: Option<(String, String)>,
    },
    ReverseUnix {
        path: PathBuf,
    },
    Unix {
        path: PathBuf,
        proxy_protocol: bool,
    },
}

impl LocalProtocol {
    pub const fn is_reverse_tunnel(&self) -> bool {
        matches!(
            self,
            Self::ReverseTcp
                | Self::ReverseUdp { .. }
                | Self::ReverseSocks5 { .. }
                | Self::ReverseUnix { .. }
                | Self::ReverseHttpProxy { .. }
        )
    }

    pub const fn is_dynamic_reverse_tunnel(&self) -> bool {
        matches!(self, Self::ReverseSocks5 { .. } | Self::ReverseHttpProxy { .. })
    }
}

#[derive(Debug, Clone)]
pub struct RemoteAddr {
    pub protocol: LocalProtocol,
    pub host: Host,
    pub port: u16,
}

pub fn to_host_port(addr: SocketAddr) -> (Host, u16) {
    match addr.ip() {
        IpAddr::V4(ip) => (Host::Ipv4(ip), addr.port()),
        IpAddr::V6(ip) => (Host::Ipv6(ip), addr.port()),
    }
}

pub fn try_to_sock_addr((host, port): (Host, u16)) -> anyhow::Result<SocketAddr> {
    match host {
        Host::Domain(_) => Err(anyhow::anyhow!("Cannot convert domain to socket address")),
        Host::Ipv4(ip) => Ok(SocketAddr::V4(SocketAddrV4::new(ip, port))),
        Host::Ipv6(ip) => Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))),
    }
}
