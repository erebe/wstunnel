pub mod client;
pub mod connectors;
pub mod listeners;
pub mod server;
mod tls_reloader;
mod transport;

use crate::TlsClientConfig;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use std::str::FromStr;
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
        matches!(self, |Self::ReverseSocks5 { .. }| Self::ReverseHttpProxy { .. })
    }
}

#[derive(Debug, Clone)]
pub struct RemoteAddr {
    pub protocol: LocalProtocol,
    pub host: Host,
    pub port: u16,
}

#[derive(Copy, Clone, Debug)]
pub enum TransportScheme {
    Ws,
    Wss,
    Http,
    Https,
}

impl TransportScheme {
    pub const fn values() -> &'static [Self] {
        &[Self::Ws, Self::Wss, Self::Http, Self::Https]
    }
    pub const fn to_str(self) -> &'static str {
        match self {
            Self::Ws => "ws",
            Self::Wss => "wss",
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    pub fn alpn_protocols(&self) -> Vec<Vec<u8>> {
        match self {
            Self::Ws => vec![],
            Self::Wss => vec![b"http/1.1".to_vec()],
            Self::Http => vec![],
            Self::Https => vec![b"h2".to_vec()],
        }
    }
}
impl FromStr for TransportScheme {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "https" => Ok(Self::Https),
            "http" => Ok(Self::Http),
            "wss" => Ok(Self::Wss),
            "ws" => Ok(Self::Ws),
            _ => Err(()),
        }
    }
}

impl Display for TransportScheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_str())
    }
}

#[derive(Clone)]
pub enum TransportAddr {
    Wss {
        tls: TlsClientConfig,
        scheme: TransportScheme,
        host: Host,
        port: u16,
    },
    Ws {
        scheme: TransportScheme,
        host: Host,
        port: u16,
    },
    Https {
        scheme: TransportScheme,
        tls: TlsClientConfig,
        host: Host,
        port: u16,
    },
    Http {
        scheme: TransportScheme,
        host: Host,
        port: u16,
    },
}

impl Debug for TransportAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}://{}:{}", self.scheme(), self.host(), self.port()))
    }
}

impl TransportAddr {
    pub fn new(scheme: TransportScheme, host: Host, port: u16, tls: Option<TlsClientConfig>) -> Option<Self> {
        match scheme {
            TransportScheme::Https => Some(Self::Https {
                scheme: TransportScheme::Https,
                tls: tls?,
                host,
                port,
            }),
            TransportScheme::Http => Some(Self::Http {
                scheme: TransportScheme::Http,
                host,
                port,
            }),
            TransportScheme::Wss => Some(Self::Wss {
                scheme: TransportScheme::Wss,
                tls: tls?,
                host,
                port,
            }),
            TransportScheme::Ws => Some(Self::Ws {
                scheme: TransportScheme::Ws,
                host,
                port,
            }),
        }
    }
    pub const fn is_websocket(&self) -> bool {
        matches!(self, Self::Ws { .. } | Self::Wss { .. })
    }

    pub const fn is_http2(&self) -> bool {
        matches!(self, Self::Http { .. } | Self::Https { .. })
    }

    pub const fn tls(&self) -> Option<&TlsClientConfig> {
        match self {
            Self::Wss { tls, .. } => Some(tls),
            Self::Https { tls, .. } => Some(tls),
            Self::Ws { .. } => None,
            Self::Http { .. } => None,
        }
    }

    pub const fn host(&self) -> &Host {
        match self {
            Self::Wss { host, .. } => host,
            Self::Ws { host, .. } => host,
            Self::Https { host, .. } => host,
            Self::Http { host, .. } => host,
        }
    }

    pub const fn port(&self) -> u16 {
        match self {
            Self::Wss { port, .. } => *port,
            Self::Ws { port, .. } => *port,
            Self::Https { port, .. } => *port,
            Self::Http { port, .. } => *port,
        }
    }

    pub const fn scheme(&self) -> &TransportScheme {
        match self {
            Self::Wss { scheme, .. } => scheme,
            Self::Ws { scheme, .. } => scheme,
            Self::Https { scheme, .. } => scheme,
            Self::Http { scheme, .. } => scheme,
        }
    }
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
