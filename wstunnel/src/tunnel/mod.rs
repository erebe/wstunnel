pub mod ca_reloader;
pub mod client;
pub mod connectors;
pub mod listeners;
pub mod server;
mod tls_reloader;
pub mod transport;

use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use std::time::Duration;
use url::Host;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
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

impl Debug for LocalProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn redacted(credentials: &Option<(String, String)>) -> Option<&'static str> {
            credentials.as_ref().map(|_| "<redacted>")
        }

        match self {
            Self::Tcp { proxy_protocol } => f.debug_struct("Tcp").field("proxy_protocol", proxy_protocol).finish(),
            Self::Udp { timeout } => f.debug_struct("Udp").field("timeout", timeout).finish(),
            Self::Stdio { proxy_protocol } => f.debug_struct("Stdio").field("proxy_protocol", proxy_protocol).finish(),
            Self::Socks5 { timeout, credentials } => f
                .debug_struct("Socks5")
                .field("timeout", timeout)
                .field("credentials", &redacted(credentials))
                .finish(),
            Self::TProxyTcp => f.write_str("TProxyTcp"),
            Self::TProxyUdp { timeout } => f.debug_struct("TProxyUdp").field("timeout", timeout).finish(),
            Self::HttpProxy {
                timeout,
                credentials,
                proxy_protocol,
            } => f
                .debug_struct("HttpProxy")
                .field("timeout", timeout)
                .field("credentials", &redacted(credentials))
                .field("proxy_protocol", proxy_protocol)
                .finish(),
            Self::ReverseTcp => f.write_str("ReverseTcp"),
            Self::ReverseUdp { timeout } => f.debug_struct("ReverseUdp").field("timeout", timeout).finish(),
            Self::ReverseSocks5 { timeout, credentials } => f
                .debug_struct("ReverseSocks5")
                .field("timeout", timeout)
                .field("credentials", &redacted(credentials))
                .finish(),
            Self::ReverseHttpProxy { timeout, credentials } => f
                .debug_struct("ReverseHttpProxy")
                .field("timeout", timeout)
                .field("credentials", &redacted(credentials))
                .finish(),
            Self::ReverseUnix { path } => f.debug_struct("ReverseUnix").field("path", path).finish(),
            Self::Unix { path, proxy_protocol } => f
                .debug_struct("Unix")
                .field("path", path)
                .field("proxy_protocol", proxy_protocol)
                .finish(),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_credentials() {
        let protocol = LocalProtocol::ReverseHttpProxy {
            timeout: Some(Duration::from_secs(30)),
            credentials: Some(("cyera".to_string(), "supersecret".to_string())),
        };

        let rendered = format!("{protocol:?}");

        assert!(!rendered.contains("supersecret"), "password leaked: {rendered}");
        assert!(!rendered.contains("cyera"), "username leaked: {rendered}");
        assert!(rendered.contains("<redacted>"), "credentials not redacted: {rendered}");
        assert!(
            rendered.contains("Some(30s)"),
            "non-secret fields should still render: {rendered}"
        );
    }

    #[test]
    fn debug_keeps_none_credentials_visible() {
        let protocol = LocalProtocol::Socks5 {
            timeout: None,
            credentials: None,
        };

        let rendered = format!("{protocol:?}");

        assert!(rendered.contains("credentials: None"), "expected None credentials: {rendered}");
    }
}
