use crate::tunnel::client::TlsClientConfig;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use url::Host;

#[derive(Copy, Clone, Debug)]
pub enum TransportScheme {
    Ws,
    Wss,
    Http,
    Https,
}

impl TransportScheme {
    #[cfg(feature = "clap")] // this is only used inside a clap value parser
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
