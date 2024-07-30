pub mod client;
pub mod connectors;
pub mod listeners;
pub mod server;
mod tls_reloader;
mod transport;

use crate::{LocalProtocol, TlsClientConfig};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};
use std::io::{Error, IoSlice};
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use url::Host;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtTunnelConfig {
    pub id: String,       // tunnel id
    pub p: LocalProtocol, // protocol to use
    pub r: String,        // remote host
    pub rp: u16,          // remote port
}

impl JwtTunnelConfig {
    fn new(request_id: Uuid, dest: &RemoteAddr) -> Self {
        Self {
            id: request_id.to_string(),
            p: match dest.protocol {
                LocalProtocol::Tcp { .. } => dest.protocol.clone(),
                LocalProtocol::Udp { .. } => dest.protocol.clone(),
                LocalProtocol::Stdio => LocalProtocol::Tcp { proxy_protocol: false },
                LocalProtocol::Socks5 { .. } => LocalProtocol::Tcp { proxy_protocol: false },
                LocalProtocol::HttpProxy { .. } => dest.protocol.clone(),
                LocalProtocol::ReverseTcp => LocalProtocol::ReverseTcp,
                LocalProtocol::ReverseUdp { .. } => dest.protocol.clone(),
                LocalProtocol::ReverseSocks5 { .. } => dest.protocol.clone(),
                LocalProtocol::TProxyTcp => LocalProtocol::Tcp { proxy_protocol: false },
                LocalProtocol::TProxyUdp { timeout } => LocalProtocol::Udp { timeout },
                LocalProtocol::Unix { .. } => LocalProtocol::Tcp { proxy_protocol: false },
                LocalProtocol::ReverseUnix { .. } => dest.protocol.clone(),
                LocalProtocol::ReverseHttpProxy { .. } => dest.protocol.clone(),
            },
            r: dest.host.to_string(),
            rp: dest.port,
        }
    }
}

fn tunnel_to_jwt_token(request_id: Uuid, tunnel: &RemoteAddr) -> String {
    let cfg = JwtTunnelConfig::new(request_id, tunnel);
    let (alg, secret) = JWT_KEY.deref();
    jsonwebtoken::encode(alg, &cfg, secret).unwrap_or_default()
}

static JWT_HEADER_PREFIX: &str = "authorization.bearer.";
static JWT_SECRET: &[u8; 15] = b"champignonfrais";
static JWT_KEY: Lazy<(Header, EncodingKey)> =
    Lazy::new(|| (Header::new(Algorithm::HS256), EncodingKey::from_secret(JWT_SECRET)));

static JWT_DECODE: Lazy<(Validation, DecodingKey)> = Lazy::new(|| {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims = HashSet::with_capacity(0);
    (validation, DecodingKey::from_secret(JWT_SECRET))
});

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

impl TryFrom<JwtTunnelConfig> for RemoteAddr {
    type Error = anyhow::Error;
    fn try_from(jwt: JwtTunnelConfig) -> anyhow::Result<Self> {
        Ok(Self {
            protocol: jwt.p,
            host: Host::parse(&jwt.r)?,
            port: jwt.rp,
        })
    }
}

pub enum TransportStream {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl AsyncRead for TransportStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(cnx) => Pin::new(cnx).poll_read(cx, buf),
            Self::Tls(cnx) => Pin::new(cnx).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TransportStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Self::Plain(cnx) => Pin::new(cnx).poll_write(cx, buf),
            Self::Tls(cnx) => Pin::new(cnx).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Self::Plain(cnx) => Pin::new(cnx).poll_flush(cx),
            Self::Tls(cnx) => Pin::new(cnx).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Self::Plain(cnx) => Pin::new(cnx).poll_shutdown(cx),
            Self::Tls(cnx) => Pin::new(cnx).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Self::Plain(cnx) => Pin::new(cnx).poll_write_vectored(cx, bufs),
            Self::Tls(cnx) => Pin::new(cnx).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self {
            Self::Plain(cnx) => cnx.is_write_vectored(),
            Self::Tls(cnx) => cnx.is_write_vectored(),
        }
    }
}

pub fn to_host_port(addr: SocketAddr) -> (Host, u16) {
    match addr.ip() {
        IpAddr::V4(ip) => (Host::Ipv4(ip), addr.port()),
        IpAddr::V6(ip) => (Host::Ipv6(ip), addr.port()),
    }
}
