pub mod client;
pub mod server;
mod tls_reloader;
mod transport;

use crate::{tcp, tls, LocalProtocol, TlsClientConfig, WsClientConfig};
use async_trait::async_trait;
use bb8::ManageConnection;
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
use tracing::instrument;
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
                LocalProtocol::ReverseTcp => LocalProtocol::ReverseTcp,
                LocalProtocol::ReverseUdp { .. } => dest.protocol.clone(),
                LocalProtocol::ReverseSocks5 => LocalProtocol::ReverseSocks5,
                LocalProtocol::TProxyTcp => LocalProtocol::Tcp { proxy_protocol: false },
                LocalProtocol::TProxyUdp { timeout } => LocalProtocol::Udp { timeout },
                LocalProtocol::Unix { .. } => LocalProtocol::Tcp { proxy_protocol: false },
                LocalProtocol::ReverseUnix { .. } => dest.protocol.clone(),
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

#[derive(Debug)]
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
    pub fn values() -> &'static [TransportScheme] {
        &[
            TransportScheme::Ws,
            TransportScheme::Wss,
            TransportScheme::Http,
            TransportScheme::Https,
        ]
    }
    pub fn to_str(self) -> &'static str {
        match self {
            TransportScheme::Ws => "ws",
            TransportScheme::Wss => "wss",
            TransportScheme::Http => "http",
            TransportScheme::Https => "https",
        }
    }
}
impl FromStr for TransportScheme {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "https" => Ok(TransportScheme::Https),
            "http" => Ok(TransportScheme::Http),
            "wss" => Ok(TransportScheme::Wss),
            "ws" => Ok(TransportScheme::Ws),
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
            TransportScheme::Https => Some(TransportAddr::Https {
                scheme: TransportScheme::Https,
                tls: tls?,
                host,
                port,
            }),
            TransportScheme::Http => Some(TransportAddr::Http {
                scheme: TransportScheme::Http,
                host,
                port,
            }),
            TransportScheme::Wss => Some(TransportAddr::Wss {
                scheme: TransportScheme::Wss,
                tls: tls?,
                host,
                port,
            }),
            TransportScheme::Ws => Some(TransportAddr::Ws {
                scheme: TransportScheme::Ws,
                host,
                port,
            }),
        }
    }
    pub fn is_websocket(&self) -> bool {
        matches!(self, TransportAddr::Ws { .. } | TransportAddr::Wss { .. })
    }

    pub fn is_http2(&self) -> bool {
        matches!(self, TransportAddr::Http { .. } | TransportAddr::Https { .. })
    }

    pub fn tls(&self) -> Option<&TlsClientConfig> {
        match self {
            TransportAddr::Wss { tls, .. } => Some(tls),
            TransportAddr::Https { tls, .. } => Some(tls),
            TransportAddr::Ws { .. } => None,
            TransportAddr::Http { .. } => None,
        }
    }

    pub fn host(&self) -> &Host {
        match self {
            TransportAddr::Wss { host, .. } => host,
            TransportAddr::Ws { host, .. } => host,
            TransportAddr::Https { host, .. } => host,
            TransportAddr::Http { host, .. } => host,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            TransportAddr::Wss { port, .. } => *port,
            TransportAddr::Ws { port, .. } => *port,
            TransportAddr::Https { port, .. } => *port,
            TransportAddr::Http { port, .. } => *port,
        }
    }

    pub fn scheme(&self) -> &TransportScheme {
        match self {
            TransportAddr::Wss { scheme, .. } => scheme,
            TransportAddr::Ws { scheme, .. } => scheme,
            TransportAddr::Https { scheme, .. } => scheme,
            TransportAddr::Http { scheme, .. } => scheme,
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
            TransportStream::Plain(cnx) => Pin::new(cnx).poll_read(cx, buf),
            TransportStream::Tls(cnx) => Pin::new(cnx).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TransportStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            TransportStream::Plain(cnx) => Pin::new(cnx).poll_write(cx, buf),
            TransportStream::Tls(cnx) => Pin::new(cnx).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            TransportStream::Plain(cnx) => Pin::new(cnx).poll_flush(cx),
            TransportStream::Tls(cnx) => Pin::new(cnx).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            TransportStream::Plain(cnx) => Pin::new(cnx).poll_shutdown(cx),
            TransportStream::Tls(cnx) => Pin::new(cnx).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            TransportStream::Plain(cnx) => Pin::new(cnx).poll_write_vectored(cx, bufs),
            TransportStream::Tls(cnx) => Pin::new(cnx).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self {
            TransportStream::Plain(cnx) => cnx.is_write_vectored(),
            TransportStream::Tls(cnx) => cnx.is_write_vectored(),
        }
    }
}

#[async_trait]
impl ManageConnection for WsClientConfig {
    type Connection = Option<TransportStream>;
    type Error = anyhow::Error;

    #[instrument(level = "trace", name = "cnx_server", skip_all)]
    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let so_mark = self.socket_so_mark;
        let timeout = self.timeout_connect;

        let tcp_stream = if let Some(http_proxy) = &self.http_proxy {
            tcp::connect_with_http_proxy(
                http_proxy,
                self.remote_addr.host(),
                self.remote_addr.port(),
                so_mark,
                timeout,
                &self.dns_resolver,
            )
            .await?
        } else {
            tcp::connect(
                self.remote_addr.host(),
                self.remote_addr.port(),
                so_mark,
                timeout,
                &self.dns_resolver,
            )
            .await?
        };

        if self.remote_addr.tls().is_some() {
            let tls_stream = tls::connect(self, tcp_stream).await?;
            Ok(Some(TransportStream::Tls(tls_stream)))
        } else {
            Ok(Some(TransportStream::Plain(tcp_stream)))
        }
    }

    async fn is_valid(&self, _conn: &mut Self::Connection) -> Result<(), Self::Error> {
        Ok(())
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        conn.is_none()
    }
}

pub fn to_host_port(addr: SocketAddr) -> (Host, u16) {
    match addr.ip() {
        IpAddr::V4(ip) => (Host::Ipv4(ip), addr.port()),
        IpAddr::V6(ip) => (Host::Ipv6(ip), addr.port()),
    }
}
