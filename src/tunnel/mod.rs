pub mod client;
mod io;
pub mod server;
mod tls_reloader;

use crate::dns::DnsResolver;
use crate::{tcp, tls, LocalProtocol, LocalToRemote, WsClientConfig};
use async_trait::async_trait;
use bb8::ManageConnection;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{Error, IoSlice};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use url::Host;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtTunnelConfig {
    pub id: String,
    pub p: LocalProtocol,
    pub r: String,
    pub rp: u16,
}

impl JwtTunnelConfig {
    fn new(request_id: Uuid, tunnel: &LocalToRemote) -> Self {
        Self {
            id: request_id.to_string(),
            p: match tunnel.local_protocol {
                LocalProtocol::Tcp => LocalProtocol::Tcp,
                LocalProtocol::Udp { .. } => tunnel.local_protocol,
                LocalProtocol::Stdio => LocalProtocol::Tcp,
                LocalProtocol::Socks5 => LocalProtocol::Tcp,
                LocalProtocol::ReverseTcp => LocalProtocol::ReverseTcp,
                LocalProtocol::ReverseUdp { .. } => tunnel.local_protocol,
                LocalProtocol::ReverseSocks5 => LocalProtocol::ReverseSocks5,
                LocalProtocol::TProxyTcp => LocalProtocol::Tcp,
                LocalProtocol::TProxyUdp { timeout } => LocalProtocol::Udp { timeout },
            },
            r: tunnel.remote.0.to_string(),
            rp: tunnel.remote.1,
        }
    }
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

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let (host, port) = &self.remote_addr;
        let so_mark = self.socket_so_mark;
        let timeout = self.timeout_connect;

        let tcp_stream = if let Some(http_proxy) = &self.http_proxy {
            tcp::connect_with_http_proxy(http_proxy, host, *port, so_mark, timeout).await?
        } else {
            tcp::connect(host, *port, so_mark, timeout, &DnsResolver::System).await?
        };

        match &self.tls {
            None => Ok(Some(TransportStream::Plain(tcp_stream))),
            Some(tls_cfg) => {
                let tls_stream = tls::connect(self, tls_cfg, tcp_stream).await?;
                Ok(Some(TransportStream::Tls(tls_stream)))
            }
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
