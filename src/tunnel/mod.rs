pub mod client;
mod io;
pub mod server;

use crate::{tcp, tls, LocalProtocol, WsClientConfig};
use async_trait::async_trait;
use bb8::ManageConnection;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtTunnelConfig {
    pub id: String,
    pub p: LocalProtocol,
    pub r: String,
    pub rp: u16,
}

static JWT_SECRET: &[u8; 15] = b"champignonfrais";
static JWT_KEY: Lazy<(Header, EncodingKey)> = Lazy::new(|| {
    (
        Header::new(Algorithm::HS256),
        EncodingKey::from_secret(JWT_SECRET),
    )
});

static JWT_DECODE: Lazy<(Validation, DecodingKey)> = Lazy::new(|| {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims = HashSet::with_capacity(0);
    (validation, DecodingKey::from_secret(JWT_SECRET))
});

pub enum MaybeTlsStream {
    Plain(Option<TcpStream>),
    Tls(Option<TlsStream<TcpStream>>),
}

impl MaybeTlsStream {
    pub fn is_used(&self) -> bool {
        match self {
            MaybeTlsStream::Plain(Some(_)) | MaybeTlsStream::Tls(Some(_)) => false,
            MaybeTlsStream::Plain(None) | MaybeTlsStream::Tls(None) => true,
        }
    }
}

#[async_trait]
impl ManageConnection for WsClientConfig {
    type Connection = MaybeTlsStream;
    type Error = anyhow::Error;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let (host, port) = &self.remote_addr;
        let so_mark = &self.socket_so_mark;
        let timeout = self.timeout_connect;

        let tcp_stream = if let Some(http_proxy) = &self.http_proxy {
            tcp::connect_with_http_proxy(http_proxy, host, *port, so_mark, timeout).await?
        } else {
            tcp::connect(host, *port, so_mark, timeout).await?
        };

        match &self.tls {
            None => Ok(MaybeTlsStream::Plain(Some(tcp_stream))),
            Some(tls_cfg) => {
                let tls_stream = tls::connect(self, tls_cfg, tcp_stream).await?;
                Ok(MaybeTlsStream::Tls(Some(tls_stream)))
            }
        }
    }

    async fn is_valid(&self, _conn: &mut Self::Connection) -> Result<(), Self::Error> {
        Ok(())
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        conn.is_used()
    }
}
