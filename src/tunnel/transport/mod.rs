use crate::tunnel::transport::http2::{Http2TunnelRead, Http2TunnelWrite};
use crate::tunnel::transport::websocket::{WebsocketTunnelRead, WebsocketTunnelWrite};
use bytes::BytesMut;
use hyper::http::{HeaderName, HeaderValue};
use std::future::Future;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::pin::Pin;
use std::str::FromStr;

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::error;

pub mod http2;
pub mod io;
pub mod websocket;

static MAX_PACKET_LENGTH: usize = 64 * 1024;

pub trait TunnelWrite: Send + 'static {
    fn buf_mut(&mut self) -> &mut BytesMut;
    fn write(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
    fn write_from(
        &mut self,
        local_rx: &mut Pin<&mut impl AsyncRead>,
    ) -> impl Future<Output = Result<(), std::io::Error>>;
    fn ping(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
    fn close(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
    fn handle_message(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
}

pub trait TunnelRead: Send + 'static {
    fn copy(
        &mut self,
        writer: impl AsyncWrite + Unpin + Send,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;
}

pub enum TunnelReader {
    Websocket(WebsocketTunnelRead),
    Http2(Http2TunnelRead),
}

impl TunnelRead for TunnelReader {
    async fn copy(&mut self, writer: impl AsyncWrite + Unpin + Send) -> Result<(), std::io::Error> {
        match self {
            Self::Websocket(s) => s.copy(writer).await,
            Self::Http2(s) => s.copy(writer).await,
        }
    }
}

pub enum TunnelWriter {
    Websocket(WebsocketTunnelWrite),
    Http2(Http2TunnelWrite),
}

impl TunnelWrite for TunnelWriter {
    fn buf_mut(&mut self) -> &mut BytesMut {
        match self {
            Self::Websocket(s) => s.buf_mut(),
            Self::Http2(s) => s.buf_mut(),
        }
    }

    async fn write_from(&mut self, local_rx: &mut Pin<&mut impl AsyncRead>) -> Result<(), std::io::Error> {
        match self {
            Self::Websocket(s) => s.write_from(local_rx).await,
            Self::Http2(s) => s.write_from(local_rx).await,
        }
    }

    async fn write(&mut self) -> Result<(), std::io::Error> {
        match self {
            Self::Websocket(s) => s.write().await,
            Self::Http2(s) => s.write().await,
        }
    }

    async fn ping(&mut self) -> Result<(), std::io::Error> {
        match self {
            Self::Websocket(s) => s.ping().await,
            Self::Http2(s) => s.ping().await,
        }
    }

    async fn close(&mut self) -> Result<(), std::io::Error> {
        match self {
            Self::Websocket(s) => s.close().await,
            Self::Http2(s) => s.close().await,
        }
    }

    async fn handle_message(&mut self) -> Result<(), std::io::Error> {
        match self {
            Self::Websocket(s) => s.handle_message().await,
            Self::Http2(s) => s.handle_message().await,
        }
    }
}

#[allow(clippy::type_complexity)]
#[inline]
pub fn headers_from_file(path: &Path) -> (Option<(HeaderName, HeaderValue)>, Vec<(HeaderName, HeaderValue)>) {
    static HOST_HEADER: HeaderName = HeaderName::from_static("host");

    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) => {
            error!("Cannot read headers from file: {:?}: {:?}", path, err);
            return (None, vec![]);
        }
    };

    let mut host_header = None;
    let headers = BufReader::new(file)
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            let (header, value) = line.split_once(':')?;
            let header = HeaderName::from_str(header.trim()).ok()?;
            let value = HeaderValue::from_str(value.trim()).ok()?;
            if header == HOST_HEADER {
                host_header = Some((header, value));
                return None;
            }
            Some((header, value))
        })
        .collect();

    (host_header, headers)
}
