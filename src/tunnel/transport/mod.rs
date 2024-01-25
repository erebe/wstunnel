use crate::tunnel::transport::http2::{Http2TunnelRead, Http2TunnelWrite};
use crate::tunnel::transport::websocket::{WebsocketTunnelRead, WebsocketTunnelWrite};
use bytes::BytesMut;
use hyper::http::{HeaderName, HeaderValue};
use std::future::Future;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str::FromStr;

use tokio::io::AsyncWrite;
use tracing::error;

pub mod http2;
pub mod io;
pub mod websocket;

static MAX_PACKET_LENGTH: usize = 64 * 1024;

pub trait TunnelWrite: Send + 'static {
    fn buf_mut(&mut self) -> &mut BytesMut;
    fn write(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
    fn ping(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
    fn close(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
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
            TunnelReader::Websocket(s) => s.copy(writer).await,
            TunnelReader::Http2(s) => s.copy(writer).await,
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
            TunnelWriter::Websocket(s) => s.buf_mut(),
            TunnelWriter::Http2(s) => s.buf_mut(),
        }
    }

    async fn write(&mut self) -> Result<(), std::io::Error> {
        match self {
            TunnelWriter::Websocket(s) => s.write().await,
            TunnelWriter::Http2(s) => s.write().await,
        }
    }

    async fn ping(&mut self) -> Result<(), std::io::Error> {
        match self {
            TunnelWriter::Websocket(s) => s.ping().await,
            TunnelWriter::Http2(s) => s.ping().await,
        }
    }

    async fn close(&mut self) -> Result<(), std::io::Error> {
        match self {
            TunnelWriter::Websocket(s) => s.close().await,
            TunnelWriter::Http2(s) => s.close().await,
        }
    }
}

#[inline]
pub fn headers_from_file(path: &Path) -> Vec<(HeaderName, HeaderValue)> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) => {
            error!("Cannot read headers from file: {:?}: {:?}", path, err);
            return vec![];
        }
    };

    BufReader::new(file)
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            let (header, value) = line.split_once(':')?;
            let header = HeaderName::from_str(header.trim()).ok()?;
            let value = HeaderValue::from_str(value.trim()).ok()?;
            Some((header, value))
        })
        .collect()
}
