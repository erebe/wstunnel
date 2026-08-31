//! WebTransport (HTTP/3 over QUIC) transport.
//!
//! The stream transports for ordinary tunnels live here; [`udp`] holds the framed variants a UDP
//! tunnel needs, [`endpoint`] the QUIC endpoint they are dialled from, [`client`] the dialling
//! itself, and [`utils`] the socket, transport-config and JWT-preamble helpers.

use super::io::{MAX_PACKET_LENGTH, TransportRead, TransportWrite};
use bytes::BytesMut;
use std::io;
use std::io::ErrorKind;
use std::sync::Arc;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use web_transport_quinn::{RecvStream, SendStream, Session};

mod client;
mod endpoint;
mod udp;
pub mod utils;

pub use client::connect;
pub(crate) use client::mk_connect_request;
pub use endpoint::WebTransportEndpoint;
pub use udp::{WebTransportUdpRead, WebTransportUdpWrite};
pub(crate) use utils::{bind_udp_socket, mk_transport_config};
pub use utils::{read_jwt_preamble, write_jwt_preamble};

pub struct WebTransportRead {
    inner: RecvStream,
    // Keep the session alive: it owns the QUIC connection, which is closed when the last
    // handle is dropped.
    _session: Session,
}

impl WebTransportRead {
    pub fn new(inner: RecvStream, session: Session) -> Self {
        Self {
            inner,
            _session: session,
        }
    }

    pub fn into_udp_stream(self) -> WebTransportUdpRead {
        WebTransportUdpRead::new(self.inner, self._session)
    }
}

impl TransportRead for WebTransportRead {
    async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
        // read_chunk hands back quinn's internal `Bytes` directly, so we forward it to the writer
        // without the extra copy into an intermediate buffer that `read` would require.
        let chunk = match self.inner.read_chunk(MAX_PACKET_LENGTH, true).await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => return Err(io::Error::new(ErrorKind::BrokenPipe, "closed")),
            Err(err) => return Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
        };

        match writer.write_all(&chunk.bytes).await {
            Ok(_) => Ok(()),
            Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
        }
    }
}

pub struct WebTransportWrite {
    inner: SendStream,
    buf: BytesMut,
    _session: Session,
}

impl WebTransportWrite {
    const ARENA_LENGTH: usize = MAX_PACKET_LENGTH * 4;

    pub fn new(inner: SendStream, session: Session) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(Self::ARENA_LENGTH),
            _session: session,
        }
    }

    pub fn into_udp_stream(self) -> WebTransportUdpWrite {
        WebTransportUdpWrite::new(self.inner, self._session)
    }
}

impl TransportWrite for WebTransportWrite {
    fn buf_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }

    async fn write(&mut self) -> Result<(), io::Error> {
        let chunk = self.buf.split().freeze();
        let ret = match self.inner.write_chunk(chunk).await {
            Ok(_) => Ok(()),
            Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
        };

        // `propagate_local_to_remote` requires room for a whole packet before every read.
        if self.buf.capacity() < MAX_PACKET_LENGTH {
            self.buf.reserve(Self::ARENA_LENGTH);
        }

        ret
    }

    async fn ping(&mut self) -> Result<(), io::Error> {
        // QUIC sends its own keep-alive PINGs, configured via `keep_alive_interval`.
        Ok(())
    }

    async fn close(&mut self) -> Result<(), io::Error> {
        // Errors here only mean the stream is already gone, which is what we wanted.
        let _ = self.inner.finish();
        Ok(())
    }

    fn pending_operations_notify(&mut self) -> Arc<Notify> {
        Arc::new(Notify::new())
    }

    async fn handle_pending_operations(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}
