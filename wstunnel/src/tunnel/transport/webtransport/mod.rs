//! WebTransport (HTTP/3 over QUIC) transport.
//!
//! The stream transports for ordinary tunnels live here; [`udp`] holds the framed variants a UDP
//! tunnel needs, [`endpoint`] the QUIC endpoint they are dialled from, [`client`] the dialling
//! itself, and [`utils`] the socket, transport-config and JWT-preamble helpers.

use super::io::{MAX_PACKET_LENGTH, TransportRead, TransportWrite};
use bytes::{Bytes, BytesMut};
use std::io::ErrorKind;
use std::io::{self, IoSlice};
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

// Bound the work per copy without waiting for more data to fill a batch.
const MAX_READ_CHUNKS: usize = 32;

pub struct WebTransportRead {
    inner: RecvStream,
    chunks: [Bytes; MAX_READ_CHUNKS],
    // Keep the session alive: it owns the QUIC connection, which is closed when the last
    // handle is dropped.
    _session: Session,
}

impl WebTransportRead {
    pub fn new(inner: RecvStream, session: Session) -> Self {
        Self {
            inner,
            chunks: [const { Bytes::new() }; MAX_READ_CHUNKS],
            _session: session,
        }
    }

    pub fn into_udp_stream(self) -> WebTransportUdpRead {
        WebTransportUdpRead::new(self.inner, self._session)
    }
}

impl TransportRead for WebTransportRead {
    async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
        // Drain ready chunks under one Quinn connection lock, retaining its buffers without
        // copying. read_chunks returns as soon as any data is ready, even for a short batch.
        let count = match self.inner.read_chunks(&mut self.chunks).await {
            Ok(Some(count)) => count,
            Ok(None) => return Err(io::Error::new(ErrorKind::BrokenPipe, "closed")),
            Err(err) => return Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
        };

        let result = write_chunks(&mut writer, &self.chunks[..count]).await;
        // Release the receive buffers before waiting for more data on an idle tunnel.
        self.chunks[..count].fill(Bytes::new());
        result.map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err))
    }
}

async fn write_chunks(writer: &mut (impl AsyncWrite + Unpin), chunks: &[Bytes]) -> io::Result<()> {
    if chunks.len() == 1 || !writer.is_write_vectored() {
        for chunk in chunks {
            writer.write_all(chunk).await?;
        }
        return Ok(());
    }

    // review(claude): put the slice buffer inside the struc
    let mut slices = [IoSlice::new(&[]); MAX_READ_CHUNKS];
    for (slice, chunk) in slices.iter_mut().zip(chunks) {
        *slice = IoSlice::new(chunk);
    }
    let mut slices = &mut slices[..chunks.len()];
    while !slices.is_empty() {
        let written = writer.write_vectored(slices).await?;
        if written == 0 {
            return Err(io::Error::new(ErrorKind::WriteZero, "failed to write WebTransport chunks"));
        }
        // A socket may accept only part of a chunk or stop between chunks.
        IoSlice::advance_slices(&mut slices, written);
    }
    Ok(())
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
