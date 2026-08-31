//! WebTransport transport for UDP tunnels.
//!
//! QUIC streams do not preserve message boundaries, so unlike the TCP case a UDP payload cannot
//! just be written into the stream: each datagram is framed with an explicit length prefix.

use super::super::io::{MAX_PACKET_LENGTH, TransportRead, TransportWrite};
use bytes::BytesMut;
use std::io;
use std::io::ErrorKind;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use web_transport_quinn::{RecvStream, SendStream, Session};

/// WebTransport stream transport for UDP tunnels. QUIC streams do not preserve message
/// boundaries, so UDP payloads need an explicit length prefix before they enter the stream.
pub struct WebTransportUdpRead {
    inner: RecvStream,
    _session: Session,
}

impl WebTransportUdpRead {
    pub fn new(inner: RecvStream, session: Session) -> Self {
        Self {
            inner,
            _session: session,
        }
    }
}

impl TransportRead for WebTransportUdpRead {
    async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
        let length = self
            .inner
            .read_u16()
            .await
            .map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err))?;

        // The payload must reach the local socket as a single write, since `UdpStreamWriter` turns
        // each write into exactly one datagram. read_chunk lets us forward quinn's own buffer
        // without a copy when the whole datagram lands in one chunk (the common case); a datagram
        // split across QUIC frames is reassembled once before the single write.
        let mut remaining = length as usize;
        let mut assembled: Option<BytesMut> = None;
        while remaining > 0 {
            let mut chunk = self
                .inner
                .read_chunk(remaining, true)
                .await
                .map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err))?
                .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "webtransport stream closed mid-datagram"))?;
            remaining -= chunk.bytes.len();

            // Fast path: the whole datagram arrived in the first chunk, forward it without a copy.
            if assembled.is_none() && remaining == 0 {
                return writer
                    .write_all_buf(&mut chunk.bytes)
                    .await
                    .map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err));
            }
            // A vectored write can't avoid this copy: the datagram has to reach the local socket as
            // a single write (one `send`), but a UDP socket has no scatter-gather send — it takes a
            // contiguous `&[u8]`, and the default `poll_write_vectored` emits one datagram per
            // slice. So a datagram split across QUIC frames must be reassembled first.
            assembled
                .get_or_insert_with(|| BytesMut::with_capacity(length as usize))
                .extend_from_slice(&chunk.bytes);
        }

        match assembled {
            Some(mut buf) => writer
                .write_all_buf(&mut buf)
                .await
                .map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err)),
            // A zero-length datagram carries nothing to forward (matches the previous behaviour).
            None => Ok(()),
        }
    }
}

pub struct WebTransportUdpWrite {
    inner: SendStream,
    buf: BytesMut,
    _session: Session,
}

impl WebTransportUdpWrite {
    const ARENA_LENGTH: usize = MAX_PACKET_LENGTH * 2;
    pub fn new(inner: SendStream, session: Session) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(Self::ARENA_LENGTH),
            _session: session,
        }
    }
}

impl TransportWrite for WebTransportUdpWrite {
    fn buf_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }

    async fn write(&mut self) -> Result<(), io::Error> {
        self.inner
            .write_u16(self.buf.len() as u16)
            .await
            .map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err))?;
        self.inner
            .write_chunk(self.buf.split().freeze())
            .await
            .map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err))?;

        // Reset the buffer for the next datagram regardless of the outcome.
        if self.buf.capacity() < MAX_PACKET_LENGTH {
            self.buf.reserve(Self::ARENA_LENGTH);
        }
        Ok(())
    }

    async fn ping(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
    async fn close(&mut self) -> Result<(), io::Error> {
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
