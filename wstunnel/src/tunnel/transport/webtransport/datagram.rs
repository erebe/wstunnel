//! Unreliable UDP data plane. A reliable stream authenticates and owns each association;
//! one receiver per WebTransport session demultiplexes data into bounded queues.

use super::super::io::{MAX_PACKET_LENGTH, TransportRead, TransportWrite};
use bytes::{BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, trace};
use web_transport_quinn::{RecvStream, SendStream, Session};

pub(crate) const ACK: &[u8; 4] = b"WUD1";

/// An expected association lifecycle event, distinct from network/socket timeouts.
#[derive(Debug)]
pub(crate) struct DatagramIdleTimeout;

impl std::fmt::Display for DatagramIdleTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UDP Datagram association idle timeout")
    }
}

impl std::error::Error for DatagramIdleTimeout {}

pub(crate) fn is_datagram_idle_timeout(error: &io::Error) -> bool {
    error.kind() == ErrorKind::TimedOut && error.get_ref().is_some_and(|cause| cause.is::<DatagramIdleTimeout>())
}
const HEADER_LEN: usize = 10;
const MAX_ASSOCIATIONS: usize = 64;
const QUEUE_PACKETS: usize = 8;

#[derive(Default)]
pub(crate) struct Counters {
    pub tx: AtomicU64,
    pub rx: AtomicU64,
    pub oversize: AtomicU64,
    pub invalid: AtomicU64,
    pub queue_full: AtomicU64,
    pub created: AtomicU64,
    pub expired: AtomicU64,
}

struct Route {
    tx: mpsc::Sender<Bytes>,
    activity: Arc<Mutex<Instant>>,
}

pub(crate) struct DatagramHub {
    routes: Mutex<HashMap<u64, Route>>,
    task: Mutex<Option<JoinHandle<()>>>,
    pub counters: Counters,
}

impl DatagramHub {
    pub fn new(session: Session) -> Arc<Self> {
        let hub = Arc::new(Self {
            routes: Mutex::new(HashMap::new()),
            task: Mutex::new(None),
            counters: Counters::default(),
        });
        let weak = Arc::downgrade(&hub);
        let task = tokio::spawn(async move {
            loop {
                let packet = match session.read_datagram().await {
                    Ok(packet) => packet,
                    Err(web_transport_quinn::SessionError::WebTransportError(
                        web_transport_quinn::WebTransportError::UnknownSession,
                    )) => {
                        if let Some(hub) = weak.upgrade() {
                            hub.counters.invalid.fetch_add(1, Ordering::Relaxed);
                        }
                        debug!("dropping invalid WebTransport Datagram session header");
                        continue;
                    }
                    Err(err) => {
                        debug!("UDP Datagram receiver ended: {err}");
                        if let Some(hub) = weak.upgrade() {
                            hub.routes.lock().unwrap().clear();
                        }
                        break;
                    }
                };
                let Some(hub) = weak.upgrade() else { break };
                hub.dispatch(packet);
            }
        });
        *hub.task.lock().unwrap() = Some(task);
        hub
    }

    fn dispatch(&self, packet: Bytes) {
        let Some(id) = decode_header(&packet) else {
            self.counters.invalid.fetch_add(1, Ordering::Relaxed);
            debug!(bytes = packet.len(), "dropping malformed UDP Datagram");
            return;
        };
        let routes = self.routes.lock().unwrap();
        let Some(route) = routes.get(&id) else {
            self.counters.invalid.fetch_add(1, Ordering::Relaxed);
            trace!(association = id, "dropping unknown UDP association");
            return;
        };
        let bytes = packet.len() - HEADER_LEN;
        match route.tx.try_send(packet.slice(HEADER_LEN..)) {
            Ok(()) => {
                *route.activity.lock().unwrap() = Instant::now();
                self.counters.rx.fetch_add(1, Ordering::Relaxed);
                trace!(association = id, bytes, "UDP Datagram rx");
            }
            Err(_) => {
                self.counters.queue_full.fetch_add(1, Ordering::Relaxed);
                trace!(association = id, "dropping UDP Datagram: receive queue unavailable");
            }
        }
    }

    fn add_route(&self, id: u64, tx: mpsc::Sender<Bytes>, activity: Arc<Mutex<Instant>>) -> io::Result<()> {
        let mut routes = self.routes.lock().unwrap();
        if routes.contains_key(&id) {
            return Err(io::Error::new(
                ErrorKind::AlreadyExists,
                "duplicate UDP Datagram association ID",
            ));
        }
        if routes.len() >= MAX_ASSOCIATIONS {
            return Err(io::Error::new(ErrorKind::OutOfMemory, "UDP Datagram association limit reached"));
        }
        routes.insert(id, Route { tx, activity });
        Ok(())
    }

    pub fn register(
        self: &Arc<Self>,
        id: u64,
        recv: RecvStream,
        send: SendStream,
        session: Session,
        timeout: Option<Duration>,
    ) -> io::Result<(DatagramRead, DatagramWrite)> {
        // Session::max_datagram_size panics when the peer does not support Datagrams.
        let _ = session.deref_max_datagram_size()?;
        if session.max_datagram_size() < HEADER_LEN {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "peer Datagram size cannot fit the association header",
            ));
        }
        let (tx, rx) = mpsc::channel(QUEUE_PACKETS);
        let activity = Arc::new(Mutex::new(Instant::now()));
        self.add_route(id, tx, activity.clone())?;
        self.counters.created.fetch_add(1, Ordering::Relaxed);
        info!(association = id, "created UDP Datagram association");
        Ok((
            DatagramRead {
                id,
                hub: self.clone(),
                rx,
                control: recv,
                activity: activity.clone(),
                timeout,
            },
            DatagramWrite {
                id,
                hub: self.clone(),
                session,
                control: send,
                activity,
                buf: BytesMut::with_capacity(MAX_PACKET_LENGTH * 2),
            },
        ))
    }
}

// Explicit dereference avoids calling Session's panic-on-unsupported convenience method.
trait DatagramCapability {
    fn deref_max_datagram_size(&self) -> io::Result<usize>;
}

impl DatagramCapability for Session {
    fn deref_max_datagram_size(&self) -> io::Result<usize> {
        std::ops::Deref::deref(self)
            .max_datagram_size()
            .ok_or_else(|| io::Error::new(ErrorKind::Unsupported, "peer does not support QUIC Datagrams"))
    }
}

impl Drop for DatagramHub {
    fn drop(&mut self) {
        if let Some(task) = self.task.get_mut().unwrap().take() {
            task.abort();
        }
        info!(
            tx = self.counters.tx.load(Ordering::Relaxed),
            rx = self.counters.rx.load(Ordering::Relaxed),
            oversize = self.counters.oversize.load(Ordering::Relaxed),
            invalid = self.counters.invalid.load(Ordering::Relaxed),
            queue_full = self.counters.queue_full.load(Ordering::Relaxed),
            created = self.counters.created.load(Ordering::Relaxed),
            expired = self.counters.expired.load(Ordering::Relaxed),
            "UDP Datagram session counters"
        );
    }
}

fn decode_header(packet: &[u8]) -> Option<u64> {
    if packet.len() < HEADER_LEN || packet.len() > HEADER_LEN + 65507 || packet[0] != 1 || packet[1] != 0 {
        return None;
    }
    Some(u64::from_be_bytes(packet[2..HEADER_LEN].try_into().ok()?))
}

fn encode_packet(id: u64, payload: &[u8]) -> Bytes {
    let mut packet = BytesMut::with_capacity(HEADER_LEN + payload.len());
    packet.put_u8(1);
    packet.put_u8(0);
    packet.put_u64(id);
    packet.extend_from_slice(payload);
    packet.freeze()
}

fn control_read_error(result: io::Result<u8>) -> io::Error {
    match result {
        Ok(byte) => io::Error::new(
            ErrorKind::InvalidData,
            format!("unexpected UDP Datagram control byte: {byte:#04x}"),
        ),
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => {
            io::Error::new(ErrorKind::BrokenPipe, "Datagram control stream finished")
        }
        Err(err) => err,
    }
}

pub struct DatagramRead {
    id: u64,
    hub: Arc<DatagramHub>,
    rx: mpsc::Receiver<Bytes>,
    control: RecvStream,
    activity: Arc<Mutex<Instant>>,
    timeout: Option<Duration>,
}

impl DatagramRead {
    pub(crate) async fn wait_ready(&mut self) -> io::Result<()> {
        let mut ack = [0; 4];
        self.control
            .read_exact(&mut ack)
            .await
            .map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err))?;
        if &ack != ACK {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "server did not acknowledge UDP Datagram protocol v1",
            ));
        }
        Ok(())
    }
}

impl Drop for DatagramRead {
    fn drop(&mut self) {
        self.hub.routes.lock().unwrap().remove(&self.id);
        info!(association = self.id, "removed UDP Datagram association");
    }
}

impl TransportRead for DatagramRead {
    async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin + Send) -> io::Result<()> {
        loop {
            let deadline = self
                .timeout
                .and_then(|timeout| self.activity.lock().unwrap().checked_add(timeout));
            let idle = async {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                packet = self.rx.recv() => {
                    let packet = packet.ok_or_else(|| io::Error::new(ErrorKind::BrokenPipe, "Datagram session ended"))?;
                    let written = writer.write(&packet).await?;
                    if written != packet.len() {
                        return Err(io::Error::new(ErrorKind::WriteZero, "partial UDP Datagram write"));
                    }
                    return Ok(());
                }
                result = self.control.read_u8() => return Err(control_read_error(result)),
                _ = idle => {
                    if let Some(timeout) = self.timeout
                        && self.activity.lock().unwrap().elapsed() >= timeout {
                        self.hub.counters.expired.fetch_add(1, Ordering::Relaxed);
                        info!(association = self.id, "UDP Datagram association expired");
                        return Err(io::Error::new(ErrorKind::TimedOut, DatagramIdleTimeout));
                    }
                }
            }
        }
    }
}

pub struct DatagramWrite {
    id: u64,
    hub: Arc<DatagramHub>,
    session: Session,
    control: SendStream,
    activity: Arc<Mutex<Instant>>,
    buf: BytesMut,
}

impl DatagramWrite {
    pub(crate) async fn acknowledge(&mut self) -> io::Result<()> {
        self.control
            .write_all(ACK)
            .await
            .map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err))
    }

    fn send_buffered(&mut self) -> io::Result<()> {
        let payload_len = self.buf.len();
        *self.activity.lock().unwrap() = Instant::now();
        self.session.deref_max_datagram_size()?;
        if payload_len + HEADER_LEN > self.session.max_datagram_size() {
            self.hub.counters.oversize.fetch_add(1, Ordering::Relaxed);
            debug!(
                association = self.id,
                bytes = payload_len,
                max = self.session.max_datagram_size().saturating_sub(HEADER_LEN),
                "dropping oversized UDP Datagram"
            );
            return Ok(());
        }
        // Framing copies into independent storage owned by QUIC; the input arena
        // can therefore be reused without changing any previously queued packet.
        match self.session.send_datagram(encode_packet(self.id, &self.buf)) {
            Ok(()) => {}
            Err(web_transport_quinn::SessionError::SendDatagramError(
                web_transport_quinn::quinn::SendDatagramError::TooLarge,
            )) => {
                self.hub.counters.oversize.fetch_add(1, Ordering::Relaxed);
                debug!(association = self.id, "dropping UDP Datagram after path MTU change");
                return Ok(());
            }
            Err(err) => return Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
        }
        self.hub.counters.tx.fetch_add(1, Ordering::Relaxed);
        trace!(association = self.id, bytes = payload_len, "UDP Datagram tx");
        Ok(())
    }
}

impl TransportWrite for DatagramWrite {
    fn allows_empty_packets(&self) -> bool {
        true
    }
    fn buf_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }
    async fn write(&mut self) -> io::Result<()> {
        let result = self.send_buffered();
        // Also clear on drop/error so the next packet cannot inherit stale bytes.
        self.buf.clear();
        result
    }
    async fn ping(&mut self) -> io::Result<()> {
        Ok(())
    }
    async fn close(&mut self) -> io::Result<()> {
        let _ = self.control.finish();
        Ok(())
    }
    fn pending_operations_notify(&mut self) -> Arc<Notify> {
        Arc::new(Notify::new())
    }
    async fn handle_pending_operations(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_errors_distinguish_normal_fin_from_faults() {
        assert_eq!(
            control_read_error(Err(io::Error::from(ErrorKind::UnexpectedEof))).kind(),
            ErrorKind::BrokenPipe
        );
        assert_eq!(control_read_error(Ok(0x7f)).kind(), ErrorKind::InvalidData);
        let reset = control_read_error(Err(io::Error::new(ErrorKind::ConnectionReset, "original reset reason")));
        assert_eq!(reset.kind(), ErrorKind::ConnectionReset);
        assert_eq!(reset.to_string(), "original reset reason");
        assert_eq!(
            control_read_error(Err(io::Error::from(ErrorKind::TimedOut))).kind(),
            ErrorKind::TimedOut
        );
    }

    #[test]
    fn idle_timeout_does_not_classify_socket_timeouts_as_expected() {
        assert!(is_datagram_idle_timeout(&io::Error::new(
            ErrorKind::TimedOut,
            DatagramIdleTimeout
        )));
        assert!(!is_datagram_idle_timeout(&io::Error::new(
            ErrorKind::TimedOut,
            "socket timeout"
        )));
        assert!(!is_datagram_idle_timeout(&io::Error::new(ErrorKind::ConnectionReset, "reset")));
    }

    #[tokio::test]
    async fn capsule_parser_distinguishes_clean_eof_but_flattens_transport_errors() {
        use web_transport_quinn::proto::{CapsuleError, Http3CapsuleReader};
        struct ResetRead;
        impl tokio::io::AsyncRead for ResetRead {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Err(io::Error::new(
                    ErrorKind::ConnectionAborted,
                    "simulated QUIC connection closure",
                )))
            }
        }
        let mut clean = Http3CapsuleReader::new(tokio::io::empty());
        assert!(clean.read().await.unwrap().is_none());
        let mut reset = Http3CapsuleReader::new(ResetRead);
        assert!(matches!(reset.read().await, Err(CapsuleError::UnexpectedEnd)));
    }

    #[test]
    fn association_limit_rejects_duplicates_and_releases_capacity() {
        let hub = DatagramHub {
            routes: Mutex::new(HashMap::new()),
            task: Mutex::new(None),
            counters: Counters::default(),
        };
        let route = |id| {
            let (tx, _rx) = mpsc::channel(QUEUE_PACKETS);
            hub.add_route(id, tx, Arc::new(Mutex::new(Instant::now())))
        };
        for id in 0..MAX_ASSOCIATIONS as u64 {
            route(id).unwrap();
        }
        assert_eq!(route(0).unwrap_err().kind(), ErrorKind::AlreadyExists);
        assert_eq!(route(MAX_ASSOCIATIONS as u64).unwrap_err().kind(), ErrorKind::OutOfMemory);
        hub.routes.lock().unwrap().remove(&0);
        route(MAX_ASSOCIATIONS as u64).unwrap();
    }

    #[test]
    fn header_validates_boundaries_version_and_flags() {
        let id = u64::MAX;
        let packet = encode_packet(id, b"hello");
        assert_eq!(decode_header(&packet), Some(id));
        assert_eq!(&packet[HEADER_LEN..], b"hello");
        assert_eq!(decode_header(&packet[..HEADER_LEN - 1]), None);
        assert_eq!(decode_header(&encode_packet(0, b"")), Some(0));
        let mut bad = packet.to_vec();
        bad[0] = 2;
        assert_eq!(decode_header(&bad), None);
        bad[0] = 1;
        bad[1] = 1;
        assert_eq!(decode_header(&bad), None);
        assert_eq!(decode_header(&encode_packet(1, &vec![0; 65508])), None);
    }

    #[tokio::test]
    async fn dispatcher_isolates_ids_and_drops_full_unknown_and_invalid_packets() {
        let hub = DatagramHub {
            routes: Mutex::new(HashMap::new()),
            task: Mutex::new(None),
            counters: Counters::default(),
        };
        let (a, mut arx) = mpsc::channel(1);
        let (b, mut brx) = mpsc::channel(1);
        for (id, tx) in [(4, a), (8, b)] {
            hub.routes.lock().unwrap().insert(
                id,
                Route {
                    tx,
                    activity: Arc::new(Mutex::new(Instant::now())),
                },
            );
        }
        hub.dispatch(encode_packet(8, b"b"));
        hub.dispatch(encode_packet(4, b"a"));
        hub.dispatch(encode_packet(4, b"overflow"));
        hub.dispatch(encode_packet(9, b"unknown"));
        hub.dispatch(Bytes::from_static(b"bad"));
        assert_eq!(&arx.recv().await.unwrap()[..], b"a");
        assert_eq!(&brx.recv().await.unwrap()[..], b"b");
        assert_eq!(hub.counters.rx.load(Ordering::Relaxed), 2);
        assert_eq!(hub.counters.queue_full.load(Ordering::Relaxed), 1);
        assert_eq!(hub.counters.invalid.load(Ordering::Relaxed), 2);
        hub.routes.lock().unwrap().remove(&4);
        hub.dispatch(encode_packet(4, b"late"));
        assert!(arx.recv().await.is_none());
    }
}
