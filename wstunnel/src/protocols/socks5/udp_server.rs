use anyhow::Context;
use futures_util::{Stream, stream};

use parking_lot::RwLock;
use pin_project::{pin_project, pinned_drop};
use std::collections::HashMap;
use std::io;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;

use crate::tunnel::to_host_port;
use bytes::{Buf, Bytes, BytesMut};
use fast_socks5::new_udp_header;
use fast_socks5::util::target_addr::TargetAddr;
use log::warn;
use std::pin::{Pin, pin};
use std::sync::{Arc, Weak};
use std::task::{Poll, ready};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Interval;
use tracing::{debug, error, info};
use url::Host;

type PeerMapKey = (SocketAddr, TargetAddr);

struct IoInner {
    sender: mpsc::Sender<Bytes>,
}
struct Socks5UdpServer {
    listener: Arc<UdpSocket>,
    peers: HashMap<PeerMapKey, Pin<Arc<IoInner>>, ahash::RandomState>,
    keys_to_delete: Arc<RwLock<Vec<PeerMapKey>>>,
    cnx_timeout: Option<Duration>,
}

impl Socks5UdpServer {
    pub fn new(listener: UdpSocket, timeout: Option<Duration>) -> Self {
        let socket = socket2::SockRef::from(&listener);

        // Increase receive buffer
        const BUF_SIZES: [usize; 7] = [64usize, 32usize, 16usize, 8usize, 4usize, 2usize, 1usize];
        for size in BUF_SIZES.iter() {
            if let Err(err) = socket.set_recv_buffer_size(size * 1024 * 1024) {
                warn!("Cannot increase UDP server recv buffer to {size} Mib: {err}");
                warn!(
                    "This is not fatal, but can lead to packet loss if you have too much throughput. You must monitor packet loss in this case"
                );
                continue;
            }

            if *size != BUF_SIZES[0] {
                info!("Increased UDP server recv buffer to {} Mib", size);
            }

            break;
        }

        for size in BUF_SIZES.iter() {
            if let Err(err) = socket.set_send_buffer_size(size * 1024 * 1024) {
                warn!("Cannot increase UDP server send buffer to {size} Mib: {err}");
                warn!(
                    "This is not fatal, but can lead to packet loss if you have too much throughput. You must monitor packet loss in this case"
                );
                continue;
            }

            if *size != BUF_SIZES[0] {
                info!("Increased UDP server send buffer to {} Mib", size);
            }
            break;
        }

        Self {
            listener: Arc::new(listener),
            peers: HashMap::with_hasher(ahash::RandomState::new()),
            keys_to_delete: Default::default(),
            cnx_timeout: timeout,
        }
    }

    #[inline]
    pub fn clean_dead_keys(&mut self) {
        let nb_key_to_delete = self.keys_to_delete.read().len();
        if nb_key_to_delete == 0 {
            return;
        }

        debug!("Cleaning {} dead udp peers", nb_key_to_delete);
        let mut keys_to_delete = self.keys_to_delete.write();
        for key in keys_to_delete.iter() {
            self.peers.remove(key);
        }
        keys_to_delete.clear();
    }
}

pub struct Socks5UdpStreamWriter {
    send_socket: Arc<UdpSocket>,
    peer: SocketAddr,
    udp_header: Vec<u8>,
}

#[pin_project(PinnedDrop)]
pub struct Socks5UdpStream {
    #[pin]
    recv_data: mpsc::Receiver<Bytes>,
    send_socket: Arc<UdpSocket>,
    destination: TargetAddr,
    peer: SocketAddr,
    udp_header: Vec<u8>,
    #[pin]
    pub watchdog_deadline: Option<Interval>,
    data_read_before_deadline: bool,
    io: Pin<Arc<IoInner>>,
    keys_to_delete: Weak<RwLock<Vec<PeerMapKey>>>,
}

#[pinned_drop]
impl PinnedDrop for Socks5UdpStream {
    fn drop(self: Pin<&mut Self>) {
        if let Some(keys_to_delete) = self.keys_to_delete.upgrade() {
            keys_to_delete.write().push((self.peer, self.destination.clone()));
        }
    }
}

impl Socks5UdpStream {
    fn new(
        send_socket: Arc<UdpSocket>,
        peer: SocketAddr,
        destination: TargetAddr,
        watchdog_deadline: Option<Duration>,
        keys_to_delete: Weak<RwLock<Vec<PeerMapKey>>>,
    ) -> (Self, Pin<Arc<IoInner>>) {
        let (tx, rx) = mpsc::channel(1024);
        let io = Arc::pin(IoInner { sender: tx });
        let udp_header = match &destination {
            TargetAddr::Ip(ip) => new_udp_header(*ip).unwrap(),
            TargetAddr::Domain(h, p) => new_udp_header((h.as_str(), *p)).unwrap(),
        };
        let s = Self {
            recv_data: rx,
            send_socket,
            peer,
            destination,
            watchdog_deadline: watchdog_deadline
                .map(|timeout| tokio::time::interval_at(tokio::time::Instant::now() + timeout, timeout)),
            data_read_before_deadline: false,
            io: io.clone(),
            keys_to_delete,
            udp_header,
        };

        (s, io)
    }

    pub fn destination(&self) -> (Host, u16) {
        match &self.destination {
            TargetAddr::Ip(sock_addr) => to_host_port(*sock_addr),
            TargetAddr::Domain(h, p) => (Host::Domain(h.clone()), *p),
        }
    }

    pub fn writer(&self) -> Socks5UdpStreamWriter {
        Socks5UdpStreamWriter {
            send_socket: self.send_socket.clone(),
            peer: self.peer,
            udp_header: self.udp_header.clone(),
        }
    }
}

impl AsyncRead for Socks5UdpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        obuf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut project = self.project();
        // Look that the timeout for client has not elapsed
        if let Some(mut deadline) = project.watchdog_deadline.as_pin_mut()
            && deadline.poll_tick(cx).is_ready()
        {
            if !*project.data_read_before_deadline {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::TimedOut,
                    format!("UDP stream timeout with {}", project.peer),
                )));
            };

            *project.data_read_before_deadline = false;
            while deadline.poll_tick(cx).is_ready() {}
        }

        let Some(data) = ready!(project.recv_data.poll_recv(cx)) else {
            return Poll::Ready(Err(Error::from(ErrorKind::UnexpectedEof)));
        };
        if obuf.remaining() < data.len() {
            return Poll::Ready(Err(Error::new(
                ErrorKind::InvalidData,
                "udp dst buffer does not have enough space left. Can't fragment",
            )));
        }

        obuf.put_slice(data.chunk());
        *project.data_read_before_deadline = true;

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Socks5UdpStreamWriter {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        let header_len = self.udp_header.len();
        self.udp_header.extend_from_slice(buf);
        let ret = self.send_socket.poll_send_to(cx, self.udp_header.as_slice(), self.peer);
        self.udp_header.truncate(header_len);
        ret.map(|r| r.map(|write_len| write_len - header_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        self.send_socket.poll_send_ready(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
}

pub async fn run_server(
    bind: SocketAddr,
    timeout: Option<Duration>,
) -> Result<impl Stream<Item = io::Result<Socks5UdpStream>>, anyhow::Error> {
    let listener = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("Cannot create UDP server {bind:?}"))?;

    let udp_server = Socks5UdpServer::new(listener, timeout);
    static MAX_PACKET_LENGTH: usize = 64 * 1024;
    let buffer = BytesMut::with_capacity(MAX_PACKET_LENGTH * 10);
    let stream = stream::unfold((udp_server, buffer), |(mut server, mut buf)| async move {
        loop {
            server.clean_dead_keys();
            buf.reserve(MAX_PACKET_LENGTH);

            let peer_addr = match server.listener.recv_buf_from(&mut buf).await {
                Ok((_read_len, peer_addr)) => peer_addr,
                Err(err) => {
                    error!("Cannot read from UDP server. Closing server: {}", err);
                    return None;
                }
            };

            let (destination_addr, data) = {
                let payload = buf.split().freeze();
                let (frag, destination_addr, data) = match fast_socks5::parse_udp_request(payload.chunk()).await {
                    Ok((frag, addr, data)) => (frag, addr, data),
                    Err(err) => {
                        warn!("Skipping invalid UDP socks5 request: {err} ");
                        debug!("Invalid UDP socks5 request: {:?}", payload.chunk());
                        continue;
                    }
                };
                // We don't support udp fragmentation
                if frag != 0 {
                    warn!("dropping UDP socks5 fragmented");
                    continue;
                }
                (destination_addr, payload.slice_ref(data))
            };

            let addr = (peer_addr, destination_addr);
            match server.peers.get(&addr) {
                Some(io) => {
                    if io.sender.send(data).await.is_err() {
                        server.peers.remove(&addr);
                    }
                }
                None => {
                    info!("New UDP connection for {}", addr.1);
                    let (udp_client, io) = Socks5UdpStream::new(
                        server.listener.clone(),
                        addr.0,
                        addr.1.clone(),
                        server.cnx_timeout,
                        Arc::downgrade(&server.keys_to_delete),
                    );
                    let _ = io.sender.send(data).await;
                    server.peers.insert(addr, io);
                    return Some((Ok(udp_client), (server, buf)));
                }
            }
        }
    });

    Ok(stream)
}
