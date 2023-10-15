use anyhow::Context;
use futures_util::{stream, Stream};
use pin_project::{pin_project, pinned_drop};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::pin::{pin, Pin};
use std::sync::{Arc, RwLock, Weak};
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::UdpSocket;
use tokio::time::Sleep;
use tracing::{debug, error, info};

const DEFAULT_UDP_BUFFER_SIZE: usize = 8 * 1024;

struct UdpServer {
    listener: UdpSocket,
    std_socket: std::net::UdpSocket,
    buffer: Vec<u8>,
    peers: HashMap<SocketAddr, DuplexStream, ahash::RandomState>,
    keys_to_delete: Arc<RwLock<Vec<SocketAddr>>>,
    pub cnx_timeout: Option<Duration>,
}

impl UdpServer {
    pub fn new(listener: UdpSocket, timeout: Option<Duration>) -> Self {
        let socket = listener.into_std().unwrap();
        let listener = UdpSocket::from_std(socket.try_clone().unwrap()).unwrap();
        Self {
            listener,
            std_socket: socket,
            peers: HashMap::with_hasher(ahash::RandomState::new()),
            buffer: vec![0u8; DEFAULT_UDP_BUFFER_SIZE],
            keys_to_delete: Default::default(),
            cnx_timeout: timeout,
        }
    }

    fn clean_dead_keys(&mut self) {
        let nb_key_to_delete = self.keys_to_delete.read().unwrap().len();
        if nb_key_to_delete == 0 {
            return;
        }

        debug!("Cleaning {} dead udp peers", nb_key_to_delete);
        let mut keys_to_delete = self.keys_to_delete.write().unwrap();
        for key in keys_to_delete.iter() {
            self.peers.remove(key);
        }
        keys_to_delete.clear();
    }

    fn clone_socket(&self) -> UdpSocket {
        UdpSocket::from_std(self.std_socket.try_clone().unwrap()).unwrap()
    }
}

#[pin_project(PinnedDrop)]
pub struct UdpStream {
    socket: UdpSocket,
    peer: SocketAddr,
    #[pin]
    deadline: Option<Sleep>,
    #[pin]
    io: DuplexStream,
    keys_to_delete: Weak<RwLock<Vec<SocketAddr>>>,
}

impl AsMut<DuplexStream> for UdpStream {
    fn as_mut(&mut self) -> &mut DuplexStream {
        &mut self.io
    }
}

#[pinned_drop]
impl PinnedDrop for UdpStream {
    fn drop(self: Pin<&mut Self>) {
        if let Some(keys_to_delete) = self.keys_to_delete.upgrade() {
            keys_to_delete.write().unwrap().push(self.peer);
        }
    }
}

impl AsyncRead for UdpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let project = self.project();
        if let Some(deadline) = project.deadline.as_pin_mut() {
            if deadline.poll(cx).is_ready() {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::TimedOut,
                    format!("UDP stream timeout with {}", project.peer),
                )));
            }
        }

        project.io.poll_read(cx, buf)
    }
}

impl AsyncWrite for UdpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        self.socket.poll_send_to(cx, buf, self.peer)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Error>> {
        self.socket.poll_send_ready(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
}

pub async fn run_server(
    bind: SocketAddr,
    timeout: Option<Duration>,
) -> Result<impl Stream<Item = io::Result<UdpStream>>, anyhow::Error> {
    info!(
        "Starting UDP server listening cnx on {} with cnx timeout of {}s",
        bind,
        timeout.unwrap_or(Duration::from_secs(0)).as_secs()
    );

    let listener = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("Cannot create UDP server {:?}", bind))?;

    let udp_server = UdpServer::new(listener, timeout);
    let stream = stream::unfold(udp_server, |mut server| async {
        loop {
            server.clean_dead_keys();
            let (nb_bytes, peer_addr) = match server.listener.recv_from(&mut server.buffer).await {
                Ok(ret) => ret,
                Err(err) => {
                    error!("Cannot read from UDP server. Closing server: {}", err);
                    return None;
                }
            };

            match server.peers.entry(peer_addr) {
                Entry::Occupied(mut peer) => {
                    let ret = peer.get_mut().write_all(&server.buffer[0..nb_bytes]).await;
                    if let Err(err) = ret {
                        info!("Peer {:?} disconnected {:?}", peer_addr, err);
                        peer.remove();
                    }
                }
                Entry::Vacant(peer) => {
                    let (mut rx, tx) = tokio::io::duplex(DEFAULT_UDP_BUFFER_SIZE);
                    rx.write_all(&server.buffer[0..nb_bytes])
                        .await
                        .unwrap_or_default(); // should never fail
                    peer.insert(rx);
                    let udp_client = UdpStream {
                        socket: server.clone_socket(),
                        peer: peer_addr,
                        deadline: server
                            .cnx_timeout
                            .and_then(|timeout| tokio::time::Instant::now().checked_add(timeout))
                            .map(tokio::time::sleep_until),
                        keys_to_delete: Arc::downgrade(&server.keys_to_delete),
                        io: tx,
                    };
                    return Some((Ok(udp_client), (server)));
                }
            }
        }
    });

    Ok(stream)
}

pub struct MyUdpSocket {
    socket: Arc<UdpSocket>,
}

impl MyUdpSocket {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self { socket }
    }
}

impl AsyncRead for MyUdpSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        unsafe { self.map_unchecked_mut(|x| &mut x.socket) }
            .poll_recv_from(cx, buf)
            .map(|x| x.map(|_| ()))
    }
}

impl AsyncWrite for MyUdpSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        unsafe { self.map_unchecked_mut(|x| &mut x.socket) }.poll_send(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
}
