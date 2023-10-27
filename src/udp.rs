use anyhow::Context;
use bytes::{Buf, BytesMut};
use futures_util::{stream, Stream};
use pin_project::{pin_project, pinned_drop};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::ops::DerefMut;
use std::pin::{pin, Pin};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::task::{Poll, Waker};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::time::Sleep;
use tracing::{debug, error, info};

const DEFAULT_UDP_BUFFER_SIZE: usize = 32 * 1024; // 32kb

type IoInner = Arc<Mutex<(BytesMut, Option<Waker>)>>;
struct UdpServer {
    listener: Arc<UdpSocket>,
    peers: HashMap<SocketAddr, IoInner, ahash::RandomState>,
    keys_to_delete: Arc<RwLock<Vec<SocketAddr>>>,
    pub cnx_timeout: Option<Duration>,
}

impl UdpServer {
    pub fn new(listener: Arc<UdpSocket>, timeout: Option<Duration>) -> Self {
        Self {
            listener,
            peers: HashMap::with_hasher(ahash::RandomState::new()),
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
    fn clone_socket(&self) -> Arc<UdpSocket> {
        self.listener.clone()
    }
}

#[pin_project(PinnedDrop)]
pub struct UdpStream {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    #[pin]
    deadline: Option<Sleep>,
    io: IoInner,
    keys_to_delete: Weak<RwLock<Vec<SocketAddr>>>,
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
        obuf: &mut ReadBuf<'_>,
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

        let mut guard = project.io.lock().unwrap();
        let (ibuf, waker) = guard.deref_mut();
        if ibuf.has_remaining() {
            let max = ibuf.remaining().min(obuf.remaining());
            obuf.put_slice(&ibuf[..max]);
            ibuf.advance(max);
            Poll::Ready(Ok(()))
        } else {
            waker.replace(cx.waker().clone());
            Poll::Pending
        }
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

    let udp_server = UdpServer::new(Arc::new(listener), timeout);
    let stream = stream::unfold(udp_server, |mut server| async {
        loop {
            server.clean_dead_keys();
            let peer_addr = match server.listener.peek_sender().await {
                Ok(ret) => ret,
                Err(err) => {
                    error!("Cannot read from UDP server. Closing server: {}", err);
                    return None;
                }
            };

            match server.peers.entry(peer_addr) {
                Entry::Occupied(mut peer) => {
                    let mut guard = peer.get_mut().lock().unwrap();
                    let (buf, waker) = guard.deref_mut();
                    // As we have done a peek_sender before, we are sure that there is pending read data
                    // and we don't want to wait to avoid holding the lock across await point
                    match server.listener.try_recv_buf(buf) {
                        Ok(0) => {} // don't wake if nothing was read
                        Ok(_) => {
                            if let Some(waker) = waker.take() {
                                waker.wake()
                            }
                        }
                        Err(_) => {
                            drop(guard);
                            server.keys_to_delete.write().unwrap().push(peer_addr);
                        }
                    }
                }
                Entry::Vacant(peer) => {
                    let mut buf = BytesMut::with_capacity(DEFAULT_UDP_BUFFER_SIZE);
                    match server.listener.recv_buf(&mut buf).await {
                        Ok(0) | Err(_) => continue,
                        Ok(len) => len,
                    };

                    let io = Arc::new(Mutex::new((buf, None)));
                    peer.insert(io.clone());
                    let udp_client = UdpStream {
                        socket: server.clone_socket(),
                        peer: peer_addr,
                        deadline: server
                            .cnx_timeout
                            .and_then(|timeout| tokio::time::Instant::now().checked_add(timeout))
                            .map(tokio::time::sleep_until),
                        keys_to_delete: Arc::downgrade(&server.keys_to_delete),
                        io,
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
