use anyhow::Context;
use futures_util::{stream, Stream};

use parking_lot::{Mutex, RwLock};
use pin_project::{pin_project, pinned_drop};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::ops::DerefMut;
use std::pin::{pin, Pin};
use std::sync::{Arc, Weak};
use std::task::{ready, Poll, Waker};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::futures::Notified;

use tokio::sync::Notify;
use tokio::time::Sleep;
use tracing::{debug, error, info};

struct IoInner {
    has_data_to_read: &'static Notify,
    waker: Mutex<Option<Waker>>,
    has_read_data: Notify,
}
struct UdpServer {
    listener: Arc<UdpSocket>,
    peers: HashMap<SocketAddr, Arc<IoInner>, ahash::RandomState>,
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
        let nb_key_to_delete = self.keys_to_delete.read().len();
        if nb_key_to_delete == 0 {
            return;
        }

        debug!("Cleaning {} dead udp peers", nb_key_to_delete);
        let mut keys_to_delete = self.keys_to_delete.write();
        for key in keys_to_delete.iter() {
            let Some(peer) = self.peers.remove(key) else {
                continue;
            };

            #[allow(mutable_transmutes)]
            unsafe {
                let _ = Box::from_raw(std::mem::transmute::<&Notify, &mut Notify>(
                    peer.has_data_to_read,
                ));
            }
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
    has_been_notified: bool,
    #[pin]
    pending_notification: Option<Notified<'static>>,
    io: Arc<IoInner>,
    keys_to_delete: Weak<RwLock<Vec<SocketAddr>>>,
}

#[pinned_drop]
impl PinnedDrop for UdpStream {
    fn drop(self: Pin<&mut Self>) {
        if let Some(keys_to_delete) = self.keys_to_delete.upgrade() {
            keys_to_delete.write().push(self.peer);
        }

        self.io.has_read_data.notify_one();
    }
}

impl AsyncRead for UdpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        obuf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut project = self.project();
        if let Some(deadline) = project.deadline.as_pin_mut() {
            if deadline.poll(cx).is_ready() {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::TimedOut,
                    format!("UDP stream timeout with {}", project.peer),
                )));
            }
        }

        if let Some(notified) = project.pending_notification.as_mut().as_pin_mut() {
            if !notified.poll(cx).is_ready() {
                project.io.waker.lock().replace(cx.waker().clone());
                return Poll::Pending;
            }
            project.pending_notification.as_mut().set(None);
        }

        let _ = ready!(project.socket.poll_recv(cx, obuf));
        project
            .pending_notification
            .as_mut()
            .set(Some(project.io.has_data_to_read.notified()));
        project.io.has_read_data.notify_one();
        Poll::Ready(Ok(()))
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
                    let io = peer.get_mut();
                    io.has_read_data.notified().await;
                    io.has_data_to_read.notify_one();
                    let waker = io.waker.lock().deref_mut().take();
                    if let Some(waker) = waker {
                        waker.wake();
                    }
                }
                Entry::Vacant(peer) => {
                    let has_data_to_read: &'static Notify = Box::leak(Box::new(Notify::new()));
                    let pending_notification = has_data_to_read.notified();
                    let has_read_data = Notify::new();
                    has_data_to_read.notify_one();
                    let io = Arc::new(IoInner {
                        has_data_to_read,
                        waker: Mutex::new(None),
                        has_read_data,
                    });
                    peer.insert(io.clone());
                    let udp_client = UdpStream {
                        socket: server.clone_socket(),
                        peer: peer_addr,
                        deadline: server
                            .cnx_timeout
                            .and_then(|timeout| tokio::time::Instant::now().checked_add(timeout))
                            .map(tokio::time::sleep_until),
                        keys_to_delete: Arc::downgrade(&server.keys_to_delete),
                        has_been_notified: false,
                        pending_notification: Some(pending_notification),
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

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{pin_mut, StreamExt};
    use tokio::io::AsyncReadExt;
    use tokio::time::error::Elapsed;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_udp_server() {
        let server_addr: SocketAddr = "[::1]:1234".parse().unwrap();
        let server = run_server(server_addr, None).await.unwrap();
        pin_mut!(server);

        // Should timeout
        let fut = timeout(Duration::from_millis(100), server.next()).await;
        assert!(matches!(fut, Err(Elapsed { .. })));

        // Send some data to the server
        let client = UdpSocket::bind("[::1]:0").await.unwrap();
        assert!(client.send_to(b"hello".as_ref(), server_addr).await.is_ok());

        // Should have a new connection
        let fut = timeout(Duration::from_millis(100), server.next()).await;
        assert!(matches!(fut, Ok(Some(Ok(_)))));

        // Should timeout again, no new client
        let fut2 = timeout(Duration::from_millis(100), server.next()).await;
        assert!(matches!(fut2, Err(Elapsed { .. })));

        // Take the stream of data
        let stream = fut.unwrap().unwrap().unwrap();
        pin_mut!(stream);

        let mut buf = [0u8; 25];
        let ret = stream.read(&mut buf).await;
        assert!(matches!(ret, Ok(5)));
        assert_eq!(&buf[..6], b"hello\0");

        assert!(client.send_to(b"world".as_ref(), server_addr).await.is_ok());
        assert!(client.send_to(b" test".as_ref(), server_addr).await.is_ok());

        // Server need to be polled to feed the stream with needed data
        let _ = timeout(Duration::from_millis(100), server.next()).await;
        // Udp Server should respect framing from the client and not merge the two packets
        let ret = timeout(Duration::from_millis(100), stream.read(&mut buf[5..])).await;
        assert!(matches!(ret, Ok(Ok(5))));

        let _ = timeout(Duration::from_millis(100), server.next()).await;
        let ret = timeout(Duration::from_millis(100), stream.read(&mut buf[10..])).await;
        assert!(matches!(ret, Ok(Ok(5))));
        assert_eq!(&buf[..16], b"helloworld test\0");
    }

    #[tokio::test]
    async fn test_multiple_client() {
        let server_addr: SocketAddr = "[::1]:1235".parse().unwrap();
        let server = run_server(server_addr, None).await.unwrap();
        pin_mut!(server);

        // Send some data to the server
        let client = UdpSocket::bind("[::1]:0").await.unwrap();
        assert!(client.send_to(b"aaaaa".as_ref(), server_addr).await.is_ok());

        let client2 = UdpSocket::bind("[::1]:0").await.unwrap();
        assert!(client2
            .send_to(b"bbbbb".as_ref(), server_addr)
            .await
            .is_ok());

        // Should have a new connection
        let fut = timeout(Duration::from_millis(100), server.next()).await;
        assert!(matches!(fut, Ok(Some(Ok(_)))));

        // Take the stream of data
        let stream = fut.unwrap().unwrap().unwrap();
        pin_mut!(stream);

        let mut buf = [0u8; 25];
        let ret = stream.read(&mut buf).await;
        assert!(matches!(ret, Ok(5)));
        assert_eq!(&buf[..6], b"aaaaa\0");

        let fut2 = timeout(Duration::from_millis(100), server.next()).await;
        assert!(matches!(fut2, Ok(Some(Ok(_)))));

        let stream2 = fut2.unwrap().unwrap().unwrap();
        pin_mut!(stream2);

        let ret = stream2.read(&mut buf).await;
        assert!(matches!(ret, Ok(5)));
        assert_eq!(&buf[..6], b"bbbbb\0");

        assert!(client.send_to(b"ccccc".as_ref(), server_addr).await.is_ok());
        assert!(client2
            .send_to(b"ddddd".as_ref(), server_addr)
            .await
            .is_ok());

        // Server need to be polled to feed the stream with need data
        let _ = timeout(Duration::from_millis(100), server.next()).await;

        let ret = stream.read(&mut buf).await;
        assert!(matches!(ret, Ok(5)));
        assert_eq!(&buf[..6], b"ccccc\0");

        let ret = stream2.read(&mut buf).await;
        assert!(matches!(ret, Ok(5)));
        assert_eq!(&buf[..6], b"ddddd\0");
    }

    #[tokio::test]
    async fn test_udp_should_timeout() {
        let server_addr: SocketAddr = "[::1]:1237".parse().unwrap();
        let socket_timeout = Duration::from_secs(1);
        let server = run_server(server_addr, Some(socket_timeout)).await.unwrap();
        pin_mut!(server);

        // Send some data to the server
        let client = UdpSocket::bind("[::1]:0").await.unwrap();
        assert!(client.send_to(b"hello".as_ref(), server_addr).await.is_ok());

        // Should have a new connection
        let fut = timeout(Duration::from_millis(100), server.next()).await;
        assert!(matches!(fut, Ok(Some(Ok(_)))));

        // Take the stream of data
        let stream = fut.unwrap().unwrap().unwrap();
        pin_mut!(stream);

        let mut buf = [0u8; 25];
        let ret = stream.read(&mut buf).await;
        assert!(matches!(ret, Ok(5)));
        assert_eq!(&buf[..6], b"hello\0");

        // Server need to be polled to feed the stream with need data
        let _ = timeout(Duration::from_millis(100), server.next()).await;
        let ret = timeout(Duration::from_millis(100), stream.read(&mut buf[5..])).await;
        assert!(ret.is_err());

        // Stream should be closed after the timeout
        tokio::time::sleep(socket_timeout).await;
        let ret = stream.read(&mut buf[5..]).await;
        assert!(ret.is_err());
    }
}
