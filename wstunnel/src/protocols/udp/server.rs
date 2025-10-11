use anyhow::{Context, anyhow};
use futures_util::{Stream, stream};

use parking_lot::RwLock;
use pin_project::{pin_project, pinned_drop};
use std::collections::HashMap;
use std::future::Future;
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::{io, task};
use tokio::task::JoinSet;

use log::warn;
use socket2::SockRef;
use std::pin::{Pin, pin};
use std::sync::{Arc, Weak};
use std::task::{Poll, ready};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::futures::Notified;

use crate::protocols::dns::DnsResolver;
use crate::somark::SoMark;
use tokio::sync::Notify;
use tokio::time::{Interval, sleep, timeout};
use tracing::{debug, error, info};
use url::Host;

struct IoInner {
    has_data_to_read: Notify,
    has_read_data: Notify,
}
struct UdpServer {
    listener: Arc<UdpSocket>,
    peers: HashMap<SocketAddr, Pin<Arc<IoInner>>, ahash::RandomState>,
    keys_to_delete: Arc<RwLock<Vec<SocketAddr>>>,
    cnx_timeout: Option<Duration>,
}

impl UdpServer {
    pub fn new(listener: UdpSocket, timeout: Option<Duration>) -> Self {
        let socket = SockRef::from(&listener);

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
    pub fn clone_socket(&self) -> Arc<UdpSocket> {
        self.listener.clone()
    }
}

#[pin_project(PinnedDrop)]
pub struct UdpStream {
    recv_socket: Arc<UdpSocket>,
    send_socket: Arc<UdpSocket>,
    peer: SocketAddr,
    #[pin]
    watchdog_deadline: Option<Interval>,
    data_read_before_deadline: bool,
    has_been_notified: bool,
    #[pin]
    pending_notification: Option<Notified<'static>>,
    io: Pin<Arc<IoInner>>,
    keys_to_delete: Weak<RwLock<Vec<SocketAddr>>>,
}

#[pinned_drop]
impl PinnedDrop for UdpStream {
    fn drop(self: Pin<&mut Self>) {
        if let Some(keys_to_delete) = self.keys_to_delete.upgrade() {
            keys_to_delete.write().push(self.peer);
        }

        // safety: we are dropping the notification as we extend its lifetime to 'static unsafely
        // So it must be gone before we drop its parent. It should never happen but in case
        let mut project = self.project();
        project.pending_notification.as_mut().set(None);
        project.io.has_read_data.notify_one();
    }
}

impl UdpStream {
    fn new(
        recv_socket: Arc<UdpSocket>,
        send_socket: Arc<UdpSocket>,
        peer: SocketAddr,
        watchdog_deadline: Option<Duration>,
        keys_to_delete: Weak<RwLock<Vec<SocketAddr>>>,
    ) -> (Self, Pin<Arc<IoInner>>) {
        let has_data_to_read = Notify::new();
        let has_read_data = Notify::new();
        let io = Arc::pin(IoInner {
            has_data_to_read,
            has_read_data,
        });
        let mut s = Self {
            recv_socket,
            send_socket,
            peer,
            watchdog_deadline: watchdog_deadline
                .map(|timeout| tokio::time::interval_at(tokio::time::Instant::now() + timeout, timeout)),
            data_read_before_deadline: false,
            has_been_notified: false,
            pending_notification: None,
            io: io.clone(),
            keys_to_delete,
        };

        let pending_notification =
            unsafe { std::mem::transmute::<Notified<'_>, Notified<'static>>(s.io.has_data_to_read.notified()) };
        s.pending_notification = Some(pending_notification);

        (s, io)
    }

    #[cfg_attr(not(target_os = "linux"), expect(dead_code))]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.send_socket.local_addr()
    }

    pub fn writer(&self) -> UdpStreamWriter {
        UdpStreamWriter {
            send_socket: self.send_socket.clone(),
            peer: self.peer,
        }
    }
}

impl AsyncRead for UdpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, obuf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
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

        if let Some(notified) = project.pending_notification.as_mut().as_pin_mut() {
            ready!(notified.poll(cx));
            project.pending_notification.as_mut().set(None);
        }

        let peer = ready!(project.recv_socket.poll_recv_from(cx, obuf))?;
        debug_assert_eq!(peer, *project.peer);
        *project.data_read_before_deadline = true;

        // re-arm notification
        let notified: Notified<'static> = unsafe { std::mem::transmute(project.io.has_data_to_read.notified()) };
        project.pending_notification.as_mut().set(Some(notified));
        project.pending_notification.as_pin_mut().unwrap().enable();

        // Let know server that we have read data
        project.io.has_read_data.notify_one();

        Poll::Ready(Ok(()))
    }
}

pub struct UdpStreamWriter {
    send_socket: Arc<UdpSocket>,
    peer: SocketAddr,
}

impl AsyncWrite for UdpStreamWriter {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        self.send_socket.poll_send_to(cx, buf, self.peer)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), Error>> {
        self.send_socket.poll_send_ready(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
}

pub async fn run_server(
    bind: SocketAddr,
    timeout: Option<Duration>,
    configure_listener: impl Fn(&UdpSocket) -> anyhow::Result<()>,
    mk_send_socket: impl Fn(&Arc<UdpSocket>) -> anyhow::Result<Arc<UdpSocket>>,
) -> Result<impl Stream<Item = io::Result<UdpStream>>, anyhow::Error> {
    info!(
        "Starting UDP server listening cnx on {} with cnx timeout of {}s",
        bind,
        timeout.unwrap_or(Duration::from_secs(0)).as_secs()
    );

    let listener = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("Cannot create UDP server {bind:?}"))?;
    configure_listener(&listener)?;

    let udp_server = UdpServer::new(listener, timeout);
    let stream = stream::unfold(
        (udp_server, None, mk_send_socket),
        |(mut server, peer_with_data, mk_send_socket)| async move {
            // New returned peer hasn't read its data yet, await for it.
            if let Some(await_peer) = peer_with_data
                && let Some(peer) = server.peers.get(&await_peer)
            {
                peer.has_read_data.notified().await;
            };

            loop {
                server.clean_dead_keys();
                let peer_addr = match server.listener.peek_sender().await {
                    Ok(ret) => ret,
                    Err(err) => {
                        error!("Cannot read from UDP server. Closing server: {}", err);
                        return None;
                    }
                };

                match server.peers.get(&peer_addr) {
                    Some(io) => {
                        io.has_data_to_read.notify_one();
                        io.has_read_data.notified().await;
                    }
                    None => {
                        info!("New UDP connection from {}", peer_addr);
                        let (udp_client, io) = UdpStream::new(
                            server.clone_socket(),
                            mk_send_socket(&server.listener).ok()?,
                            peer_addr,
                            server.cnx_timeout,
                            Arc::downgrade(&server.keys_to_delete),
                        );
                        io.has_data_to_read.notify_waiters();
                        server.peers.insert(peer_addr, io);
                        return Some((Ok(udp_client), (server, Some(peer_addr), mk_send_socket)));
                    }
                }
            }
        },
    );

    Ok(stream)
}

#[derive(Clone)]
pub struct WsUdpSocket {
    socket: Arc<UdpSocket>,
}

impl WsUdpSocket {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self { socket }
    }
}

impl AsyncRead for WsUdpSocket {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        unsafe { self.map_unchecked_mut(|x| &mut x.socket) }
            .poll_recv_from(cx, buf)
            .map(|x| x.map(|_| ()))
    }
}

impl AsyncWrite for WsUdpSocket {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        unsafe { self.map_unchecked_mut(|x| &mut x.socket) }.poll_send(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
}

pub async fn connect(
    host: &Host<String>,
    port: u16,
    connect_timeout: Duration,
    so_mark: SoMark,
    dns_resolver: &DnsResolver,
) -> anyhow::Result<WsUdpSocket> {
    info!("Opening UDP connection to {}:{}", host, port);

    let socket_addrs: Vec<SocketAddr> = match host {
        Host::Domain(domain) => dns_resolver
            .lookup_host(domain.as_str(), port)
            .await
            .with_context(|| format!("cannot resolve domain: {domain}"))?,
        Host::Ipv4(ip) => vec![SocketAddr::V4(SocketAddrV4::new(*ip, port))],
        Host::Ipv6(ip) => vec![SocketAddr::V6(SocketAddrV6::new(*ip, port, 0, 0))],
    };

    let mut cnx = None;
    let mut last_err = None;
    let mut join_set = JoinSet::new();

    for (ix, addr) in socket_addrs.into_iter().enumerate() {
        let socket = match &addr {
            SocketAddr::V4(_) => UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await,
            SocketAddr::V6(_) => UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)).await,
        };

        let socket = match socket {
            Ok(socket) => socket,
            Err(err) => {
                warn!("cannot bind udp socket {err:?}");
                continue;
            }
        };

        so_mark
            .set_mark(SockRef::from(&socket))
            .context("cannot set SO_MARK on socket")?;

        // Spawn the connection attempt in the join set.
        // We include a delay of ix * 250 milliseconds, as per RFC8305.
        // See https://datatracker.ietf.org/doc/html/rfc8305#section-5
        let fut = async move {
            if ix > 0 {
                sleep(Duration::from_millis(250 * ix as u64)).await;
            }

            debug!("connecting to {}", addr);
            match timeout(connect_timeout, socket.connect(addr)).await {
                Ok(Ok(())) => Ok(Ok(socket)),
                Ok(Err(e)) => Ok(Err((addr, e))),
                Err(e) => Err((addr, e)),
            }
        };
        join_set.spawn(fut);
    }

    // Wait for the next future that finishes in the join set, until we got one
    // that resulted in a successful connection.
    // If cnx is no longer None, we exit the loop, since this means that we got
    // a successful connection.
    while let (None, Some(res)) = (&cnx, join_set.join_next().await) {
        match res? {
            Ok(Ok(socket)) => {
                // We've got a successful connection, so we can abort all other
                // ongoing attempts.
                join_set.abort_all();

                debug!(
                    "Connected to udp endpoint {}, aborted all other connection attempts",
                    socket.peer_addr()?
                );
                cnx = Some(socket);
            }
            Ok(Err((addr, err))) => {
                debug!("Cannot connect to udp endpoint {addr} reason {err}");
                last_err = Some(err);
            }
            Err((addr, _)) => {
                warn!(
                    "Cannot connect to udp endpoint {addr} due to timeout of {}s elapsed",
                    connect_timeout.as_secs()
                );
            }
        }
    }

    if let Some(cnx) = cnx {
        Ok(WsUdpSocket::new(Arc::new(cnx)))
    } else {
        Err(anyhow!("Cannot connect to udp peer {host}:{port} reason {last_err:?}"))
    }
}

#[cfg(target_os = "linux")]
pub fn configure_tproxy(listener: &UdpSocket) -> anyhow::Result<()> {
    use std::net::IpAddr;
    use std::os::fd::AsFd;

    socket2::SockRef::from(&listener).set_ip_transparent_v4(true)?;
    match listener.local_addr().unwrap().ip() {
        IpAddr::V4(_) => {
            nix::sys::socket::setsockopt(&listener.as_fd(), nix::sys::socket::sockopt::Ipv4OrigDstAddr, &true)?;
        }
        IpAddr::V6(_) => {
            nix::sys::socket::setsockopt(&listener.as_fd(), nix::sys::socket::sockopt::Ipv6OrigDstAddr, &true)?;
        }
    };
    Ok(())
}

#[cfg(target_os = "linux")]
#[inline]
pub fn mk_send_socket_tproxy(listener: &Arc<UdpSocket>) -> anyhow::Result<Arc<UdpSocket>> {
    use nix::cmsg_space;
    use nix::sys::socket::{ControlMessageOwned, RecvMsg, SockaddrIn};
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::io::IoSliceMut;
    use std::net::IpAddr;
    use std::os::fd::AsRawFd;

    let mut cmsg_space = cmsg_space!(nix::libc::sockaddr_in6);
    let mut buf = [0; 8];
    let mut io = [IoSliceMut::new(&mut buf)];
    let msg: RecvMsg<SockaddrIn> = nix::sys::socket::recvmsg(
        listener.as_raw_fd(),
        &mut io,
        Some(&mut cmsg_space),
        nix::sys::socket::MsgFlags::MSG_PEEK,
    )?;

    let mut remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    for cmsg in msg.cmsgs()? {
        match cmsg {
            ControlMessageOwned::Ipv4OrigDstAddr(ip) => {
                remote_addr = SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(ip.sin_addr.s_addr))),
                    u16::from_be(ip.sin_port),
                );
            }
            ControlMessageOwned::Ipv6OrigDstAddr(ip) => {
                remote_addr = SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(ip.sin6_addr.s6_addr))),
                    u16::from_be(ip.sin6_port),
                );
            }
            _ => {
                warn!("Unknown control message {cmsg:?}");
            }
        }
    }

    let socket = Socket::new(Domain::for_address(remote_addr), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_ip_transparent_v4(true)?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.bind(&SockAddr::from(remote_addr))?;
    socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(std::net::UdpSocket::from(socket))?;

    Ok(Arc::new(socket))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{StreamExt, pin_mut};
    use tokio::io::AsyncReadExt;
    use tokio::time::error::Elapsed;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_udp_server() {
        let server_addr: SocketAddr = "[::1]:1234".parse().unwrap();
        let server = run_server(server_addr, None, |_| Ok(()), |l| Ok(l.clone()))
            .await
            .unwrap();
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
        let mut server = Box::pin(
            run_server(server_addr, None, |_| Ok(()), |l| Ok(l.clone()))
                .await
                .unwrap(),
        );

        // Send some data to the server
        let client = UdpSocket::bind("[::1]:0").await.unwrap();
        assert!(client.send_to(b"aaaaa".as_ref(), server_addr).await.is_ok());

        let client2 = UdpSocket::bind("[::1]:0").await.unwrap();
        assert!(client2.send_to(b"bbbbb".as_ref(), server_addr).await.is_ok());

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

        // make the server make progress
        let fut2 = timeout(Duration::from_millis(100), server.next()).await;
        assert!(matches!(fut2, Ok(Some(Ok(_)))));

        let stream2 = fut2.unwrap().unwrap().unwrap();
        pin_mut!(stream2);

        // let the server make progress
        tokio::spawn(async move {
            loop {
                let _ = server.next().await;
            }
        });

        let ret = stream2.read(&mut buf).await;
        assert!(matches!(ret, Ok(5)));
        assert_eq!(&buf[..6], b"bbbbb\0");

        assert!(client.send_to(b"ccccc".as_ref(), server_addr).await.is_ok());
        assert!(client2.send_to(b"ddddd".as_ref(), server_addr).await.is_ok());
        assert!(client2.send_to(b"eeeee".as_ref(), server_addr).await.is_ok());
        assert!(client.send_to(b"fffff".as_ref(), server_addr).await.is_ok());

        let ret = stream.read(&mut buf).await;
        assert!(matches!(ret, Ok(5)));
        assert_eq!(&buf[..6], b"ccccc\0");

        let ret = stream2.read(&mut buf).await;
        assert!(matches!(ret, Ok(5)));
        assert_eq!(&buf[..6], b"ddddd\0");

        let ret = stream2.read(&mut buf).await;
        assert!(matches!(ret, Ok(5)));
        assert_eq!(&buf[..6], b"eeeee\0");

        let ret = stream.read(&mut buf).await;
        assert!(matches!(ret, Ok(5)));
        assert_eq!(&buf[..6], b"fffff\0");
    }

    #[tokio::test]
    async fn test_udp_should_timeout() {
        let server_addr: SocketAddr = "[::1]:1237".parse().unwrap();
        let socket_timeout = Duration::from_secs(1);
        let server = run_server(server_addr, Some(socket_timeout), |_| Ok(()), |l| Ok(l.clone()))
            .await
            .unwrap();
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
