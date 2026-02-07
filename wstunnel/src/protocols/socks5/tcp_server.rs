use super::udp_server::{Socks5UdpStream, Socks5UdpStreamWriter};
use crate::tunnel::LocalProtocol;
use anyhow::Context;
use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command, consts};
use futures_util::{Stream, StreamExt, stream};
use std::io::{Error, IoSlice};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::task::JoinSet;
use tracing::{info, warn};
use url::Host;

/// Max time a client has to send its SOCKS5 greeting and command once connected.
/// The accept loop handles connections one at a time, so an idle client must not
/// hold it: a real client sends its handshake immediately.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Withholds the SOCKS5 reply produced by [`Socks5ServerProtocol`].
///
/// A CONNECT reply must not reach the client before the upstream connection has
/// actually been established: a client that is told `Succeeded` cannot tell a
/// working tunnel from one that fails immediately afterwards, and never sees the
/// real status code. The protocol type owns the client socket and only returns
/// it from `reply_success`, so the reply it writes is produced and discarded
/// here. The real reply is sent once the connect result is known, by
/// [`Socks5WriteHalf::send_reply_if_needed`].
///
/// Writes pass straight through until [`WithheldReplyHandle::arm`] is called, so
/// the greeting and authentication exchange behave exactly as before.
struct WithheldReply<T> {
    inner: T,
    armed: Arc<AtomicBool>,
}

#[derive(Clone)]
struct WithheldReplyHandle(Arc<AtomicBool>);

impl WithheldReplyHandle {
    /// Discard everything written from here on.
    fn arm(&self) {
        self.0.store(true, Ordering::Release);
    }
}

impl<T> WithheldReply<T> {
    fn new(inner: T) -> (Self, WithheldReplyHandle) {
        let armed = Arc::new(AtomicBool::new(false));
        (
            Self {
                inner,
                armed: Arc::clone(&armed),
            },
            WithheldReplyHandle(armed),
        )
    }

    fn into_inner(self) -> T {
        self.inner
    }

    fn is_armed(&self) -> bool {
        self.armed.load(Ordering::Acquire)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for WithheldReply<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for WithheldReply<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        if self.is_armed() {
            return Poll::Ready(Ok(buf.len()));
        }
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        if self.is_armed() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        if self.is_armed() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Build a raw SOCKS5 reply packet.
///
/// Upstream dropped this helper when the CONNECT path moved to
/// `Socks5ServerProtocol`, whose reply methods consume the protocol object. The
/// deferred reply is sent after the socket has already been split, so the bytes
/// have to be assembled directly.
fn new_reply(error: &ReplyError, sock_addr: SocketAddr) -> Vec<u8> {
    let (addr_type, mut ip_oct, mut port) = match sock_addr {
        SocketAddr::V4(sock) => (
            consts::SOCKS5_ADDR_TYPE_IPV4,
            sock.ip().octets().to_vec(),
            sock.port().to_be_bytes().to_vec(),
        ),
        SocketAddr::V6(sock) => (
            consts::SOCKS5_ADDR_TYPE_IPV6,
            sock.ip().octets().to_vec(),
            sock.port().to_be_bytes().to_vec(),
        ),
    };

    let mut reply = vec![
        consts::SOCKS5_VERSION,
        error.as_u8(), // transform the error into byte code
        0x00,          // reserved
        addr_type,     // address type (ipv4, v6, domain)
    ];
    reply.append(&mut ip_oct);
    reply.append(&mut port);

    reply
}

#[allow(clippy::type_complexity)]
pub struct Socks5Listener {
    socks_server: Pin<Box<dyn Stream<Item = anyhow::Result<(Socks5Stream, (Host, u16))>> + Send>>,
}

pub enum Socks5ReadHalf {
    Tcp(OwnedReadHalf),
    Udp(Socks5UdpStream),
}

pub enum Socks5WriteHalf {
    Tcp {
        writer: OwnedWriteHalf,
        pending_reply: bool,
    },
    Udp(Socks5UdpStreamWriter),
}

pub enum Socks5Stream {
    Tcp { stream: TcpStream, pending_reply: bool },
    Udp((Socks5UdpStream, Socks5UdpStreamWriter)),
}

impl Socks5Stream {
    pub fn local_protocol(&self) -> LocalProtocol {
        match self {
            Self::Tcp { .. } => LocalProtocol::Tcp { proxy_protocol: false }, // TODO: Implement proxy protocol
            Self::Udp(s) => LocalProtocol::Udp {
                timeout: s.0.watchdog_deadline.as_ref().map(|x| x.period()),
            },
        }
    }

    pub fn into_split(self) -> (Socks5ReadHalf, Socks5WriteHalf) {
        match self {
            Self::Tcp { stream, pending_reply } => {
                let (r, w) = stream.into_split();
                (
                    Socks5ReadHalf::Tcp(r),
                    Socks5WriteHalf::Tcp {
                        writer: w,
                        pending_reply,
                    },
                )
            }
            Self::Udp((r, w)) => (Socks5ReadHalf::Udp(r), Socks5WriteHalf::Udp(w)),
        }
    }
}

impl Stream for Socks5Listener {
    type Item = anyhow::Result<(Socks5Stream, (Host, u16))>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        unsafe { self.map_unchecked_mut(|x| &mut x.socks_server) }.poll_next(cx)
    }
}

pub async fn run_server(
    bind: SocketAddr,
    timeout: Option<Duration>,
    credentials: Option<(String, String)>,
) -> Result<Socks5Listener, anyhow::Error> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("Cannot create socks5 server {bind:?}"))?;

    info!(
        "Starting SOCKS5 server listening cnx on {} with credentials {:?}",
        listener.local_addr().unwrap_or(bind),
        credentials
    );

    let udp_server = super::udp_server::run_server(bind, timeout).await?;
    let stream = stream::unfold(
        (listener, Box::pin(udp_server), JoinSet::new(), credentials),
        move |(listener, mut udp_server, mut tasks, credentials)| async move {
            loop {
                let socket = select! {
                    biased;

                    cnx = listener.accept() => match cnx {
                        Err(err) => {
                            return Some((Err(anyhow::Error::new(err)), (listener, udp_server, tasks, credentials)));
                        }
                        Ok((socket, _addr)) => socket,
                    },

                    // new incoming udp stream
                    udp_conn = udp_server.next() => {
                        return match udp_conn {
                            Some(Ok(stream)) => {
                                let dest = stream.destination();
                                let writer = stream.writer();
                                Some((Ok((Socks5Stream::Udp((stream, writer)), dest)), (listener, udp_server, tasks, credentials)))
                            }
                            Some(Err(err)) => {
                                Some((Err(anyhow::Error::new(err)), (listener, udp_server, tasks, credentials)))
                            }
                            None => {
                                None
                            }
                        };
                    }
                };

                // Authenticate the connection, bounding the handshake read so a
                // silent client cannot hold the accept loop (see HANDSHAKE_TIMEOUT).
                // See WithheldReply: the CONNECT reply must not go out until the
                // upstream connect result is known.
                let (socket, withhold) = WithheldReply::new(socket);
                let proto = if let Some((ref username, ref password)) = credentials {
                    let username = username.clone();
                    let password = password.clone();
                    match tokio::time::timeout(
                        HANDSHAKE_TIMEOUT,
                        Socks5ServerProtocol::accept_password_auth(socket, move |user, pass| {
                            user == username && pass == password
                        }),
                    )
                    .await
                    {
                        Ok(Ok((proto, _))) => proto,
                        Ok(Err(err)) => {
                            warn!("Rejecting socks5 cnx (auth failed): {}", err);
                            continue;
                        }
                        Err(_) => {
                            warn!("Rejecting socks5 cnx: handshake timed out after {:?}", HANDSHAKE_TIMEOUT);
                            continue;
                        }
                    }
                } else {
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, Socks5ServerProtocol::accept_no_auth(socket)).await {
                        Ok(Ok(proto)) => proto,
                        Ok(Err(err)) => {
                            warn!("Rejecting socks5 cnx (auth failed): {}", err);
                            continue;
                        }
                        Err(_) => {
                            warn!("Rejecting socks5 cnx: handshake timed out after {:?}", HANDSHAKE_TIMEOUT);
                            continue;
                        }
                    }
                };

                // Read the SOCKS5 command, bounded by the same handshake timeout.
                let (proto, cmd, target_addr) =
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, proto.read_command()).await {
                        Ok(Ok(result)) => result,
                        Ok(Err(err)) => {
                            warn!("Rejecting socks5 cnx: {}", err);
                            continue;
                        }
                        Err(_) => {
                            warn!("Rejecting socks5 cnx: command read timed out after {:?}", HANDSHAKE_TIMEOUT);
                            continue;
                        }
                    };

                let (host, port) = match &target_addr {
                    TargetAddr::Ip(SocketAddr::V4(ip)) => (Host::Ipv4(*ip.ip()), ip.port()),
                    TargetAddr::Ip(SocketAddr::V6(ip)) => (Host::Ipv6(*ip.ip()), ip.port()),
                    TargetAddr::Domain(host, port) => (Host::Domain(host.clone()), *port),
                };

                // Special case for UDP Associate where we return the bind addr of the udp server
                if matches!(cmd, Socks5Command::UDPAssociate) {
                    let cnx = match proto.reply_success(bind).await {
                        Ok(cnx) => cnx,
                        Err(err) => {
                            warn!("Cannot reply to socks5 udp client: {}", err);
                            continue;
                        }
                    };
                    let mut cnx = cnx.into_inner();
                    tasks.spawn(async move {
                        let mut buf = [0u8; 8];
                        loop {
                            match cnx.read(&mut buf).await {
                                Ok(0) => return,
                                Err(_) => return,
                                _ => {}
                            }
                        }
                    });
                    continue;
                };

                // Withhold the CONNECT reply. The protocol type owns the socket and
                // only hands it back from reply_success, so let it produce the reply
                // and drop it: the real one is sent once the tunnel connect result
                // is known, carrying the true status code.
                withhold.arm();
                let cnx = match proto
                    .reply_success(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
                    .await
                {
                    Ok(cnx) => cnx,
                    Err(err) => {
                        warn!("Cannot reply to socks5 client: {}", err);
                        continue;
                    }
                };

                return Some((
                    Ok((
                        Socks5Stream::Tcp {
                            stream: cnx.into_inner(),
                            pending_reply: true,
                        },
                        (host, port),
                    )),
                    (listener, udp_server, tasks, credentials),
                ));
            }
        },
    );

    let listener = Socks5Listener {
        socks_server: Box::pin(stream),
    };

    Ok(listener)
}

impl Unpin for Socks5Stream {}

impl Socks5WriteHalf {
    pub(crate) async fn send_reply_if_needed(&mut self, error: ReplyError) -> anyhow::Result<()> {
        let should_reply = match self {
            Self::Tcp { pending_reply, .. } => {
                if *pending_reply {
                    *pending_reply = false;
                    true
                } else {
                    false
                }
            }
            Self::Udp(_) => false,
        };

        if should_reply {
            let bind_addr = match error {
                ReplyError::Succeeded => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            };
            self.write_all(&new_reply(&error, bind_addr)).await?;
        }

        Ok(())
    }
}
impl AsyncRead for Socks5ReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Udp(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Socks5WriteHalf {
    fn poll_write(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Self::Tcp { writer, .. } => Pin::new(writer).poll_write(cx, buf),
            Self::Udp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Self::Tcp { writer, .. } => Pin::new(writer).poll_flush(cx),
            Self::Udp(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Self::Tcp { writer, .. } => Pin::new(writer).poll_shutdown(cx),
            Self::Udp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Self::Tcp { writer, .. } => Pin::new(writer).poll_write_vectored(cx, bufs),
            Self::Udp(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Tcp { writer, .. } => writer.is_write_vectored(),
            Self::Udp(s) => s.is_write_vectored(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::time::{Duration, timeout};

    async fn tcp_writer_with_client(pending_reply: bool) -> (tokio::net::TcpStream, Socks5WriteHalf) {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let (_, writer) = server.into_split();

        (client, Socks5WriteHalf::Tcp { writer, pending_reply })
    }

    #[tokio::test]
    async fn deferred_socks5_reply_is_sent_only_when_requested() {
        let (mut client, mut writer) = tcp_writer_with_client(true).await;

        assert!(timeout(Duration::from_millis(30), client.read_u8()).await.is_err());

        writer.send_reply_if_needed(ReplyError::Succeeded).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();

        assert_eq!(reply[0], consts::SOCKS5_VERSION);
        assert_eq!(reply[1], ReplyError::Succeeded.as_u8());
    }

    #[tokio::test]
    async fn deferred_socks5_reply_is_one_shot() {
        let (mut client, mut writer) = tcp_writer_with_client(true).await;

        writer.send_reply_if_needed(ReplyError::GeneralFailure).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], ReplyError::GeneralFailure.as_u8());

        writer.send_reply_if_needed(ReplyError::Succeeded).await.unwrap();
        assert!(timeout(Duration::from_millis(30), client.read_u8()).await.is_err());
    }

    #[tokio::test]
    async fn socks5_reply_is_skipped_when_not_pending() {
        let (mut client, mut writer) = tcp_writer_with_client(false).await;
        writer.send_reply_if_needed(ReplyError::Succeeded).await.unwrap();
        assert!(timeout(Duration::from_millis(30), client.read_u8()).await.is_err());
    }
}
