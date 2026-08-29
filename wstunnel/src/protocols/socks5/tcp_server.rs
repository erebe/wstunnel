use super::udp_server::{Socks5UdpStream, Socks5UdpStreamWriter};
use crate::tunnel::LocalProtocol;
use crate::tunnel::downstream_listeners::DownstreamWrite;
use anyhow::Context;
use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::server::states::CommandRead;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command};
use futures_util::{Stream, StreamExt, stream};
use std::future::Future;
use std::io::{Error, ErrorKind, IoSlice};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tracing::{info, warn};
use url::Host;

/// Max time a client has to send its SOCKS5 greeting and command once connected.
/// The accept loop handles connections one at a time, so an idle client must not
/// hold it: a real client sends its handshake immediately.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[allow(clippy::type_complexity)]
pub struct Socks5Listener {
    socks_server: Pin<Box<dyn Stream<Item = anyhow::Result<(Socks5Stream, (Host, u16))>> + Send>>,
}

pub enum Socks5ReadHalf {
    Tcp(OwnedReadHalf),
    /// Before the tunnel is confirmed we don't yet own the read half; it arrives over the oneshot
    /// once the write half has replied success and split the socket. A closed/`None` receiver means
    /// the write half replied an error (or was dropped) => treat as EOF.
    TcpPending(Option<oneshot::Receiver<OwnedReadHalf>>),
    Udp(Socks5UdpStream),
}

pub enum Socks5WriteHalf {
    Tcp(OwnedWriteHalf),
    /// Carries the whole client socket (via the `CommandRead` proto) plus the reply address until
    /// the tunnel outcome is known. [`Socks5WriteHalf::on_tunnel_ready`] consumes the proto to send
    /// the SOCKS5 reply, then splits the socket and hands the read half to
    /// [`Socks5ReadHalf::TcpPending`].
    TcpPending {
        proto: Option<Socks5ServerProtocol<TcpStream, CommandRead>>,
        reply_addr: SocketAddr,
        read_half_tx: Option<oneshot::Sender<OwnedReadHalf>>,
    },
    Udp(Socks5UdpStreamWriter),
}

pub enum Socks5Stream {
    /// The SOCKS5 command has been read but not yet replied to: `proto` still owns the whole client
    /// socket. The reply (`reply_addr`) is deferred until the tunnel is known to be up or down.
    Tcp {
        proto: Socks5ServerProtocol<TcpStream, CommandRead>,
        reply_addr: SocketAddr,
    },
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
            Self::Tcp { proto, reply_addr } => {
                let (read_half_tx, rx) = oneshot::channel();
                (
                    Socks5ReadHalf::TcpPending(Some(rx)),
                    Socks5WriteHalf::TcpPending {
                        proto: Some(proto),
                        reply_addr,
                        read_half_tx: Some(read_half_tx),
                    },
                )
            }
            Self::Udp((r, w)) => (Socks5ReadHalf::Udp(r), Socks5WriteHalf::Udp(w)),
        }
    }
}

impl DownstreamWrite for Socks5WriteHalf {
    /// Send the deferred SOCKS5 reply now that the end-to-end tunnel outcome is known, then split the
    /// client socket for data forwarding. Called exactly once per connection.
    async fn on_tunnel_ready(&mut self, result: Result<(), &anyhow::Error>) -> std::io::Result<()> {
        let Self::TcpPending {
            proto,
            reply_addr,
            read_half_tx,
        } = self
        else {
            // UDP, or an already-finalized TCP write half: nothing to acknowledge.
            return Ok(());
        };

        let Some(proto) = proto.take() else {
            panic!("on_tunnel_ready called twice on a TcpPending half");
        };

        match result {
            Ok(()) => {
                let stream = proto.reply_success(*reply_addr).await.map_err(Error::other)?;
                let (read_half, write_half) = stream.into_split();
                // Hand the read half to the paired `Socks5ReadHalf::TcpPending`. If the receiver is
                // gone (read half dropped) there is nothing to read anyway, so ignore the error.
                if let Some(tx) = read_half_tx.take() {
                    let _ = tx.send(read_half);
                }
                *self = Self::Tcp(write_half);
                Ok(())
            }
            Err(_) => {
                // Tell the local SOCKS5 client the connection failed. The upstream error is opaque
                // (any target failure collapses to a rejected tunnel request), so report the generic
                // failure code. Dropping `read_half_tx` signals EOF to the read half.
                let _ = proto.reply_error(&ReplyError::GeneralFailure).await;
                *read_half_tx = None;
                Err(Error::new(ErrorKind::ConnectionRefused, "socks5: upstream tunnel failed"))
            }
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
                    let mut cnx = match proto.reply_success(bind).await {
                        Ok(cnx) => cnx,
                        Err(err) => {
                            warn!("Cannot reply to socks5 udp client: {}", err);
                            continue;
                        }
                    };
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

                // Defer the SOCKS5 reply: it is sent by `Socks5WriteHalf::on_tunnel_ready` only once
                // the tunnel to the remote endpoint (and onward to the target) is confirmed up, or
                // an error reply is sent if it failed.
                let reply_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
                return Some((
                    Ok((Socks5Stream::Tcp { proto, reply_addr }, (host, port))),
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
impl AsyncRead for Socks5ReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            match self.as_mut().get_mut() {
                Self::Tcp(s) => return Pin::new(s).poll_read(cx, buf),
                Self::Udp(s) => return Pin::new(s).poll_read(cx, buf),
                Self::TcpPending(rx_opt) => {
                    let Some(rx) = rx_opt.as_mut() else {
                        // The write half already replied an error (or was dropped): stable EOF.
                        return Poll::Ready(Ok(()));
                    };
                    // A compliant SOCKS5 client sends no payload until it receives our reply, which
                    // is exactly when the read half is delivered over this channel, so parking here
                    // cannot drop client bytes.
                    match Pin::new(rx).poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(read_half)) => {
                            *self.as_mut().get_mut() = Self::Tcp(read_half);
                            // Loop around to read from the now-available half.
                        }
                        Poll::Ready(Err(_)) => {
                            *rx_opt = None;
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
            }
        }
    }
}

impl AsyncWrite for Socks5WriteHalf {
    fn poll_write(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Udp(s) => Pin::new(s).poll_write(cx, buf),
            // Unreachable by design: the client waits for our reply before sending, and forwarding
            // only starts after `on_tunnel_ready` has finalized this half.
            Self::TcpPending { .. } => {
                Poll::Ready(Err(Error::other("socks5: write before tunnel handshake completed")))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Udp(s) => Pin::new(s).poll_flush(cx),
            Self::TcpPending { .. } => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Udp(s) => Pin::new(s).poll_shutdown(cx),
            Self::TcpPending { .. } => Poll::Ready(Ok(())),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Udp(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::TcpPending { .. } => {
                Poll::Ready(Err(Error::other("socks5: write before tunnel handshake completed")))
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Tcp(s) => s.is_write_vectored(),
            Self::Udp(s) => s.is_write_vectored(),
            Self::TcpPending { .. } => false,
        }
    }
}
