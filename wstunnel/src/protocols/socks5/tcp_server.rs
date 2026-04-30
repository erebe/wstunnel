use super::udp_server::{Socks5UdpStream, Socks5UdpStreamWriter};
use crate::tunnel::LocalProtocol;
use anyhow::Context;
use fast_socks5::Socks5Command;
use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::util::target_addr::TargetAddr;
use futures_util::{Stream, StreamExt, stream};
use std::io::{Error, IoSlice};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::task::JoinSet;
use tracing::{info, warn};
use url::Host;

#[allow(clippy::type_complexity)]
pub struct Socks5Listener {
    socks_server: Pin<Box<dyn Stream<Item = anyhow::Result<(Socks5Stream, (Host, u16))>> + Send>>,
}

pub enum Socks5ReadHalf {
    Tcp(OwnedReadHalf),
    Udp(Socks5UdpStream),
}

pub enum Socks5WriteHalf {
    Tcp(OwnedWriteHalf),
    Udp(Socks5UdpStreamWriter),
}

pub enum Socks5Stream {
    Tcp(TcpStream),
    Udp((Socks5UdpStream, Socks5UdpStreamWriter)),
}

impl Socks5Stream {
    pub fn local_protocol(&self) -> LocalProtocol {
        match self {
            Self::Tcp(_) => LocalProtocol::Tcp { proxy_protocol: false }, // TODO: Implement proxy protocol
            Self::Udp(s) => LocalProtocol::Udp {
                timeout: s.0.watchdog_deadline.as_ref().map(|x| x.period()),
            },
        }
    }

    pub fn into_split(self) -> (Socks5ReadHalf, Socks5WriteHalf) {
        match self {
            Self::Tcp(s) => {
                let (r, w) = s.into_split();
                (Socks5ReadHalf::Tcp(r), Socks5WriteHalf::Tcp(w))
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
    info!(
        "Starting SOCKS5 server listening cnx on {} with credentials {:?}",
        bind, credentials
    );

    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("Cannot create socks5 server {bind:?}"))?;

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

                // Authenticate the connection
                let proto = if let Some((ref username, ref password)) = credentials {
                    let username = username.clone();
                    let password = password.clone();
                    match Socks5ServerProtocol::accept_password_auth(socket, move |user, pass| {
                        user == username && pass == password
                    })
                    .await
                    {
                        Ok((proto, _)) => proto,
                        Err(err) => {
                            warn!("Rejecting socks5 cnx (auth failed): {}", err);
                            continue;
                        }
                    }
                } else {
                    match Socks5ServerProtocol::accept_no_auth(socket).await {
                        Ok(proto) => proto,
                        Err(err) => {
                            warn!("Rejecting socks5 cnx (auth failed): {}", err);
                            continue;
                        }
                    }
                };

                // Read the SOCKS5 command
                let (proto, cmd, target_addr) = match proto.read_command().await {
                    Ok(result) => result,
                    Err(err) => {
                        warn!("Rejecting socks5 cnx: {}", err);
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
                    Ok((Socks5Stream::Tcp(cnx), (host, port))),
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
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Udp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Udp(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Udp(s) => Pin::new(s).poll_shutdown(cx),
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
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Tcp(s) => s.is_write_vectored(),
            Self::Udp(s) => s.is_write_vectored(),
        }
    }
}
