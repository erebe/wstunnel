use crate::socks5_udp::Socks5UdpStream;
use crate::{socks5_udp, LocalProtocol};
use anyhow::Context;
use fast_socks5::server::{Config, DenyAuthentication, Socks5Server};
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{consts, ReplyError};
use futures_util::{stream, Stream, StreamExt};
use std::io::{Error, IoSlice};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::select;
use tracing::{info, warn};
use url::Host;

#[allow(clippy::type_complexity)]
pub struct Socks5Listener {
    socks_server: Pin<Box<dyn Stream<Item = anyhow::Result<(Socks5Stream, (Host, u16))>> + Send>>,
}

pub enum Socks5Stream {
    Tcp(TcpStream),
    Udp(Socks5UdpStream),
}

impl Socks5Stream {
    pub fn local_protocol(&self) -> LocalProtocol {
        match self {
            Socks5Stream::Tcp(_) => LocalProtocol::Tcp { proxy_protocol: false },
            Socks5Stream::Udp(s) => LocalProtocol::Udp {
                timeout: s.watchdog_deadline.as_ref().map(|x| x.period()),
            },
        }
    }
}

impl Stream for Socks5Listener {
    type Item = anyhow::Result<(Socks5Stream, (Host, u16))>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        unsafe { self.map_unchecked_mut(|x| &mut x.socks_server) }.poll_next(cx)
    }
}

pub async fn run_server(bind: SocketAddr, timeout: Option<Duration>) -> Result<Socks5Listener, anyhow::Error> {
    info!("Starting SOCKS5 server listening cnx on {}", bind);

    let server = Socks5Server::<DenyAuthentication>::bind(bind)
        .await
        .with_context(|| format!("Cannot create socks5 server {:?}", bind))?;

    let mut cfg = Config::<DenyAuthentication>::default();
    cfg.set_allow_no_auth(true);
    cfg.set_dns_resolve(false);
    cfg.set_execute_command(false);
    cfg.set_udp_support(true);

    let udp_server = socks5_udp::run_server(bind, timeout).await?;
    let server = server.with_config(cfg);
    let stream = stream::unfold((server, Box::pin(udp_server)), move |(server, mut udp_server)| async move {
        let mut acceptor = server.incoming();
        loop {
            let cnx = select! {
                biased;

                cnx = acceptor.next() => match cnx {
                    None => return None,
                    Some(Err(err)) => {
                        drop(acceptor);
                        return Some((Err(anyhow::Error::new(err)), (server, udp_server)));
                    }
                    Some(Ok(cnx)) => cnx,
                },

                // new incoming udp stream
                udp_conn = udp_server.next() => {
                    drop(acceptor);
                    return match udp_conn {
                        Some(Ok(stream)) => {
                            let dest = stream.destination();
                            Some((Ok((Socks5Stream::Udp(stream), dest)), (server, udp_server)))
                        }
                        Some(Err(err)) => {
                            Some((Err(anyhow::Error::new(err)), (server, udp_server)))
                        }
                        None => {
                            None
                        }
                    };
                }
            };

            let cnx = match cnx.upgrade_to_socks5().await {
                Ok(cnx) => cnx,
                Err(err) => {
                    warn!("Rejecting socks5 cnx: {}", err);
                    continue;
                }
            };

            let Some(target) = cnx.target_addr() else {
                warn!("Rejecting socks5 cnx: no target addr");
                continue;
            };

            let (host, port) = match target {
                TargetAddr::Ip(SocketAddr::V4(ip)) => (Host::Ipv4(*ip.ip()), ip.port()),
                TargetAddr::Ip(SocketAddr::V6(ip)) => (Host::Ipv6(*ip.ip()), ip.port()),
                TargetAddr::Domain(host, port) => (Host::Domain(host.clone()), *port),
            };

            // Special case for UDP Associate where we return the bind addr of the udp server
            if let Some(fast_socks5::Socks5Command::UDPAssociate) = cnx.cmd() {
                let mut cnx = cnx.into_inner();
                let ret = cnx.write_all(&new_reply(&ReplyError::Succeeded, bind)).await;

                if let Err(err) = ret {
                    warn!("Cannot reply to socks5 udp client: {}", err);
                    continue;
                }
                tokio::spawn(async move {
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

            let mut cnx = cnx.into_inner();
            let ret = cnx
                .write_all(&new_reply(
                    &ReplyError::Succeeded,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
                ))
                .await;

            if let Err(err) = ret {
                warn!("Cannot reply to socks5 client: {}", err);
                continue;
            }

            drop(acceptor);
            return Some((Ok((Socks5Stream::Tcp(cnx), (host, port))), (server, udp_server)));
        }
    });

    let listener = Socks5Listener {
        socks_server: Box::pin(stream),
    };

    Ok(listener)
}

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

impl Unpin for Socks5Stream {}
impl AsyncRead for Socks5Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Socks5Stream::Tcp(s) => unsafe { Pin::new_unchecked(s) }.poll_read(cx, buf),
            Socks5Stream::Udp(s) => unsafe { Pin::new_unchecked(s) }.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Socks5Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Socks5Stream::Tcp(s) => unsafe { Pin::new_unchecked(s) }.poll_write(cx, buf),
            Socks5Stream::Udp(s) => unsafe { Pin::new_unchecked(s) }.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Socks5Stream::Tcp(s) => unsafe { Pin::new_unchecked(s) }.poll_flush(cx),
            Socks5Stream::Udp(s) => unsafe { Pin::new_unchecked(s) }.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Socks5Stream::Tcp(s) => unsafe { Pin::new_unchecked(s) }.poll_shutdown(cx),
            Socks5Stream::Udp(s) => unsafe { Pin::new_unchecked(s) }.poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Socks5Stream::Tcp(s) => unsafe { Pin::new_unchecked(s) }.poll_write_vectored(cx, bufs),
            Socks5Stream::Udp(s) => unsafe { Pin::new_unchecked(s) }.poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Socks5Stream::Tcp(s) => s.is_write_vectored(),
            Socks5Stream::Udp(s) => s.is_write_vectored(),
        }
    }
}

//#[cfg(test)]
//mod test {
//    use super::*;
//    use futures_util::StreamExt;
//    use std::str::FromStr;
//
//    #[tokio::test]
//    async fn socks5_server() {
//        let mut x = run_server(SocketAddr::from_str("[::]:4343").unwrap())
//            .await
//            .unwrap();
//
//        loop {
//            let cnx = x.next().await.unwrap().unwrap();
//            eprintln!("{:?}", cnx);
//        }
//    }
//}
