use crate::udp::UdpStream;
use anyhow::Context;
use fast_socks5::server::{Config, DenyAuthentication, Socks5Server};
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{consts, ReplyError};
use futures_util::{stream, Stream, StreamExt};
use std::io::{Error, IoSlice};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{info, warn};
use url::Host;

#[allow(clippy::type_complexity)]
pub struct Socks5Listener {
    stream: Pin<Box<dyn Stream<Item = anyhow::Result<(Socks5Protocol, (Host, u16))>> + Send>>,
}

pub enum Socks5Protocol {
    Tcp(TcpStream),
    Udp(UdpStream),
}
impl Stream for Socks5Listener {
    type Item = anyhow::Result<(Socks5Protocol, (Host, u16))>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        unsafe { self.map_unchecked_mut(|x| &mut x.stream) }.poll_next(cx)
    }
}

pub async fn run_server(bind: SocketAddr) -> Result<Socks5Listener, anyhow::Error> {
    info!("Starting SOCKS5 server listening cnx on {}", bind);

    let server = Socks5Server::<DenyAuthentication>::bind(bind)
        .await
        .with_context(|| format!("Cannot create socks5 server {:?}", bind))?;

    let mut cfg = Config::<DenyAuthentication>::default();
    cfg.set_allow_no_auth(true);
    cfg.set_dns_resolve(false);
    cfg.set_execute_command(false);
    cfg.set_udp_support(true);

    let server = server.with_config(cfg);
    let stream = stream::unfold(server, move |server| async {
        let mut acceptor = server.incoming();
        loop {
            let cnx = match acceptor.next().await {
                None => return None,
                Some(Err(err)) => {
                    drop(acceptor);
                    return Some((Err(anyhow::Error::new(err)), server));
                }
                Some(Ok(cnx)) => cnx,
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
            let Some(cmd) = cnx.cmd() else {
                warn!("Rejecting socks5 cnx: no command");
                continue;
            };

            let (host, port) = match target {
                TargetAddr::Ip(SocketAddr::V4(ip)) => (Host::Ipv4(*ip.ip()), ip.port()),
                TargetAddr::Ip(SocketAddr::V6(ip)) => (Host::Ipv6(*ip.ip()), ip.port()),
                TargetAddr::Domain(host, port) => (Host::Domain(host.clone()), *port),
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
            return Some((Ok((Socks5Protocol::Tcp(cnx), (host, port))), server));
        }
    });

    let listener = Socks5Listener {
        stream: Box::pin(stream),
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

impl Unpin for Socks5Protocol {}
impl AsyncRead for Socks5Protocol {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Socks5Protocol::Tcp(s) => unsafe { Pin::new_unchecked(s) }.poll_read(cx, buf),
            Socks5Protocol::Udp(s) => unsafe { Pin::new_unchecked(s) }.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Socks5Protocol {
    fn poll_write(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Socks5Protocol::Tcp(s) => unsafe { Pin::new_unchecked(s) }.poll_write(cx, buf),
            Socks5Protocol::Udp(s) => unsafe { Pin::new_unchecked(s) }.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Socks5Protocol::Tcp(s) => unsafe { Pin::new_unchecked(s) }.poll_flush(cx),
            Socks5Protocol::Udp(s) => unsafe { Pin::new_unchecked(s) }.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Socks5Protocol::Tcp(s) => unsafe { Pin::new_unchecked(s) }.poll_shutdown(cx),
            Socks5Protocol::Udp(s) => unsafe { Pin::new_unchecked(s) }.poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Socks5Protocol::Tcp(s) => unsafe { Pin::new_unchecked(s) }.poll_write_vectored(cx, bufs),
            Socks5Protocol::Udp(s) => unsafe { Pin::new_unchecked(s) }.poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Socks5Protocol::Tcp(s) => s.is_write_vectored(),
            Socks5Protocol::Udp(s) => s.is_write_vectored(),
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
