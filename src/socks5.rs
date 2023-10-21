use anyhow::Context;
use fast_socks5::server::{Config, DenyAuthentication, Socks5Server};
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{consts, ReplyError};
use futures_util::{stream, Stream, StreamExt};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::Poll;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{info, warn};
use url::Host;

#[allow(clippy::type_complexity)]
pub struct Socks5Listener {
    stream: Pin<Box<dyn Stream<Item = anyhow::Result<(TcpStream, (Host, u16))>> + Send>>,
}

impl Stream for Socks5Listener {
    type Item = anyhow::Result<(TcpStream, (Host, u16))>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
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
            return Some((Ok((cnx, (host, port))), server));
        }
    });

    let listener = Socks5Listener {
        stream: Box::pin(stream),
    };

    Ok(listener)
}

pub fn new_reply(error: &ReplyError, sock_addr: SocketAddr) -> Vec<u8> {
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

#[cfg(test)]
mod test {
    use super::*;
    use futures_util::StreamExt;
    use std::str::FromStr;

    #[tokio::test]
    async fn socks5_server() {
        let mut x = run_server(SocketAddr::from_str("[::]:4343").unwrap())
            .await
            .unwrap();

        loop {
            let cnx = x.next().await.unwrap().unwrap();
            eprintln!("{:?}", cnx);
        }
    }
}
