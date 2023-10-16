use anyhow::Context;
use fast_socks5::server::{Config, DenyAuthentication, Socks5Server};
use fast_socks5::util::target_addr::TargetAddr;
use futures_util::{stream, Stream, StreamExt};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Poll;
use tokio::net::TcpStream;

use log::warn;
use tracing::{info, warn};
use url::Host;

pub struct Socks5Listener {
    stream: Pin<Box<dyn Stream<Item = anyhow::Result<(TcpStream, Host, u16)>>>>,
}

impl Stream for Socks5Listener {
    type Item = anyhow::Result<(TcpStream, Host, u16)>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        unsafe { self.map_unchecked_mut(|x| &mut x.stream) }.poll_next(cx)
    }
}

pub async fn run_server(bind: SocketAddr) -> Result<Socks5Listener, anyhow::Error> {
    info!("Starting TCP server listening cnx on {}", bind);

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
            drop(acceptor);
            return Some((Ok((cnx.into_inner(), host, port)), server));
        }
    });

    let listener = Socks5Listener {
        stream: Box::pin(stream),
    };

    Ok(listener)
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
