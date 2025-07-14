use anyhow::{Context, anyhow};
use std::{io, vec};
use tokio::task::JoinSet;

use base64::Engine;
use bytes::BytesMut;
use log::warn;
use socket2::{SockRef, TcpKeepalive};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::protocols::dns::DnsResolver;
use crate::somark::SoMark;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::{sleep, timeout};
use tokio_stream::wrappers::TcpListenerStream;
use tracing::log::info;
use tracing::{debug, instrument};
use url::{Host, Url};

pub fn configure_socket(socket: SockRef, so_mark: SoMark) -> Result<(), anyhow::Error> {
    socket
        .set_tcp_nodelay(true)
        .with_context(|| format!("cannot set no_delay on socket: {:?}", io::Error::last_os_error()))?;

    #[cfg(not(any(target_os = "windows", target_os = "openbsd")))]
    let tcp_keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(10))
        .with_retries(3);

    #[cfg(target_os = "windows")]
    let tcp_keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(10));

    #[cfg(target_os = "openbsd")]
    let tcp_keepalive = TcpKeepalive::new().with_time(Duration::from_secs(60));

    socket
        .set_tcp_keepalive(&tcp_keepalive)
        .with_context(|| format!("cannot set tcp_keepalive on socket: {:?}", io::Error::last_os_error()))?;

    so_mark.set_mark(socket).context("cannot set SO_MARK on socket")?;

    Ok(())
}

pub async fn connect(
    host: &Host<String>,
    port: u16,
    so_mark: SoMark,
    connect_timeout: Duration,
    dns_resolver: &DnsResolver,
) -> Result<TcpStream, anyhow::Error> {
    info!("Opening TCP connection to {host}:{port}");

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
            SocketAddr::V4(_) => TcpSocket::new_v4(),
            SocketAddr::V6(_) => TcpSocket::new_v6(),
        };
        let socket = match socket {
            Ok(s) => s,
            Err(err) => {
                last_err = Some(err);
                continue;
            }
        };
        configure_socket(socket2::SockRef::from(&socket), so_mark)?;

        // Spawn the connection attempt in the join set.
        // We include a delay of ix * 250 milliseconds, as per RFC8305.
        // See https://datatracker.ietf.org/doc/html/rfc8305#section-5
        let fut = async move {
            if ix > 0 {
                sleep(Duration::from_millis(250 * ix as u64)).await;
            }
            debug!("Connecting to {}", addr);
            match timeout(connect_timeout, socket.connect(addr)).await {
                Ok(Ok(s)) => Ok(Ok(s)),
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
            Ok(Ok(stream)) => {
                // We've got a successful connection, so we can abort all other
                // ongoing attempts.
                join_set.abort_all();

                debug!(
                    "Connected to tcp endpoint {}, aborted all other connection attempts",
                    stream.peer_addr()?
                );
                cnx = Some(stream);
            }
            Ok(Err((addr, err))) => {
                debug!("Cannot connect to tcp endpoint {addr} reason {err}");
                last_err = Some(err);
            }
            Err((addr, _)) => {
                warn!(
                    "Cannot connect to tcp endpoint {addr} due to timeout of {}s elapsed",
                    connect_timeout.as_secs()
                );
            }
        }
    }

    cnx.ok_or_else(|| anyhow!("Cannot connect to tcp endpoint {}:{} reason {:?}", host, port, last_err))
}

#[instrument(level = "info", name = "http_proxy", skip_all)]
pub async fn connect_with_http_proxy(
    proxy: &Url,
    host: &Host<String>,
    port: u16,
    so_mark: SoMark,
    connect_timeout: Duration,
    dns_resolver: &DnsResolver,
) -> Result<TcpStream, anyhow::Error> {
    let proxy_host = proxy.host().context("Cannot parse proxy host")?.to_owned();
    let proxy_port = proxy.port_or_known_default().unwrap_or(80);

    info!("Connecting to http proxy {}:{}", proxy_host, proxy_port);
    let mut socket = connect(&proxy_host, proxy_port, so_mark, connect_timeout, dns_resolver).await?;
    debug!("Connected to http proxy {}", socket.peer_addr()?);

    let authorization = if let Some((user, password)) = proxy.password().map(|p| (proxy.username(), p)) {
        let user = urlencoding::decode(user).with_context(|| format!("Cannot urldecode proxy user: {user}"))?;
        let password =
            urlencoding::decode(password).with_context(|| format!("Cannot urldecode proxy password: {password}"))?;
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        format!("Proxy-Authorization: Basic {creds}\r\n")
    } else {
        "".to_string()
    };

    let connect_request = format!("CONNECT {host}:{port} HTTP/1.0\r\nHost: {host}:{port}\r\n{authorization}\r\n");
    debug!("Sending request:\n{}", connect_request);
    socket.write_all(connect_request.as_bytes()).await?;

    let mut buf = BytesMut::with_capacity(1024);
    loop {
        let nb_bytes = tokio::time::timeout(connect_timeout, socket.read_buf(&mut buf)).await;
        match nb_bytes {
            Ok(Ok(0)) => {
                return Err(anyhow!(
                    "Cannot connect to http proxy. Proxy closed the connection without returning any response"
                ));
            }
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                return Err(anyhow!("Cannot connect to http proxy. {err}"));
            }
            Err(_) => {
                return Err(anyhow!("Cannot connect to http proxy. Proxy took too long to connect"));
            }
        };

        static END_HTTP_RESPONSE: &[u8; 4] = b"\r\n\r\n"; // It is reversed from \r\n\r\n as we reverse scan the buffer
        if buf.len() > 50 * 1024
            || buf
                .windows(END_HTTP_RESPONSE.len())
                .any(|window| window == END_HTTP_RESPONSE)
        {
            break;
        }
    }

    static OK_RESPONSE_10: &[u8] = b"HTTP/1.0 200 ";
    static OK_RESPONSE_11: &[u8] = b"HTTP/1.1 200 ";
    if !buf
        .windows(OK_RESPONSE_10.len())
        .any(|window| window == OK_RESPONSE_10 || window == OK_RESPONSE_11)
    {
        return Err(anyhow!(
            "Cannot connect to http proxy. Proxy returned an invalid response: {}",
            String::from_utf8_lossy(&buf)
        ));
    }

    debug!("Got response from proxy:\n{}", String::from_utf8_lossy(&buf));
    info!("Http proxy accepted connection to remote host {}:{}", host, port);
    Ok(socket)
}

#[cfg_attr(not(target_os = "linux"), expect(unused_variables))]
pub async fn run_server(bind: SocketAddr, ip_transparent: bool) -> Result<TcpListenerStream, anyhow::Error> {
    info!("Starting TCP server listening cnx on {bind}");

    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("Cannot create TCP server {bind:?}"))?;

    #[cfg(target_os = "linux")]
    if ip_transparent {
        info!("TCP server listening in TProxy mode");
        socket2::SockRef::from(&listener).set_ip_transparent_v4(ip_transparent)?;
    }

    Ok(TcpListenerStream::new(listener))
}

// there is no docker on OpenBSD
#[cfg(all(test, not(target_os = "openbsd")))]
mod tests {
    use super::*;
    use futures_util::pin_mut;
    use std::borrow::Cow;
    use std::net::IpAddr;
    use testcontainers::core::WaitFor;
    use testcontainers::runners::AsyncRunner;
    use testcontainers::{ContainerAsync, Image, ImageExt};

    #[derive(Debug, Clone, Default)]
    pub struct MitmProxy;

    impl Image for MitmProxy {
        fn name(&self) -> &str {
            "mitmproxy/mitmproxy"
        }

        fn tag(&self) -> &str {
            "10.1.1"
        }

        fn ready_conditions(&self) -> Vec<WaitFor> {
            vec![WaitFor::Duration {
                length: Duration::from_secs(5),
            }]
        }

        fn cmd(&self) -> impl IntoIterator<Item = impl Into<Cow<'_, str>>> {
            ["mitmdump"]
        }
    }

    #[tokio::test]
    async fn test_proxy_connection() {
        let (network_name, host) = if cfg!(not(target_os = "macos")) {
            ("host", "127.0.0.1".parse::<IpAddr>().unwrap())
        } else {
            let host = get_if_addrs::get_if_addrs()
                .unwrap()
                .into_iter()
                .map(|iface| iface.addr.ip())
                .find(|ip| ip.is_ipv4() && !ip.is_loopback())
                .unwrap();
            ("wstunnel_test_proxy_connection", host)
        };

        let mitm_proxy: ContainerAsync<MitmProxy> = MitmProxy.with_network(network_name).start().await.unwrap();

        let proxy_port = match network_name {
            "host" => 8080,
            _ => mitm_proxy.get_host_port_ipv4(8080).await.unwrap(),
        };

        // bind to a dynamic port - avoid conflicts
        let server = TcpListener::bind((host, 0)).await.unwrap();
        let server_port = server.local_addr().unwrap().port();

        let mut client = connect_with_http_proxy(
            &Url::parse(&format!("http://127.0.0.1:{proxy_port}")).unwrap(),
            &Host::Domain(host.to_string()),
            server_port,
            SoMark::new(None),
            Duration::from_secs(1),
            &DnsResolver::System,
        )
        .await
        .unwrap();

        client.write_all(b"GET / HTTP/1.1\r\n\r\n".as_slice()).await.unwrap();
        let client_srv = server.accept().await.unwrap().0;
        pin_mut!(client_srv);

        let mut buf = [0u8; 25];
        let ret = client_srv.read(&mut buf).await;
        assert!(matches!(ret, Ok(18)));
        client_srv.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();

        client_srv.get_mut().shutdown().await.unwrap();
        let _ = client.read(&mut buf).await.unwrap();
        assert!(buf.starts_with(b"HTTP/1.1 200 OK\r\n\r\n"));
    }
}
