use anyhow::{anyhow, Context};
use std::{io, vec};

use base64::Engine;
use bytes::BytesMut;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::timeout;
use tokio_stream::wrappers::TcpListenerStream;
use tracing::debug;
use tracing::log::info;
use url::{Host, Url};

fn configure_socket(socket: &mut TcpSocket, so_mark: &Option<i32>) -> Result<(), anyhow::Error> {
    socket
        .set_nodelay(true)
        .with_context(|| format!("cannot set no_delay on socket: {}", io::Error::last_os_error()))?;

    #[cfg(target_os = "linux")]
    if let Some(so_mark) = so_mark {
        use std::os::fd::AsRawFd;
        unsafe {
            let optval: libc::c_int = *so_mark;
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            );

            if ret != 0 {
                return Err(anyhow!("Cannot set SO_MARK on the connection {:?}", io::Error::last_os_error()));
            }
        }
    }

    Ok(())
}

pub async fn connect(
    host: &Host<String>,
    port: u16,
    so_mark: &Option<i32>,
    connect_timeout: Duration,
) -> Result<TcpStream, anyhow::Error> {
    info!("Opening TCP connection to {}:{}", host, port);

    let socket_addrs: Vec<SocketAddr> = match host {
        Host::Domain(domain) => tokio::net::lookup_host(format!("{}:{}", domain, port))
            .await
            .with_context(|| format!("cannot resolve domain: {}", domain))?
            .collect(),
        Host::Ipv4(ip) => vec![SocketAddr::V4(SocketAddrV4::new(*ip, port))],
        Host::Ipv6(ip) => vec![SocketAddr::V6(SocketAddrV6::new(*ip, port, 0, 0))],
    };

    let mut cnx = None;
    let mut last_err = None;
    for addr in socket_addrs {
        debug!("connecting to {}", addr);

        let mut socket = match &addr {
            SocketAddr::V4(_) => TcpSocket::new_v4()?,
            SocketAddr::V6(_) => TcpSocket::new_v6()?,
        };

        configure_socket(&mut socket, so_mark)?;
        match timeout(connect_timeout, socket.connect(addr)).await {
            Ok(Ok(stream)) => {
                cnx = Some(stream);
                break;
            }
            Ok(Err(err)) => {
                debug!("Cannot connect to tcp endpoint {addr} reason {err}");
                last_err = Some(err);
            }
            Err(_) => {
                debug!(
                    "Cannot connect to tcp endpoint {addr} due to timeout of {}s elapsed",
                    connect_timeout.as_secs()
                );
            }
        }
    }

    if let Some(cnx) = cnx {
        Ok(cnx)
    } else {
        Err(anyhow!(
            "Cannot connect to tcp endpoint {}:{} reason {:?}",
            host,
            port,
            last_err
        ))
    }
}

pub async fn connect_with_http_proxy(
    proxy: &Url,
    host: &Host<String>,
    port: u16,
    so_mark: &Option<i32>,
    connect_timeout: Duration,
) -> Result<TcpStream, anyhow::Error> {
    let proxy_host = proxy.host().context("Cannot parse proxy host")?.to_owned();
    let proxy_port = proxy.port_or_known_default().unwrap_or(80);

    let mut socket = connect(&proxy_host, proxy_port, so_mark, connect_timeout).await?;
    info!("Connected to http proxy {}:{}", proxy_host, proxy_port);

    let authorization = if let Some((user, password)) = proxy.password().map(|p| (proxy.username(), p)) {
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, password));
        format!("Proxy-Authorization: Basic {}\r\n", creds)
    } else {
        "".to_string()
    };

    let connect_request = format!("CONNECT {host}:{port} HTTP/1.0\r\nHost: {host}:{port}\r\n{authorization}\r\n");
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

    info!("http proxy connected to remote host {}:{}", host, port);
    Ok(socket)
}

pub async fn run_server(bind: SocketAddr) -> Result<TcpListenerStream, anyhow::Error> {
    info!("Starting TCP server listening cnx on {}", bind);

    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("Cannot create TCP server {:?}", bind))?;
    Ok(TcpListenerStream::new(listener))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::pin_mut;
    use std::net::SocketAddr;
    use testcontainers::core::WaitFor;
    use testcontainers::{Image, ImageArgs, RunnableImage};

    #[derive(Debug, Clone, Default)]
    pub struct MitmProxy {}

    impl ImageArgs for MitmProxy {
        fn into_iterator(self) -> Box<dyn Iterator<Item = String>> {
            Box::new(vec!["mitmdump".to_string()].into_iter())
        }
    }

    impl Image for MitmProxy {
        type Args = Self;

        fn name(&self) -> String {
            "mitmproxy/mitmproxy".to_string()
        }

        fn tag(&self) -> String {
            "10.1.1".to_string()
        }

        fn ready_conditions(&self) -> Vec<WaitFor> {
            vec![WaitFor::Duration {
                length: Duration::from_secs(5),
            }]
        }
    }

    #[tokio::test]
    async fn test_proxy_connection() {
        let server_addr: SocketAddr = "[::1]:1236".parse().unwrap();
        let server = TcpListener::bind(server_addr).await.unwrap();

        let docker = testcontainers::clients::Cli::default();
        let mitm_proxy: RunnableImage<MitmProxy> = RunnableImage::from(MitmProxy {}).with_network("host".to_string());
        let _node = docker.run(mitm_proxy);

        let mut client = connect_with_http_proxy(
            &"http://localhost:8080".parse().unwrap(),
            &Host::Domain("[::1]".to_string()),
            1236,
            &None,
            Duration::from_secs(1),
        )
        .await
        .unwrap();

        client.write_all(b"GET / HTTP/1.1\r\n\r\n".as_slice()).await.unwrap();
        let client_srv = server.accept().await.unwrap().0;
        pin_mut!(client_srv);

        let mut buf = [0u8; 25];
        let ret = client_srv.read(&mut buf).await;
        assert!(matches!(ret, Ok(18)));
        client_srv
            .write_all("HTTP/1.1 200 OK\r\n\r\n".as_bytes())
            .await
            .unwrap();

        client_srv.get_mut().shutdown().await.unwrap();
        let _ = client.read(&mut buf).await.unwrap();
        assert!(buf.starts_with(b"HTTP/1.1 200 OK\r\n\r\n"));
    }
}
