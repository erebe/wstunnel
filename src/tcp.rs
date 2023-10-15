use anyhow::{anyhow, Context};
use std::{io, vec};

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::timeout;
use tokio_stream::wrappers::TcpListenerStream;
use tracing::debug;
use tracing::log::info;
use url::Host;

fn configure_socket(socket: &mut TcpSocket, so_mark: &Option<i32>) -> Result<(), anyhow::Error> {
    socket.set_nodelay(true).with_context(|| {
        format!(
            "cannot set no_delay on socket: {}",
            io::Error::last_os_error()
        )
    })?;

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
                return Err(anyhow!(
                    "Cannot set SO_MARK on the connection {:?}",
                    io::Error::last_os_error()
                ));
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

    // TODO: Avoid allocation of vec by extracting the code that does the connection in a separate function
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

pub async fn run_server(bind: SocketAddr) -> Result<TcpListenerStream, anyhow::Error> {
    info!("Starting TCP server listening cnx on {}", bind);

    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("Cannot create TCP server {:?}", bind))?;
    Ok(TcpListenerStream::new(listener))
}
