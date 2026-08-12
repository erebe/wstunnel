use super::io::{MAX_PACKET_LENGTH, TunnelRead, TunnelWrite};
use crate::somark::SoMark;
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::WsClient;
use crate::tunnel::transport::headers_from_file;
use crate::tunnel::transport::jwt::tunnel_to_jwt_token;
use anyhow::{Context, anyhow};
use bytes::BytesMut;
use hyper::Response;
use hyper::header::{AUTHORIZATION, COOKIE, HeaderValue};
use hyper::http::response::Parts;
use log::debug;
use socket2::SockRef;
use std::io;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tracing::warn;
use url::{Host, Url};
use uuid::Uuid;
use web_transport_quinn::proto::ConnectRequest;
use web_transport_quinn::quinn::crypto::rustls::QuicClientConfig;
use web_transport_quinn::{RecvStream, SendStream, Session, quinn};

/// Upper bound on the JWT preamble length (see [`read_jwt_preamble`]).
///
/// Tunnel JWTs run a few hundred bytes. This bound only exists so that a corrupt or hostile
/// length prefix cannot drive a large allocation.
const MAX_JWT_PREAMBLE_LEN: usize = 8 * 1024;

/// Client-side QUIC endpoint used by the WebTransport transport.
///
/// This holds the raw quinn endpoint and config rather than a [`web_transport_quinn::Client`]
/// because that type's `connect()` resolves names with `tokio::net::lookup_host`, which would
/// bypass wstunnel's `--dns-resolver`. Driving `quinn::Endpoint::connect_with` ourselves also
/// lets us pass the SNI name independently of the address we dial, which is what makes
/// `--tls-sni-override` work.
pub struct WebTransportEndpoint {
    endpoint: quinn::Endpoint,
    config: quinn::ClientConfig,
}

impl WebTransportEndpoint {
    pub fn new(
        tls_config: tokio_rustls::rustls::ClientConfig,
        so_mark: SoMark,
        keep_alive_interval: Option<Duration>,
    ) -> anyhow::Result<Self> {
        let quic_tls = QuicClientConfig::try_from(tls_config)
            .with_context(|| "cannot use the TLS configuration for QUIC, TLS 1.3 is required")?;
        let mut config = quinn::ClientConfig::new(Arc::new(quic_tls));
        config.transport_config(Arc::new(mk_transport_config(keep_alive_interval)?));

        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            bind_udp_socket(None, so_mark)?,
            Arc::new(quinn::TokioRuntime),
        )
        .with_context(|| "cannot create the QUIC endpoint for webtransport")?;

        Ok(Self { endpoint, config })
    }
}

/// QUIC transport settings shared by the client endpoint and the server config.
///
/// The websocket ping frequency maps onto QUIC's own keep-alive. The idle timeout is then set to
/// three times that, so a connection is not torn down between two pings.
///
/// When pings are disabled the idle timeout is disabled too. That matters: quinn defaults it to
/// 30s, which would silently drop an idle tunnel that the websocket and http2 transports keep
/// open indefinitely, since TCP has no equivalent timeout. Matching them is the least surprising
/// behaviour for a user who asked for no periodic traffic.
pub(crate) fn mk_transport_config(keep_alive_interval: Option<Duration>) -> anyhow::Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();

    let Some(interval) = keep_alive_interval else {
        transport.keep_alive_interval(None);
        transport.max_idle_timeout(None);
        return Ok(transport);
    };

    let idle_timeout = interval
        .checked_mul(3)
        .with_context(|| format!("ping frequency {interval:?} is too large to derive a QUIC idle timeout"))?;

    transport.keep_alive_interval(Some(interval));
    transport.max_idle_timeout(Some(
        idle_timeout
            .try_into()
            .with_context(|| format!("ping frequency {interval:?} is too large for a QUIC idle timeout"))?,
    ));

    Ok(transport)
}

/// Bind a UDP socket for a QUIC endpoint, applying `SO_MARK`.
///
/// With no `bind` address, this binds a wildcard dual-stack socket, mirroring what
/// `quinn::Endpoint::client` does: an IPv6 socket with `IPV6_V6ONLY` cleared reaches both
/// families, because `connect_with` rewrites IPv4 peers to their IPv4-mapped form. Some
/// environments refuse dual-stack (or IPv6 outright), so fall back to IPv4-only.
pub(crate) fn bind_udp_socket(bind: Option<SocketAddr>, so_mark: SoMark) -> anyhow::Result<std::net::UdpSocket> {
    let addr = bind.unwrap_or_else(|| SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)));

    let socket = match socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    ) {
        Ok(socket) => socket,
        // Only worth retrying when we picked IPv6 ourselves.
        Err(err) if bind.is_none() => {
            debug!("cannot create an IPv6 UDP socket, falling back to IPv4: {err:?}");
            return bind_udp_socket(Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))), so_mark);
        }
        Err(err) => return Err(err).with_context(|| format!("cannot create a UDP socket for {addr}")),
    };

    if addr.is_ipv6()
        && let Err(err) = socket.set_only_v6(false)
    {
        debug!("cannot make the UDP socket dual-stack, IPv4 servers may be unreachable: {err:?}");
    }

    socket
        .bind(&socket2::SockAddr::from(addr))
        .with_context(|| format!("cannot bind the UDP socket to {addr}"))?;
    so_mark
        .set_mark(SockRef::from(&socket))
        .with_context(|| "cannot set SO_MARK on the UDP socket")?;

    Ok(socket.into())
}

pub struct WebTransportTunnelRead {
    inner: RecvStream,
    buf: Box<[u8]>,
    // Keep the session alive: it owns the QUIC connection, which is closed when the last
    // handle is dropped.
    _session: Session,
}

impl WebTransportTunnelRead {
    pub fn new(inner: RecvStream, session: Session) -> Self {
        Self {
            inner,
            buf: vec![0; MAX_PACKET_LENGTH].into_boxed_slice(),
            _session: session,
        }
    }
}

impl TunnelRead for WebTransportTunnelRead {
    async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
        match self.inner.read(&mut self.buf).await {
            Ok(Some(0)) | Ok(None) => Err(io::Error::new(ErrorKind::BrokenPipe, "closed")),
            Ok(Some(read_len)) => match writer.write_all(&self.buf[..read_len]).await {
                Ok(_) => Ok(()),
                Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
            },
            Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
        }
    }
}

pub struct WebTransportTunnelWrite {
    inner: SendStream,
    buf: BytesMut,
    _session: Session,
}

impl WebTransportTunnelWrite {
    pub fn new(inner: SendStream, session: Session) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(MAX_PACKET_LENGTH),
            _session: session,
        }
    }
}

impl TunnelWrite for WebTransportTunnelWrite {
    fn buf_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }

    async fn write(&mut self) -> Result<(), io::Error> {
        let ret = match self.inner.write_all(&self.buf).await {
            Ok(_) => Ok(()),
            Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
        };

        self.buf.clear();
        // `propagate_local_to_remote` requires room for a whole packet before every read.
        if self.buf.capacity() < MAX_PACKET_LENGTH {
            self.buf.reserve(MAX_PACKET_LENGTH);
        }

        ret
    }

    async fn ping(&mut self) -> Result<(), io::Error> {
        // QUIC sends its own keep-alive PINGs, configured via `keep_alive_interval`.
        Ok(())
    }

    async fn close(&mut self) -> Result<(), io::Error> {
        // Errors here only mean the stream is already gone, which is what we wanted.
        let _ = self.inner.finish();
        Ok(())
    }

    fn pending_operations_notify(&mut self) -> Arc<Notify> {
        Arc::new(Notify::new())
    }

    async fn handle_pending_operations(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

/// Write the tunnel JWT as a length-prefixed preamble: `[u16 big-endian length][JWT bytes]`.
///
/// `ConnectResponse` carries only a status and a subprotocol, so unlike the websocket and http2
/// transports the server cannot answer with a `Cookie` header. Dynamic reverse tunnels need the
/// server to tell the client which destination it resolved, so for those the JWT is sent as the
/// first bytes of the stream instead. QUIC streams are ordered and reliable, so it always
/// arrives before any tunnel payload.
///
/// Both peers decide whether a preamble is present from the same value —
/// [`crate::tunnel::LocalProtocol::is_dynamic_reverse_tunnel`] — so they cannot disagree.
pub async fn write_jwt_preamble(stream: &mut SendStream, jwt: &str) -> anyhow::Result<()> {
    let jwt = jwt.as_bytes();
    let len =
        u16::try_from(jwt.len()).with_context(|| format!("tunnel JWT is too long to send: {} bytes", jwt.len()))?;

    stream
        .write_all(&len.to_be_bytes())
        .await
        .with_context(|| "cannot send the tunnel JWT length")?;
    stream
        .write_all(jwt)
        .await
        .with_context(|| "cannot send the tunnel JWT")?;

    Ok(())
}

/// Read the preamble written by [`write_jwt_preamble`].
pub async fn read_jwt_preamble(stream: &mut RecvStream) -> anyhow::Result<String> {
    let mut len = [0u8; 2];
    stream
        .read_exact(&mut len)
        .await
        .with_context(|| "cannot read the tunnel JWT length")?;

    let len = u16::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_JWT_PREAMBLE_LEN {
        return Err(anyhow!(
            "invalid tunnel JWT length {len} in webtransport preamble, expected 1..={MAX_JWT_PREAMBLE_LEN}"
        ));
    }

    let mut jwt = vec![0u8; len];
    stream
        .read_exact(&mut jwt)
        .await
        .with_context(|| "cannot read the tunnel JWT")?;

    String::from_utf8(jwt).with_context(|| "tunnel JWT is not valid utf-8")
}

pub async fn connect(
    request_id: Uuid,
    client: &WsClient<impl crate::TokioExecutorRef>,
    dest_addr: &RemoteAddr,
) -> anyhow::Result<(WebTransportTunnelRead, WebTransportTunnelWrite, Parts)> {
    let client_cfg = &client.config;
    let Some(webtransport) = client.webtransport.as_ref() else {
        return Err(anyhow!(
            "no webtransport endpoint configured, the server url scheme must be wts://"
        ));
    };

    let host = client_cfg.remote_addr.host();
    let port = client_cfg.remote_addr.port();

    // Resolve with wstunnel's resolver so --dns-resolver is honoured.
    let addrs: Vec<SocketAddr> = match host {
        Host::Domain(domain) => client_cfg
            .dns_resolver
            .lookup_host(domain.as_str(), port)
            .await
            .with_context(|| format!("cannot resolve domain: {domain}"))?,
        Host::Ipv4(ip) => vec![SocketAddr::from((*ip, port))],
        Host::Ipv6(ip) => vec![SocketAddr::from((*ip, port))],
    };

    // The SNI name is independent of the address we dial, so --tls-sni-override is just a
    // different name here.
    let sni = client_cfg.quic_server_name();

    let authority = match host {
        Host::Ipv6(ip) => format!("[{ip}]:{port}"),
        Host::Ipv4(ip) => format!("{ip}:{port}"),
        Host::Domain(domain) => format!("{domain}:{port}"),
    };
    let url = Url::parse(&format!("https://{authority}/{}/events", client_cfg.http_upgrade_path_prefix)).with_context(
        || {
            format!(
                "cannot build the webtransport url, most likely path_prefix `{}` is not valid",
                client_cfg.http_upgrade_path_prefix
            )
        },
    )?;

    let mut request = ConnectRequest::new(url).with_header(COOKIE, {
        let jwt = tunnel_to_jwt_token(request_id, dest_addr);
        HeaderValue::from_str(&jwt).with_context(|| "cannot use the tunnel jwt as a header value")?
    });

    for (k, v) in &client_cfg.http_headers {
        request.headers.remove(k);
        request.headers.append(k, v.clone());
    }

    if let Some(auth) = &client_cfg.http_upgrade_credentials {
        request.headers.remove(AUTHORIZATION);
        request.headers.append(AUTHORIZATION, auth.clone());
    }

    if let Some(headers_file_path) = &client_cfg.http_headers_file {
        let (host_header, headers_file) = headers_from_file(headers_file_path);
        for (k, v) in headers_file {
            request.headers.remove(&k);
            request.headers.append(k, v);
        }
        // Unlike http1, there is no Host header: the authority lives in the request url.
        if let Some((_, val)) = host_header {
            debug!("ignoring Host header from the headers file, webtransport uses the url authority: {val:?}");
        }
    }

    debug!("with webtransport connect request {request:?}");

    let mut last_err = None;
    let mut session = None;
    for addr in &addrs {
        // Bound the handshake like the TCP transports do, so a server that never answers on UDP
        // fails with a clear error instead of hanging until the QUIC idle timeout. This is the
        // common symptom of a firewall or port mapping that only forwards TCP.
        let handshake = async {
            let cnx = webtransport
                .endpoint
                .connect_with(webtransport.config.clone(), *addr, &sni)
                .with_context(|| format!("cannot start a QUIC connection to {addr}"))?
                .await
                .with_context(|| format!("cannot establish a QUIC connection to {addr}"))?;

            Session::connect(cnx, request.clone())
                .await
                .with_context(|| format!("webtransport handshake with {addr} failed"))
        };

        match tokio::time::timeout(client_cfg.timeout_connect, handshake).await {
            Ok(Ok(s)) => {
                session = Some(s);
                break;
            }
            Ok(Err(err)) => {
                warn!("{err:?}");
                last_err = Some(err);
            }
            Err(_) => {
                let timeout = client_cfg.timeout_connect;
                warn!("timed out after {timeout:?} doing the webtransport handshake with {addr}");
                last_err = Some(anyhow!(
                    "timed out after {timeout:?} doing the webtransport handshake with {addr}. Is UDP reachable on that port?"
                ));
            }
        }
    }

    let session = match session {
        Some(session) => session,
        None => {
            return Err(last_err
                .unwrap_or_else(|| anyhow!("no address to connect to"))
                .context(format!(
                    "failed to open a webtransport session with the server {:?}",
                    client_cfg.remote_addr
                )));
        }
    };

    let (send, mut recv) = session
        .open_bi()
        .await
        .with_context(|| format!("failed to open a webtransport stream with {:?}", client_cfg.remote_addr))?;

    // For dynamic reverse tunnels the server tells us the destination it resolved, via the
    // preamble. Surfacing it as a Cookie header keeps `run_reverse_tunnel` unchanged.
    let response = if dest_addr.protocol.is_dynamic_reverse_tunnel() {
        let jwt = read_jwt_preamble(&mut recv)
            .await
            .with_context(|| "cannot read the tunnel jwt sent by the server")?;
        let mut response = Response::new(());
        response.headers_mut().insert(
            COOKIE,
            HeaderValue::from_str(&jwt).with_context(|| "server sent an invalid tunnel jwt")?,
        );
        response.into_parts().0
    } else {
        Response::new(()).into_parts().0
    };

    Ok((
        WebTransportTunnelRead::new(recv, session.clone()),
        WebTransportTunnelWrite::new(send, session),
        response,
    ))
}
