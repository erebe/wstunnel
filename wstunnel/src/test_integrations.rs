use crate::embedded_certificate;
use crate::executor::DefaultTokioExecutor;
use crate::protocols;
use crate::protocols::dns::DnsResolver;
use crate::restrictions::types;
use crate::restrictions::types::{AllowConfig, MatchConfig, RestrictionConfig, RestrictionsRules};
use crate::somark::SoMark;
use crate::tunnel::client::{Client, ClientConfig, TlsClientConfig};
use crate::tunnel::downstream_listeners::{Socks5DownstreamListener, TcpDownstreamListener, UdpDownstreamListener};
use crate::tunnel::server::{Server, ServerConfig, TlsServerConfig};
use crate::tunnel::transport::{TransportAddr, TransportScheme};
use crate::tunnel::{LocalProtocol, RemoteAddr};
use bytes::{Bytes, BytesMut};
use futures_util::{Stream, StreamExt};
use http_body_util::Empty;
use hyper::http::HeaderValue;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use regex::Regex;
use rstest::{fixture, rstest};
use scopeguard::defer;
use serial_test::serial;
use std::collections::{BTreeSet, HashMap};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::pin;
use tokio_rustls::TlsAcceptor;
use url::Host;
use uuid::Uuid;

/// Ports already handed out by [`free_port`] in this process. A port becomes free again as soon
/// as the probe socket is dropped, so without this two calls could hand out the same one.
static HANDED_OUT_PORTS: Mutex<BTreeSet<u16>> = Mutex::new(BTreeSet::new());

/// Reserve a loopback port that is free for both TCP and UDP.
///
/// Webtransport serves QUIC/UDP on the same port as the TCP listener, so a port free for only
/// one of the two would make its tests flaky. Both probe sockets are dropped before returning:
/// the port is picked, not held, and the caller binds it right after.
fn free_port() -> u16 {
    loop {
        let tcp = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("Cannot bind a free TCP port");
        let port = tcp.local_addr().expect("Cannot read the bound TCP port").port();
        drop(tcp);

        if HANDED_OUT_PORTS.lock().unwrap().insert(port)
            && std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
        {
            return port;
        }
    }
}

/// A loopback address on a free port, with its host apart, as tunnel listeners take both.
fn free_addr() -> (SocketAddr, Host) {
    (
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, free_port())),
        Host::Ipv4(Ipv4Addr::LOCALHOST),
    )
}

#[fixture]
fn dns_resolver() -> DnsResolver {
    // Whichever provider the crate was built with, as only one of the two is compiled in.
    // Installing twice is expected across fixtures, hence the ignored result.
    #[cfg(feature = "aws-lc-rs")]
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    DnsResolver::new_from_urls(&[], None, SoMark::new(None), true).expect("Cannot create DNS resolver")
}

#[fixture]
fn server_no_tls(dns_resolver: DnsResolver) -> Server {
    let server_config = ServerConfig {
        socket_so_mark: SoMark::new(None),
        bind: free_addr().0,
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        timeout_connect: Duration::from_secs(10),
        websocket_mask_frame: false,
        tls: None,
        dns_resolver,
        restriction_config: None,
        http_proxy: None,
        remote_server_idle_timeout: Duration::from_secs(30),
        enable_webtransport: false,
    };
    Server::new(server_config, DefaultTokioExecutor::default())
}

/// Server serving webtransport over UDP, alongside websocket/http2 over TCP.
#[fixture]
fn server_webtransport(dns_resolver: DnsResolver) -> Server {
    let server_config = ServerConfig {
        socket_so_mark: SoMark::new(None),
        bind: free_addr().0,
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        timeout_connect: Duration::from_secs(10),
        websocket_mask_frame: false,
        tls: Some(TlsServerConfig {
            tls_certificate: parking_lot::Mutex::new(embedded_certificate::TLS_CERTIFICATE.0.clone()),
            tls_key: parking_lot::Mutex::new(embedded_certificate::TLS_CERTIFICATE.1.clone_key()),
            tls_client_ca_certificates: None,
            tls_certificate_path: None,
            tls_key_path: None,
            tls_client_ca_certs_path: None,
        }),
        dns_resolver,
        restriction_config: None,
        http_proxy: None,
        remote_server_idle_timeout: Duration::from_secs(30),
        enable_webtransport: true,
    };
    Server::new(server_config, DefaultTokioExecutor::default())
}

/// Not a fixture, as the port to dial is only known once the server fixture has picked one.
async fn client_webtransport(server_port: u16, dns_resolver: DnsResolver) -> Client {
    // The embedded certificate is self-signed with no SAN, so verification must be off.
    let tls_connector =
        crate::protocols::tls::tls_connector(false, TransportScheme::Wts.alpn_protocols(), true, None, None, None)
            .unwrap();
    let tls = TlsClientConfig {
        tls_sni_disabled: false,
        tls_sni_override: None,
        tls_verify_certificate: false,
        tls_connector: Arc::new(parking_lot::RwLock::new(tls_connector)),
        tls_certificate_path: None,
        tls_key_path: None,
    };

    let client_config = ClientConfig {
        remote_addr: TransportAddr::new(TransportScheme::Wts, Host::Ipv4(Ipv4Addr::LOCALHOST), server_port, Some(tls))
            .unwrap(),
        socket_so_mark: SoMark::new(None),
        http_upgrade_path_prefix: "wstunnel".to_string(),
        http_upgrade_credentials: None,
        http_headers: HashMap::new(),
        http_headers_file: None,
        custom_http_header_host: None,
        timeout_connect: Duration::from_secs(10),
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        websocket_mask_frame: false,
        dns_resolver,
        http_proxy: None,
        webtransport: Some(Arc::new(
            crate::tunnel::transport::webtransport::WebTransportEndpoint::new(
                crate::protocols::tls::quic_client_config(false, None, None).unwrap(),
                SoMark::new(None),
                Some(Duration::from_secs(10)),
            )
            .unwrap(),
        )),
        max_redirects: 5,
        forward_credentials_on_redirect: false,
        tls_verify_certificate: false,
    };

    Client::new(
        client_config,
        1,
        Duration::from_secs(1),
        Duration::from_secs(1),
        DefaultTokioExecutor::default(),
    )
    .await
    .unwrap()
}

/// Not a fixture, as the port to dial is only known once the server fixture has picked one.
async fn client_ws(server_port: u16, dns_resolver: DnsResolver) -> Client {
    client_ws_with_redirects(server_port, 5, dns_resolver).await
}

/// Builds the `ClientConfig` used by the redirect tests.
///
/// `custom_host` stands for a `-H "Host: ..."` on the command line; when `None` the transports
/// derive the host/authority from the address they are dialing.
fn test_client_config(
    scheme: TransportScheme,
    server_port: u16,
    max_redirects: usize,
    custom_host: Option<&str>,
    dns_resolver: DnsResolver,
) -> ClientConfig {
    let tls = matches!(scheme, TransportScheme::Wss | TransportScheme::Https).then(|| {
        let connector =
            crate::protocols::tls::tls_connector(false, scheme.alpn_protocols(), true, None, None, None).unwrap();
        TlsClientConfig {
            tls_sni_disabled: false,
            tls_sni_override: None,
            tls_verify_certificate: false,
            tls_connector: Arc::new(parking_lot::RwLock::new(connector)),
            tls_certificate_path: None,
            tls_key_path: None,
        }
    });

    ClientConfig {
        remote_addr: TransportAddr::new(scheme, Host::Ipv4(Ipv4Addr::LOCALHOST), server_port, tls).unwrap(),
        socket_so_mark: SoMark::new(None),
        http_upgrade_path_prefix: "wstunnel".to_string(),
        http_upgrade_credentials: None,
        http_headers: HashMap::new(),
        http_headers_file: None,
        custom_http_header_host: custom_host.map(|host| HeaderValue::from_str(host).unwrap()),
        timeout_connect: Duration::from_secs(10),
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        websocket_mask_frame: false,
        dns_resolver,
        http_proxy: None,
        webtransport: None,
        max_redirects,
        forward_credentials_on_redirect: false,
        tls_verify_certificate: false,
    }
}

async fn new_test_client(client_config: ClientConfig) -> Client {
    Client::new(
        client_config,
        1,
        Duration::from_secs(1),
        Duration::from_secs(1),
        DefaultTokioExecutor::default(),
    )
    .await
    .unwrap()
}

/// Creates a test `Client` instance configured with WebSocket transport and custom `max_redirects`.
async fn client_ws_with_redirects(server_port: u16, max_redirects: usize, dns_resolver: DnsResolver) -> Client {
    new_test_client(test_client_config(
        TransportScheme::Ws,
        server_port,
        max_redirects,
        None,
        dns_resolver,
    ))
    .await
}

/// Creates a test `Client` instance configured with HTTP/2 transport and custom `max_redirects`.
async fn client_h2_with_redirects(server_port: u16, max_redirects: usize, dns_resolver: DnsResolver) -> Client {
    new_test_client(test_client_config(
        TransportScheme::Http,
        server_port,
        max_redirects,
        None,
        dns_resolver,
    ))
    .await
}

/// Creates a test `Client` instance configured with WebSocket over TLS (`wss://`) and custom `max_redirects`.
async fn client_wss_with_redirects(server_port: u16, max_redirects: usize, dns_resolver: DnsResolver) -> Client {
    new_test_client(test_client_config(
        TransportScheme::Wss,
        server_port,
        max_redirects,
        None,
        dns_resolver,
    ))
    .await
}

fn test_tls_acceptor() -> TlsAcceptor {
    let tls_server_config = TlsServerConfig {
        tls_certificate: parking_lot::Mutex::new(embedded_certificate::TLS_CERTIFICATE.0.clone()),
        tls_key: parking_lot::Mutex::new(embedded_certificate::TLS_CERTIFICATE.1.clone_key()),
        tls_client_ca_certificates: None,
        tls_certificate_path: None,
        tls_key_path: None,
        tls_client_ca_certs_path: None,
    };
    crate::protocols::tls::tls_acceptor(&tls_server_config, Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()])).unwrap()
}

/// Spawns a mock HTTP/1.1 and HTTP/2 redirect server (optionally wrapped in TLS)
/// that responds with the specified status code and Location header.
async fn start_auto_redirect_server(
    status_code: u16,
    target_url: Arc<parking_lot::RwLock<String>>,
    tls_acceptor: Option<TlsAcceptor>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let target_url = target_url.clone();
            let tls_acceptor = tls_acceptor.clone();
            tokio::spawn(async move {
                let status = StatusCode::from_u16(status_code).unwrap();
                let service = service_fn(move |_req: Request<hyper::body::Incoming>| {
                    let target = target_url.read().clone();
                    let resp = Response::builder()
                        .status(status)
                        .header(hyper::header::LOCATION, target)
                        .header(hyper::header::CONTENT_LENGTH, "0")
                        .body(Empty::<Bytes>::new())
                        .unwrap();
                    async move { Ok::<_, std::convert::Infallible>(resp) }
                });

                let mut auto_builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                auto_builder.http1().timer(TokioTimer::new());
                auto_builder.http2().timer(TokioTimer::new());

                if let Some(acceptor) = tls_acceptor {
                    if let Ok(tls_stream) = acceptor.accept(stream).await {
                        let io = TokioIo::new(tls_stream);
                        let _ = auto_builder.serve_connection_with_upgrades(io, service).await;
                    }
                } else {
                    let io = TokioIo::new(stream);
                    let _ = auto_builder.serve_connection_with_upgrades(io, service).await;
                }
            });
        }
    });

    (addr, handle)
}

/// Spawns a mock HTTP redirect server that responds with the specified status code and Location header.
async fn start_redirect_server(
    status_code: u16,
    target_url: Arc<parking_lot::RwLock<String>>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    start_auto_redirect_server(status_code, target_url, None).await
}

#[fixture]
fn no_restrictions() -> RestrictionsRules {
    pub fn default_host() -> Regex {
        Regex::new("^.*$").unwrap()
    }

    pub fn default_cidr() -> Vec<IpNet> {
        vec![IpNet::V4(Ipv4Net::default()), IpNet::V6(Ipv6Net::default())]
    }

    let tunnels = types::AllowConfig::Tunnel(types::AllowTunnelConfig {
        protocol: vec![],
        port: vec![],
        host: default_host(),
        cidr: default_cidr(),
    });
    let reverse_tunnel = AllowConfig::ReverseTunnel(types::AllowReverseTunnelConfig {
        protocol: vec![],
        port: vec![],
        port_mapping: Default::default(),
        cidr: default_cidr(),
        unix_path: default_host(),
    });

    RestrictionsRules {
        restrictions: vec![RestrictionConfig {
            name: "".to_string(),
            r#match: vec![MatchConfig::Any],
            allow: vec![tunnels, reverse_tunnel],
        }],
    }
}

#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_tcp_tunnel(server_no_tls: Server, no_restrictions: RestrictionsRules, dns_resolver: DnsResolver) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_no_tls.config.bind.port();
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client_ws = client_ws(server_port, dns_resolver.clone()).await;

    let server = TcpDownstreamListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), false)
        .await
        .unwrap();
    tokio::spawn(async move {
        client_ws.run_tunnel(server).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(endpoint_listen, false).await.unwrap();
    let mut client = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello").await.unwrap();
    let mut dd = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..5], b"Hello");
    buf.clear();

    dd.write_all(b"world!").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..6], b"world!");
}

#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_udp_tunnel(server_no_tls: Server, no_restrictions: RestrictionsRules, dns_resolver: DnsResolver) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_no_tls.config.bind.port();
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client_ws = client_ws(server_port, dns_resolver.clone()).await;

    let server = UdpDownstreamListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), None)
        .await
        .unwrap();
    tokio::spawn(async move {
        client_ws.run_tunnel(server).await.unwrap();
    });

    let udp_listener = protocols::udp::run_server(endpoint_listen, None, |_| Ok(()), |s| Ok(s.clone()))
        .await
        .unwrap();
    let mut client = protocols::udp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        Duration::from_secs(10),
        SoMark::new(None),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello").await.unwrap();
    pin!(udp_listener);
    let dd = udp_listener.next().await.unwrap().unwrap();
    pin!(dd);
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..5], b"Hello");
    buf.clear();

    dd.writer().write_all(b"world!").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..6], b"world!");
}

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_tcp_tunnel_webtransport(
    server_webtransport: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_webtransport.config.bind.port();
    let server_h = tokio::spawn(server_webtransport.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client = client_webtransport(server_port, dns_resolver.clone()).await;

    let server = TcpDownstreamListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), false)
        .await
        .unwrap();
    tokio::spawn(async move {
        client.run_tunnel(server).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(endpoint_listen, false).await.unwrap();
    let mut client = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello").await.unwrap();
    let mut dd = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..5], b"Hello");
    buf.clear();

    dd.write_all(b"world!").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..6], b"world!");
}

/// Read exactly one datagram from `reader`, while keeping `listener` polled.
///
/// The UDP server stream is what dispatches incoming datagrams to the streams it already handed
/// out (it peeks the sender, then notifies that peer), so a read that is not raced with a poll of
/// the listener would block forever on the second datagram. In production the listener is polled
/// by its own accept loop; a test that holds a single stream has to drive it by hand.
async fn read_one_datagram(
    listener: &mut (impl Stream<Item = std::io::Result<protocols::udp::UdpStream>> + Unpin),
    reader: &mut (impl AsyncReadExt + Unpin),
    buf: &mut BytesMut,
) {
    // Reserved up front: `read_buf` only grows a `BytesMut` by a small increment, and a UDP recv
    // truncates whatever does not fit, which would read as a boundary bug rather than a short buffer.
    buf.reserve(64 * 1024);
    tokio::select! {
        biased;
        res = reader.read_buf(buf) => { res.unwrap(); }
        next = listener.next() => panic!("unexpected second UDP connection: {:?}", next.map(|r| r.map(|_| ()))),
    }
}

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_udp_tunnel_webtransport(
    server_webtransport: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_webtransport.config.bind.port();
    let server_h = tokio::spawn(server_webtransport.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client = client_webtransport(server_port, dns_resolver.clone()).await;

    let server = UdpDownstreamListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), None)
        .await
        .unwrap();
    tokio::spawn(async move {
        client.run_tunnel(server).await.unwrap();
    });

    let udp_listener = protocols::udp::run_server(endpoint_listen, None, |_| Ok(()), |s| Ok(s.clone()))
        .await
        .unwrap();
    let mut client = protocols::udp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        Duration::from_secs(10),
        SoMark::new(None),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello").await.unwrap();
    client.write_all(b"John").await.unwrap();
    client.flush().await.unwrap();
    pin!(udp_listener);
    let dd = udp_listener.next().await.unwrap().unwrap();
    pin!(dd);
    let mut buf = BytesMut::new();
    // Compared on the whole buffer, not a prefix: the two datagrams were sent back to back, so a
    // transport that lost their boundaries would hand over "HelloJohn" in one read, and a prefix
    // comparison would accept it here and only hang on the read that follows.
    read_one_datagram(&mut udp_listener, &mut dd, &mut buf).await;
    assert_eq!(&buf[..], b"Hello");
    buf.clear();
    read_one_datagram(&mut udp_listener, &mut dd, &mut buf).await;
    assert_eq!(&buf[..], b"John");
    buf.clear();

    dd.writer().write_all(b"world!").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..], b"world!");
}

/// Perform a SOCKS5 no-auth greeting + CONNECT to `dst`, and return the reply code byte (0x00 =
/// success, non-zero = failure per RFC 1928). Drains the full reply, including the bound address.
async fn socks5_handshake_connect(
    stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> u8 {
    // Greeting: version 5, one method offered: no-auth (0x00).
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00], "server must select no-auth");

    // CONNECT (0x01) to an IPv4 destination.
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&dst_ip.octets());
    req.extend_from_slice(&dst_port.to_be_bytes());
    stream.write_all(&req).await.unwrap();

    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x05, "reply must be SOCKS5");
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.unwrap();
            len[0] as usize
        }
        other => panic!("unexpected ATYP in reply: {other}"),
    };
    let mut rest = vec![0u8; addr_len + 2];
    stream.read_exact(&mut rest).await.unwrap();
    head[1]
}

#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_socks5_tunnel(server_no_tls: Server, no_restrictions: RestrictionsRules, dns_resolver: DnsResolver) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, _endpoint_host) = free_addr();

    let server_port = server_no_tls.config.bind.port();
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client_ws = client_ws(server_port, dns_resolver.clone()).await;

    let server = Socks5DownstreamListener::new(tunnel_listen, None, None).await.unwrap();
    tokio::spawn(async move {
        client_ws.run_tunnel(server).await.unwrap();
    });

    // Reachable endpoint: the wstunnel server must connect to it before the SOCKS5 reply is sent.
    let mut tcp_listener = protocols::tcp::run_server(endpoint_listen, false).await.unwrap();
    let mut client = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    let rep = socks5_handshake_connect(&mut client, Ipv4Addr::LOCALHOST, endpoint_listen.port()).await;
    assert_eq!(rep, 0x00, "reply must be success once the tunnel is established");

    client.write_all(b"Hello").await.unwrap();
    let mut dd = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..5], b"Hello");
    buf.clear();

    dd.write_all(b"world!").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..6], b"world!");
}

#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_socks5_tunnel_unreachable_target_replies_error(
    server_no_tls: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let (tunnel_listen, tunnel_host) = free_addr();
    // A reserved-but-unbound port: the wstunnel server's connect to it is refused.
    let (dead_endpoint, _) = free_addr();

    let server_port = server_no_tls.config.bind.port();
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client_ws = client_ws(server_port, dns_resolver.clone()).await;

    let server = Socks5DownstreamListener::new(tunnel_listen, None, None).await.unwrap();
    tokio::spawn(async move {
        client_ws.run_tunnel(server).await.unwrap();
    });

    let mut client = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    // The target is unreachable, so the reply must report failure (not a premature success).
    let rep = socks5_handshake_connect(&mut client, Ipv4Addr::LOCALHOST, dead_endpoint.port()).await;
    assert_ne!(rep, 0x00, "reply must report failure when the target is unreachable");
    assert_eq!(rep, 0x01, "expected GeneralFailure reply code");
}

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_tcp_tunnel_websocket_redirect_301(
    server_no_tls: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_no_tls.config.bind.port();
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    // Start redirect server that sends 301 to the wstunnel server
    let redirect_target = Arc::new(parking_lot::RwLock::new(format!(
        "ws://127.0.0.1:{server_port}/wstunnel/events"
    )));
    let (redirect_addr, redirect_h) = start_redirect_server(301, redirect_target).await;
    defer! { redirect_h.abort(); };

    // Point client to the redirect server
    let client_ws = client_ws_with_redirects(redirect_addr.port(), 5, dns_resolver.clone()).await;

    let server = TcpDownstreamListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), false)
        .await
        .unwrap();
    let client_ws_clone = client_ws.clone();
    tokio::spawn(async move {
        client_ws_clone.run_tunnel(server).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(endpoint_listen, false).await.unwrap();

    // First connection: triggers 301 redirection and updates active target
    let mut client = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello 1").await.unwrap();
    let mut dd = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"Hello 1");
    buf.clear();

    dd.write_all(b"world 1").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"world 1");
    buf.clear();

    // Verify active target was updated to the server_port
    assert_eq!(client_ws.active_target().addr.port(), server_port);

    // Stop redirect server to strictly prove connection 2 bypasses it completely and uses cached active target
    redirect_h.abort();

    // Second connection: uses the cached active target directly
    let mut client2 = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client2.write_all(b"Hello 2").await.unwrap();
    let mut dd2 = tcp_listener.next().await.unwrap().unwrap();
    dd2.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"Hello 2");
    buf.clear();

    dd2.write_all(b"world 2").await.unwrap();
    client2.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"world 2");
}

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_upgrade_request_keeps_origin_scoped_headers(dns_resolver: DnsResolver) {
    // No redirect: the configured server is the origin the credentials belong to, so everything is
    // sent.
    let (mock_addr, mock_h, request_rx) = start_recording_server().await;
    defer! { mock_h.abort(); };

    let client = new_test_client(client_config_with_scoped_headers(
        TransportScheme::Ws,
        mock_addr.port(),
        dns_resolver,
    ))
    .await;
    let _ = crate::tunnel::transport::websocket::connect(Uuid::new_v4(), &client, &dummy_remote_addr()).await;

    let request = request_rx.await.unwrap();
    assert_eq!(request_header(&request, "authorization").as_deref(), Some("Basic dXNlcjpwYXNz"));
    assert_eq!(request_header(&request, "cookie").as_deref(), Some("sid=abc"));
    assert_eq!(request_header(&request, "host").as_deref(), Some("pinned.example.com"));
    assert_eq!(request_header(&request, "x-custom").as_deref(), Some("keep-me"));
}

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_redirect_drops_credentials_on_other_origin(dns_resolver: DnsResolver) {
    // The redirect target is the same host on another port: a different origin, so credentials must
    // not be forwarded, while the pinned Host and non-sensitive headers still apply (curl's rules).
    let (target_addr, target_h, request_rx) = start_recording_server().await;
    defer! { target_h.abort(); };

    let redirect_target = Arc::new(parking_lot::RwLock::new(format!(
        "ws://127.0.0.1:{}/wstunnel/events",
        target_addr.port()
    )));
    let (redirect_addr, redirect_h) = start_redirect_server(301, redirect_target).await;
    defer! { redirect_h.abort(); };

    let client = new_test_client(client_config_with_scoped_headers(
        TransportScheme::Ws,
        redirect_addr.port(),
        dns_resolver,
    ))
    .await;
    let _ = crate::tunnel::transport::websocket::connect(Uuid::new_v4(), &client, &dummy_remote_addr()).await;

    let request = request_rx.await.unwrap();
    assert_eq!(request_header(&request, "authorization"), None, "request was:\n{request}");
    assert_eq!(request_header(&request, "cookie"), None, "request was:\n{request}");
    assert_eq!(request_header(&request, "host").as_deref(), Some("pinned.example.com"));
    assert_eq!(request_header(&request, "x-custom").as_deref(), Some("keep-me"));
}

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_redirect_drops_pinned_host_on_other_host(dns_resolver: DnsResolver) {
    // A redirect to another host must derive the Host header from the new address instead of reusing
    // the pinned one, and must not forward credentials either.
    let other_host = Ipv4Addr::new(127, 0, 0, 2);
    let (target_addr, target_h, request_rx) = start_recording_server_on(other_host).await;
    defer! { target_h.abort(); };

    let redirect_target = Arc::new(parking_lot::RwLock::new(format!(
        "ws://{other_host}:{}/wstunnel/events",
        target_addr.port()
    )));
    let (redirect_addr, redirect_h) = start_redirect_server(301, redirect_target).await;
    defer! { redirect_h.abort(); };

    let client = new_test_client(client_config_with_scoped_headers(
        TransportScheme::Ws,
        redirect_addr.port(),
        dns_resolver,
    ))
    .await;
    let _ = crate::tunnel::transport::websocket::connect(Uuid::new_v4(), &client, &dummy_remote_addr()).await;

    let request = request_rx.await.unwrap();
    assert_eq!(request_header(&request, "authorization"), None, "request was:\n{request}");
    assert_eq!(
        request_header(&request, "host").as_deref(),
        Some(format!("{other_host}:{}", target_addr.port()).as_str()),
        "request was:\n{request}"
    );
    assert_eq!(request_header(&request, "x-custom").as_deref(), Some("keep-me"));
}

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_redirect_forwards_credentials_with_flag(dns_resolver: DnsResolver) {
    // `--forward-credentials-on-redirect` restores curl's `--location-trusted` behaviour.
    let (target_addr, target_h, request_rx) = start_recording_server().await;
    defer! { target_h.abort(); };

    let redirect_target = Arc::new(parking_lot::RwLock::new(format!(
        "ws://127.0.0.1:{}/wstunnel/events",
        target_addr.port()
    )));
    let (redirect_addr, redirect_h) = start_redirect_server(301, redirect_target).await;
    defer! { redirect_h.abort(); };

    let mut cfg = client_config_with_scoped_headers(TransportScheme::Ws, redirect_addr.port(), dns_resolver);
    cfg.forward_credentials_on_redirect = true;
    let client = new_test_client(cfg).await;
    let _ = crate::tunnel::transport::websocket::connect(Uuid::new_v4(), &client, &dummy_remote_addr()).await;

    let request = request_rx.await.unwrap();
    assert_eq!(
        request_header(&request, "authorization").as_deref(),
        Some("Basic dXNlcjpwYXNz"),
        "request was:\n{request}"
    );
    assert_eq!(request_header(&request, "cookie").as_deref(), Some("sid=abc"));
}

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_http2_redirect_scopes_credentials_but_keeps_pinned_authority(dns_resolver: DnsResolver) {
    let (target_addr, target_h, request_rx) = start_h2_recording_server(Ipv4Addr::LOCALHOST).await;
    defer! { target_h.abort(); };

    let redirect_target = Arc::new(parking_lot::RwLock::new(format!(
        "http://127.0.0.1:{}/wstunnel/events",
        target_addr.port()
    )));
    let (redirect_addr, redirect_h) = start_auto_redirect_server(301, redirect_target, None).await;
    defer! { redirect_h.abort(); };

    let client = new_test_client(client_config_with_scoped_headers(
        TransportScheme::Http,
        redirect_addr.port(),
        dns_resolver,
    ))
    .await;
    let _ = crate::tunnel::transport::http2::connect(Uuid::new_v4(), &client, &dummy_remote_addr()).await;

    let (headers, authority) = request_rx.await.unwrap();
    let headers = headers.to_lowercase();
    assert!(!headers.contains("authorization"), "headers were:\n{headers}");
    assert!(
        !headers.contains("sid=abc"),
        "the user cookie must not be forwarded:\n{headers}"
    );
    assert!(headers.contains("x-custom: keep-me"), "headers were:\n{headers}");
    // Same host, other port: the pinned authority still applies.
    assert_eq!(authority, "pinned.example.com");
}

#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_websocket_error_body_is_not_read(dns_resolver: DnsResolver) {
    // Answers 403 with a body it starts and never finishes, then keeps the socket open. A client
    // that read the error body would stall here until the test timeout and would leak the partial
    // body into the error message; the status must be reported without touching the body.
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move {
        let mut open_connections = Vec::new();
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 1048576\r\n\r\nLEAKED-BODY-PREFIX")
                .await;
            let _ = stream.flush().await;
            open_connections.push(stream);
        }
    });
    defer! { h.abort(); };

    let client = client_ws_with_redirects(addr.port(), 5, dns_resolver).await;
    let err = connect_ws_expect_err(&client, &dummy_remote_addr()).await;

    assert!(err.contains("403"), "unexpected error: {err}");
    assert!(
        !err.contains("LEAKED-BODY-PREFIX"),
        "the error body should not be included: {err}"
    );
}

#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_http2_error_body_is_not_read(dns_resolver: DnsResolver) {
    use hyper::body::{Frame, Incoming};
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as AutoBuilder;

    // Answers 403 with one body frame and then never completes the body: a client that read the
    // error body would leak that partial frame into the message and then stall.
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|_req: hyper::Request<Incoming>| async {
                    let body = http_body_util::StreamBody::new(
                        futures_util::stream::once(async {
                            Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from_static(b"LEAKED-BODY-PREFIX")))
                        })
                        .chain(futures_util::stream::pending()),
                    );
                    Ok::<_, std::convert::Infallible>(hyper::Response::builder().status(403).body(body).unwrap())
                });
                let io = TokioIo::new(stream);
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(io, svc)
                    .await;
            });
        }
    });
    defer! { h.abort(); };

    let client = client_h2_with_redirects(addr.port(), 5, dns_resolver).await;
    let err = connect_h2_expect_err(&client, &dummy_remote_addr()).await;

    assert!(err.contains("403"), "unexpected error: {err}");
    assert!(
        !err.contains("LEAKED-BODY-PREFIX"),
        "the error body should not be included: {err}"
    );
}

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_tcp_tunnel_websocket_redirect_to_empty_prefix(
    server_no_tls: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_no_tls.config.bind.port();
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    // The target serves the upgrade on "/events", i.e. with an empty path prefix ("//events" on the
    // wire). A redirect to "/events" must be followed literally instead of being read as "keep the
    // configured prefix".
    let redirect_target = Arc::new(parking_lot::RwLock::new(format!("ws://127.0.0.1:{server_port}/events")));
    let (redirect_addr, redirect_h) = start_redirect_server(301, redirect_target).await;
    defer! { redirect_h.abort(); };

    // The client itself is configured with the default "wstunnel" prefix.
    let client_ws = client_ws_with_redirects(redirect_addr.port(), 5, dns_resolver.clone()).await;

    let server = TcpDownstreamListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), false)
        .await
        .unwrap();
    let client_ws_clone = client_ws.clone();
    tokio::spawn(async move {
        client_ws_clone.run_tunnel(server).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(endpoint_listen, false).await.unwrap();

    let mut client = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello 0pfx").await.unwrap();
    let mut dd = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..10], b"Hello 0pfx");
    buf.clear();

    dd.write_all(b"world 0pfx").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..10], b"world 0pfx");

    // The redirect target was accepted with the empty prefix, and that is what got cached.
    assert_eq!(client_ws.active_target().path_prefix, "");
}

#[rstest]
#[timeout(Duration::from_secs(20))]
#[tokio::test]
#[serial]
async fn test_temporary_redirect_drops_stale_cached_target(
    server_no_tls: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let server_port = server_no_tls.config.bind.port();
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    // The server the stale cached target redirects to.
    let target = Arc::new(parking_lot::RwLock::new(format!(
        "ws://127.0.0.1:{server_port}/wstunnel/events"
    )));
    // `cached` stands in for a target cached earlier through a permanent chain that now answers
    // with a temporary redirect instead.
    let (cached_addr, cached_h) = start_redirect_server(302, target).await;
    defer! { cached_h.abort(); };

    // The canonical server the client was configured with. It is never dialed in this test.
    let canonical_target = Arc::new(parking_lot::RwLock::new(format!(
        "ws://127.0.0.1:{server_port}/wstunnel/events"
    )));
    let (canonical_addr, canonical_h) = start_redirect_server(302, canonical_target).await;
    defer! { canonical_h.abort(); };

    // A real destination, since the wstunnel server dials it as part of accepting the tunnel.
    let (endpoint_listen, endpoint_host) = free_addr();
    let _endpoint_listener = protocols::tcp::run_server(endpoint_listen, false).await.unwrap();
    let dest = RemoteAddr {
        protocol: LocalProtocol::Tcp { proxy_protocol: false },
        host: endpoint_host,
        port: endpoint_listen.port(),
    };

    let client = client_ws_with_redirects(canonical_addr.port(), 5, dns_resolver).await;
    client.set_active_target(
        TransportAddr::new(TransportScheme::Ws, Host::Ipv4(Ipv4Addr::LOCALHOST), cached_addr.port(), None).unwrap(),
        "wstunnel".to_string(),
    );
    assert_eq!(client.active_target().addr.port(), cached_addr.port());

    // Connecting to the cached target succeeds, but only via a temporary redirect. The stale
    // cache entry must be dropped so the next connection re-resolves from the canonical URL.
    let _ = crate::tunnel::transport::websocket::connect(Uuid::new_v4(), &client, &dest)
        .await
        .expect("the redirect target should accept the tunnel");

    assert_eq!(
        client.active_target().addr.port(),
        canonical_addr.port(),
        "a temporary redirect must not leave the stale cached target in place"
    );
}

/// A tunnel request for an arbitrary destination, used by the transport-level tests below.
fn dummy_remote_addr() -> RemoteAddr {
    RemoteAddr {
        protocol: LocalProtocol::Tcp { proxy_protocol: false },
        host: Host::Domain("target.invalid".to_string()),
        port: 22,
    }
}

/// Runs a WebSocket handshake that is expected to fail and returns the rendered error chain.
async fn connect_ws_expect_err<E: crate::TokioExecutorRef>(client: &Client<E>, dest: &RemoteAddr) -> String {
    match crate::tunnel::transport::websocket::connect(Uuid::new_v4(), client, dest).await {
        Ok(_) => panic!("expected the websocket handshake to fail"),
        Err(err) => format!("{err:#}"),
    }
}

/// Runs an HTTP/2 handshake that is expected to fail and returns the rendered error chain.
async fn connect_h2_expect_err<E: crate::TokioExecutorRef>(client: &Client<E>, dest: &RemoteAddr) -> String {
    match crate::tunnel::transport::http2::connect(Uuid::new_v4(), client, dest).await {
        Ok(_) => panic!("expected the http2 handshake to fail"),
        Err(err) => format!("{err:#}"),
    }
}

/// Reads a header out of a recorded HTTP/1.1 request.
fn request_header(request: &str, name: &str) -> Option<String> {
    request.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim().to_string())
    })
}

/// A client config carrying the headers whose redirect scoping we test: credentials, a cookie, a
/// pinned `Host` and a custom header.
fn client_config_with_scoped_headers(scheme: TransportScheme, port: u16, dns_resolver: DnsResolver) -> ClientConfig {
    let mut cfg = test_client_config(scheme, port, 5, None, dns_resolver);
    cfg.http_upgrade_credentials = Some(HeaderValue::from_static("Basic dXNlcjpwYXNz"));
    cfg.custom_http_header_host = Some(HeaderValue::from_static("pinned.example.com"));
    cfg.http_headers
        .insert(hyper::header::COOKIE, HeaderValue::from_static("sid=abc"));
    cfg.http_headers.insert(
        hyper::header::HeaderName::from_static("x-custom"),
        HeaderValue::from_static("keep-me"),
    );
    cfg
}

/// Spawns a mock server that records the first request it receives and never answers it.
async fn start_recording_server() -> (SocketAddr, tokio::task::JoinHandle<()>, tokio::sync::oneshot::Receiver<String>) {
    start_recording_server_on(Ipv4Addr::LOCALHOST).await
}

/// Same as [`start_recording_server`], bound to a specific loopback address.
async fn start_recording_server_on(
    ip: Ipv4Addr,
) -> (SocketAddr, tokio::task::JoinHandle<()>, tokio::sync::oneshot::Receiver<String>) {
    let listener = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();

    let handle = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            if let Ok(n) = stream.read(&mut buf).await {
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
            }
        }
    });

    (addr, handle, rx)
}

/// Spawns an HTTP/2 mock that records the headers and authority of the first request it receives and
/// answers 400, so the caller sees a clean failure after inspecting what was sent.
async fn start_h2_recording_server(
    ip: Ipv4Addr,
) -> (
    SocketAddr,
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Receiver<(String, String)>,
) {
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as AutoBuilder;

    let listener = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = Arc::new(Mutex::new(Some(tx)));

    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: hyper::Request<Incoming>| {
                    let tx = tx.clone();
                    async move {
                        let headers = req
                            .headers()
                            .iter()
                            .map(|(name, value)| format!("{name}: {}", value.to_str().unwrap_or_default()))
                            .collect::<Vec<_>>()
                            .join("\n");
                        let authority = req.uri().authority().map(|a| a.to_string()).unwrap_or_default();
                        if let Some(tx) = tx.lock().unwrap().take() {
                            let _ = tx.send((headers, authority));
                        }
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(400)
                                .body(Empty::<Bytes>::new())
                                .unwrap(),
                        )
                    }
                });
                let io = TokioIo::new(stream);
                let _ = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(io, service)
                    .await;
            });
        }
    });

    (addr, handle, rx)
}

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_websocket_custom_host_header_is_sent(dns_resolver: DnsResolver) {
    let (mock_addr, mock_h, request_rx) = start_recording_server().await;
    defer! { mock_h.abort(); };

    let client = new_test_client(test_client_config(
        TransportScheme::Ws,
        mock_addr.port(),
        5,
        Some("custom.example.com"),
        dns_resolver,
    ))
    .await;

    // The mock never completes the handshake; only the request it received matters.
    let _ = crate::tunnel::transport::websocket::connect(Uuid::new_v4(), &client, &dummy_remote_addr()).await;

    let request = request_rx.await.unwrap().to_lowercase();
    assert!(
        request.contains("host: custom.example.com"),
        "custom Host header was not sent:\n{request}"
    );
    assert!(
        !request.contains(&format!("host: 127.0.0.1:{}", mock_addr.port())),
        "auto-derived Host leaked instead of the custom one:\n{request}"
    );
}

#[rstest]
#[timeout(Duration::from_secs(20))]
#[tokio::test]
#[serial]
async fn test_tcp_tunnel_mixed_redirect_chain_is_not_cached(
    server_no_tls: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_no_tls.config.bind.port();
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    // Second hop answers with a temporary redirect to the wstunnel server.
    let second_target = Arc::new(parking_lot::RwLock::new(format!(
        "ws://127.0.0.1:{server_port}/wstunnel/events"
    )));
    let (second_addr, second_h) = start_redirect_server(302, second_target).await;
    defer! { second_h.abort(); };

    // First hop answers with a permanent redirect, so the chain is permanent -> temporary.
    let first_target = Arc::new(parking_lot::RwLock::new(format!(
        "ws://127.0.0.1:{}/wstunnel/events",
        second_addr.port()
    )));
    let (first_addr, first_h) = start_redirect_server(301, first_target).await;
    defer! { first_h.abort(); };

    let client_ws = client_ws_with_redirects(first_addr.port(), 5, dns_resolver.clone()).await;
    let server = TcpDownstreamListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), false)
        .await
        .unwrap();
    let client_ws_clone = client_ws.clone();
    tokio::spawn(async move {
        client_ws_clone.run_tunnel(server).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(endpoint_listen, false).await.unwrap();

    let mut client = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello mix").await.unwrap();
    let mut dd = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..9], b"Hello mix");
    buf.clear();

    dd.write_all(b"world mix").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..9], b"world mix");

    // A chain containing a temporary hop must not be cached: the canonical URL stays active.
    assert_eq!(client_ws.active_target().addr.port(), first_addr.port());
}

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_websocket_redirect_loop_is_rejected(dns_resolver: DnsResolver) {
    // A redirector that always points back at itself.
    let target = Arc::new(parking_lot::RwLock::new(String::new()));
    let (redirect_addr, redirect_h) = start_redirect_server(302, target.clone()).await;
    defer! { redirect_h.abort(); };
    *target.write() = format!("ws://127.0.0.1:{}/wstunnel/events", redirect_addr.port());

    let client = client_ws_with_redirects(redirect_addr.port(), 5, dns_resolver).await;

    let err = connect_ws_expect_err(&client, &dummy_remote_addr()).await;
    assert!(err.contains("Redirect loop detected"), "unexpected error: {err}");
}

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_websocket_secure_redirect_to_cleartext_is_rejected(dns_resolver: DnsResolver) {
    // A TLS redirector asking the client to downgrade to cleartext.
    let target = Arc::new(parking_lot::RwLock::new("ws://127.0.0.1:9/wstunnel/events".to_string()));
    let tls_acceptor = test_tls_acceptor();
    let (redirect_addr, redirect_h) = start_auto_redirect_server(301, target, Some(tls_acceptor)).await;
    defer! { redirect_h.abort(); };

    let client = client_wss_with_redirects(redirect_addr.port(), 5, dns_resolver).await;

    let err = connect_ws_expect_err(&client, &dummy_remote_addr()).await;
    assert!(err.contains("Refusing to downgrade"), "unexpected error: {err}");
}

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_tcp_tunnel_websocket_redirect_302(
    server_no_tls: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_no_tls.config.bind.port();
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    // Start redirect server that sends 302 to the wstunnel server
    let redirect_target = Arc::new(parking_lot::RwLock::new(format!(
        "ws://127.0.0.1:{server_port}/wstunnel/events"
    )));
    let (redirect_addr, redirect_h) = start_redirect_server(302, redirect_target).await;
    defer! { redirect_h.abort(); };

    let client_ws = client_ws_with_redirects(redirect_addr.port(), 5, dns_resolver.clone()).await;

    let server = TcpDownstreamListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), false)
        .await
        .unwrap();
    let client_ws_clone = client_ws.clone();
    tokio::spawn(async move {
        client_ws_clone.run_tunnel(server).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(endpoint_listen, false).await.unwrap();

    let mut client = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello 302").await.unwrap();
    let mut dd = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..9], b"Hello 302");
    buf.clear();

    dd.write_all(b"world 302").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..9], b"world 302");
    buf.clear();

    // Active target must NOT be updated because 302 is a temporary redirect
    assert_eq!(client_ws.active_target().addr.port(), redirect_addr.port());

    // Connection 2: should contact redirect server again and succeed
    let mut client2 = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client2.write_all(b"Hello 302 again").await.unwrap();
    let mut dd2 = tcp_listener.next().await.unwrap().unwrap();
    dd2.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..15], b"Hello 302 again");
    buf.clear();

    dd2.write_all(b"world 302 again").await.unwrap();
    client2.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..15], b"world 302 again");

    // Active target still remains the canonical redirect server
    assert_eq!(client_ws.active_target().addr.port(), redirect_addr.port());
}

#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_tcp_tunnel_redirect_max_redirects_zero(
    server_no_tls: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_no_tls.config.bind.port();
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    let redirect_target = Arc::new(parking_lot::RwLock::new(format!(
        "ws://127.0.0.1:{server_port}/wstunnel/events"
    )));
    let (redirect_addr, redirect_h) = start_redirect_server(302, redirect_target).await;
    defer! { redirect_h.abort(); };

    // Point client to redirect server, but with max_redirects = 0
    let client_ws = client_ws_with_redirects(redirect_addr.port(), 0, dns_resolver.clone()).await;

    let server = TcpDownstreamListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), false)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = client_ws.run_tunnel(server).await;
    });

    let _tcp_listener = protocols::tcp::run_server(endpoint_listen, false).await.unwrap();

    let mut client = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    // Client connection should be closed by the listener because redirect failed
    let mut buf = [0u8; 128];
    let n = client.read(&mut buf).await.unwrap_or(0);
    assert_eq!(n, 0, "connection should be closed when max_redirects is exceeded");
}

#[rstest]
#[timeout(Duration::from_secs(20))]
#[tokio::test]
#[serial]
async fn test_tcp_tunnel_cached_redirect_fallback(dns_resolver: DnsResolver, no_restrictions: RestrictionsRules) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    // Server 1
    let (s1_listen, _) = free_addr();
    let server1_config = ServerConfig {
        socket_so_mark: SoMark::new(None),
        bind: s1_listen,
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        timeout_connect: Duration::from_secs(10),
        websocket_mask_frame: false,
        tls: None,
        dns_resolver: dns_resolver.clone(),
        restriction_config: None,
        http_proxy: None,
        remote_server_idle_timeout: Duration::from_secs(30),
        enable_webtransport: false,
    };
    let server1 = Server::new(server1_config, DefaultTokioExecutor::default());
    let server1_port = s1_listen.port();
    let server1_h = tokio::spawn(server1.serve(no_restrictions.clone()));

    // Canonical redirect server pointing initially to Server 1
    let redirect_target = Arc::new(parking_lot::RwLock::new(format!(
        "ws://127.0.0.1:{server1_port}/wstunnel/events"
    )));
    let (redirect_addr, redirect_h) = start_redirect_server(301, redirect_target.clone()).await;
    defer! { redirect_h.abort(); };

    let client_ws = client_ws_with_redirects(redirect_addr.port(), 5, dns_resolver.clone()).await;

    let server = TcpDownstreamListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), false)
        .await
        .unwrap();
    let client_ws_clone = client_ws.clone();
    tokio::spawn(async move {
        client_ws_clone.run_tunnel(server).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(endpoint_listen, false).await.unwrap();

    // Connection 1 to Server 1
    let mut client1 = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client1.write_all(b"Hello 1").await.unwrap();
    let mut dd1 = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    dd1.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"Hello 1");
    buf.clear();
    dd1.write_all(b"world 1").await.unwrap();
    client1.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"world 1");
    buf.clear();
    drop(client1);
    drop(dd1);

    // Active target is now Server 1
    assert_eq!(client_ws.active_target().addr.port(), server1_port);

    // Abort Server 1 to simulate server restart / NAT port change
    server1_h.abort();

    // Start Server 2 on a new port
    let (s2_listen, _) = free_addr();
    let server2_config = ServerConfig {
        socket_so_mark: SoMark::new(None),
        bind: s2_listen,
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        timeout_connect: Duration::from_secs(10),
        websocket_mask_frame: false,
        tls: None,
        dns_resolver: dns_resolver.clone(),
        restriction_config: None,
        http_proxy: None,
        remote_server_idle_timeout: Duration::from_secs(30),
        enable_webtransport: false,
    };
    let server2 = Server::new(server2_config, DefaultTokioExecutor::default());
    let server2_port = s2_listen.port();
    let server2_h = tokio::spawn(server2.serve(no_restrictions));
    defer! { server2_h.abort(); };

    // Update canonical redirect target to point to Server 2
    *redirect_target.write() = format!("ws://127.0.0.1:{server2_port}/wstunnel/events");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connection 2: should fail connecting to dead Server 1, fall back to canonical redirect server,
    // get redirected to Server 2, update active target, and succeed!
    let mut client2 = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client2.write_all(b"Hello 2").await.unwrap();
    let mut dd2 = tcp_listener.next().await.unwrap().unwrap();
    dd2.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"Hello 2");

    // Active target is now updated to Server 2!
    assert_eq!(client_ws.active_target().addr.port(), server2_port);
}

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_tcp_tunnel_http2_redirect_301(
    server_no_tls: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_no_tls.config.bind.port();
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    // Start auto redirect server that sends 301 over HTTP/2 to the wstunnel server
    let redirect_target = Arc::new(parking_lot::RwLock::new(format!(
        "http://127.0.0.1:{server_port}/wstunnel/events"
    )));
    let (redirect_addr, redirect_h) = start_auto_redirect_server(301, redirect_target, None).await;
    defer! { redirect_h.abort(); };

    // Point client to the redirect server with HTTP/2 transport
    let client_h2 = client_h2_with_redirects(redirect_addr.port(), 5, dns_resolver.clone()).await;

    let server = TcpDownstreamListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), false)
        .await
        .unwrap();
    let client_h2_clone = client_h2.clone();
    tokio::spawn(async move {
        client_h2_clone.run_tunnel(server).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(endpoint_listen, false).await.unwrap();

    // First connection: triggers HTTP/2 301 redirection and updates active target
    let mut client = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello 1").await.unwrap();
    let mut dd = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"Hello 1");
    buf.clear();

    dd.write_all(b"world 1").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"world 1");
    buf.clear();

    // Verify active target was updated to the server_port
    assert_eq!(client_h2.active_target().addr.port(), server_port);

    // Stop redirect server to strictly prove connection 2 bypasses it completely and uses cached active target
    redirect_h.abort();

    // Second connection: uses the cached active target directly
    let mut client2 = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client2.write_all(b"Hello 2").await.unwrap();
    let mut dd2 = tcp_listener.next().await.unwrap().unwrap();
    dd2.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"Hello 2");
    buf.clear();

    dd2.write_all(b"world 2").await.unwrap();
    client2.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"world 2");
}

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_tcp_tunnel_websocket_redirect_tls(
    server_webtransport: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_webtransport.config.bind.port();
    let server_h = tokio::spawn(server_webtransport.serve(no_restrictions));
    defer! { server_h.abort(); };

    // Start TLS auto redirect server that sends 301 to the wstunnel TLS server
    let redirect_target = Arc::new(parking_lot::RwLock::new(format!(
        "wss://127.0.0.1:{server_port}/wstunnel/events"
    )));
    let tls_acceptor = test_tls_acceptor();
    let (redirect_addr, redirect_h) = start_auto_redirect_server(301, redirect_target, Some(tls_acceptor)).await;
    defer! { redirect_h.abort(); };

    // Point client to the TLS redirect server with wss:// transport
    let client_wss = client_wss_with_redirects(redirect_addr.port(), 5, dns_resolver.clone()).await;

    let server = TcpDownstreamListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), false)
        .await
        .unwrap();
    let client_wss_clone = client_wss.clone();
    tokio::spawn(async move {
        client_wss_clone.run_tunnel(server).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(endpoint_listen, false).await.unwrap();

    // First connection: triggers TLS 301 redirection and updates active target
    let mut client = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello 1").await.unwrap();
    let mut dd = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"Hello 1");
    buf.clear();

    dd.write_all(b"world 1").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"world 1");
    buf.clear();

    // Verify active target was updated to the server_port
    assert_eq!(client_wss.active_target().addr.port(), server_port);

    // Stop redirect server to strictly prove connection 2 bypasses it completely and uses cached active target
    redirect_h.abort();

    // Second connection: uses the cached active target directly
    let mut client2 = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client2.write_all(b"Hello 2").await.unwrap();
    let mut dd2 = tcp_listener.next().await.unwrap().unwrap();
    dd2.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"Hello 2");
    buf.clear();

    dd2.write_all(b"world 2").await.unwrap();
    client2.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"world 2");
}

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_tcp_tunnel_websocket_redirect_cleartext_to_tls(
    server_webtransport: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_webtransport.config.bind.port();
    let server_h = tokio::spawn(server_webtransport.serve(no_restrictions));
    defer! { server_h.abort(); };

    // Cleartext redirect server that sends 301 pointing to wss:// wstunnel server
    let redirect_target = Arc::new(parking_lot::RwLock::new(format!(
        "wss://127.0.0.1:{server_port}/wstunnel/events"
    )));
    let (redirect_addr, redirect_h) = start_redirect_server(301, redirect_target).await;
    defer! { redirect_h.abort(); };

    // Client begins with plain ws://
    let client_ws = client_ws_with_redirects(redirect_addr.port(), 5, dns_resolver.clone()).await;

    let server = TcpDownstreamListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), false)
        .await
        .unwrap();
    let client_ws_clone = client_ws.clone();
    tokio::spawn(async move {
        client_ws_clone.run_tunnel(server).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(endpoint_listen, false).await.unwrap();

    let mut client = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello 1").await.unwrap();
    let mut dd = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"Hello 1");
    buf.clear();

    dd.write_all(b"world 1").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"world 1");
    buf.clear();

    // Verify active target was updated to the server_port and scheme is Wss
    assert_eq!(client_ws.active_target().addr.port(), server_port);
    assert_eq!(*client_ws.active_target().addr.scheme(), TransportScheme::Wss);

    // Stop redirect server to strictly prove connection 2 bypasses it completely
    redirect_h.abort();

    let mut client2 = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client2.write_all(b"Hello 2").await.unwrap();
    let mut dd2 = tcp_listener.next().await.unwrap().unwrap();
    dd2.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"Hello 2");
    buf.clear();

    dd2.write_all(b"world 2").await.unwrap();
    client2.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"world 2");
}
