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
use bytes::BytesMut;
use futures_util::{Stream, StreamExt};
use hyper::http::HeaderValue;
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
use url::Host;

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
        http_header_host: HeaderValue::from_str(&format!("127.0.0.1:{server_port}")).unwrap(),
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
    let client_config = ClientConfig {
        remote_addr: TransportAddr::new(TransportScheme::Ws, Host::Ipv4(Ipv4Addr::LOCALHOST), server_port, None)
            .unwrap(),
        socket_so_mark: SoMark::new(None),
        http_upgrade_path_prefix: "wstunnel".to_string(),
        http_upgrade_credentials: None,
        http_headers: HashMap::new(),
        http_headers_file: None,
        http_header_host: HeaderValue::from_str(&format!("127.0.0.1:{server_port}")).unwrap(),
        custom_http_header_host: None,
        timeout_connect: Duration::from_secs(10),
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        websocket_mask_frame: false,
        dns_resolver,
        http_proxy: None,
        webtransport: None,
        max_redirects: 5,
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

/// Creates a test `Client` instance configured with WebSocket transport and custom `max_redirects`.
async fn client_ws_with_redirects(server_port: u16, max_redirects: usize, dns_resolver: DnsResolver) -> Client {
    let client_config = ClientConfig {
        remote_addr: TransportAddr::new(TransportScheme::Ws, Host::Ipv4(Ipv4Addr::LOCALHOST), server_port, None)
            .unwrap(),
        socket_so_mark: SoMark::new(None),
        http_upgrade_path_prefix: "wstunnel".to_string(),
        http_upgrade_credentials: None,
        http_headers: HashMap::new(),
        http_headers_file: None,
        http_header_host: HeaderValue::from_str(&format!("127.0.0.1:{server_port}")).unwrap(),
        custom_http_header_host: None,
        timeout_connect: Duration::from_secs(10),
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        websocket_mask_frame: false,
        dns_resolver,
        http_proxy: None,
        webtransport: None,
        max_redirects,
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

/// Spawns a mock HTTP redirect server that responds with the specified status code and Location header.
async fn start_redirect_server(
    status_code: u16,
    status_text: &'static str,
    target_url: Arc<parking_lot::RwLock<String>>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let target = target_url.read().clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 {status_code} {status_text}\r\nLocation: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            });
        }
    });

    (addr, handle)
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
    let redirect_target = Arc::new(parking_lot::RwLock::new(format!("ws://127.0.0.1:{server_port}/wstunnel/events")));
    let (redirect_addr, redirect_h) = start_redirect_server(301, "Moved Permanently", redirect_target).await;
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
    let redirect_target = Arc::new(parking_lot::RwLock::new(format!("ws://127.0.0.1:{server_port}/wstunnel/events")));
    let (redirect_addr, redirect_h) = start_redirect_server(302, "Found", redirect_target).await;
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

    let redirect_target = Arc::new(parking_lot::RwLock::new(format!("ws://127.0.0.1:{server_port}/wstunnel/events")));
    let (redirect_addr, redirect_h) = start_redirect_server(302, "Found", redirect_target).await;
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
async fn test_tcp_tunnel_cached_redirect_fallback(
    dns_resolver: DnsResolver,
    no_restrictions: RestrictionsRules,
) {
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
    let redirect_target = Arc::new(parking_lot::RwLock::new(format!("ws://127.0.0.1:{server1_port}/wstunnel/events")));
    let (redirect_addr, redirect_h) = start_redirect_server(301, "Moved Permanently", redirect_target.clone()).await;
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
