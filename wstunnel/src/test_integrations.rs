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
use crate::tunnel::upstream_connectors::TcpUpstreamConnector;
use crate::tunnel::{LocalProtocol, RemoteAddr};
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::pin;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
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
        timeout_connect: Duration::from_secs(10),
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        websocket_mask_frame: false,
        dns_resolver,
        http_proxy: None,
        webtransport: None,
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
#[case(TransportScheme::Ws)]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_reverse_tunnel_timeout_recovers(
    server_no_tls: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
    #[case] scheme: TransportScheme,
) {
    let server_addr = server_no_tls.config.bind;
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    let proxy = TcpListener::bind(free_addr().0).await.unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let proxy_h = tokio::spawn(async move {
        let attempts = Arc::new(AtomicUsize::new(0));
        let mut connections = JoinSet::new();
        loop {
            let (mut downstream, _) = proxy.accept().await.unwrap();
            let attempts = attempts.clone();
            let events = events_tx.clone();
            connections.spawn(async move {
                let mut buf = [0; 4096];
                let len = downstream.read(&mut buf).await.unwrap();
                if len == 0 {
                    return; // Ignore unused connections from the client's pool.
                }
                let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                let mut upstream = TcpStream::connect(server_addr).await.unwrap();
                upstream.write_all(&buf[..len]).await.unwrap();
                events.send((attempt, "opened")).unwrap();
                if attempt == 2 {
                    // Silently stall the next pending request while keeping TCP open.
                    // Established sessions and later attempts still pass through normally.
                    while let Ok(len) = downstream.read(&mut buf).await {
                        if len == 0 {
                            break;
                        }
                    }
                } else {
                    let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
                }
                drop(upstream);
                drop(downstream);
                let _ = events.send((attempt, "closed"));
            });
        }
    });
    defer! { proxy_h.abort(); };

    let client = client_ws(proxy_port, dns_resolver.clone()).await;
    let mut config = (*client.config).clone();
    drop(client);
    config.remote_addr = TransportAddr::new(scheme, Host::Ipv4(Ipv4Addr::LOCALHOST), proxy_port, None).unwrap();
    // Avoid unused pooled connections so every connection belongs to one attempt.
    let client = Client::new(
        config,
        0,
        Duration::from_secs(1),
        Duration::from_secs(1),
        DefaultTokioExecutor::default(),
    )
    .await
    .unwrap();
    let endpoint = TcpListener::bind(free_addr().0).await.unwrap();
    let (reverse_addr, reverse_host) = free_addr();
    let connector = TcpUpstreamConnector::new(
        Host::Ipv4(Ipv4Addr::LOCALHOST),
        endpoint.local_addr().unwrap().port(),
        SoMark::new(None),
        Duration::from_secs(1),
        dns_resolver,
    );
    let client_h = tokio::spawn(client.run_reverse_tunnel(
        RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: reverse_host,
            port: reverse_addr.port(),
        },
        connector,
    ));
    defer! { client_h.abort(); };

    assert_eq!(events_rx.recv().await, Some((1, "opened")));
    // The proxy observes the request just before the server binds the reverse listener.
    let mut first = loop {
        match TcpStream::connect(reverse_addr).await {
            Ok(stream) => break stream,
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(err) => panic!("Cannot connect to reverse listener: {err}"),
        }
    };
    let (mut first_endpoint, _) = endpoint.accept().await.unwrap();

    assert_eq!(events_rx.recv().await, Some((2, "opened")));
    // Expiry must close the old TCP connection, not just abandon the handshake future.
    assert_eq!(events_rx.recv().await, Some((2, "closed")));
    assert_eq!(events_rx.recv().await, Some((3, "opened")));
    // Also expire a healthy idle request, to exercise cleanup of the server's waiter.
    assert_eq!(events_rx.recv().await, Some((3, "closed")));
    assert_eq!(events_rx.recv().await, Some((4, "opened")));

    first.write_all(b"still alive").await.unwrap();
    let mut buf = [0; 11];
    first_endpoint.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"still alive");
    first_endpoint.write_all(b"still alive").await.unwrap();
    first.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"still alive");

    // An expired waiter must not consume the new application connection.
    let mut second = TcpStream::connect(reverse_addr).await.unwrap();
    let (mut second_endpoint, _) = endpoint.accept().await.unwrap();
    second.write_all(b"new session").await.unwrap();
    second_endpoint.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"new session");
}

#[rstest]
#[timeout(Duration::from_secs(5))]
#[tokio::test]
async fn test_reverse_tunnel_timeout_disabled(dns_resolver: DnsResolver) {
    let server = TcpListener::bind(free_addr().0).await.unwrap();
    let client = client_ws(server.local_addr().unwrap().port(), dns_resolver.clone()).await;
    let (reverse_addr, reverse_host) = free_addr();
    let connector = TcpUpstreamConnector::new(
        Host::Ipv4(Ipv4Addr::LOCALHOST),
        free_port(),
        SoMark::new(None),
        Duration::from_secs(1),
        dns_resolver,
    );
    let client_h = tokio::spawn(client.run_reverse_tunnel(
        RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: reverse_host,
            port: reverse_addr.port(),
        },
        connector,
    ));
    defer! { client_h.abort(); };

    let (mut pending, _) = server.accept().await.unwrap();
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        request.push(pending.read_u8().await.unwrap());
    }
    assert!(request.starts_with(b"GET "));
    // Zero means unlimited waiting, rather than an immediately expired attempt.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), pending.read_u8())
            .await
            .is_err()
    );
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

#[rstest]
#[timeout(Duration::from_secs(20))]
#[tokio::test]
#[serial]
async fn test_udp_datagram_multi_association_oversize_and_empty(
    server_webtransport: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let endpoint = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint_addr = endpoint.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut buf = [0; 65536];
        loop {
            let (len, peer) = endpoint.recv_from(&mut buf).await.unwrap();
            endpoint.send_to(&buf[..len], peer).await.unwrap();
        }
    });
    let echo_abort = echo.abort_handle();
    defer! { echo_abort.abort(); };
    let port = server_webtransport.config.bind.port();
    let server_h = tokio::spawn(server_webtransport.serve(no_restrictions));
    defer! { server_h.abort(); };
    let client = client_webtransport(port, dns_resolver).await;
    let tunnel_addr = free_addr().0;
    let listener = UdpDownstreamListener::new(
        tunnel_addr,
        (Host::Ipv4(Ipv4Addr::LOCALHOST), endpoint_addr.port()),
        Some(Duration::from_secs(1)),
    )
    .await
    .unwrap()
    .with_transport(crate::tunnel::UdpTransport::Datagram);
    let tunnel_h = tokio::spawn(client.clone().run_tunnel(listener));
    defer! { tunnel_h.abort(); };
    let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    a.connect(tunnel_addr).await.unwrap();
    b.connect(tunnel_addr).await.unwrap();
    let mut buf = [0; 65536];
    a.send(b"association-a").await.unwrap();
    b.send(b"association-b").await.unwrap();
    let len = a.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..len], b"association-a");
    let len = b.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..len], b"association-b");
    let hub = client
        .datagram_hubs
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .upgrade()
        .unwrap();
    assert_eq!(hub.counters.created.load(Ordering::Relaxed), 2);
    a.send(&vec![0x55; 60000]).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), a.recv(&mut buf))
            .await
            .is_err()
    );
    a.send(b"after-oversize").await.unwrap();
    let len = a.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..len], b"after-oversize");
    assert_eq!(hub.counters.oversize.load(Ordering::Relaxed), 1);
    a.send(b"").await.unwrap();
    assert_eq!(a.recv(&mut buf).await.unwrap(), 0);
    // Both directions can expire, then the same local source creates a fresh association.
    tokio::time::sleep(Duration::from_millis(1300)).await;
    a.send(b"after-idle").await.unwrap();
    let len = a.recv(&mut buf).await.unwrap();
    assert_eq!(&buf[..len], b"after-idle");
    let created: u64 = client
        .datagram_hubs
        .lock()
        .unwrap()
        .values()
        .filter_map(std::sync::Weak::upgrade)
        .map(|hub| hub.counters.created.load(Ordering::Relaxed))
        .sum();
    assert!(created >= 3);
}

#[rstest]
#[timeout(Duration::from_secs(20))]
#[tokio::test]
#[serial]
async fn test_udp_datagram_remote_activity_close_and_reconnect(
    server_webtransport: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    use crate::tunnel::transport::io::{TransportRead, TransportWrite};
    use crate::tunnel::transport::webtransport::connect_datagram;
    let endpoint = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint_port = endpoint.local_addr().unwrap().port();
    let producer = tokio::spawn(async move {
        let mut buf = [0; 64];
        loop {
            let (_, peer) = endpoint.recv_from(&mut buf).await.unwrap();
            // Only remote->local traffic for longer than the idle timeout.
            for _ in 0..6 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                endpoint.send_to(b"remote-activity", peer).await.unwrap();
            }
        }
    });
    defer! { producer.abort(); };
    let port = server_webtransport.config.bind.port();
    let server_h = tokio::spawn(server_webtransport.serve(no_restrictions));
    defer! { server_h.abort(); };
    let client = client_webtransport(port, dns_resolver).await;
    let target = RemoteAddr {
        protocol: LocalProtocol::Udp {
            timeout: Some(Duration::from_millis(350)),
            transport: crate::tunnel::UdpTransport::Datagram,
        },
        host: Host::Ipv4(Ipv4Addr::LOCALHOST),
        port: endpoint_port,
    };
    let (mut read, mut write, _) = connect_datagram(uuid::Uuid::now_v7(), &client, &target).await.unwrap();
    let initial_session = {
        let pooled = client.cnx_pool.get().await.unwrap();
        pooled.as_ref().unwrap().as_ref().right().unwrap().clone()
    };
    initial_session
        .send_datagram(bytes::Bytes::from_static(b"bad application header"))
        .unwrap();
    std::ops::Deref::deref(&initial_session)
        .send_datagram(bytes::Bytes::from_static(&[0x3f, 1, 2, 3]))
        .unwrap();
    write.buf_mut().extend_from_slice(b"start");
    write.write().await.unwrap();
    for _ in 0..6 {
        let mut buf = Vec::new();
        read.copy(&mut buf).await.unwrap();
        assert_eq!(&buf, b"remote-activity");
    }
    let expired = read.copy(tokio::io::sink()).await.unwrap_err();
    assert!(crate::tunnel::transport::webtransport::datagram::is_datagram_idle_timeout(
        &expired
    ));
    drop(read);
    drop(write);
    let (mut read, mut write, _) = connect_datagram(uuid::Uuid::now_v7(), &client, &target).await.unwrap();
    write.close().await.unwrap();
    assert!(read.copy(tokio::io::sink()).await.is_err());
    drop(read);
    drop(write);
    // Closing the underlying connection models loss of the server's session state.
    let session = {
        let pooled = client.cnx_pool.get().await.unwrap();
        pooled.as_ref().unwrap().as_ref().right().unwrap().clone()
    };
    session.close(0, b"test reconnect");
    let (mut read, mut write, _) = connect_datagram(uuid::Uuid::now_v7(), &client, &target).await.unwrap();
    write.buf_mut().extend_from_slice(b"reconnected");
    write.write().await.unwrap();
    let mut buf = Vec::new();
    read.copy(&mut buf).await.unwrap();
    assert_eq!(&buf, b"remote-activity");
}

#[rstest]
#[timeout(Duration::from_secs(20))]
#[tokio::test]
#[serial]
async fn test_udp_datagram_buffer_reuse_and_error_cleanup(
    server_webtransport: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    use crate::tunnel::transport::io::{TransportRead, TransportWrite};
    use crate::tunnel::transport::webtransport::connect_datagram;
    let endpoint = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint_port = endpoint.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
        let mut buf = [0; 65536];
        loop {
            let (len, peer) = endpoint.recv_from(&mut buf).await.unwrap();
            endpoint.send_to(&buf[..len], peer).await.unwrap();
        }
    });
    defer! { echo.abort(); };
    let port = server_webtransport.config.bind.port();
    let server_h = tokio::spawn(server_webtransport.serve(no_restrictions));
    defer! { server_h.abort(); };
    let client = client_webtransport(port, dns_resolver).await;
    let target = RemoteAddr {
        protocol: LocalProtocol::Udp {
            timeout: None,
            transport: crate::tunnel::UdpTransport::Datagram,
        },
        host: Host::Ipv4(Ipv4Addr::LOCALHOST),
        port: endpoint_port,
    };
    let (mut read, mut write, _) = connect_datagram(uuid::Uuid::now_v7(), &client, &target).await.unwrap();
    let session = {
        let pooled = client.cnx_pool.get().await.unwrap();
        pooled.as_ref().unwrap().as_ref().right().unwrap().clone()
    };
    let address = write.buf_mut().as_ptr() as usize;
    let capacity = write.buf_mut().capacity();
    for iteration in 0..8u8 {
        let maximum = session.max_datagram_size() - 10;
        for size in [0, 64, 960, 1180.min(maximum), maximum] {
            let packet = vec![iteration; size];
            write.buf_mut().extend_from_slice(&packet);
            write.write().await.unwrap();
            assert!(write.buf_mut().is_empty());
            assert_eq!(write.buf_mut().as_ptr() as usize, address);
            assert_eq!(write.buf_mut().capacity(), capacity);
            let mut received = Vec::new();
            read.copy(&mut received).await.unwrap();
            assert_eq!(received, packet);
        }
    }
    write.buf_mut().extend_from_slice(&vec![0x55; 60000]);
    write.write().await.unwrap();
    assert!(write.buf_mut().is_empty());
    assert_eq!(write.buf_mut().as_ptr() as usize, address);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), read.copy(tokio::io::sink()))
            .await
            .is_err()
    );
    write.buf_mut().extend_from_slice(b"after-drop");
    write.write().await.unwrap();
    let mut received = Vec::new();
    read.copy(&mut received).await.unwrap();
    assert_eq!(&received, b"after-drop");
    // Force the QUIC connection closed to exercise the send-error cleanup path.
    std::ops::Deref::deref(&session).close(0u32.into(), b"test send error");
    write.buf_mut().extend_from_slice(b"failed-send");
    assert!(write.write().await.is_err());
    assert!(write.buf_mut().is_empty());
    assert_eq!(write.buf_mut().as_ptr() as usize, address);
}

#[rstest]
#[case::fin("fin")]
#[case::reset("reset")]
#[case::unexpected_byte("byte")]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_udp_datagram_control_error_classification(
    server_webtransport: Server,
    dns_resolver: DnsResolver,
    #[case] action: &'static str,
) {
    use crate::tunnel::transport::io::TransportRead;
    use web_transport_quinn::quinn;
    let tls = crate::protocols::tls::quic_server_config(server_webtransport.config.tls.as_ref().unwrap()).unwrap();
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(
        crate::tunnel::transport::webtransport::mk_transport_config(None).unwrap(),
    ));
    let endpoint = quinn::Endpoint::server(config, server_webtransport.config.bind).unwrap();
    let mut server = web_transport_quinn::Server::new(endpoint);
    let port = server_webtransport.config.bind.port();
    let (trigger, ready) = tokio::sync::oneshot::channel();
    let server_h = tokio::spawn(async move {
        let session = server.accept().await.unwrap().ok().await.unwrap();
        let (mut send, mut recv) = session.accept_bi().await.unwrap();
        crate::tunnel::transport::webtransport::read_jwt_preamble(&mut recv)
            .await
            .unwrap();
        send.write_all(b"WUD1").await.unwrap();
        ready.await.unwrap();
        match action {
            "fin" => {
                send.finish().unwrap();
            }
            "reset" => {
                send.reset(499).unwrap();
            }
            "byte" => {
                send.write_all(&[0x7f]).await.unwrap();
            }
            _ => unreachable!(),
        }
        let _streams = (send, recv);
        session.closed().await;
    });
    defer! { server_h.abort(); };
    let client = client_webtransport(port, dns_resolver).await;
    let target = RemoteAddr {
        protocol: LocalProtocol::Udp {
            timeout: None,
            transport: crate::tunnel::UdpTransport::Datagram,
        },
        host: Host::Ipv4(Ipv4Addr::LOCALHOST),
        port: 1234,
    };
    let (mut read, _write, _) =
        crate::tunnel::transport::webtransport::connect_datagram(uuid::Uuid::now_v7(), &client, &target)
            .await
            .unwrap();
    trigger.send(()).unwrap();
    let err = read.copy(tokio::io::sink()).await.unwrap_err();
    match action {
        "fin" => assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe),
        "byte" => assert_eq!(err.kind(), std::io::ErrorKind::InvalidData),
        "reset" => {
            assert_ne!(err.kind(), std::io::ErrorKind::BrokenPipe);
            // Tokio AsyncRead delegates to raw Quinn, so the source carries the
            // HTTP/3-mapped reset code rather than the WebTransport code 499.
            match err
                .get_ref()
                .and_then(|source| source.downcast_ref::<quinn::ReadError>())
            {
                Some(quinn::ReadError::Reset(code)) => {
                    assert_eq!(web_transport_quinn::proto::error_from_http3(code.into_inner()), Some(499))
                }
                _ => panic!("reset source lost: {err}"),
            }
        }
        _ => unreachable!(),
    }
}

#[rstest]
#[case::unsupported_quic(false, false)]
#[case::wrong_protocol_version(true, true)]
#[case::legacy_server_without_ack(true, false)]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_udp_datagram_unsupported_peer(
    server_webtransport: Server,
    dns_resolver: DnsResolver,
    #[case] supports_datagrams: bool,
    #[case] wrong_ack: bool,
) {
    use web_transport_quinn::quinn;
    let tls = crate::protocols::tls::quic_server_config(server_webtransport.config.tls.as_ref().unwrap()).unwrap();
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = crate::tunnel::transport::webtransport::mk_transport_config(None).unwrap();
    if !supports_datagrams {
        transport.datagram_receive_buffer_size(None);
    }
    config.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(config, server_webtransport.config.bind).unwrap();
    let mut server = web_transport_quinn::Server::new(endpoint);
    let port = server_webtransport.config.bind.port();
    let server_h = tokio::spawn(async move {
        let session = server.accept().await.unwrap().ok().await.unwrap();
        let (mut send, mut recv) = session.accept_bi().await.unwrap();
        crate::tunnel::transport::webtransport::read_jwt_preamble(&mut recv)
            .await
            .unwrap();
        if wrong_ack {
            send.write_all(b"WUD0").await.unwrap();
        }
        let _streams = (send, recv);
        session.closed().await;
    });
    defer! { server_h.abort(); };
    let mut client = client_webtransport(port, dns_resolver).await;
    Arc::make_mut(&mut client.config).timeout_connect = Duration::from_millis(250);
    let target = RemoteAddr {
        protocol: LocalProtocol::Udp {
            timeout: None,
            transport: crate::tunnel::UdpTransport::Datagram,
        },
        host: Host::Ipv4(Ipv4Addr::LOCALHOST),
        port: 1234,
    };
    let result = crate::tunnel::transport::webtransport::connect_datagram(uuid::Uuid::now_v7(), &client, &target).await;
    let err = match result {
        Err(err) => err,
        Ok(_) => panic!("unsupported peer accepted Datagram mode"),
    };
    let error = format!("{err:#}");
    if !supports_datagrams {
        assert!(error.contains("does not support QUIC Datagrams"), "{error}");
    } else if wrong_ack {
        assert!(error.contains("did not acknowledge"), "{error}");
    } else {
        assert!(error.contains("timed out negotiating"), "{error}");
    }
}

#[rstest]
#[timeout(Duration::from_secs(20))]
#[tokio::test]
#[serial]
async fn test_udp_datagram_coexists_with_tcp(
    server_webtransport: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let endpoint = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = endpoint.local_addr().unwrap();
    let udp_endpoint = tokio::net::UdpSocket::bind(target_addr).await.unwrap();
    let echo = tokio::spawn(async move {
        let tcp = async {
            let (mut stream, _) = endpoint.accept().await.unwrap();
            let mut buf = [0; 10];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"tcp-stream");
            stream.write_all(&buf).await.unwrap();
        };
        let udp = async {
            let mut buf = [0; 64];
            let (len, peer) = udp_endpoint.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], b"udp-datagram");
            udp_endpoint.send_to(&buf[..len], peer).await.unwrap();
        };
        tokio::join!(tcp, udp);
    });
    defer! { echo.abort(); };
    let port = server_webtransport.config.bind.port();
    let server_h = tokio::spawn(server_webtransport.serve(no_restrictions));
    defer! { server_h.abort(); };
    let client = client_webtransport(port, dns_resolver).await;
    let bind = free_addr().0;
    let tcp = TcpDownstreamListener::new(bind, (Host::Ipv4(Ipv4Addr::LOCALHOST), target_addr.port()), false)
        .await
        .unwrap();
    let udp = UdpDownstreamListener::new(bind, (Host::Ipv4(Ipv4Addr::LOCALHOST), target_addr.port()), None)
        .await
        .unwrap()
        .with_transport(crate::tunnel::UdpTransport::Datagram);
    let tcp_h = tokio::spawn(client.clone().run_tunnel(tcp));
    let udp_h = tokio::spawn(client.run_tunnel(udp));
    defer! { tcp_h.abort(); udp_h.abort(); };
    let mut tcp = TcpStream::connect(bind).await.unwrap();
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.connect(bind).await.unwrap();
    let (tcp_sent, udp_sent) = tokio::join!(tcp.write_all(b"tcp-stream"), udp.send(b"udp-datagram"));
    tcp_sent.unwrap();
    udp_sent.unwrap();
    let mut tcp_buf = [0; 10];
    tcp.read_exact(&mut tcp_buf).await.unwrap();
    assert_eq!(&tcp_buf, b"tcp-stream");
    let mut udp_buf = [0; 64];
    let len = udp.recv(&mut udp_buf).await.unwrap();
    assert_eq!(&udp_buf[..len], b"udp-datagram");
    // The receive assertions above also verify both echo branches.
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
