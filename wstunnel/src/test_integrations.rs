use crate::executor::DefaultTokioExecutor;
use crate::protocols;
use crate::protocols::dns::DnsResolver;
use crate::restrictions::types;
use crate::restrictions::types::{AllowConfig, MatchConfig, RestrictionConfig, RestrictionsRules};
use crate::somark::SoMark;
use crate::tunnel::client::{TlsClientConfig, WsClient, WsClientConfig};
use crate::tunnel::listeners::{TcpTunnelListener, UdpTunnelListener};
use crate::tunnel::server::{TlsServerConfig, WsServer, WsServerConfig};
use crate::tunnel::transport::{TransportAddr, TransportScheme};
use bytes::BytesMut;
use futures_util::StreamExt;
use hyper::http::HeaderValue;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use parking_lot::{Mutex, RwLock};
use rcgen::generate_simple_self_signed;
use rstest::{fixture, rstest};
use scopeguard::defer;
use serial_test::serial;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::pin;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use url::Host;

#[fixture]
fn dns_resolver() -> DnsResolver {
    protocols::tls::init();
    DnsResolver::new_from_urls(&[], None, SoMark::new(None), true).expect("Cannot create DNS resolver")
}

fn generate_tls_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let subject_alt_names = vec!["127.0.0.1".to_string(), "localhost".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names).unwrap();
    let key_pair = cert.signing_key.serialized_der().to_vec();
    let cert = cert.cert.der().to_vec();

    let cert = CertificateDer::from(cert);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair));
    (vec![cert], key)
}

#[fixture]
fn tls_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    generate_tls_cert()
}

#[fixture]
fn server_quic(
    dns_resolver: DnsResolver,
    #[from(tls_cert)] cert_key: (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
) -> WsServer {
    let (cert, key) = cert_key;
    let server_config = WsServerConfig {
        socket_so_mark: SoMark::new(None),
        bind: "127.0.0.1:8080".parse().unwrap(),
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        timeout_connect: Duration::from_secs(10),
        websocket_mask_frame: false,
        tls: Some(TlsServerConfig {
            tls_certificate: Mutex::new(cert),
            tls_key: Mutex::new(key),
            tls_client_ca_certificates: None,
            tls_certificate_path: None,
            tls_key_path: None,
            tls_client_ca_certs_path: None,
        }),
        dns_resolver,
        restriction_config: None,
        http_proxy: None,
        remote_server_idle_timeout: Duration::from_secs(30),
        quic_listen: Some("127.0.0.1:8081".parse().unwrap()),
        quic_initial_max_data: 1024 * 1024,
        quic_initial_max_stream_data: 1024 * 1024,
        quic_max_concurrent_bi_streams: 100,
        quic_max_idle_timeout: None,
        quic_keep_alive_interval: Duration::from_secs(10),
    };
    WsServer::new(server_config, DefaultTokioExecutor::default())
}

#[fixture]
fn server_no_tls(dns_resolver: DnsResolver) -> WsServer {
    let server_config = WsServerConfig {
        socket_so_mark: SoMark::new(None),
        bind: "127.0.0.1:8080".parse().unwrap(),
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        timeout_connect: Duration::from_secs(10),
        websocket_mask_frame: false,
        tls: None,
        dns_resolver,
        restriction_config: None,
        http_proxy: None,
        remote_server_idle_timeout: Duration::from_secs(30),
        quic_listen: None,
        quic_initial_max_data: 1024 * 1024,
        quic_initial_max_stream_data: 1024 * 1024,
        quic_max_concurrent_bi_streams: 100,
        quic_max_idle_timeout: None,
        quic_keep_alive_interval: Duration::from_secs(10),
    };
    WsServer::new(server_config, DefaultTokioExecutor::default())
}

#[fixture]
async fn client_ws(dns_resolver: DnsResolver) -> WsClient {
    let client_config = WsClientConfig {
        remote_addr: TransportAddr::new(TransportScheme::Ws, Host::Ipv4("127.0.0.1".parse().unwrap()), 8080, None)
            .unwrap(),
        socket_so_mark: SoMark::new(None),
        http_upgrade_path_prefix: "wstunnel".to_string(),
        http_upgrade_credentials: None,
        http_headers: HashMap::new(),
        http_headers_file: None,
        http_header_host: HeaderValue::from_static("127.0.0.1:8080"),
        timeout_connect: Duration::from_secs(10),
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        websocket_mask_frame: false,
        dns_resolver,
        http_proxy: None,
        quic_initial_max_data: 1024 * 1024,
        quic_initial_max_stream_data: 1024 * 1024,
        quic_max_concurrent_bi_streams: 100,
        quic_max_idle_timeout: None,
        quic_keep_alive_interval: Duration::from_secs(10),
    };

    WsClient::new(
        client_config,
        1,
        Duration::from_secs(1),
        Duration::from_secs(1),
        10,
        DefaultTokioExecutor::default(),
    )
    .await
    .unwrap()
}

#[fixture]
async fn client_quic(
    dns_resolver: DnsResolver,
    #[from(tls_cert)] cert_key: (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
) -> WsClient {
    let (cert, _) = cert_key;
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    for c in cert {
        root_store.add(c).unwrap();
    }

    let client_config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let client_config = WsClientConfig {
        remote_addr: TransportAddr::new(
            TransportScheme::Quic,
            Host::Ipv4("127.0.0.1".parse().unwrap()),
            8081, // QUIC server listens on 8081
            Some(TlsClientConfig {
                tls_sni_disabled: false,
                tls_sni_override: None,
                tls_verify_certificate: true,
                tls_connector: Arc::new(RwLock::new(tokio_rustls::TlsConnector::from(Arc::new(client_config)))),
                tls_certificate_path: None,
                tls_key_path: None,
            }),
        )
        .unwrap(),
        socket_so_mark: SoMark::new(None),
        http_upgrade_path_prefix: "wstunnel".to_string(),
        http_upgrade_credentials: None,
        http_headers: HashMap::new(),
        http_headers_file: None,
        http_header_host: HeaderValue::from_static("127.0.0.1:8081"),
        timeout_connect: Duration::from_secs(10),
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        websocket_mask_frame: false,
        dns_resolver,
        http_proxy: None,
        quic_initial_max_data: 1024 * 1024,
        quic_initial_max_stream_data: 1024 * 1024,
        quic_max_concurrent_bi_streams: 100,
        quic_max_idle_timeout: None,
        quic_keep_alive_interval: Duration::from_secs(10),
    };
    WsClient::new(
        client_config,
        0, // Set to 0 to avoid creating connections before server starts
        Duration::from_secs(1),
        Duration::from_secs(1),
        10,
        DefaultTokioExecutor::default(),
    )
    .await
    .unwrap()
}

#[fixture]
fn no_restrictions() -> RestrictionsRules {
    pub fn default_host() -> String {
        ".*".to_string()
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

const TUNNEL_LISTEN: (SocketAddr, Host) = (
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9998)),
    Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
);
const ENDPOINT_LISTEN: (SocketAddr, Host) = (
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9999)),
    Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
);

#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_tcp_tunnel(
    #[future] client_ws: WsClient,
    server_no_tls: WsServer,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client_ws = client_ws.await;

    let server = TcpTunnelListener::new(TUNNEL_LISTEN.0, (ENDPOINT_LISTEN.1, ENDPOINT_LISTEN.0.port()), false)
        .await
        .unwrap();
    tokio::spawn(async move {
        client_ws.run_tunnel(server).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(ENDPOINT_LISTEN.0, false).await.unwrap();
    let mut client = protocols::tcp::connect(
        &TUNNEL_LISTEN.1,
        TUNNEL_LISTEN.0.port(),
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

#[ignore]
#[rstest]
#[timeout(Duration::from_secs(20))]
#[tokio::test]
#[serial]
async fn test_quic_tunnel(
    #[future] client_quic: WsClient,
    server_quic: WsServer,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let server_h = tokio::spawn(server_quic.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client_ws = client_quic.await;

    let server = TcpTunnelListener::new(TUNNEL_LISTEN.0, (ENDPOINT_LISTEN.1, ENDPOINT_LISTEN.0.port()), false)
        .await
        .unwrap();
    tokio::spawn(async move {
        client_ws.run_tunnel(server).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(ENDPOINT_LISTEN.0, false).await.unwrap();
    let mut client = protocols::tcp::connect(
        &TUNNEL_LISTEN.1,
        TUNNEL_LISTEN.0.port(),
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

#[ignore]
#[rstest]
#[timeout(Duration::from_secs(20))]
#[tokio::test]
#[serial]
async fn test_quic_connection_pooling(
    #[future] client_quic: WsClient,
    server_quic: WsServer,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let server_h = tokio::spawn(server_quic.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client_ws = client_quic.await;

    // Verify QUIC connection pool is initialized
    assert!(client_ws.quic_cnx_pool.is_some(), "QUIC connection pool should be initialized");

    let pool = client_ws.quic_cnx_pool.clone().unwrap();

    // Check pool state before any connections
    let state = pool.state();
    assert_eq!(state.connections, 0, "Pool should start with 0 connections");

    let server = TcpTunnelListener::new(TUNNEL_LISTEN.0, (ENDPOINT_LISTEN.1, ENDPOINT_LISTEN.0.port()), false)
        .await
        .unwrap();
    tokio::spawn(async move {
        client_ws.run_tunnel(server).await.unwrap();
    });

    // Create multiple connections to test pooling
    let mut tcp_listener = protocols::tcp::run_server(ENDPOINT_LISTEN.0, false).await.unwrap();

    // First connection - should create a new QUIC connection
    let mut client1 = protocols::tcp::connect(
        &TUNNEL_LISTEN.1,
        TUNNEL_LISTEN.0.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client1.write_all(b"First").await.unwrap();
    let mut dd1 = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    dd1.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..5], b"First");
    buf.clear();

    // Give the pool time to update
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second connection - should reuse the existing QUIC connection (by opening a new stream)
    let mut client2 = protocols::tcp::connect(
        &TUNNEL_LISTEN.1,
        TUNNEL_LISTEN.0.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client2.write_all(b"Second").await.unwrap();
    let mut dd2 = tcp_listener.next().await.unwrap().unwrap();
    dd2.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..6], b"Second");

    // Verify that connections were pooled (we should have at least 1 connection in the pool)
    let state = pool.state();
    assert!(state.connections >= 1, "Pool should have at least 1 connection after use");
}

#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_udp_tunnel(
    #[future] client_ws: WsClient,
    server_no_tls: WsServer,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client_ws = client_ws.await;

    let server = UdpTunnelListener::new(TUNNEL_LISTEN.0, (ENDPOINT_LISTEN.1, ENDPOINT_LISTEN.0.port()), None)
        .await
        .unwrap();
    tokio::spawn(async move {
        client_ws.run_tunnel(server).await.unwrap();
    });

    let udp_listener = protocols::udp::run_server(ENDPOINT_LISTEN.0, None, |_| Ok(()), |s| Ok(s.clone()))
        .await
        .unwrap();
    let mut client = protocols::udp::connect(
        &TUNNEL_LISTEN.1,
        TUNNEL_LISTEN.0.port(),
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
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_ws_reverse_tunnel_reconnect(
    #[future] client_ws: WsClient,
    server_no_tls: WsServer,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client1 = client_ws.await;
    // Create a second client with same config to simulate restart/new session
    let client2 = WsClient::new(
        client1.config.as_ref().clone(),
        0,
        Duration::from_secs(1),
        Duration::from_secs(1),
        10,
        DefaultTokioExecutor::default(),
    )
    .await
    .unwrap();

    let reverse_port = 9997;
    let remote_addr = crate::tunnel::RemoteAddr {
        protocol: crate::tunnel::LocalProtocol::ReverseTcp,
        host: Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
        port: reverse_port,
    };

    let local_dest_port = 9996;
    let local_dest_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), local_dest_port));
    let mut local_server = protocols::tcp::run_server(local_dest_addr, false).await.unwrap();

    let target_host = Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1));

    // 1. Run Reverse Tunnel on Client 1
    let c1 = client1.clone();
    let r1 = remote_addr.clone();
    let t1 = target_host.clone();
    let r_dns1 = dns_resolver.clone();
    let h1 = tokio::spawn(async move {
        let connector = crate::tunnel::connectors::TcpTunnelConnector::new(
            &t1,
            local_dest_port,
            SoMark::new(None),
            Duration::from_secs(1),
            &r_dns1,
        );
        c1.run_reverse_tunnel(r1, connector).await
    });

    // Give it a moment to connect
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 2. Connect to Reverse Port (Verify it works)
    {
        let mut client_sock = protocols::tcp::connect(
            &Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
            reverse_port,
            SoMark::new(None),
            Duration::from_secs(5),
            &dns_resolver,
        )
        .await
        .unwrap();

        client_sock.write_all(b"Session1").await.unwrap();
        let mut dd = local_server.next().await.unwrap().unwrap();
        let mut buf = BytesMut::new();
        dd.read_buf(&mut buf).await.unwrap();
        assert_eq!(&buf[..8], b"Session1");
    }

    // 3. Run Reverse Tunnel on Client 2 (Simulating restart/hijack)
    let c2 = client2.clone();
    let r2 = remote_addr.clone();
    let t2 = target_host.clone();
    let r_dns2 = dns_resolver.clone();
    let h2 = tokio::spawn(async move {
        let connector = crate::tunnel::connectors::TcpTunnelConnector::new(
            &t2,
            local_dest_port,
            SoMark::new(None),
            Duration::from_secs(1),
            &r_dns2,
        );
        c2.run_reverse_tunnel(r2, connector).await
    });

    // Give it a moment to take over
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 4. Connect to Reverse Port AGAIN (Verify Client 2 handles it)
    {
        let mut client_sock = protocols::tcp::connect(
            &Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
            reverse_port,
            SoMark::new(None),
            Duration::from_secs(5),
            &dns_resolver,
        )
        .await
        .unwrap();

        client_sock.write_all(b"Session2").await.unwrap();
        let mut dd = local_server.next().await.unwrap().unwrap();
        let mut buf = BytesMut::new();
        dd.read_buf(&mut buf).await.unwrap();
        assert_eq!(&buf[..8], b"Session2");
    }

    h1.abort();
    h2.abort();
}

//#[rstest]
//#[timeout(Duration::from_secs(10))]
//#[tokio::test]
//async fn test_socks5_tunnel(
//    #[future] client_ws: WsClient,
//    server_no_tls: WsServer,
//    no_restrictions: RestrictionsRules,
//    dns_resolver: DnsResolver,
//) {
//    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
//    defer! { server_h.abort(); };
//
//    let client_ws = client_ws.await;
//
//    let server = Socks5TunnelListener::new(TUNNEL_LISTEN.0, None, None).await.unwrap();
//    tokio::spawn(async move { client_ws.run_tunnel(server).await.unwrap(); });
//
//    let socks5_listener = protocols::socks5::run_server(ENDPOINT_LISTEN.0, None, None).await.unwrap();
//    let mut client = protocols::tcp::connect(&TUNNEL_LISTEN.1, TUNNEL_LISTEN.0.port(), None, Duration::from_secs(10), &dns_resolver).await.unwrap();
//
//    client.write_all(b"Hello").await.unwrap();
//    pin!(socks5_listener);
//    let (dd, _) = socks5_listener.next().await.unwrap().unwrap();
//    let (mut read, mut write) = dd.into_split();
//    let mut buf = BytesMut::new();
//    read.read_buf(&mut buf).await.unwrap();
//    assert_eq!(&buf[..5], b"Hello");
//    buf.clear();
//
//    write.write_all(b"world!").await.unwrap();
//    client.read_buf(&mut buf).await.unwrap();
//    assert_eq!(&buf[..6], b"world!");
//}
