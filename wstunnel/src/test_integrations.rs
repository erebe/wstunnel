use crate::embedded_certificate;
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
fn server_no_tls(dns_resolver: DnsResolver) -> WsServer {
    let server_config = WsServerConfig {
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
    WsServer::new(server_config, DefaultTokioExecutor::default())
}

/// Server serving webtransport over UDP, alongside websocket/http2 over TCP.
#[fixture]
fn server_webtransport(dns_resolver: DnsResolver) -> WsServer {
    let server_config = WsServerConfig {
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
    WsServer::new(server_config, DefaultTokioExecutor::default())
}

/// Not a fixture, as the port to dial is only known once the server fixture has picked one.
async fn client_webtransport(server_port: u16, dns_resolver: DnsResolver) -> WsClient {
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

    let client_config = WsClientConfig {
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
    };

    WsClient::new(
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
async fn client_ws(server_port: u16, dns_resolver: DnsResolver) -> WsClient {
    let client_config = WsClientConfig {
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
    };

    WsClient::new(
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
async fn test_tcp_tunnel(server_no_tls: WsServer, no_restrictions: RestrictionsRules, dns_resolver: DnsResolver) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_no_tls.config.bind.port();
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client_ws = client_ws(server_port, dns_resolver.clone()).await;

    let server = TcpTunnelListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), false)
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
async fn test_udp_tunnel(server_no_tls: WsServer, no_restrictions: RestrictionsRules, dns_resolver: DnsResolver) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_no_tls.config.bind.port();
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client_ws = client_ws(server_port, dns_resolver.clone()).await;

    let server = UdpTunnelListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), None)
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
    server_webtransport: WsServer,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_webtransport.config.bind.port();
    let server_h = tokio::spawn(server_webtransport.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client = client_webtransport(server_port, dns_resolver.clone()).await;

    let server = TcpTunnelListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), false)
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

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_udp_tunnel_webtransport(
    server_webtransport: WsServer,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_webtransport.config.bind.port();
    let server_h = tokio::spawn(server_webtransport.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client = client_webtransport(server_port, dns_resolver.clone()).await;

    let server = UdpTunnelListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), None)
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
