use crate::executor::DefaultTokioExecutor;
use crate::protocols;
use crate::protocols::dns::DnsResolver;
use crate::restrictions::types;
use crate::restrictions::types::{AllowConfig, MatchConfig, RestrictionConfig, RestrictionsRules};
use crate::somark::SoMark;
use crate::tunnel::client::{WsClient, WsClientConfig};
use crate::tunnel::listeners::{TcpTunnelListener, UdpTunnelListener};
use crate::tunnel::server::{WsServer, WsServerConfig};
use crate::tunnel::transport::{TransportAddr, TransportScheme};
use bytes::BytesMut;
use futures_util::StreamExt;
use hyper::http::HeaderValue;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use regex::Regex;
use rstest::{fixture, rstest};
use scopeguard::defer;
use serial_test::serial;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::pin;
use url::Host;

#[fixture]
fn dns_resolver() -> DnsResolver {
    DnsResolver::new_from_urls(&[], None, SoMark::new(None), true).expect("Cannot create DNS resolver")
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
