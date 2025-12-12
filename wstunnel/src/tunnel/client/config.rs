use crate::protocols::dns::DnsResolver;
use crate::somark::SoMark;
use crate::tunnel::transport::TransportAddr;
use hyper::header::{HeaderName, HeaderValue};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{DnsName, ServerName};
use url::{Host, Url};

#[derive(Clone, Debug)]
pub struct WsClientConfig {
    pub remote_addr: TransportAddr,
    pub socket_so_mark: SoMark,
    pub http_upgrade_path_prefix: String,
    pub http_upgrade_credentials: Option<HeaderValue>,
    pub http_headers: HashMap<HeaderName, HeaderValue>,
    pub http_headers_file: Option<PathBuf>,
    pub http_header_host: HeaderValue,
    pub timeout_connect: Duration,
    pub websocket_ping_frequency: Option<Duration>,
    pub websocket_mask_frame: bool,
    pub http_proxy: Option<Url>,
    pub dns_resolver: DnsResolver,
}

impl WsClientConfig {
    pub fn tls_server_name(&self) -> ServerName<'static> {
        static INVALID_DNS_NAME: LazyLock<DnsName> =
            LazyLock::new(|| DnsName::try_from("dns-name-invalid.com").unwrap());

        self.remote_addr
            .tls()
            .and_then(|tls| tls.tls_sni_override.as_ref())
            .map_or_else(
                || match &self.remote_addr.host() {
                    Host::Domain(domain) => ServerName::DnsName(
                        DnsName::try_from(domain.clone()).unwrap_or_else(|_| INVALID_DNS_NAME.clone()),
                    ),
                    Host::Ipv4(ip) => ServerName::IpAddress(IpAddr::V4(*ip).into()),
                    Host::Ipv6(ip) => ServerName::IpAddress(IpAddr::V6(*ip).into()),
                },
                |sni_override| ServerName::DnsName(sni_override.clone()),
            )
    }
}

#[derive(Clone)]
pub struct TlsClientConfig {
    pub tls_sni_disabled: bool,
    pub tls_sni_override: Option<DnsName<'static>>,
    pub tls_verify_certificate: bool,
    pub tls_connector: Arc<RwLock<TlsConnector>>,
    pub tls_certificate_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
}

impl TlsClientConfig {
    pub fn tls_connector(&self) -> TlsConnector {
        self.tls_connector.read().clone()
    }
}
