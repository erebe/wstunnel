use crate::protocols::dns::DnsResolver;
use crate::somark::SoMark;
use crate::tunnel::transport::TransportAddr;
use crate::tunnel::transport::webtransport::WebTransportEndpoint;
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
pub struct ClientConfig {
    pub remote_addr: TransportAddr,
    pub socket_so_mark: SoMark,
    pub http_upgrade_path_prefix: String,
    pub http_upgrade_credentials: Option<HeaderValue>,
    pub http_headers: HashMap<HeaderName, HeaderValue>,
    pub http_headers_file: Option<PathBuf>,
    pub http_header_host: HeaderValue,
    /// Host header explicitly supplied by the user via `-H "Host: ..."`.
    /// `None` if the host header was auto-derived from `remote_addr`.
    pub custom_http_header_host: Option<HeaderValue>,
    pub timeout_connect: Duration,
    pub websocket_ping_frequency: Option<Duration>,
    pub websocket_mask_frame: bool,
    pub http_proxy: Option<Url>,
    pub dns_resolver: DnsResolver,
    /// QUIC endpoint, only for the webtransport transport. `None` for every other scheme.
    /// Built in `create_client`, so a bad TLS setup fails at startup rather than on the
    /// first tunnel.
    pub webtransport: Option<Arc<WebTransportEndpoint>>,
    /// Maximum number of HTTP redirects to follow for server URL. 0 disables redirects.
    pub max_redirects: usize,
    /// Whether TLS certificate verification is enabled for the client.
    pub tls_verify_certificate: bool,
}

impl ClientConfig {
    pub fn quic_server_name(&self) -> String {
        self.remote_addr
            .tls()
            .and_then(|tls| tls.tls_sni_override.as_ref())
            .map_or_else(
                || match &self.remote_addr.host() {
                    Host::Domain(domain) => domain.clone(),
                    Host::Ipv4(ip) => ip.to_string(),
                    Host::Ipv6(ip) => ip.to_string(),
                },
                |sni_override| sni_override.as_ref().to_string(),
            )
    }
    /// Derive the TLS `ServerName` (for SNI and certificate verification) for a specific target address.
    ///
    /// If `--tls-sni-override` was specified on the TLS configuration, that name is used.
    /// Otherwise, the host from `remote_addr` (domain name or IP address) is used.
    pub fn tls_server_name_for(&self, remote_addr: &TransportAddr) -> ServerName<'static> {
        static INVALID_DNS_NAME: LazyLock<DnsName> =
            LazyLock::new(|| DnsName::try_from("dns-name-invalid.com").unwrap());

        remote_addr
            .tls()
            .and_then(|tls| tls.tls_sni_override.as_ref())
            .map_or_else(
                || match remote_addr.host() {
                    Host::Domain(domain) => ServerName::DnsName(
                        DnsName::try_from(domain.clone()).unwrap_or_else(|_| INVALID_DNS_NAME.clone()),
                    ),
                    Host::Ipv4(ip) => ServerName::IpAddress(IpAddr::V4(*ip).into()),
                    Host::Ipv6(ip) => ServerName::IpAddress(IpAddr::V6(*ip).into()),
                },
                |sni_override| ServerName::DnsName(sni_override.clone()),
            )
    }

    /// Derive the TLS `ServerName` for the client's configured default `remote_addr`.
    pub fn tls_server_name(&self) -> ServerName<'static> {
        self.tls_server_name_for(&self.remote_addr)
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
