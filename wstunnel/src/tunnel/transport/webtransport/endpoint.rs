//! The client-side QUIC endpoint every webtransport session is dialled from.

use super::utils::{bind_udp_socket, mk_transport_config};
use crate::somark::SoMark;
use anyhow::Context;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use web_transport_quinn::quinn;
use web_transport_quinn::quinn::crypto::rustls::QuicClientConfig;

/// Client-side QUIC endpoint used by the WebTransport transport.
///
/// This holds the raw quinn endpoint and config rather than a [`web_transport_quinn::Client`]
/// because that type's `connect()` resolves names with `tokio::net::lookup_host`, which would
/// bypass wstunnel's `--dns-resolver`. Driving `quinn::Endpoint::connect_with` ourselves also
/// lets us pass the SNI name independently of the address we dial, which is what makes
/// `--tls-sni-override` work.
#[derive(Debug)]
pub struct WebTransportEndpoint {
    endpoint: quinn::Endpoint,
    /// Dials IPv4 peers when `endpoint` is IPv6-only. Only ever set on BSDs, see [`Self::new`].
    endpoint_v4: Option<quinn::Endpoint>,
    pub(crate) config: quinn::ClientConfig,
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

        let socket = bind_udp_socket(None, so_mark)?;

        // `socket` reaches IPv4 peers only if it is dual-stack, as `connect_with` rewrites them to
        // their IPv4-mapped form. OpenBSD has no dual-stack sockets, and sending to a mapped address
        // from an IPv6-only socket fails with `EADDRNOTAVAIL`, so there IPv4 peers need a socket of
        // their own. Other BSDs can be configured the same way, hence asking the kernel.
        #[cfg(any(
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ))]
        let endpoint_v4 = {
            let only_v6 = socket.local_addr()?.is_ipv6() && socket2::SockRef::from(&socket).only_v6().unwrap_or(true);
            if only_v6 {
                let socket_v4 = bind_udp_socket(Some(SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))), so_mark)?;
                Some(mk_endpoint(socket_v4)?)
            } else {
                None
            }
        };
        #[cfg(not(any(
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        )))]
        let endpoint_v4 = None;

        Ok(Self {
            endpoint: mk_endpoint(socket)?,
            endpoint_v4,
            config,
        })
    }

    /// The endpoint to dial `addr` from.
    pub(crate) fn endpoint_for(&self, addr: SocketAddr) -> &quinn::Endpoint {
        match (addr, &self.endpoint_v4) {
            (SocketAddr::V4(_), Some(endpoint_v4)) => endpoint_v4,
            _ => &self.endpoint,
        }
    }
}

fn mk_endpoint(socket: UdpSocket) -> anyhow::Result<quinn::Endpoint> {
    quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, Arc::new(quinn::TokioRuntime))
        .with_context(|| "cannot create the QUIC endpoint for webtransport")
}
