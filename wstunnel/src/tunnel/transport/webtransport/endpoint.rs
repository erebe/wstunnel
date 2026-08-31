//! The client-side QUIC endpoint every webtransport session is dialled from.

use super::utils::{bind_udp_socket, mk_transport_config};
use crate::somark::SoMark;
use anyhow::Context;
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
    pub(crate) endpoint: quinn::Endpoint,
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
