use crate::protocols::tls;
use crate::tunnel::client::WsClientConfig;
use anyhow::{Context, anyhow};
use bb8::ManageConnection;
use quinn::{Connection, Endpoint};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ops::Deref;
use std::sync::{Arc, LazyLock};
use tracing::{debug, info, instrument, warn};
use url::Host;

// Global endpoint to reuse the socket
static ENDPOINT: LazyLock<Endpoint> = LazyLock::new(|| {
    Endpoint::client(SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0)))
        .expect("Failed to create QUIC endpoint")
});

fn get_endpoint() -> Endpoint {
    ENDPOINT.clone()
}

#[derive(Clone)]
pub struct QuicConnection(Arc<WsClientConfig>);

impl QuicConnection {
    pub fn new(config: Arc<WsClientConfig>) -> Self {
        Self(config)
    }
}

impl Deref for QuicConnection {
    type Target = WsClientConfig;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ManageConnection for QuicConnection {
    type Connection = Option<Connection>;
    type Error = anyhow::Error;

    #[instrument(level = "trace", name = "quic_cnx_server", skip_all)]
    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let endpoint = get_endpoint();

        // 1. Resolve DNS
        let host = self.remote_addr.host();
        let port = self.remote_addr.port();

        let remote_addr = match host {
            Host::Domain(domain) => {
                let addrs = self
                    .dns_resolver
                    .lookup_host(domain, port)
                    .await
                    .with_context(|| format!("cannot resolve domain: {domain}"))?;
                addrs
                    .first()
                    .cloned()
                    .ok_or_else(|| anyhow!("no address found for {domain}"))?
            }
            Host::Ipv4(ip) => SocketAddr::V4(SocketAddrV4::new(*ip, port)),
            Host::Ipv6(ip) => SocketAddr::V6(SocketAddrV6::new(*ip, port, 0, 0)),
        };

        // 2. Get TLS configuration
        let tls_config = self
            .remote_addr
            .tls()
            .ok_or_else(|| anyhow!("QUIC requires TLS configuration"))?;

        let (tls_client_certificate, tls_client_key) =
            if let (Some(cert_path), Some(key_path)) = (&tls_config.tls_certificate_path, &tls_config.tls_key_path) {
                let certs = tls::load_certificates_from_pem(cert_path).context("Cannot load client TLS certificate")?;
                let key = tls::load_private_key_from_file(key_path).context("Cannot load client TLS private key")?;
                (Some(certs), Some(key))
            } else {
                (None, None)
            };

        info!(
            "Creating QUIC client config for {} (SNI: {:?}), mTLS: {}",
            remote_addr,
            self.tls_server_name(),
            tls_client_certificate.is_some()
        );

        let rustls_config = tls::rustls_client_config(
            tls_config.tls_verify_certificate,
            vec![b"h3".to_vec()],
            !tls_config.tls_sni_disabled,
            None, // ECH not piped through yet
            tls_client_certificate,
            tls_client_key,
        )?;

        debug!("Created rustls ClientConfig, converting to QuicClientConfig");
        let mut client_config =
            quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)?));
        debug!("QuicClientConfig created successfully");

        let mut transport_config = quinn::TransportConfig::default();

        // Configure max idle timeout
        // Use 10 minutes by default to support long-lived reverse tunnels and file transfers
        let idle_timeout = self
            .quic_max_idle_timeout
            .unwrap_or(std::time::Duration::from_secs(600));
        debug!("QUIC idle timeout: {}s", idle_timeout.as_secs());
        transport_config.max_idle_timeout(Some(quinn::IdleTimeout::from(
            quinn::VarInt::from_u64(idle_timeout.as_millis() as u64).unwrap(),
        )));

        // Configure keep-alive interval
        debug!("QUIC keep-alive interval: {}s", self.quic_keep_alive_interval.as_secs());
        transport_config.keep_alive_interval(Some(self.quic_keep_alive_interval));

        // Configure stream limits
        debug!("QUIC concurrent streams: {} bidirectional", self.quic_max_concurrent_bi_streams);
        transport_config.max_concurrent_bidi_streams(
            quinn::VarInt::from_u64(self.quic_max_concurrent_bi_streams)
                .expect("QUIC concurrent bidirectional streams limit too large"),
        );
        transport_config.max_concurrent_uni_streams(0u32.into()); // We don't use unidirectional streams

        // Configure flow control limits via TransportConfig
        // Connection-level flow control (total data across all streams)
        debug!(
            "QUIC flow control - connection: {} bytes, stream: {} bytes",
            self.quic_initial_max_data, self.quic_initial_max_stream_data
        );
        transport_config.receive_window(
            quinn::VarInt::from_u64(self.quic_initial_max_data).expect("QUIC initial max data limit too large"),
        );
        transport_config.send_window(self.quic_initial_max_data);

        // Per-stream flow control
        transport_config.stream_receive_window(
            quinn::VarInt::from_u64(self.quic_initial_max_stream_data)
                .expect("QUIC initial max stream data limit too large"),
        );

        client_config.transport_config(Arc::new(transport_config));

        // Connect using the configured client config
        info!(
            "Initiating QUIC connection to {} (SNI: {:?})",
            remote_addr,
            self.tls_server_name()
        );
        let connecting = endpoint.connect_with(client_config, remote_addr, self.tls_server_name().to_str().as_ref())?;

        debug!("Waiting for QUIC handshake to complete...");
        let connection = match connecting.await {
            Ok(conn) => {
                info!("QUIC connection established successfully to {}", remote_addr);
                conn
            }
            Err(e) => {
                warn!("QUIC connection failed to {}: {:?}", remote_addr, e);
                return Err(e).context("failed to connect to QUIC server");
            }
        };

        debug!("QUIC connection ready for use");
        Ok(Some(connection))
    }

    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        match conn {
            Some(c) => {
                // Check if connection has been explicitly closed
                if c.close_reason().is_some() {
                    warn!(
                        "Connection pool: Connection {} has close_reason, marking as invalid",
                        c.stable_id()
                    );
                    return Err(anyhow!("connection is closed"));
                }

                // Connection appears valid, allow it to be reused
                debug!("Connection pool: Connection {} validated successfully, reusing", c.stable_id());
                Ok(())
            }
            None => Err(anyhow!("connection is None")),
        }
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        match conn {
            Some(c) => c.close_reason().is_some(),
            None => true,
        }
    }
}
