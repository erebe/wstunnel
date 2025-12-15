use crate::protocols::tls;
use crate::tunnel::client::WsClientConfig;
use anyhow::{Context, anyhow};
use bb8::ManageConnection;
use quinn::{Connection, Endpoint};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, instrument, warn};
use url::Host;

#[derive(Clone)]
pub struct QuicConnection {
    inner: Arc<QuicConnectionInner>,
}

pub struct QuicConnectionInner {
    config: Arc<WsClientConfig>,
    endpoint: Endpoint,
    is_broken: AtomicBool,
}

impl QuicConnection {
    pub fn new(config: Arc<WsClientConfig>) -> Self {
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
            .expect("Failed to create UDP socket");

        // Increase buffer sizes for high throughput based on config
        let requested_size = if config.quic_socket_buffer_size == 0 {
            25 * 1024 * 1024
        } else {
            config.quic_socket_buffer_size as usize
        };

        let _ = socket.set_send_buffer_size(requested_size);
        let _ = socket.set_recv_buffer_size(requested_size);

        if let Ok(size) = socket.send_buffer_size()
            && size < requested_size && config.quic_socket_buffer_size > 0 {
                warn!(
                    "QUIC UDP send buffer size is small: {} bytes. This may limit throughput. Consider increasing net.core.wmem_max.",
                    size
                );
            }
        if let Ok(size) = socket.recv_buffer_size()
            && size < requested_size && config.quic_socket_buffer_size > 0 {
                warn!(
                    "QUIC UDP recv buffer size is small: {} bytes. This may limit throughput. Consider increasing net.core.rmem_max.",
                    size
                );
            }

        let addr = SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0));
        socket.bind(&addr.into()).expect("Failed to bind UDP socket");
        socket.set_nonblocking(true).expect("Failed to set non-blocking");
        let socket: std::net::UdpSocket = socket.into();

        let endpoint = Endpoint::new(quinn::EndpointConfig::default(), None, socket, Arc::new(quinn::TokioRuntime))
            .expect("Failed to create QUIC endpoint");

        Self {
            inner: Arc::new(QuicConnectionInner {
                config,
                endpoint,
                is_broken: AtomicBool::new(false),
            }),
        }
    }
}

impl Deref for QuicConnection {
    type Target = QuicConnectionInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl ManageConnection for QuicConnection {
    type Connection = Option<Connection>;
    type Error = anyhow::Error;

    #[instrument(level = "trace", name = "quic_cnx_server", skip_all)]
    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        // 1. Resolve DNS
        self.inner.is_broken.store(false, Ordering::SeqCst);
        let host = self.inner.config.remote_addr.host();
        let port = self.inner.config.remote_addr.port();

        let remote_addr = match host {
            Host::Domain(domain) => {
                let addrs = self
                    .inner
                    .config
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
            .inner
            .config
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

        debug!(
            "Creating QUIC client config for {} (SNI: {:?}), mTLS: {}",
            remote_addr,
            self.inner.config.tls_server_name(),
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
            .inner
            .config
            .quic_max_idle_timeout
            .unwrap_or(std::time::Duration::from_secs(600));
        debug!("QUIC idle timeout: {}s", idle_timeout.as_secs());
        transport_config.max_idle_timeout(Some(quinn::IdleTimeout::from(
            quinn::VarInt::from_u64(idle_timeout.as_millis() as u64).unwrap(),
        )));

        // Configure keep-alive interval
        debug!(
            "QUIC keep-alive interval: {}s",
            self.inner.config.quic_keep_alive_interval.as_secs()
        );
        transport_config.keep_alive_interval(Some(self.inner.config.quic_keep_alive_interval));

        // Configure stream limits
        debug!(
            "QUIC concurrent streams: {} bidirectional",
            self.inner.config.quic_max_concurrent_bi_streams
        );
        transport_config.max_concurrent_bidi_streams(
            quinn::VarInt::from_u64(self.inner.config.quic_max_concurrent_bi_streams)
                .expect("QUIC concurrent bidirectional streams limit too large"),
        );
        transport_config.max_concurrent_uni_streams(0u32.into()); // We don't use unidirectional streams

        // Configure flow control limits via TransportConfig
        // Connection-level flow control (total data across all streams)
        debug!(
            "QUIC flow control - connection: {} bytes, stream: {} bytes",
            self.inner.config.quic_initial_max_data, self.inner.config.quic_initial_max_stream_data
        );
        transport_config.receive_window(
            quinn::VarInt::from_u64(self.inner.config.quic_initial_max_data)
                .expect("QUIC initial max data limit too large"),
        );
        transport_config.send_window(self.inner.config.quic_initial_max_data);

        // Per-stream flow control
        transport_config.stream_receive_window(
            quinn::VarInt::from_u64(self.inner.config.quic_initial_max_stream_data)
                .expect("QUIC initial max stream data limit too large"),
        );

        if let Some(mtu) = self.inner.config.quic_initial_mtu {
            transport_config.initial_mtu(mtu);
        }

        client_config.transport_config(Arc::new(transport_config));

        // Connect using the configured client config
        debug!(
            "Initiating QUIC connection to {} (SNI: {:?})",
            remote_addr,
            self.inner.config.tls_server_name()
        );
        let connecting = self.endpoint.connect_with(
            client_config,
            remote_addr,
            self.inner.config.tls_server_name().to_str().as_ref(),
        )?;

        debug!("Waiting for QUIC handshake to complete...");
        let connection = match connecting.await {
            Ok(conn) => {
                debug!("QUIC connection established successfully to {}", remote_addr);
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
        if self.inner.is_broken.load(Ordering::SeqCst) {
            warn!("Connection pool: Connection marked as broken, discarding");
            return true;
        }

        match conn {
            Some(c) => {
                if c.close_reason().is_some() {
                    warn!("Connection pool: Connection has close_reason, discarding");
                    return true;
                }
                false
            }
            None => true, // No connection, so it's "broken"
        }
    }
}
