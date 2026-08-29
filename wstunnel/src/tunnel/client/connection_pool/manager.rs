use crate::protocols;
use crate::protocols::tls;
use crate::tunnel::client::ClientConfig;
use crate::tunnel::client::connection_pool::l4_stream::L4Stream;
use crate::tunnel::transport;
use anyhow::{Context, anyhow};
use bb8::ManageConnection;
use bytes::Bytes;
use either::Either;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use tracing::{instrument, warn};
use url::Host;
use web_transport_quinn::Session;

#[derive(Clone)]
pub struct L4StreamManager(Arc<ClientConfig>);

impl L4StreamManager {
    pub fn new(config: Arc<ClientConfig>) -> Self {
        Self(config)
    }
}

impl Deref for L4StreamManager {
    type Target = ClientConfig;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl L4StreamManager {
    /// Establish a webtransport session with the server, trying each resolved address in turn.
    ///
    /// This does the whole expensive part up front — QUIC handshake, TLS 1.3, HTTP/3 SETTINGS and
    /// the session-level CONNECT — so a pooled session is ready to carry tunnels immediately. The
    /// CONNECT deliberately carries no destination: tunnels announce theirs per stream, which is
    /// what lets one session serve many of them (see `transport::webtransport::mk_connect_request`).
    async fn connect_webtransport(&self) -> anyhow::Result<Session> {
        let webtransport = self
            .webtransport
            .as_ref()
            .ok_or_else(|| anyhow!("no webtransport endpoint configured, the server url scheme must be wts://"))?;
        let request = transport::webtransport::mk_connect_request(self)?;

        let host = self.remote_addr.host();
        let port = self.remote_addr.port();

        // Resolve with wstunnel's resolver so --dns-resolver is honoured.
        let addrs: Vec<SocketAddr> = match host {
            Host::Domain(domain) => self
                .dns_resolver
                .lookup_host(domain.as_str(), port)
                .await
                .with_context(|| format!("cannot resolve domain: {domain}"))?,
            Host::Ipv4(ip) => vec![SocketAddr::from((*ip, port))],
            Host::Ipv6(ip) => vec![SocketAddr::from((*ip, port))],
        };

        // The SNI name is independent of the address we dial, so --tls-sni-override is just a
        // different name here.
        let sni = self.quic_server_name();
        let timeout = self.timeout_connect;

        let mut last_err = None;
        for addr in &addrs {
            // Bound the handshake like the TCP transports do, so a server that never answers on
            // UDP fails with a clear error instead of hanging until the QUIC idle timeout. This is
            // the common symptom of a firewall or port mapping that only forwards TCP.
            let handshake = async {
                let cnx = webtransport
                    .endpoint
                    .connect_with(webtransport.config.clone(), *addr, &sni)
                    .with_context(|| format!("cannot start a QUIC connection to {addr}"))?
                    .await
                    .with_context(|| format!("cannot establish a QUIC connection to {addr}"))?;

                Session::connect(cnx, request.clone())
                    .await
                    .with_context(|| format!("webtransport handshake with {addr} failed"))
            };

            match tokio::time::timeout(timeout, handshake).await {
                Ok(Ok(session)) => return Ok(session),
                Ok(Err(err)) => {
                    warn!("{err:?}");
                    last_err = Some(err);
                }
                Err(_) => {
                    warn!("timed out after {timeout:?} doing the webtransport handshake with {addr}");
                    last_err = Some(anyhow!(
                        "timed out after {timeout:?} doing the webtransport handshake with {addr}. Is UDP reachable on that port?"
                    ));
                }
            }
        }

        Err(last_err
            .unwrap_or_else(|| anyhow!("no address to connect to"))
            .context(format!(
                "failed to open a webtransport session with the server {:?}",
                self.remote_addr
            )))
    }
}

impl ManageConnection for L4StreamManager {
    type Connection = Option<Either<L4Stream, Session>>;
    type Error = anyhow::Error;

    #[instrument(level = "trace", name = "cnx_server", skip_all)]
    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        // wts:// rides QUIC over UDP, so it never borrows a TCP stream.
        if self.remote_addr.scheme().is_webtransport() {
            return Ok(Some(Either::Right(self.connect_webtransport().await?)));
        }

        let timeout = self.timeout_connect;
        let tcp_stream = if let Some(http_proxy) = &self.http_proxy {
            protocols::tcp::connect_with_http_proxy(
                http_proxy,
                self.remote_addr.host(),
                self.remote_addr.port(),
                self.socket_so_mark,
                timeout,
                &self.dns_resolver,
            )
            .await?
        } else {
            protocols::tcp::connect(
                self.remote_addr.host(),
                self.remote_addr.port(),
                self.socket_so_mark,
                timeout,
                &self.dns_resolver,
            )
            .await?
        };

        if self.remote_addr.tls().is_some() {
            // Bound the TLS handshake with the same timeout as the TCP connect,
            // so a peer that accepts the connection but never completes the
            // handshake is dropped instead of held.
            let tls_stream = match tokio::time::timeout(timeout, tls::connect(self, tcp_stream)).await {
                Ok(res) => res?,
                Err(_) => {
                    warn!("Timed out after {timeout:?} doing the TLS handshake with the server");
                    return Err(anyhow!("Timed out doing the TLS handshake with the server"));
                }
            };
            Ok(Some(Either::Left(L4Stream::from_client_tls(tls_stream, Bytes::default()))))
        } else {
            Ok(Some(Either::Left(L4Stream::from_tcp(tcp_stream, Bytes::default()))))
        }
    }

    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        match conn
            .as_ref()
            .and_then(|c| c.as_ref().right())
            .and_then(Session::close_reason)
        {
            Some(err) => Err(anyhow!("pooled webtransport session is closed: {err}")),
            None => Ok(()),
        }
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        // Unlike a TCP stream, which is taken out of the slot by whoever borrowed it, a
        // webtransport session stays in the pool and can be closed by the peer or time out while
        // idle. The handle still looks usable, so ask it.
        match conn.as_ref() {
            None => true,
            Some(Either::Left(_)) => false,
            Some(Either::Right(session)) => session.close_reason().is_some(),
        }
    }
}
