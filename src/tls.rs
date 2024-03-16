use crate::{TlsServerConfig, WsClientConfig};
use anyhow::{anyhow, Context};
use std::fs::File;

use log::warn;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::client::{ServerCertVerified, ServerCertVerifier};

use crate::tunnel::TransportAddr;
use tokio_rustls::rustls::{Certificate, ClientConfig, PrivateKey, ServerName};
use tokio_rustls::{rustls, TlsAcceptor, TlsConnector};
use tracing::info;

struct NullVerifier;
impl ServerCertVerifier for NullVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

pub fn load_certificates_from_pem(path: &Path) -> anyhow::Result<Vec<Certificate>> {
    info!("Loading tls certificate from {:?}", path);

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader);

    Ok(certs
        .into_iter()
        .filter_map(|cert| match cert {
            Ok(cert) => Some(Certificate(cert.to_vec())),
            Err(err) => {
                warn!("Error while parsing tls certificate: {:?}", err);
                None
            }
        })
        .collect())
}

pub fn load_private_key_from_file(path: &Path) -> anyhow::Result<PrivateKey> {
    info!("Loading tls private key from {:?}", path);

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let Some(private_key) = rustls_pemfile::private_key(&mut reader)? else {
        return Err(anyhow!("No private key found in {path:?}"));
    };

    Ok(PrivateKey(private_key.secret_der().to_vec()))
}

pub fn tls_connector(
    tls_verify_certificate: bool,
    alpn_protocols: Option<Vec<Vec<u8>>>,
    enable_sni: bool,
) -> anyhow::Result<TlsConnector> {
    let mut root_store = rustls::RootCertStore::empty();

    // Load system certificates and add them to the root store
    let certs = rustls_native_certs::load_native_certs().with_context(|| "Cannot load system certificates")?;
    for cert in certs {
        if let Err(err) = root_store.add(&Certificate(cert.as_ref().to_vec())) {
            warn!("cannot load a system certificate: {:?}", err);
            continue;
        }
    }

    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.enable_sni = enable_sni;

    // To bypass certificate verification
    if !tls_verify_certificate {
        config.dangerous().set_certificate_verifier(Arc::new(NullVerifier));
    }

    if let Some(alpn_protocols) = alpn_protocols {
        config.alpn_protocols = alpn_protocols;
    }
    let tls_connector = TlsConnector::from(Arc::new(config));
    Ok(tls_connector)
}

pub fn tls_acceptor(tls_cfg: &TlsServerConfig, alpn_protocols: Option<Vec<Vec<u8>>>) -> anyhow::Result<TlsAcceptor> {
    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(tls_cfg.tls_certificate.lock().clone(), tls_cfg.tls_key.lock().clone())
        .with_context(|| "invalid tls certificate or private key")?;

    if let Some(alpn_protocols) = alpn_protocols {
        config.alpn_protocols = alpn_protocols;
    }
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub async fn connect(client_cfg: &WsClientConfig, tcp_stream: TcpStream) -> anyhow::Result<TlsStream<TcpStream>> {
    let sni = client_cfg.tls_server_name();
    let (tls_connector, sni_disabled) = match &client_cfg.remote_addr {
        TransportAddr::Wss { tls, .. } => (&tls.tls_connector, tls.tls_sni_disabled),
        TransportAddr::Https { tls, .. } => (&tls.tls_connector, tls.tls_sni_disabled),
        TransportAddr::Http { .. } | TransportAddr::Ws { .. } => {
            return Err(anyhow!("Transport does not support TLS: {}", client_cfg.remote_addr.scheme()))
        }
    };

    if sni_disabled {
        info!(
            "Doing TLS handshake without SNI with the server {}:{}",
            client_cfg.remote_addr.host(),
            client_cfg.remote_addr.port()
        );
    } else {
        info!(
            "Doing TLS handshake using SNI {sni:?} with the server {}:{}",
            client_cfg.remote_addr.host(),
            client_cfg.remote_addr.port()
        );
    }

    let tls_stream = tls_connector.connect(sni, tcp_stream).await.with_context(|| {
        format!(
            "failed to do TLS handshake with the server {}:{}",
            client_cfg.remote_addr.host(),
            client_cfg.remote_addr.port()
        )
    })?;

    Ok(tls_stream)
}
