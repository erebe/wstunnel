use anyhow::{Context, anyhow};
use std::fs::File;
use tokio_rustls::rustls::client::{EchConfig, EchMode};

use log::warn;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::tunnel::client::WsClientConfig;
use crate::tunnel::server::TlsServerConfig;
use crate::tunnel::transport::TransportAddr;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::server::danger::ClientCertVerifier;
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, Error, KeyLogFile, RootCertStore, SignatureScheme};
use tokio_rustls::{TlsAcceptor, TlsConnector, rustls};
use tracing::info;

#[derive(Debug)]
struct NullVerifier;

impl ServerCertVerifier for NullVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

pub fn load_certificates_from_pem(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    info!("Loading tls certificate from {:?}", path);

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader);

    Ok(certs
        .into_iter()
        .filter_map(|cert| match cert {
            Ok(cert) => Some(cert),
            Err(err) => {
                warn!("Error while parsing tls certificate: {err:?}");
                None
            }
        })
        .collect())
}

pub fn load_private_key_from_file(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    info!("Loading tls private key from {:?}", path);

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let Some(private_key) = rustls_pemfile::private_key(&mut reader)? else {
        return Err(anyhow!("No private key found in {path:?}"));
    };

    Ok(private_key)
}

pub fn tls_connector(
    tls_verify_certificate: bool,
    alpn_protocols: Vec<Vec<u8>>,
    enable_sni: bool,
    ech_config: Option<EchConfig>,
    tls_client_certificate: Option<Vec<CertificateDer<'static>>>,
    tls_client_key: Option<PrivateKeyDer<'static>>,
) -> anyhow::Result<TlsConnector> {
    // Load system certificates
    let root_store = crate::tunnel::ca_reloader::get_root_store();
    let crypto_provider = rustls::crypto::CryptoProvider::get_default().unwrap().clone();

    let config_builder = ClientConfig::builder_with_provider(crypto_provider);
    let config_builder = if let Some(ech_config) = ech_config {
        info!("Using TLS ECH (encrypted sni) with config: {:?}", ech_config);
        config_builder.with_ech(EchMode::Enable(ech_config))?
    } else {
        config_builder.with_safe_default_protocol_versions()?
    };
    let config_builder = config_builder.with_root_certificates(root_store);

    let mut config = match (tls_client_certificate, tls_client_key) {
        (Some(tls_client_certificate), Some(tls_client_key)) => config_builder
            .with_client_auth_cert(tls_client_certificate, tls_client_key)
            .with_context(|| "Error setting up mTLS")?,
        _ => config_builder.with_no_client_auth(),
    };

    config.enable_sni = enable_sni;
    config.key_log = Arc::new(KeyLogFile::new());

    // To bypass certificate verification
    if !tls_verify_certificate {
        config.dangerous().set_certificate_verifier(Arc::new(NullVerifier));
    }

    config.alpn_protocols = alpn_protocols;
    let tls_connector = TlsConnector::from(Arc::new(config));
    Ok(tls_connector)
}

/// Build the mTLS client certificate verifier for a server config, or a no-op verifier when
/// the server is not configured to authenticate clients.
fn client_cert_verifier(tls_cfg: &TlsServerConfig) -> anyhow::Result<Arc<dyn ClientCertVerifier>> {
    let Some(tls_client_ca_certificates) = &tls_cfg.tls_client_ca_certificates else {
        return Ok(WebPkiClientVerifier::no_client_auth());
    };

    let mut root_store = RootCertStore::empty();
    for tls_client_ca_certificate in tls_client_ca_certificates.lock().iter() {
        root_store
            .add(tls_client_ca_certificate.clone())
            .with_context(|| "Failed to add mTLS client CA certificate")?;
    }

    WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|err| anyhow!("Failed to build mTLS client verifier: {err:?}"))
}

pub fn tls_acceptor(tls_cfg: &TlsServerConfig, alpn_protocols: Option<Vec<Vec<u8>>>) -> anyhow::Result<TlsAcceptor> {
    let client_cert_verifier = client_cert_verifier(tls_cfg)?;

    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(tls_cfg.tls_certificate.lock().clone(), tls_cfg.tls_key.lock().clone_key())
        .with_context(|| "invalid tls certificate or private key")?;

    config.key_log = Arc::new(KeyLogFile::new());
    if let Some(alpn_protocols) = alpn_protocols {
        config.alpn_protocols = alpn_protocols;
    }
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// TLS config for a QUIC/WebTransport **server**.
///
/// QUIC mandates TLS 1.3 and negotiates the HTTP/3 ALPN, so this cannot reuse
/// [`tls_acceptor`]'s config, which allows TLS 1.2 and advertises `h2`/`http/1.1`. The mTLS
/// client verifier and certificate material are shared with the TCP path.
pub fn quic_server_config(tls_cfg: &TlsServerConfig) -> anyhow::Result<rustls::ServerConfig> {
    let crypto_provider = rustls::crypto::CryptoProvider::get_default()
        .ok_or_else(|| anyhow!("No default crypto provider installed for rustls"))?
        .clone();

    let mut config = rustls::ServerConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .with_context(|| "QUIC requires TLS 1.3 support")?
        .with_client_cert_verifier(client_cert_verifier(tls_cfg)?)
        .with_single_cert(tls_cfg.tls_certificate.lock().clone(), tls_cfg.tls_key.lock().clone_key())
        .with_context(|| "invalid tls certificate or private key")?;

    config.key_log = Arc::new(KeyLogFile::new());
    config.alpn_protocols = vec![web_transport_quinn::ALPN.as_bytes().to_vec()];

    Ok(config)
}

/// TLS config for a QUIC/WebTransport **client**.
///
/// Mirrors [`tls_connector`] — same root store, same mTLS client certificate handling, same
/// opt-out of certificate verification — but restricted to TLS 1.3 with the HTTP/3 ALPN.
///
/// ECH is not plumbed here: it is only wired for the TCP transports.
pub fn quic_client_config(
    tls_verify_certificate: bool,
    tls_client_certificate: Option<Vec<CertificateDer<'static>>>,
    tls_client_key: Option<PrivateKeyDer<'static>>,
) -> anyhow::Result<ClientConfig> {
    let root_store = crate::tunnel::ca_reloader::get_root_store();
    let crypto_provider = rustls::crypto::CryptoProvider::get_default()
        .ok_or_else(|| anyhow!("No default crypto provider installed for rustls"))?
        .clone();

    let config_builder = ClientConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .with_context(|| "QUIC requires TLS 1.3 support")?
        .with_root_certificates(root_store);

    let mut config = match (tls_client_certificate, tls_client_key) {
        (Some(tls_client_certificate), Some(tls_client_key)) => config_builder
            .with_client_auth_cert(tls_client_certificate, tls_client_key)
            .with_context(|| "Error setting up mTLS")?,
        _ => config_builder.with_no_client_auth(),
    };

    config.key_log = Arc::new(KeyLogFile::new());

    // To bypass certificate verification
    if !tls_verify_certificate {
        config.dangerous().set_certificate_verifier(Arc::new(NullVerifier));
    }

    config.alpn_protocols = vec![web_transport_quinn::ALPN.as_bytes().to_vec()];

    Ok(config)
}

pub async fn connect(client_cfg: &WsClientConfig, tcp_stream: TcpStream) -> anyhow::Result<TlsStream<TcpStream>> {
    let sni = client_cfg.tls_server_name();
    let tls_config = match &client_cfg.remote_addr {
        TransportAddr::Wss { tls, .. } => tls,
        TransportAddr::Https { tls, .. } => tls,
        // WebTransport does its own TLS 1.3 handshake inside QUIC, over UDP. It never goes
        // through the TCP connection pool, so it must not reach this function.
        TransportAddr::WebTransport { .. } => {
            return Err(anyhow!(
                "WebTransport does not use a TCP TLS stream, it handshakes inside QUIC: {}",
                client_cfg.remote_addr.scheme()
            ));
        }
        TransportAddr::Http { .. } | TransportAddr::Ws { .. } => {
            return Err(anyhow!("Transport does not support TLS: {}", client_cfg.remote_addr.scheme()));
        }
    };

    if tls_config.tls_sni_disabled {
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

    let tls_connector = tls_config.tls_connector();
    let tls_stream = tls_connector.connect(sni, tcp_stream).await?;

    Ok(tls_stream)
}
