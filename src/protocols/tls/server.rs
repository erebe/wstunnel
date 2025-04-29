use anyhow::{Context, anyhow};
use tokio_rustls::rustls::client::{EchConfig, EchMode};
use tokio_rustls::rustls::crypto::ring;
use std::fs::File;

use log::warn;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::tunnel::client::{TlsClientConfig, WsClientConfig};
use crate::tunnel::server::TlsServerConfig;
use crate::tunnel::transport::TransportAddr;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
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
                warn!("Error while parsing tls certificate: {:?}", err);
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
    tls_client_certificate: Option<Vec<CertificateDer<'static>>>,
    tls_client_key: Option<PrivateKeyDer<'static>>,
) -> anyhow::Result<(TlsConnector, RootCertStore)> {
    let mut root_store = rustls::RootCertStore::empty();

    // Load system certificates and add them to the root store
    let certs = rustls_native_certs::load_native_certs();
    certs.errors.iter().for_each(|err| {
        warn!("cannot load system some system certificates: {}", err);
    });
    for cert in certs.certs {
        if let Err(err) = root_store.add(cert) {
            warn!("cannot load a system certificate: {:?}", err);
            continue;
        }
    }
    
    rustls::crypto::ring::default_provider().install_default().expect("Failed to install rustls crypto provider");

    let config_builder = ClientConfig::builder().with_root_certificates(root_store.clone());

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
    Ok((tls_connector, root_store))
}

pub fn tls_acceptor(tls_cfg: &TlsServerConfig, alpn_protocols: Option<Vec<Vec<u8>>>) -> anyhow::Result<TlsAcceptor> {
    let client_cert_verifier = if let Some(tls_client_ca_certificates) = &tls_cfg.tls_client_ca_certificates {
        let mut root_store = rustls::RootCertStore::empty();
        for tls_client_ca_certificate in tls_client_ca_certificates.lock().iter() {
            root_store
                .add(tls_client_ca_certificate.clone())
                .with_context(|| "Failed to add mTLS client CA certificate")?;
        }

        WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|err| anyhow!("Failed to build mTLS client verifier: {:?}", err))?
    } else {
        WebPkiClientVerifier::no_client_auth()
    };

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

pub async fn connect(client_cfg: &WsClientConfig, tcp_stream: (TcpStream, Option<EchConfig>)) -> anyhow::Result<TlsStream<TcpStream>> {
    let sni = client_cfg.tls_server_name();
    let (tls_connector, sni_disabled) = match &client_cfg.remote_addr {
        TransportAddr::Wss { tls, .. } => (tls.tls_connector(), tls.tls_sni_disabled),
        TransportAddr::Https { tls, .. } => (tls.tls_connector(), tls.tls_sni_disabled),
        TransportAddr::Http { .. } | TransportAddr::Ws { .. } => {
            return Err(anyhow!("Transport does not support TLS: {}", client_cfg.remote_addr.scheme()));
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

    let connector = tls_connector.clone();

    let tls_config = match &client_cfg.remote_addr {
        TransportAddr::Wss { tls, .. } => Some(tls),
        TransportAddr::Https { tls, .. } => Some(tls),
        _ => None,
    };

    let tls_stream = if let (Some(tls_config) , Some(ech_config), Some(true)) = (tls_config, tcp_stream.1, is_ech_enabled(tls_config)) {
        tls_connect_with_ech(ech_config, tls_config, tls_connector.clone(), client_cfg,  tcp_stream.0, sni).await?
    } else {
        connector.connect(sni, tcp_stream.0).await?
    };

    Ok(tls_stream)
}

fn is_ech_enabled(tls_config: Option<&TlsClientConfig>) -> Option<bool> {
    match tls_config {
        Some(config) => return Some(config.tls_ech_enabled),
        _ => None
    }
}

async fn tls_connect_with_ech(
    ech_config: EchConfig,
    tls_config: &TlsClientConfig, 
    original_connector: TlsConnector,
    client_cfg: &WsClientConfig,
    tcp_stream: TcpStream,
    sni: ServerName<'static>
) -> anyhow::Result<TlsStream<TcpStream>>  {
    let mut ech_client_config = ClientConfig::builder_with_provider(ring::default_provider().into())
                    .with_ech(EchMode::from(ech_config))?
                    .with_root_certificates(tls_config.root_store.clone())
                    .with_no_client_auth();

    let original_config = original_connector.config();
                ech_client_config.key_log = original_config.key_log.clone();
                ech_client_config.alpn_protocols = original_config.alpn_protocols.clone();
                
    return TlsConnector::from(Arc::new(ech_client_config))
        .connect(sni, tcp_stream)
        .await.with_context(|| {
        format!(
            "failed to do TLS handshake with the server {}:{}",
            client_cfg.remote_addr.host(),
            client_cfg.remote_addr.port()
        )
    });
}