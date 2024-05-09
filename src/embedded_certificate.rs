use log::info;
use once_cell::sync::Lazy;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub static TLS_PRIVATE_KEY: Lazy<PrivateKeyDer<'static>> = Lazy::new(|| {
    info!("Loading embedded tls private key");

    let key = include_bytes!("../certs/key.pem");
    let key = rustls_pemfile::private_key(&mut key.as_slice())
        .expect("failed to load embedded tls private key")
        .expect("failed to load embedded tls private key");
    key
});
pub static TLS_CERTIFICATE: Lazy<Vec<CertificateDer<'static>>> = Lazy::new(|| {
    info!("Loading embedded tls certificate");

    let cert = include_bytes!("../certs/cert.pem");
    let certs = rustls_pemfile::certs(&mut cert.as_slice())
        .next()
        .expect("failed to load embedded tls certificate");

    certs.into_iter().collect()
});
