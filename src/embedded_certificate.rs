use log::info;
use once_cell::sync::Lazy;
use tokio_rustls::rustls::{Certificate, PrivateKey};

pub static TLS_PRIVATE_KEY: Lazy<PrivateKey> = Lazy::new(|| {
    info!("Loading embedded tls private key");

    let key = include_bytes!("../certs/key.pem");
    let key = rustls_pemfile::private_key(&mut key.as_slice())
        .expect("failed to load embedded tls private key")
        .expect("failed to load embedded tls private key");
    PrivateKey(key.secret_der().to_vec())
});
pub static TLS_CERTIFICATE: Lazy<Vec<Certificate>> = Lazy::new(|| {
    info!("Loading embedded tls certificate");

    let cert = include_bytes!("../certs/cert.pem");
    let certs = rustls_pemfile::certs(&mut cert.as_slice())
        .next()
        .expect("failed to load embedded tls certificate");

    certs
        .into_iter()
        .map(|cert| Certificate(cert.as_ref().to_vec()))
        .collect()
});
