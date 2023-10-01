use once_cell::sync::Lazy;
use tokio_rustls::rustls::{Certificate, PrivateKey};

pub static TLS_PRIVATE_KEY: Lazy<PrivateKey> = Lazy::new(|| {
    let key = include_bytes!("../certs/key.pem");
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key.as_slice())
        .expect("failed to load embedded tls private key");
    PrivateKey(keys.remove(0))
});
pub static TLS_CERTIFICATE: Lazy<Vec<Certificate>> = Lazy::new(|| {
    let cert = include_bytes!("../certs/cert.pem");
    let certs = rustls_pemfile::certs(&mut cert.as_slice())
        .expect("failed to load embedded tls certificate");

    certs.into_iter().map(Certificate).collect()
});
