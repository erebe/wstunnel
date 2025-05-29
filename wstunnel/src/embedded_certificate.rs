use log::info;
use rcgen::{CertificateParams, DnType, KeyPair, date_time_ymd};
use std::sync::LazyLock;
use std::time::Instant;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub static TLS_CERTIFICATE: LazyLock<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> = LazyLock::new(|| {
    info!("Generating self-signed tls certificate");

    let now = Instant::now();
    let key_pair = KeyPair::generate().unwrap();
    let mut cert = CertificateParams::new(vec![]).unwrap();
    cert.distinguished_name = rcgen::DistinguishedName::new();
    cert.distinguished_name.push(DnType::CountryName, "FR".to_string());
    let el = now.elapsed();
    let year = 2024 - (el.as_nanos() % 2) as i32;
    let month = 1 + (el.as_nanos() % 12) as u8;
    let day = 1 + (el.as_nanos() % 28) as u8;
    cert.not_before = date_time_ymd(year, month, day);

    let el = now.elapsed();
    let year = 2025 + (el.as_nanos() % 50) as i32;
    let month = 1 + (el.as_nanos() % 12) as u8;
    let day = 1 + (el.as_nanos() % 28) as u8;
    cert.not_after = date_time_ymd(year, month, day);

    let cert = cert.self_signed(&key_pair).unwrap().der().clone();
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialized_der().to_vec()));

    (vec![cert], private_key)
});
