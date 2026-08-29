use log::info;
use rcgen::{CertificateParams, DnType, KeyPair, date_time_ymd};
use std::sync::LazyLock;
use time::OffsetDateTime;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub static TLS_CERTIFICATE: LazyLock<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> = LazyLock::new(|| {
    info!("Generating self-signed tls certificate");

    let key_pair = KeyPair::generate().unwrap();
    let mut cert = CertificateParams::new(vec![]).unwrap();
    cert.distinguished_name = rcgen::DistinguishedName::new();
    cert.distinguished_name.push(DnType::CountryName, "FR".to_string());

    let now = OffsetDateTime::now_utc();
    cert.not_before = date_time_ymd(now.year(), now.month() as u8, 1);
    cert.not_after = date_time_ymd(now.year() + 1, now.month() as u8, 1);

    let cert = cert.self_signed(&key_pair).unwrap().der().clone();
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialized_der().to_vec()));

    (vec![cert], private_key)
});
