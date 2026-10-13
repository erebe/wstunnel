use super::{load_certificates_from_pem, load_private_key_from_file, tls_acceptor};
use base64::Engine;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, ServerName};

struct PemFiles(PathBuf);
impl PemFiles {
    fn new() -> Self {
        let root = std::env::temp_dir().canonicalize().unwrap();
        let path = root.join(format!("wstunnel-pem-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&path).unwrap();
        let path = path.canonicalize().unwrap();
        assert_eq!(path.parent(), Some(root.as_path()));
        Self(path)
    }
    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }
}
impl Drop for PemFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    )
}

#[test]
fn pem_certificate_chain_order_and_error_recovery() {
    let files = PemFiles::new();
    let data = format!(
        "{}{}{}{}",
        pem("PRIVATE KEY", &[9]),
        pem("CERTIFICATE", &[1, 2, 3]),
        "-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n",
        pem("CERTIFICATE", &[4, 5, 6])
    );
    let path = files.write("chain.pem", data.replace('\n', "\r\n"));
    let certs = load_certificates_from_pem(&path).unwrap();
    assert_eq!(certs.len(), 2);
    assert_eq!(certs[0].as_ref(), &[1, 2, 3]);
    assert_eq!(certs[1].as_ref(), &[4, 5, 6]);
    let empty = files.write("empty.pem", "");
    assert!(load_certificates_from_pem(&empty).unwrap().is_empty());
    assert!(load_certificates_from_pem(&files.0.join("missing.pem")).is_err());
}

#[test]
fn pem_private_key_formats_first_key_and_missing_errors() {
    let files = PemFiles::new();
    // Dummy DER tests the PEM wrapper/type only, not cryptographic key validity.
    for (label, format) in [("RSA PRIVATE KEY", 1), ("PRIVATE KEY", 8), ("EC PRIVATE KEY", 2)] {
        let path = files.write(
            "key.pem",
            format!(
                "{}{}{}",
                pem("CERTIFICATE", &[0]),
                pem(label, &[1, 2, 3]),
                pem("PRIVATE KEY", &[4, 5, 6])
            ),
        );
        let key = load_private_key_from_file(&path).unwrap();
        assert_eq!(key.secret_der(), &[1, 2, 3]);
        assert!(matches!(
            (&key, format),
            (PrivateKeyDer::Pkcs1(_), 1) | (PrivateKeyDer::Pkcs8(_), 8) | (PrivateKeyDer::Sec1(_), 2)
        ));
    }
    let empty = files.write("no-key.pem", pem("CERTIFICATE", &[1]));
    assert!(
        load_private_key_from_file(&empty)
            .unwrap_err()
            .to_string()
            .contains("No private key found")
    );
    let invalid = files.write("invalid.pem", "-----BEGIN PRIVATE KEY-----\n%%%\n-----END PRIVATE KEY-----\n");
    assert!(load_private_key_from_file(&invalid).is_err());
    let truncated = files.write("truncated.pem", "-----BEGIN PRIVATE KEY-----\nAQID\n");
    assert!(load_private_key_from_file(&truncated).is_err());
    assert!(load_private_key_from_file(&files.0.join("missing.pem")).is_err());
}

fn provider() {
    #[cfg(feature = "aws-lc-rs")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn tls_files_config(cert: &Path, key: &Path, ca: &Path) -> crate::tunnel::server::TlsServerConfig {
    crate::tunnel::server::TlsServerConfig {
        tls_certificate: parking_lot::Mutex::new(load_certificates_from_pem(cert).unwrap()),
        tls_key: parking_lot::Mutex::new(load_private_key_from_file(key).unwrap()),
        tls_client_ca_certificates: Some(parking_lot::Mutex::new(load_certificates_from_pem(ca).unwrap())),
        tls_certificate_path: Some(cert.to_owned()),
        tls_key_path: Some(key.to_owned()),
        tls_client_ca_certs_path: Some(ca.to_owned()),
    }
}

#[tokio::test]
async fn pem_loaded_material_supports_mtls_and_file_reload() {
    use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
    provider();
    let files = PemFiles::new();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let ca_path = files.write("ca.pem", pem("CERTIFICATE", ca_cert.der()));
    let leaf = |usage| {
        let mut params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &issuer).unwrap();
        (cert, key)
    };
    let (server_cert, server_key) = leaf(ExtendedKeyUsagePurpose::ServerAuth);
    let cert_path = files.write(
        "server.pem",
        format!("{}{}", pem("CERTIFICATE", server_cert.der()), pem("CERTIFICATE", ca_cert.der())),
    );
    let key_path = files.write("server-key.pem", pem("PRIVATE KEY", &server_key.serialize_der()));
    let (client_cert, client_key) = leaf(ExtendedKeyUsagePurpose::ClientAuth);
    let client_cert_path = files.write("client.pem", pem("CERTIFICATE", client_cert.der()));
    let client_key_path = files.write("client-key.pem", pem("PRIVATE KEY", &client_key.serialize_der()));
    let config = Arc::new(crate::tunnel::server::ServerConfig {
        socket_so_mark: crate::somark::SoMark::new(None),
        bind: "127.0.0.1:0".parse().unwrap(),
        websocket_ping_frequency: None,
        timeout_connect: std::time::Duration::from_secs(3),
        websocket_mask_frame: false,
        tls: Some(tls_files_config(&cert_path, &key_path, &ca_path)),
        dns_resolver: crate::protocols::dns::DnsResolver::System,
        restriction_config: None,
        http_proxy: None,
        remote_server_idle_timeout: std::time::Duration::from_secs(30),
        enable_webtransport: false,
    });
    let reloader = crate::tunnel::TestTlsReloader::new_for_server(config.clone()).unwrap();
    let tls_cfg = config.tls.as_ref().unwrap();
    let acceptor = tls_acceptor(tls_cfg, None).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(load_certificates_from_pem(&ca_path).unwrap().remove(0))
        .unwrap();
    let authenticated = rustls::ClientConfig::builder()
        .with_root_certificates(roots.clone())
        .with_client_auth_cert(
            load_certificates_from_pem(&client_cert_path).unwrap(),
            load_private_key_from_file(&client_key_path).unwrap(),
        )
        .unwrap();
    let anonymous = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    for (client_config, expected) in [(authenticated, true), (anonymous, false)] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_acceptor = acceptor.clone();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            server_acceptor.accept(socket).await.is_ok()
        });
        let socket = tokio::net::TcpStream::connect(address).await.unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let client_result = connector
            .connect(ServerName::try_from("localhost").unwrap(), socket)
            .await;
        assert_eq!(server.await.unwrap(), expected);
        if expected {
            assert!(client_result.is_ok());
        }
    }
    let (replacement_cert, replacement_key) = leaf(ExtendedKeyUsagePurpose::ServerAuth);
    files.write(
        "server.pem",
        format!(
            "{}{}",
            pem("CERTIFICATE", replacement_cert.der()),
            pem("CERTIFICATE", ca_cert.der())
        ),
    );
    files.write("server-key.pem", pem("PRIVATE KEY", &replacement_key.serialize_der()));
    tokio::time::timeout(std::time::Duration::from_secs(8), async {
        loop {
            if tls_cfg.tls_certificate.lock()[0].as_ref() == replacement_cert.der().as_ref()
                && tls_cfg.tls_key.lock().secret_der() == replacement_key.serialize_der()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("certificate/key file changes were not reloaded");
    assert!(reloader.should_reload_certificate());
    assert!(tls_acceptor(tls_cfg, None).is_ok());
}
