mod server;
mod utils;

pub use server::connect;
pub use server::load_certificates_from_pem;
pub use server::load_private_key_from_file;
pub use server::rustls_client_config;
pub use server::rustls_server_config;
pub use server::tls_acceptor;
pub use server::tls_connector;
pub use utils::CertificateVars;
pub use utils::cn_from_certificate;
pub use utils::find_leaf_certificate;

pub fn init() {
    #[cfg(feature = "aws-lc-rs")]
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    #[cfg(feature = "ring")]
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}
