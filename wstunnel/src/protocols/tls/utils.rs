use tokio_rustls::rustls::pki_types::CertificateDer;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::X509Certificate;

/// Find a leaf certificate in a vector of certificates. It is assumed only a single leaf certificate
/// is present in the vector. The other certificates should be (intermediate) CA certificates.
pub fn find_leaf_certificate<'a>(tls_certificates: &'a [CertificateDer<'static>]) -> Option<X509Certificate<'a>> {
    for tls_certificate in tls_certificates {
        if let Ok((_, tls_certificate_x509)) = parse_x509_certificate(tls_certificate)
            && !tls_certificate_x509.is_ca()
        {
            return Some(tls_certificate_x509);
        }
    }
    None
}

/// Returns the common name (CN) as specified in the supplied certificate.
pub fn cn_from_certificate(tls_certificate_x509: &X509Certificate) -> Option<String> {
    tls_certificate_x509
        .tbs_certificate
        .subject
        .iter_common_name()
        .flat_map(|cn| cn.as_str().ok())
        .next()
        .map(|cn| cn.to_string())
}
