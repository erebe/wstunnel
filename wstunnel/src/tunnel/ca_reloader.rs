use arc_swap::ArcSwap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio_rustls::rustls::RootCertStore;
use tracing::{debug, warn};

// Global thread-safe store for system CA certificates
static SYSTEM_ROOT_STORE: LazyLock<ArcSwap<RootCertStore>> = LazyLock::new(|| {
    SystemCaReloader::init_crypto_provider();
    ArcSwap::from_pointee(SystemCaReloader::load_system_ca_certs())
});

/// Get the global system root store
pub fn get_root_store() -> Arc<RootCertStore> {
    SYSTEM_ROOT_STORE.load().clone()
}

pub struct SystemCaReloader;

impl SystemCaReloader {
    /// Spawn a background task to periodically reload system CA certificates
    pub fn start(interval: Option<Duration>) -> tokio::task::JoinHandle<()> {
        let interval = interval.unwrap_or(Duration::from_secs(3600));
        let _ = get_root_store();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Skip first tick as it is loaded by LazyLock on first use
            ticker.tick().await;

            loop {
                ticker.tick().await;
                let new_store = Self::load_system_ca_certs();
                SYSTEM_ROOT_STORE.store(Arc::new(new_store));
                debug!("System CA certificates reloaded successfully");
            }
        })
    }

    /// Safely initializes the process-wide default CryptoProvider exactly once
    fn init_crypto_provider() {
        #[cfg(feature = "aws-lc-rs")]
        {
            if tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .is_err()
            {
                #[cfg(feature = "ring")]
                let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
            }
        }
        #[cfg(all(not(feature = "aws-lc-rs"), feature = "ring"))]
        {
            let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        }
    }

    /// Helper function to load system certificates into a RootCertStore
    fn load_system_ca_certs() -> RootCertStore {
        let mut root_store = RootCertStore::empty();
        let certs = rustls_native_certs::load_native_certs();
        certs.errors.iter().for_each(|err| {
            warn!("cannot load system some system certificates: {err}");
        });
        for cert in certs.certs {
            if let Err(err) = root_store.add(cert) {
                warn!("cannot load a system certificate: {err:?}");
                continue;
            }
        }
        root_store
    }
}
