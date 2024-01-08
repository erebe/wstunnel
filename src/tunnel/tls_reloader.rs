use crate::{tls, WsServerConfig};
use anyhow::Context;
use log::trace;
use notify::{EventKind, RecommendedWatcher, Watcher};
use parking_lot::Mutex;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{error, info, warn};

struct TlsReloaderState {
    fs_watcher: Mutex<RecommendedWatcher>,
    tls_reload_certificate: AtomicBool,
    server_config: Arc<WsServerConfig>,
    cert_path: PathBuf,
    key_path: PathBuf,
}
pub struct TlsReloader {
    state: Option<Arc<TlsReloaderState>>,
}

impl TlsReloader {
    pub fn new(server_config: Arc<WsServerConfig>) -> anyhow::Result<Self> {
        // If there is no custom certificate and private key, there is nothing to watch
        let Some((Some(cert_path), Some(key_path))) = server_config
            .tls
            .as_ref()
            .map(|t| (&t.tls_certificate_path, &t.tls_key_path))
        else {
            return Ok(Self { state: None });
        };

        let this = Arc::new(TlsReloaderState {
            fs_watcher: Mutex::new(notify::recommended_watcher(|_| {})?),
            tls_reload_certificate: AtomicBool::new(false),
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
            server_config,
        });

        info!("Starting to watch tls certificate and private key for changes to reload them");
        let mut watcher = notify::recommended_watcher({
            let this = this.clone();

            move |event: notify::Result<notify::Event>| Self::handle_fs_event(&this, event)
        })
        .with_context(|| "Cannot create tls certificate watcher")?;

        watcher.watch(&this.cert_path, notify::RecursiveMode::NonRecursive)?;
        watcher.watch(&this.key_path, notify::RecursiveMode::NonRecursive)?;
        *this.fs_watcher.lock() = watcher;

        Ok(Self { state: Some(this) })
    }

    #[inline]
    pub fn should_reload_certificate(&self) -> bool {
        match &self.state {
            None => false,
            Some(this) => this.tls_reload_certificate.swap(false, Ordering::Relaxed),
        }
    }

    fn try_rewatch_certificate(this: Arc<TlsReloaderState>, path: PathBuf) {
        thread::spawn(move || {
            while !path.exists() {
                warn!("TLS file {:?} does not exist anymore, waiting for it to be created", path);
                thread::sleep(Duration::from_secs(10));
            }
            let mut watcher = this.fs_watcher.lock();
            let _ = watcher.unwatch(&path);
            let Ok(_) = watcher
                .watch(&path, notify::RecursiveMode::NonRecursive)
                .map_err(|err| {
                    error!("Cannot re-set a watch for TLS file {:?}: {:?}", path, err);
                    error!("TLS certificate will not be auto-reloaded anymore");
                })
            else {
                return;
            };
            drop(watcher);

            // Generate a fake event to force-reload the certificate
            let event = notify::Event {
                kind: EventKind::Create(notify::event::CreateKind::Any),
                paths: vec![path],
                attrs: Default::default(),
            };
            Self::handle_fs_event(&this, Ok(event));
        });
    }

    fn handle_fs_event(this: &Arc<TlsReloaderState>, event: notify::Result<notify::Event>) {
        let event = match event {
            Ok(event) => event,
            Err(err) => {
                error!("Error while watching tls certificate and private key for changes {:?}", err);
                return;
            }
        };

        if event.kind.is_access() {
            return;
        }

        let tls = this.server_config.tls.as_ref().unwrap();
        if let Some(path) = event.paths.iter().find(|p| p.ends_with(&this.cert_path)) {
            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => match tls::load_certificates_from_pem(&this.cert_path) {
                    Ok(tls_certs) => {
                        *tls.tls_certificate.lock() = tls_certs;
                        this.tls_reload_certificate.store(true, Ordering::Relaxed);
                    }
                    Err(err) => {
                        warn!("Error while loading TLS certificate {:?}", err);
                        Self::try_rewatch_certificate(this.clone(), path.to_path_buf());
                    }
                },
                EventKind::Remove(_) => {
                    warn!("TLS certificate file has been removed, trying to re-set a watch for it");
                    Self::try_rewatch_certificate(this.clone(), path.to_path_buf());
                }
                EventKind::Access(_) | EventKind::Other | EventKind::Any => {
                    trace!("Ignoring event {:?}", event);
                }
            }
        }

        if let Some(path) = event.paths.iter().find(|p| p.ends_with(&this.key_path)) {
            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => match tls::load_private_key_from_file(&this.key_path) {
                    Ok(tls_key) => {
                        *tls.tls_key.lock() = tls_key;
                        this.tls_reload_certificate.store(true, Ordering::Relaxed);
                    }
                    Err(err) => {
                        warn!("Error while loading TLS private key {:?}", err);
                        Self::try_rewatch_certificate(this.clone(), path.to_path_buf());
                    }
                },
                EventKind::Remove(_) => {
                    warn!("TLS private key file has been removed, trying to re-set a watch for it");
                    Self::try_rewatch_certificate(this.clone(), path.to_path_buf());
                }
                EventKind::Access(_) | EventKind::Other | EventKind::Any => {
                    trace!("Ignoring event {:?}", event);
                }
            }
        }
    }
}
