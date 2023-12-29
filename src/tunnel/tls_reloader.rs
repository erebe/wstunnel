use crate::{tls, WsServerConfig};
use anyhow::Context;
use log::trace;
use notify::{EventKind, RecommendedWatcher, Watcher};
use parking_lot::Mutex;
use std::fs::File;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};
use tracing::{error, info, warn};

pub struct TlsReloader {
    fs_watcher: Arc<Mutex<Option<RecommendedWatcher>>>,
    pub tls_reload_certificate: Arc<AtomicBool>,
}

impl TlsReloader {
    pub fn new(server_config: Arc<WsServerConfig>) -> anyhow::Result<Self> {
        let this = Self {
            fs_watcher: Arc::new(Mutex::new(None)),
            tls_reload_certificate: Arc::new(AtomicBool::new(false)),
        };

        // If there is no custom certificate and private key, there is nothing to watch
        let Some((Some(cert_path), Some(key_path))) = server_config
            .tls
            .as_ref()
            .map(|t| (&t.tls_certificate_path, &t.tls_key_path))
        else {
            return Ok(this);
        };

        info!("Starting to watch tls certificate and private key for changes to reload them");
        let tls_reload_certificate = this.tls_reload_certificate.clone();
        let watcher = this.fs_watcher.clone();
        let server_config = server_config.clone();

        let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
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

            let tls = server_config.tls.as_ref().unwrap();
            let cert_path = tls.tls_certificate_path.as_ref().unwrap();
            let key_path = tls.tls_key_path.as_ref().unwrap();

            if let Some(path) = event.paths.iter().find(|p| p.ends_with(cert_path)) {
                match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) => match tls::load_certificates_from_pem(cert_path) {
                        Ok(tls_certs) => {
                            *tls.tls_certificate.lock() = tls_certs;
                            tls_reload_certificate.store(true, Ordering::Relaxed);
                        }
                        Err(err) => {
                            warn!("Error while loading TLS certificate {:?}", err);
                        }
                    },
                    EventKind::Remove(_) => {
                        warn!("TLS certificate file has been removed, trying to re-set a watch for it");
                        Self::try_rewatch_certificate(watcher.clone(), path.to_path_buf());
                    }
                    EventKind::Access(_) | EventKind::Other | EventKind::Any => {
                        trace!("Ignoring event {:?}", event);
                    }
                }
            }

            if let Some(path) = event.paths.iter().find(|p| p.ends_with(key_path)) {
                match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) => match tls::load_private_key_from_file(key_path) {
                        Ok(tls_key) => {
                            *tls.tls_key.lock() = tls_key;
                            tls_reload_certificate.store(true, Ordering::Relaxed);
                        }
                        Err(err) => {
                            warn!("Error while loading TLS private key {:?}", err);
                        }
                    },
                    EventKind::Remove(_) => {
                        warn!("TLS private key file has been removed, trying to re-set a watch for it");
                        Self::try_rewatch_certificate(watcher.clone(), path.to_path_buf());
                    }
                    EventKind::Access(_) | EventKind::Other | EventKind::Any => {
                        trace!("Ignoring event {:?}", event);
                    }
                }
            }
        })
        .with_context(|| "Cannot create tls certificate watcher")?;

        watcher.watch(cert_path, notify::RecursiveMode::NonRecursive)?;
        watcher.watch(key_path, notify::RecursiveMode::NonRecursive)?;
        *this.fs_watcher.lock() = Some(watcher);

        Ok(this)
    }

    fn try_rewatch_certificate(watcher: Arc<Mutex<Option<RecommendedWatcher>>>, path: PathBuf) {
        thread::spawn(move || {
            while !path.exists() {
                warn!("TLS file {:?} does not exist anymore, waiting for it to be created", path);
                thread::sleep(Duration::from_secs(10));
            }
            let mut watcher = watcher.lock();
            let _ = watcher.as_mut().unwrap().unwatch(&path);
            let Ok(_) = watcher
                .as_mut()
                .unwrap()
                .watch(&path, notify::RecursiveMode::NonRecursive)
                .map_err(|err| {
                    error!("Cannot re-set a watch for TLS file {:?}: {:?}", path, err);
                    error!("TLS certificate will not be auto-reloaded anymore");
                })
            else {
                return;
            };

            let Ok(file) = File::open(&path) else {
                return;
            };
            let _ = file.set_modified(SystemTime::now()).map_err(|err| {
                error!("Cannot force reload TLS file {:?}:  {:?}", path, err);
                error!("Old certificate will be used until the next change");
            });
        });
    }
}
