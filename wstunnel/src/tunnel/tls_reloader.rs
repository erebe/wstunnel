use crate::protocols::tls;
use crate::tunnel::client::WsClientConfig;
use crate::tunnel::server::WsServerConfig;
use crate::tunnel::tls_reloader::TlsReloaderState::{Client, Server};
use anyhow::Context;
use log::trace;
use notify::{Config, EventKind, PollWatcher, RecommendedWatcher, Watcher};
use parking_lot::Mutex;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{error, info, warn};

/// Build a content-comparing [`PollWatcher`] and register the given paths on it.
///
/// The inotify [`RecommendedWatcher`] watches inodes, so it misses certbot-style renewals that
/// atomically swap the `live/` symlink to a brand new file in `archive/` (the watched inode is
/// never modified, so no event fires). The `PollWatcher` re-reads the symlink-resolved paths on
/// an interval and, with `compare_contents`, emits a `Modify` event whenever the bytes change —
/// feeding the exact same event handlers as the inotify watcher.
fn poll_watcher<F: notify::EventHandler>(handler: F, paths: &[&Path]) -> anyhow::Result<PollWatcher> {
    const POLL_INTERVAL: Duration = Duration::from_mins(5);

    let config = Config::default()
        .with_poll_interval(POLL_INTERVAL)
        .with_compare_contents(true);
    let mut watcher = PollWatcher::new(handler, config).with_context(|| "Cannot create tls certificate poll watcher")?;
    for path in paths {
        watcher.watch(path, notify::RecursiveMode::NonRecursive)?;
    }
    Ok(watcher)
}

struct TlsReloaderServerState {
    fs_watcher: Mutex<RecommendedWatcher>,
    poll_watcher: Mutex<PollWatcher>,
    tls_reload_certificate: AtomicBool,
    server_config: Arc<WsServerConfig>,
    cert_path: PathBuf,
    key_path: PathBuf,
    client_ca_path: Option<PathBuf>,
}

impl TlsReloaderServerState {
    /// Re-read the certificate from disk and swap it into the shared config, flagging a reload.
    fn reload_cert(&self) -> anyhow::Result<()> {
        let tls = self.server_config.tls.as_ref().unwrap();
        let tls_certs = tls::load_certificates_from_pem(&self.cert_path)?;
        *tls.tls_certificate.lock() = tls_certs;
        self.tls_reload_certificate.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Re-read the private key from disk and swap it into the shared config, flagging a reload.
    fn reload_key(&self) -> anyhow::Result<()> {
        let tls = self.server_config.tls.as_ref().unwrap();
        let tls_key = tls::load_private_key_from_file(&self.key_path)?;
        *tls.tls_key.lock() = tls_key;
        self.tls_reload_certificate.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Re-read the client CA certificates from disk and swap them into the shared config.
    fn reload_client_ca(&self) -> anyhow::Result<()> {
        let Some(client_ca_path) = &self.client_ca_path else {
            return Ok(());
        };
        let tls = self.server_config.tls.as_ref().unwrap();
        let tls_certs = tls::load_certificates_from_pem(client_ca_path)?;
        if let Some(client_certs) = &tls.tls_client_ca_certificates {
            *client_certs.lock() = tls_certs;
            self.tls_reload_certificate.store(true, Ordering::Relaxed);
        }
        Ok(())
    }
}

struct TlsReloaderClientState {
    fs_watcher: Mutex<RecommendedWatcher>,
    poll_watcher: Mutex<PollWatcher>,
    tls_reload_certificate: AtomicBool,
    client_config: Arc<WsClientConfig>,
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl TlsReloaderClientState {
    /// Re-read the certificate and private key from disk and rebuild the TLS connector.
    fn reload(&self) -> anyhow::Result<()> {
        let tls = self.client_config.remote_addr.tls().unwrap();
        let tls_certs = tls::load_certificates_from_pem(&self.cert_path)?;
        let tls_key = tls::load_private_key_from_file(&self.key_path)?;
        let tls_connector = tls::tls_connector(
            tls.tls_verify_certificate,
            self.client_config.remote_addr.scheme().alpn_protocols(),
            !tls.tls_sni_disabled,
            None,
            Some(tls_certs),
            Some(tls_key),
        )?;
        *tls.tls_connector.write() = tls_connector;
        self.tls_reload_certificate.store(true, Ordering::Relaxed);
        Ok(())
    }
}

enum TlsReloaderState {
    Empty,
    Server(Arc<TlsReloaderServerState>),
    Client(Arc<TlsReloaderClientState>),
}

impl TlsReloaderState {
    fn fs_watcher(&self) -> &Mutex<RecommendedWatcher> {
        match self {
            Self::Empty => unreachable!(),
            Server(this) => &this.fs_watcher,
            Client(this) => &this.fs_watcher,
        }
    }
}

pub struct TlsReloader {
    state: TlsReloaderState,
}

impl TlsReloader {
    pub fn new_for_server(server_config: Arc<WsServerConfig>) -> anyhow::Result<Self> {
        // If there is no custom certificate and private key, there is nothing to watch
        let Some((Some(cert_path), Some(key_path), client_ca_certs)) = server_config
            .tls
            .as_ref()
            .map(|t| (&t.tls_certificate_path, &t.tls_key_path, &t.tls_client_ca_certs_path))
        else {
            return Ok(Self {
                state: TlsReloaderState::Empty,
            });
        };

        let this = Arc::new(TlsReloaderServerState {
            fs_watcher: Mutex::new(notify::recommended_watcher(|_| {})?),
            // Placeholder replaced below; manual polling so its idle thread blocks instead of ticking.
            poll_watcher: Mutex::new(PollWatcher::new(|_| {}, Config::default().with_manual_polling())?),
            tls_reload_certificate: AtomicBool::new(false),
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
            client_ca_path: client_ca_certs.as_ref().map(|x| x.to_path_buf()),
            server_config,
        });

        info!("Starting to watch tls certificates and private key for changes to reload them");
        let mut paths = vec![this.cert_path.as_path(), this.key_path.as_path()];
        if let Some(client_ca_path) = &this.client_ca_path {
            paths.push(client_ca_path.as_path());
        }

        // inotify watcher: instant reload on in-place file writes.
        let mut watcher = notify::recommended_watcher({
            let this = Server(this.clone());

            move |event: notify::Result<notify::Event>| Self::handle_server_fs_event(&this, event)
        })
        .with_context(|| "Cannot create tls certificate watcher")?;
        for path in &paths {
            watcher.watch(path, notify::RecursiveMode::NonRecursive)?;
        }
        *this.fs_watcher.lock() = watcher;

        // Poll watcher: fallback catching renewals inotify misses (e.g. certbot symlink swaps).
        let poll_watcher = poll_watcher(
            {
                let this = Server(this.clone());
                move |event: notify::Result<notify::Event>| Self::handle_server_fs_event(&this, event)
            },
            &paths,
        )?;
        *this.poll_watcher.lock() = poll_watcher;

        Ok(Self { state: Server(this) })
    }

    pub fn new_for_client(client_config: Arc<WsClientConfig>) -> anyhow::Result<Self> {
        // If there is no custom certificate and private key, there is nothing to watch
        let Some((Some(cert_path), Some(key_path))) = client_config
            .remote_addr
            .tls()
            .map(|t| (&t.tls_certificate_path, &t.tls_key_path))
        else {
            return Ok(Self {
                state: TlsReloaderState::Empty,
            });
        };

        let this = Arc::new(TlsReloaderClientState {
            fs_watcher: Mutex::new(notify::recommended_watcher(|_| {})?),
            // Placeholder replaced below; manual polling so its idle thread blocks instead of ticking.
            poll_watcher: Mutex::new(PollWatcher::new(|_| {}, Config::default().with_manual_polling())?),
            tls_reload_certificate: AtomicBool::new(false),
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
            client_config,
        });

        info!("Starting to watch tls certificates and private key for changes to reload them");
        let paths = [this.cert_path.as_path(), this.key_path.as_path()];

        // inotify watcher: instant reload on in-place file writes.
        let mut watcher = notify::recommended_watcher({
            let this = Client(this.clone());

            move |event: notify::Result<notify::Event>| Self::handle_client_fs_event(&this, event)
        })
        .with_context(|| "Cannot create tls certificate watcher")?;
        for path in &paths {
            watcher.watch(path, notify::RecursiveMode::NonRecursive)?;
        }
        *this.fs_watcher.lock() = watcher;

        // Poll watcher: fallback catching renewals inotify misses (e.g. certbot symlink swaps).
        let poll_watcher = poll_watcher(
            {
                let this = Client(this.clone());
                move |event: notify::Result<notify::Event>| Self::handle_client_fs_event(&this, event)
            },
            &paths,
        )?;
        *this.poll_watcher.lock() = poll_watcher;

        Ok(Self { state: Client(this) })
    }

    #[inline]
    pub fn should_reload_certificate(&self) -> bool {
        match &self.state {
            TlsReloaderState::Empty => false,
            Server(this) => this.tls_reload_certificate.swap(false, Ordering::Relaxed),
            Client(this) => this.tls_reload_certificate.swap(false, Ordering::Relaxed),
        }
    }

    fn try_rewatch_certificate(this: TlsReloaderState, path: PathBuf) {
        thread::spawn(move || {
            while !path.exists() {
                warn!("TLS file {:?} does not exist anymore, waiting for it to be created", path);
                thread::sleep(Duration::from_secs(10));
            }
            let mut watcher = this.fs_watcher().lock();
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

            match &this {
                Server(_) => Self::handle_server_fs_event(&this, Ok(event)),
                Client(_) => Self::handle_client_fs_event(&this, Ok(event)),
                TlsReloaderState::Empty => {}
            }
        });
    }

    fn handle_server_fs_event(this: &TlsReloaderState, event: notify::Result<notify::Event>) {
        let this = match this {
            TlsReloaderState::Empty | Client(_) => return,
            Server(st) => st,
        };

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

        if let Some(path) = event.paths.iter().find(|p| p.ends_with(&this.cert_path)) {
            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    if let Err(err) = this.reload_cert() {
                        warn!("Error while loading TLS certificate {:?}", err);
                        Self::try_rewatch_certificate(Server(this.clone()), path.to_path_buf());
                    }
                }
                EventKind::Remove(_) => {
                    warn!("TLS certificate file has been removed, trying to re-set a watch for it");
                    Self::try_rewatch_certificate(Server(this.clone()), path.to_path_buf());
                }
                EventKind::Access(_) | EventKind::Other | EventKind::Any => {
                    trace!("Ignoring event {event:?}");
                }
            }
        }

        if let Some(path) = event.paths.iter().find(|p| p.ends_with(&this.key_path)) {
            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    if let Err(err) = this.reload_key() {
                        warn!("Error while loading TLS private key {:?}", err);
                        Self::try_rewatch_certificate(Server(this.clone()), path.to_path_buf());
                    }
                }
                EventKind::Remove(_) => {
                    warn!("TLS private key file has been removed, trying to re-set a watch for it");
                    Self::try_rewatch_certificate(Server(this.clone()), path.to_path_buf());
                }
                EventKind::Access(_) | EventKind::Other | EventKind::Any => {
                    trace!("Ignoring event {event:?}");
                }
            }
        }

        if let Some(client_ca_path) = &this.client_ca_path
            && let Some(path) = event.paths.iter().find(|p| p.ends_with(client_ca_path))
        {
            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    if let Err(err) = this.reload_client_ca() {
                        warn!("Error while loading TLS client certificate {:?}", err);
                        Self::try_rewatch_certificate(Server(this.clone()), path.to_path_buf());
                    }
                }
                EventKind::Remove(_) => {
                    warn!("TLS client certificate has been removed, trying to re-set a watch for it");
                    Self::try_rewatch_certificate(Server(this.clone()), path.to_path_buf());
                }
                EventKind::Access(_) | EventKind::Other | EventKind::Any => {
                    trace!("Ignoring event {event:?}");
                }
            }
        }
    }

    fn handle_client_fs_event(this: &TlsReloaderState, event: notify::Result<notify::Event>) {
        let this = match this {
            TlsReloaderState::Empty | Server(_) => return,
            Client(st) => st,
        };

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

        let tls = this.client_config.remote_addr.tls().unwrap();
        if let Some(path) = event.paths.iter().find(|p| p.ends_with(&this.cert_path)) {
            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    if let Err(err) = this.reload() {
                        warn!("Error while loading TLS certificate {:?}", err);
                        Self::try_rewatch_certificate(Client(this.clone()), path.to_path_buf());
                    }
                }
                EventKind::Remove(_) => {
                    warn!("TLS certificate file has been removed, trying to re-set a watch for it");
                    Self::try_rewatch_certificate(Client(this.clone()), path.to_path_buf());
                }
                EventKind::Access(_) | EventKind::Other | EventKind::Any => {
                    trace!("Ignoring event {event:?}");
                }
            }
        }

        if let Some(path) = event
            .paths
            .iter()
            .find(|p| p.ends_with(tls.tls_key_path.as_ref().unwrap()))
        {
            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    if let Err(err) = this.reload() {
                        warn!("Error while loading TLS private key {:?}", err);
                        Self::try_rewatch_certificate(Client(this.clone()), path.to_path_buf());
                    }
                }
                EventKind::Remove(_) => {
                    warn!("TLS private key file has been removed, trying to re-set a watch for it");
                    Self::try_rewatch_certificate(Client(this.clone()), path.to_path_buf());
                }
                EventKind::Access(_) | EventKind::Other | EventKind::Any => {
                    trace!("Ignoring event {event:?}");
                }
            }
        }
    }
}
