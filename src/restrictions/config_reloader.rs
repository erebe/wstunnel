use super::types::RestrictionsRules;
use crate::restrictions::config_reloader::RestrictionsRulesReloaderState::{Config, Static};
use anyhow::Context;
use log::trace;
use notify::{EventKind, RecommendedWatcher, Watcher};
use parking_lot::Mutex;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::sync::futures::Notified;
use tokio::sync::Notify;
use tracing::{error, info, warn};

struct ConfigReloaderState {
    fs_watcher: Mutex<RecommendedWatcher>,
    config_path: PathBuf,
    should_reload_config: Notify,
}

enum RestrictionsRulesReloaderState {
    Static(Notify),
    Config(Arc<ConfigReloaderState>),
}

impl RestrictionsRulesReloaderState {
    fn fs_watcher(&self) -> &Mutex<RecommendedWatcher> {
        match self {
            Static(_) => unreachable!(),
            Config(this) => &this.fs_watcher,
        }
    }
}

pub struct RestrictionsRulesReloader {
    state: RestrictionsRulesReloaderState,
    restrictions: Arc<RestrictionsRules>,
}

impl RestrictionsRulesReloader {
    pub fn new(restrictions_rules: RestrictionsRules, config_path: Option<PathBuf>) -> anyhow::Result<Self> {
        // If there is no custom certificate and private key, there is nothing to watch
        let config_path = if let Some(config_path) = config_path {
            config_path
        } else {
            return Ok(Self {
                state: Static(Notify::new()),
                restrictions: Arc::new(restrictions_rules),
            });
        };

        let this = Arc::new(ConfigReloaderState {
            fs_watcher: Mutex::new(notify::recommended_watcher(|_| {})?),
            should_reload_config: Notify::new(),
            config_path,
        });

        info!("Starting to watch restriction config file for changes to reload them");
        let mut watcher = notify::recommended_watcher({
            let this = Config(this.clone());

            move |event: notify::Result<notify::Event>| Self::handle_config_fs_event(&this, event)
        })
        .with_context(|| "Cannot create restriction config watcher")?;

        watcher.watch(&this.config_path, notify::RecursiveMode::NonRecursive)?;
        *this.fs_watcher.lock() = watcher;

        Ok(Self {
            state: Config(this),
            restrictions: Arc::new(restrictions_rules),
        })
    }

    pub fn reload_restrictions_config(&mut self) {
        let restrictions = match &self.state {
            Static(_) => return,
            Config(st) => match RestrictionsRules::from_config_file(&st.config_path) {
                Ok(restrictions) => {
                    info!("Restrictions config file has been reloaded");
                    restrictions
                }
                Err(err) => {
                    error!("Cannot reload restrictions config file, keeping the old one. Error: {:?}", err);
                    return;
                }
            },
        };

        self.restrictions = Arc::new(restrictions);
    }

    pub fn restrictions_rules(&self) -> &Arc<RestrictionsRules> {
        &self.restrictions
    }

    pub fn wait_for_reload(&self) -> Notified {
        match &self.state {
            Static(st) => st.notified(),
            Config(st) => st.should_reload_config.notified(),
        }
    }

    fn try_rewatch_config(this: RestrictionsRulesReloaderState, path: PathBuf) {
        thread::spawn(move || {
            while !path.exists() {
                warn!(
                    "Restrictions config file {:?} does not exist anymore, waiting for it to be created",
                    path
                );
                thread::sleep(Duration::from_secs(10));
            }
            let mut watcher = this.fs_watcher().lock();
            let _ = watcher.unwatch(&path);
            let Ok(_) = watcher
                .watch(&path, notify::RecursiveMode::NonRecursive)
                .map_err(|err| {
                    error!("Cannot re-set a watch for Restriction config file {:?}: {:?}", path, err);
                    error!("Restriction config file will not be auto-reloaded anymore");
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
                Static(_) => Self::handle_config_fs_event(&this, Ok(event)),
                Config(_) => Self::handle_config_fs_event(&this, Ok(event)),
            }
        });
    }

    fn handle_config_fs_event(this: &RestrictionsRulesReloaderState, event: notify::Result<notify::Event>) {
        let this = match this {
            Static(_) => return,
            Config(st) => st,
        };

        let event = match event {
            Ok(event) => event,
            Err(err) => {
                error!("Error while watching restrictions config file for changes {:?}", err);
                return;
            }
        };

        if event.kind.is_access() {
            return;
        }

        trace!("Received event: {:#?}", event);
        if let Some(path) = event.paths.iter().find(|p| p.ends_with(&this.config_path)) {
            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    this.should_reload_config.notify_one();
                }
                EventKind::Remove(_) => {
                    warn!("Restriction config file has been removed, trying to re-set a watch for it");
                    Self::try_rewatch_config(Config(this.clone()), path.to_path_buf());
                }
                EventKind::Access(_) | EventKind::Other | EventKind::Any => {
                    trace!("Ignoring event {:?}", event);
                }
            }
        }
    }
}
