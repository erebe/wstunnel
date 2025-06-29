use super::types::RestrictionsRules;
use crate::restrictions::config_reloader::RestrictionsRulesReloaderState::{Config, Static};
use anyhow::Context;
use arc_swap::ArcSwap;
use log::trace;
use notify::{EventKind, RecommendedWatcher, Watcher};
use parking_lot::Mutex;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{error, info, warn};

struct ConfigReloaderState {
    fs_watcher: Mutex<RecommendedWatcher>,
    config_path: PathBuf,
}

#[derive(Clone)]
enum RestrictionsRulesReloaderState {
    Static,
    Config(Arc<ConfigReloaderState>),
}

impl RestrictionsRulesReloaderState {
    fn fs_watcher(&self) -> &Mutex<RecommendedWatcher> {
        match self {
            Static => unreachable!(),
            Config(this) => &this.fs_watcher,
        }
    }
}

#[derive(Clone)]
pub struct RestrictionsRulesReloader {
    state: RestrictionsRulesReloaderState,
    restrictions: Arc<ArcSwap<RestrictionsRules>>,
}

impl RestrictionsRulesReloader {
    pub fn new(restrictions_rules: RestrictionsRules, config_path: Option<PathBuf>) -> anyhow::Result<Self> {
        // If there is no custom certificate and private key, there is nothing to watch
        let config_path = if let Some(config_path) = config_path {
            config_path
        } else {
            return Ok(Self {
                state: Static,
                restrictions: Arc::new(ArcSwap::from_pointee(restrictions_rules)),
            });
        };
        let reloader = Self {
            state: Config(Arc::new(ConfigReloaderState {
                fs_watcher: Mutex::new(notify::recommended_watcher(|_| {})?),
                config_path,
            })),
            restrictions: Arc::new(ArcSwap::from_pointee(restrictions_rules)),
        };

        info!("Starting to watch restriction config file for changes to reload them");
        let mut watcher = notify::recommended_watcher({
            let reloader = reloader.clone();

            move |event: notify::Result<notify::Event>| Self::handle_config_fs_event(&reloader, event)
        })
        .with_context(|| "Cannot create restriction config watcher")?;

        match &reloader.state {
            Static => {}
            Config(cfg) => {
                watcher.watch(&cfg.config_path, notify::RecursiveMode::NonRecursive)?;
                *cfg.fs_watcher.lock() = watcher
            }
        }

        Ok(reloader)
    }

    pub fn reload_restrictions_config(&self) {
        let restrictions = match &self.state {
            Static => return,
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

        self.restrictions.store(Arc::new(restrictions));
    }

    pub const fn restrictions_rules(&self) -> &Arc<ArcSwap<RestrictionsRules>> {
        &self.restrictions
    }

    fn try_rewatch_config(this: RestrictionsRulesReloader, path: PathBuf) {
        thread::spawn(move || {
            while !path.exists() {
                warn!(
                    "Restrictions config file {:?} does not exist anymore, waiting for it to be created",
                    path
                );
                thread::sleep(Duration::from_secs(10));
            }
            let mut watcher = this.state.fs_watcher().lock();
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

            // Generate a fake event to force-reload the config
            let event = notify::Event {
                kind: EventKind::Create(notify::event::CreateKind::Any),
                paths: vec![path],
                attrs: Default::default(),
            };

            Self::handle_config_fs_event(&this, Ok(event))
        });
    }

    fn handle_config_fs_event(reloader: &RestrictionsRulesReloader, event: notify::Result<notify::Event>) {
        let this = match &reloader.state {
            Static => return,
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

        trace!("Received event: {event:#?}");
        if let Some(path) = event.paths.iter().find(|p| p.ends_with(&this.config_path)) {
            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    reloader.reload_restrictions_config();
                }
                EventKind::Remove(_) => {
                    warn!("Restriction config file has been removed, trying to re-set a watch for it");
                    Self::try_rewatch_config(reloader.clone(), path.to_path_buf());
                }
                EventKind::Access(_) | EventKind::Other | EventKind::Any => {
                    trace!("Ignoring event {event:?}");
                }
            }
        }
    }
}
