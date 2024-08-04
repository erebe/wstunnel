use crate::tunnel::listeners::TunnelListener;
use crate::tunnel::RemoteAddr;
use ahash::{HashMap, HashMapExt};
use anyhow::anyhow;
use futures_util::{pin_mut, StreamExt};
use log::warn;
use parking_lot::Mutex;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::{select, time};
use tracing::{info, Instrument, Span};

struct ReverseTunnelItem<T: TunnelListener> {
    #[allow(clippy::type_complexity)]
    receiver: async_channel::Receiver<((<T as TunnelListener>::Reader, <T as TunnelListener>::Writer), RemoteAddr)>,
    nb_seen_clients: Arc<AtomicUsize>,
}

impl<T: TunnelListener> Clone for ReverseTunnelItem<T> {
    fn clone(&self) -> Self {
        Self {
            receiver: self.receiver.clone(),
            nb_seen_clients: self.nb_seen_clients.clone(),
        }
    }
}

pub struct ReverseTunnelServer<T: TunnelListener> {
    servers: Arc<Mutex<HashMap<SocketAddr, ReverseTunnelItem<T>>>>,
}

impl<T: TunnelListener> ReverseTunnelServer<T> {
    pub fn new() -> Self {
        Self {
            servers: Arc::new(Mutex::new(HashMap::with_capacity(1))),
        }
    }

    pub async fn run_listening_server(
        &self,
        bind_addr: SocketAddr,
        gen_listening_server: impl Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<((<T as TunnelListener>::Reader, <T as TunnelListener>::Writer), RemoteAddr)>
    where
        T: TunnelListener + Send + 'static,
    {
        let listening_server = self.servers.lock().get(&bind_addr).cloned();
        let item = if let Some(listening_server) = listening_server {
            listening_server
        } else {
            let listening_server = gen_listening_server.await?;
            let send_timeout = Duration::from_secs(60 * 3);
            let (tx, rx) = async_channel::bounded(10);
            let nb_seen_clients = Arc::new(AtomicUsize::new(0));
            let seen_clients = nb_seen_clients.clone();
            let server = self.servers.clone();
            let local_srv2 = bind_addr;

            let fut = async move {
                scopeguard::defer!({
                    server.lock().remove(&local_srv2);
                });

                let mut timer = time::interval(send_timeout);
                pin_mut!(listening_server);
                loop {
                    select! {
                        biased;
                        cnx = listening_server.next() => {
                           match cnx {
                                None => break,
                                Some(Err(err)) => {
                                    warn!("Error while listening for incoming connections {err:?}");
                                    continue;
                                }
                                Some(Ok(cnx)) => {
                                    if time::timeout(send_timeout, tx.send(cnx)).await.is_err() {
                                        info!("New reverse connection failed to be picked by client after {}s. Closing reverse tunnel server", send_timeout.as_secs());
                                        break;
                                    }
                                }
                            }
                        },
                        _ = timer.tick() => {

                            // if no client connected to the reverse tunnel server, close it
                            // <= 1 because the server itself has a receiver
                            if seen_clients.swap(0, Ordering::Relaxed) == 0 && tx.receiver_count() <= 1 {
                                info!("No client connected to reverse tunnel server for {}s. Closing reverse tunnel server", send_timeout.as_secs());
                                break;
                            }
                        },
                    }
                }
                info!("Stopping listening reverse server");
            };

            tokio::spawn(fut.instrument(Span::current()));
            let item = ReverseTunnelItem {
                receiver: rx,
                nb_seen_clients,
            };
            self.servers.lock().insert(bind_addr, item.clone());
            item
        };

        item.nb_seen_clients.fetch_add(1, Ordering::Relaxed);
        let cnx = item
            .receiver
            .recv()
            .await
            .map_err(|_| anyhow!("listening reverse server stopped"))?;
        Ok(cnx)
    }
}
