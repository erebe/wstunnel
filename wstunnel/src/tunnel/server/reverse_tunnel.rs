use crate::executor::TokioExecutorRef;
use crate::tunnel::RemoteAddr;
use crate::tunnel::listeners::TunnelListener;
use ahash::AHashMap;
use anyhow::anyhow;
use futures_util::{StreamExt, pin_mut};
use log::warn;
use parking_lot::Mutex;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::task::AbortHandle;
use tokio::{select, time};
use tracing::{Instrument, Span, info};

struct ReverseTunnelItem<T: TunnelListener> {
    #[allow(clippy::type_complexity)]
    receiver: async_channel::Receiver<((<T as TunnelListener>::Reader, <T as TunnelListener>::Writer), RemoteAddr)>,
    nb_seen_clients: Arc<AtomicUsize>,
    server_task: AbortHandle,
    sessions: Arc<Mutex<AHashMap<usize, Arc<Notify>>>>,
}

impl<T: TunnelListener> Clone for ReverseTunnelItem<T> {
    fn clone(&self) -> Self {
        Self {
            receiver: self.receiver.clone(),
            nb_seen_clients: self.nb_seen_clients.clone(),
            server_task: self.server_task.clone(),
            sessions: self.sessions.clone(),
        }
    }
}

impl<T: TunnelListener> ReverseTunnelItem<T> {
    #[allow(clippy::type_complexity)]
    pub fn get_cnx_awaiter(
        &self,
    ) -> async_channel::Receiver<((<T as TunnelListener>::Reader, <T as TunnelListener>::Writer), RemoteAddr)> {
        self.nb_seen_clients.fetch_add(1, Ordering::Relaxed);
        self.receiver.clone()
    }
}

pub struct ReverseTunnelServer<T: TunnelListener> {
    servers: Arc<Mutex<AHashMap<SocketAddr, ReverseTunnelItem<T>>>>,
    binding_locks: Arc<Mutex<AHashMap<SocketAddr, Arc<tokio::sync::Mutex<()>>>>>,
}

impl<T: TunnelListener> ReverseTunnelServer<T> {
    pub fn new() -> Self {
        Self {
            servers: Arc::new(Mutex::new(AHashMap::with_capacity(1))),
            binding_locks: Arc::new(Mutex::new(AHashMap::new())),
        }
    }

    pub async fn run_listening_server(
        &self,
        executor: &impl TokioExecutorRef,
        bind_addr: SocketAddr,
        idle_timeout: Duration,
        gen_listening_server: impl Future<Output = anyhow::Result<T>>,
        conn_id: usize,
    ) -> anyhow::Result<(
        ((<T as TunnelListener>::Reader, <T as TunnelListener>::Writer), RemoteAddr),
        Arc<Notify>,
    )>
    where
        T: TunnelListener + Send + 'static,
    {
        let bind_lock = {
            let mut locks = self.binding_locks.lock();
            locks
                .entry(bind_addr)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _guard = bind_lock.lock().await;

        let item = self.servers.lock().get(&bind_addr).cloned();
        let (cnx_awaiter, session_notify) = if let Some(item) = item {
            {
                let mut sessions = item.sessions.lock();
                let keys: Vec<_> = sessions.keys().cloned().collect();
                for id in keys {
                    if id != conn_id
                        && let Some(notify) = sessions.remove(&id) {
                            notify.notify_waiters();
                        }
                }
                let notify = sessions
                    .entry(conn_id)
                    .or_insert_with(|| Arc::new(Notify::new()))
                    .clone();

                let cnx_awaiter = item.get_cnx_awaiter();
                (cnx_awaiter, notify)
            }
        } else {
            let listening_server = gen_listening_server.await?;
            let (tx, rx) = async_channel::bounded(10);
            let nb_seen_clients = Arc::new(AtomicUsize::new(0));
            let seen_clients = nb_seen_clients.clone();
            let server = self.servers.clone();
            let local_srv2 = bind_addr;

            let fut = async move {
                scopeguard::defer!({
                    server.lock().remove(&local_srv2);
                });

                let mut timer = time::interval(idle_timeout);
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
                                    match time::timeout(idle_timeout, tx.send(cnx)).await {
                                        Ok(Ok(())) => {}
                                        Ok(Err(_)) => {
                                            info!("All clients disconnected. Closing reverse tunnel server");
                                            break;
                                        }
                                        Err(_) => {
                                            info!(
                                                "New reverse connection failed to be picked by client after {}s. Closing reverse tunnel server",
                                                idle_timeout.as_secs()
                                            );
                                            break;
                                        }
                                    }
                                }
                            }
                        },
                        _ = timer.tick() => {

                            // if no client connected to the reverse tunnel server, close it
                            // <= 1 because the server itself has a receiver
                            if seen_clients.swap(0, Ordering::Relaxed) == 0 && tx.receiver_count() <= 1 {
                                info!("No client connected to reverse tunnel server for {}s. Closing reverse tunnel server", idle_timeout.as_secs());
                                break;
                            }
                        },
                    }
                }
                info!("Stopping listening reverse server");
            }
            .instrument(Span::current());

            let sessions = Arc::new(Mutex::new(AHashMap::new()));
            let notify = Arc::new(Notify::new());
            sessions.lock().insert(conn_id, notify.clone());

            let item = ReverseTunnelItem {
                receiver: rx,
                nb_seen_clients,
                server_task: executor.spawn(fut),
                sessions,
            };
            let cnx_awaiter = item.get_cnx_awaiter();
            self.servers.lock().insert(bind_addr, item);
            (cnx_awaiter, notify)
        };

        let cnx = cnx_awaiter
            .recv()
            .await
            .map_err(|_| anyhow!("listening reverse server stopped"))?;
        Ok((cnx, session_notify))
    }
}
