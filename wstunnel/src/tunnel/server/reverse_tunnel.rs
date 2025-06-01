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
use tokio::task::AbortHandle;
use tokio::{select, time};
use tracing::{Instrument, Span, info};

struct ReverseTunnelItem<T: TunnelListener> {
    #[allow(clippy::type_complexity)]
    receiver: async_channel::Receiver<((<T as TunnelListener>::Reader, <T as TunnelListener>::Writer), RemoteAddr)>,
    nb_seen_clients: Arc<AtomicUsize>,
    server_task: AbortHandle,
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

impl<T: TunnelListener> Drop for ReverseTunnelItem<T> {
    fn drop(&mut self) {
        self.server_task.abort();
    }
}

pub struct ReverseTunnelServer<T: TunnelListener> {
    servers: Arc<Mutex<AHashMap<SocketAddr, ReverseTunnelItem<T>>>>,
}

impl<T: TunnelListener> ReverseTunnelServer<T> {
    pub fn new() -> Self {
        Self {
            servers: Arc::new(Mutex::new(AHashMap::with_capacity(1))),
        }
    }

    pub async fn run_listening_server(
        &self,
        executor: &impl TokioExecutorRef,
        bind_addr: SocketAddr,
        idle_timeout: Duration,
        gen_listening_server: impl Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<((<T as TunnelListener>::Reader, <T as TunnelListener>::Writer), RemoteAddr)>
    where
        T: TunnelListener + Send + 'static,
    {
        let listening_server = self
            .servers
            .lock()
            .get(&bind_addr)
            .map(|server| server.get_cnx_awaiter());
        let cnx = if let Some(listening_server) = listening_server {
            listening_server
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
                                    if time::timeout(idle_timeout, tx.send(cnx)).await.is_err() {
                                        info!("New reverse connection failed to be picked by client after {}s. Closing reverse tunnel server", idle_timeout.as_secs());
                                        break;
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
            }.instrument(Span::current());

            let item = ReverseTunnelItem {
                receiver: rx,
                nb_seen_clients,
                server_task: executor.spawn(fut),
            };
            let cnx_awaiter = item.get_cnx_awaiter();
            self.servers.lock().insert(bind_addr, item);
            cnx_awaiter
        };

        let cnx = cnx
            .recv()
            .await
            .map_err(|_| anyhow!("listening reverse server stopped"))?;
        Ok(cnx)
    }
}
