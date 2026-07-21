use crate::protocols::udp::WsUdpSocket;
use ahash::AHashMap;
use parking_lot::Mutex;
use std::future::Future;
use std::sync::{Arc, Weak};
use tokio::net::UdpSocket;
use uuid::Uuid;

/// Server-side registry that maps a UDP multiplexing `flow_id` to a single shared upstream UDP socket.
///
/// When a client enables `--udp-multiplex N`, it opens N tunnel connections that all carry the same
/// `flow_id`. Without this registry each connection would open its own upstream UDP socket, so the
/// destination would observe N different source ports and any stateful protocol (WireGuard, QUIC, ...)
/// would break. With the registry, the first connection of a flow creates the upstream socket and the
/// siblings reuse it, so the destination only ever sees a single 5-tuple.
///
/// Only `Weak` references are stored: the socket's lifetime is owned by the `WsUdpSocket` clones held
/// by the live tunnel connections. Once every connection of a flow is gone, the strong count drops to
/// zero and the socket is closed automatically. Dead entries are reaped opportunistically on insert.
#[derive(Clone, Default)]
pub struct UdpFlowRegistry {
    flows: Arc<Mutex<AHashMap<Uuid, Weak<UdpSocket>>>>,
}

impl UdpFlowRegistry {
    /// Return the shared socket for `flow_id`, creating it via `connect` if this is the first
    /// connection of the flow. Concurrent first-connections race-safely converge on a single socket.
    pub async fn get_or_connect<F, Fut>(&self, flow_id: Uuid, connect: F) -> anyhow::Result<WsUdpSocket>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<WsUdpSocket>>,
    {
        // Fast path: a sibling connection already created the socket.
        if let Some(socket) = self.flows.lock().get(&flow_id).and_then(Weak::upgrade) {
            return Ok(WsUdpSocket::new(socket));
        }

        // Slow path: create the upstream socket without holding the lock across the await.
        let socket = connect().await?;

        let mut flows = self.flows.lock();
        // Another connection may have won the race while we were connecting; reuse its socket.
        if let Some(existing) = flows.get(&flow_id).and_then(Weak::upgrade) {
            return Ok(WsUdpSocket::new(existing));
        }

        // Reap entries whose connections have all gone away to bound the map size.
        flows.retain(|_, weak| weak.strong_count() > 0);
        flows.insert(flow_id, socket.downgrade());

        Ok(socket)
    }
}
