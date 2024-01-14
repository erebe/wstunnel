use crate::tunnel::transport::{TunnelRead, TunnelWrite};
use bytes::BufMut;
use futures_util::{pin_mut, FutureExt};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::select;
use tokio::sync::oneshot;
use tokio::time::Instant;
use tracing::log::debug;
use tracing::{error, info, warn};

pub async fn propagate_local_to_remote(
    local_rx: impl AsyncRead,
    mut ws_tx: impl TunnelWrite,
    mut close_tx: oneshot::Sender<()>,
    ping_frequency: Option<Duration>,
) -> anyhow::Result<()> {
    let _guard = scopeguard::guard((), |_| {
        info!("Closing local => remote tunnel");
    });

    static MAX_PACKET_LENGTH: usize = 64 * 1024;

    // We do our own pin_mut! to avoid shadowing timeout and be able to reset it, on next loop iteration
    // We reuse the future to avoid creating a timer in the tight loop
    let frequency = ping_frequency.unwrap_or(Duration::from_secs(3600 * 24));
    let start_at = Instant::now().checked_add(frequency).unwrap_or(Instant::now());
    let timeout = tokio::time::interval_at(start_at, frequency);
    let should_close = close_tx.closed().fuse();

    pin_mut!(timeout);
    pin_mut!(should_close);
    pin_mut!(local_rx);
    loop {
        debug_assert!(
            ws_tx.buf_mut().chunk_mut().len() >= MAX_PACKET_LENGTH,
            "buffer must be large enough to receive a whole packet length"
        );

        let read_len = select! {
            biased;

            read_len = local_rx.read_buf(ws_tx.buf_mut()) => read_len,

            _ = &mut should_close => break,

            _ = timeout.tick(), if ping_frequency.is_some() => {
                debug!("sending ping to keep connection alive");
                ws_tx.ping().await?;
                continue;
            }
        };

        let _read_len = match read_len {
            Ok(0) => break,
            Ok(read_len) => read_len,
            Err(err) => {
                warn!("error while reading incoming bytes from local tx tunnel: {}", err);
                break;
            }
        };

        //debug!("read {} wasted {}% usable {} capa {}", read_len, 100 - (read_len * 100 / buffer.capacity()), buffer.as_slice().len(), buffer.capacity());
        if let Err(err) = ws_tx.write().await {
            warn!("error while writing to tx tunnel {}", err);
            break;
        }
    }

    // Send normal close
    let _ = ws_tx.close().await;

    Ok(())
}

pub async fn propagate_remote_to_local(
    local_tx: impl AsyncWrite + Send,
    mut ws_rx: impl TunnelRead,
    mut close_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let _guard = scopeguard::guard((), |_| {
        info!("Closing local <= remote tunnel");
    });

    pin_mut!(local_tx);
    loop {
        let msg = select! {
            biased;
            msg = ws_rx.copy(&mut local_tx) => msg,
            _ = &mut close_rx => break,
        };

        if let Err(err) = msg {
            error!("error while reading from tunnel rx {}", err);
            break;
        }
    }

    Ok(())
}
