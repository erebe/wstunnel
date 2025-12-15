use crate::tunnel::transport::http2::{Http2TunnelRead, Http2TunnelWrite};
use crate::tunnel::transport::quic::{QuicTunnelRead, QuicTunnelWrite};
use crate::tunnel::transport::websocket::{WebsocketTunnelRead, WebsocketTunnelWrite};
use bytes::{BufMut, BytesMut};
use futures_util::{FutureExt, pin_mut};
use std::future::Future;
use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::select;
use tokio::sync::{Notify, oneshot};
use tokio::time::Instant;
use tracing::log::debug;
use tracing::{error, info, warn};

pub(super) static MAX_PACKET_LENGTH: usize = 64 * 1024;

pub trait TunnelWrite: Send + 'static {
    fn buf_mut(&mut self) -> &mut BytesMut;
    fn write(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
    fn ping(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
    fn close(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
    fn pending_operations_notify(&mut self) -> Arc<Notify>;
    fn handle_pending_operations(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
}

pub trait TunnelRead: Send + 'static {
    fn copy(
        &mut self,
        writer: impl AsyncWrite + Unpin + Send,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;
}

pub enum TunnelReader {
    Websocket(WebsocketTunnelRead),
    Http2(Http2TunnelRead),
    Quic(QuicTunnelRead),
}

impl TunnelRead for TunnelReader {
    async fn copy(&mut self, writer: impl AsyncWrite + Unpin + Send) -> Result<(), std::io::Error> {
        match self {
            Self::Websocket(s) => s.copy(writer).await,
            Self::Http2(s) => s.copy(writer).await,
            Self::Quic(s) => s.copy(writer).await,
        }
    }
}

pub enum TunnelWriter {
    Websocket(WebsocketTunnelWrite),
    Http2(Http2TunnelWrite),
    Quic(QuicTunnelWrite),
}

impl TunnelWrite for TunnelWriter {
    fn buf_mut(&mut self) -> &mut BytesMut {
        match self {
            Self::Websocket(s) => s.buf_mut(),
            Self::Http2(s) => s.buf_mut(),
            Self::Quic(s) => s.buf_mut(),
        }
    }

    async fn write(&mut self) -> Result<(), std::io::Error> {
        match self {
            Self::Websocket(s) => s.write().await,
            Self::Http2(s) => s.write().await,
            Self::Quic(s) => s.write().await,
        }
    }

    async fn ping(&mut self) -> Result<(), std::io::Error> {
        match self {
            Self::Websocket(s) => s.ping().await,
            Self::Http2(s) => s.ping().await,
            Self::Quic(s) => s.ping().await,
        }
    }

    async fn close(&mut self) -> Result<(), std::io::Error> {
        match self {
            Self::Websocket(s) => s.close().await,
            Self::Http2(s) => s.close().await,
            Self::Quic(s) => s.close().await,
        }
    }

    fn pending_operations_notify(&mut self) -> Arc<Notify> {
        match self {
            Self::Websocket(s) => s.pending_operations_notify(),
            Self::Http2(s) => s.pending_operations_notify(),
            Self::Quic(s) => s.pending_operations_notify(),
        }
    }

    async fn handle_pending_operations(&mut self) -> Result<(), std::io::Error> {
        match self {
            Self::Websocket(s) => s.handle_pending_operations().await,
            Self::Http2(s) => s.handle_pending_operations().await,
            Self::Quic(s) => s.handle_pending_operations().await,
        }
    }
}

pub async fn propagate_local_to_remote(
    local_rx: impl AsyncRead,
    mut ws_tx: impl TunnelWrite,
    mut close_tx: oneshot::Sender<()>,
    ping_frequency: Option<Duration>,
) -> anyhow::Result<()> {
    let _guard = scopeguard::guard((), |_| {
        info!("Closing local => remote tunnel");
    });

    // We do our own pin_mut! to avoid shadowing timeout and be able to reset it, on next loop iteration
    // We reuse the future to avoid creating a timer in the tight loop
    let frequency = ping_frequency.unwrap_or(Duration::from_secs(3600 * 24));
    let start_at = Instant::now().checked_add(frequency).unwrap_or_else(Instant::now);
    let timeout = tokio::time::interval_at(start_at, frequency);
    let should_close = close_tx.closed().fuse();
    let notify = ws_tx.pending_operations_notify();
    let mut has_pending_operations = notify.notified();
    let mut has_pending_operations_pin = unsafe { Pin::new_unchecked(&mut has_pending_operations) };

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

            _ = &mut has_pending_operations_pin => {
                has_pending_operations = notify.notified();
                has_pending_operations_pin = unsafe { Pin::new_unchecked(&mut has_pending_operations) };
                match ws_tx.handle_pending_operations().await {
                    Ok(_) => continue,
                    Err(err) => {
                        warn!("error while handling pending operations {}", err);
                        break;
                    }
                }
            },

            read_len = local_rx.read_buf(ws_tx.buf_mut()) => read_len,

            _ = &mut should_close => break,

            _ = timeout.tick(), if ping_frequency.is_some() => {
                debug!("sending ping to keep connection alive");
                ws_tx.ping().await?;
                continue;
            }
        };

        // Coalescing Loop: Try to read more if available to fill the buffer
        // This helps batching small packets (e.g. from iperf -l 400) into larger QUIC frames
        if let Ok(len) = &read_len {
            if *len > 0 {
                loop {
                    // Stop if buffer is full
                    if ws_tx.buf_mut().chunk_mut().len() == 0 {
                        break;
                    }

                    // Try to read more with a small timeout to encourage batching
                    // This prevents sending millions of tiny packets (e.g. iperf -l 400) which overwhelms the receiver
                    let fut = local_rx.read_buf(ws_tx.buf_mut());
                    match fut.now_or_never() {
                        Some(Ok(0)) => break, // EOF
                        Some(Ok(_n)) => continue,
                        Some(Err(_)) => break, // Error
                        None => break,         // Pending, write what we have
                    }
                }
            }
        }

        let _read_len = match read_len {
            Ok(0) => break,
            Ok(read_len) => read_len,
            Err(err) => {
                match err.kind() {
                    ErrorKind::ConnectionReset | ErrorKind::BrokenPipe => {
                        debug!("local tx tunnel closed: {}", err)
                    }
                    _ => warn!("error while reading incoming bytes from local tx tunnel: {}", err),
                }
                break;
            }
        };

        if let Err(err) = ws_tx.write().await {
            warn!("error while writing to tx tunnel {}", err);
            break;
        }
    }

    // Send normal close
    let _ = ws_tx.close().await;

    Ok(())
}

pub async fn propagate_remote_to_local<F>(
    local_tx: impl AsyncWrite + Send,
    mut ws_rx: impl TunnelRead,
    _close_rx: oneshot::Receiver<()>,
    graceful_shutdown: F,
) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send,
{
    let _guard = scopeguard::guard((), |_| {
        info!("Closing local <= remote tunnel");
    });

    pin_mut!(local_tx);
    pin_mut!(graceful_shutdown);

    loop {
        let msg = select! {
            biased;
            msg = ws_rx.copy(&mut local_tx) => msg,
        };

        if let Err(err) = msg {
            match err.kind() {
                ErrorKind::NotConnected => debug!("Connection closed frame received"),
                ErrorKind::BrokenPipe => debug!("Remote side closed connection"),
                ErrorKind::ConnectionReset => debug!("Connection reset by peer"),
                ErrorKind::ConnectionAborted => debug!("Connection aborted"),
                _ => error!("error while reading from tunnel rx {err}"),
            }
            break;
        }
    }

    // Ensure data is flushed and FIN sent
    let _ = local_tx.flush().await;
    let _ = local_tx.shutdown().await;

    // Before we close the tunnel, we wait for the graceful shutdown to complete
    // This is important to ensure that we don't close the tunnel while there are still
    // pending operations
    graceful_shutdown.await;

    Ok(())
}
