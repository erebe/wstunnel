use fastwebsockets::{Frame, OpCode, Payload, WebSocketError, WebSocketRead, WebSocketWrite};
use futures_util::pin_mut;
use hyper::upgrade::Upgraded;

use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::select;
use tokio::sync::oneshot;
use tokio::time::Instant;
use tracing::log::debug;
use tracing::{error, info, trace, warn};

pub(super) async fn propagate_read(
    local_rx: impl AsyncRead,
    mut ws_tx: WebSocketWrite<WriteHalf<Upgraded>>,
    mut close_tx: oneshot::Sender<()>,
    ping_frequency: Duration,
) -> Result<(), WebSocketError> {
    let _guard = scopeguard::guard((), |_| {
        info!("Closing local tx ==> websocket tx tunnel");
    });

    static MAX_PACKET_LENGTH: usize = 64 * 1024;
    let mut buffer = vec![0u8; MAX_PACKET_LENGTH];

    // We do our own pin_mut! to avoid shadowing timeout and be able to reset it, on next loop iteration
    // We reuse the future to avoid creating a timer in the tight loop
    let start_at = Instant::now()
        .checked_add(ping_frequency)
        .unwrap_or(Instant::now() + Duration::from_secs(3600 * 24));
    let timeout = tokio::time::interval_at(start_at, ping_frequency);
    pin_mut!(timeout);

    pin_mut!(local_rx);
    loop {
        let read_len = select! {
            biased;

            read_len = local_rx.read(&mut buffer) => read_len,

            _ = close_tx.closed() => break,

            _ = timeout.tick() => {
                debug!("sending ping to keep websocket connection alive");
                ws_tx.write_frame(Frame::new(true, OpCode::Ping, None, Payload::BorrowedMut(&mut []))).await?;

                continue;
            }
        };

        let read_len = match read_len {
            Ok(0) => break,
            Ok(read_len) => read_len,
            Err(err) => {
                warn!("error while reading incoming bytes from local tx tunnel: {}", err);
                break;
            }
        };

        trace!("read {} bytes", read_len);
        if let Err(err) = ws_tx
            .write_frame(Frame::binary(Payload::BorrowedMut(&mut buffer[..read_len])))
            .await
        {
            warn!("error while writing to websocket tx tunnel {}", err);
            break;
        }

        // If the buffer has been completely filled with previous read, Double it !
        // For the buffer to not be a bottleneck when the TCP window scale
        // For udp, the buffer will never grows.
        if buffer.capacity() == read_len {
            buffer.clear();
            buffer.resize(buffer.capacity() * 2, 0);
        }
    }

    // Send normal close
    let _ = ws_tx.write_frame(Frame::close(1000, &[])).await;

    Ok(())
}

pub(super) async fn propagate_write(
    local_tx: impl AsyncWrite,
    mut ws_rx: WebSocketRead<ReadHalf<Upgraded>>,
    mut close_rx: oneshot::Receiver<()>,
) -> Result<(), WebSocketError> {
    let _guard = scopeguard::guard((), |_| {
        info!("Closing local rx <== websocket rx tunnel");
    });
    let mut x = |x: Frame<'_>| {
        debug!("frame {:?} {:?}", x.opcode, x.payload);
        futures_util::future::ready(anyhow::Ok(()))
    };

    pin_mut!(local_tx);
    loop {
        let msg = select! {
            biased;
            msg = ws_rx.read_frame(&mut x) => msg,

            _ = &mut close_rx => break,
        };

        let msg = match msg {
            Ok(msg) => msg,
            Err(err) => {
                error!("error while reading from websocket rx {}", err);
                break;
            }
        };

        trace!("receive ws frame {:?} {:?}", msg.opcode, msg.payload);
        let ret = match msg.opcode {
            OpCode::Continuation | OpCode::Text | OpCode::Binary => local_tx.write_all(msg.payload.as_ref()).await,
            OpCode::Close => break,
            OpCode::Ping => Ok(()),
            OpCode::Pong => Ok(()),
        };

        if let Err(err) = ret {
            error!("error while writing bytes to local for rx tunnel {}", err);
            break;
        }
    }

    Ok(())
}
