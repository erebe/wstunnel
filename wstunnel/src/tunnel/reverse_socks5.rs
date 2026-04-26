use std::future::Future;
use std::io;
use std::io::ErrorKind;
use std::time::Duration;

pub(crate) const HANDSHAKE_CONNECT_OK: u8 = 0;
pub(crate) const HANDSHAKE_CONNECT_FAIL: u8 = 1;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ReverseSocks5ConnectResult {
    Connected,
    Failed,
}

pub(crate) async fn read_reverse_socks5_connect_result(
    read_handshake_byte: impl Future<Output = io::Result<u8>>,
    timeout: Duration,
) -> io::Result<ReverseSocks5ConnectResult> {
    match tokio::time::timeout(timeout, read_handshake_byte).await {
        Ok(Ok(HANDSHAKE_CONNECT_OK)) => Ok(ReverseSocks5ConnectResult::Connected),
        Ok(Ok(_)) => Ok(ReverseSocks5ConnectResult::Failed),
        Ok(Err(err)) => Err(err),
        Err(_) => Err(io::Error::new(ErrorKind::TimedOut, "reverse socks5 handshake timeout")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn reverse_socks5_handshake_reports_connected() {
        let ret = read_reverse_socks5_connect_result(async { Ok(HANDSHAKE_CONNECT_OK) }, Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(ret, ReverseSocks5ConnectResult::Connected);
    }

    #[tokio::test]
    async fn reverse_socks5_handshake_reports_failed() {
        let ret = read_reverse_socks5_connect_result(async { Ok(HANDSHAKE_CONNECT_FAIL) }, Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(ret, ReverseSocks5ConnectResult::Failed);
    }

    #[tokio::test]
    async fn reverse_socks5_handshake_times_out() {
        let err = read_reverse_socks5_connect_result(
            async {
                sleep(Duration::from_millis(25)).await;
                Ok(HANDSHAKE_CONNECT_OK)
            },
            Duration::from_millis(5),
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn reverse_socks5_handshake_propagates_io_error() {
        let err = read_reverse_socks5_connect_result(
            async { Err(io::Error::new(ErrorKind::ConnectionAborted, "oops")) },
            Duration::from_millis(50),
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ConnectionAborted);
    }
}
