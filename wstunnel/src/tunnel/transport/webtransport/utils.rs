//! Pieces the webtransport transport needs that are not the transport itself: QUIC socket and
//! transport-config setup, and the length-prefixed JWT preamble that carries per-stream tunnel
//! information.

use crate::somark::SoMark;
use anyhow::{Context, anyhow};
use log::debug;
use socket2::SockRef;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use web_transport_quinn::{RecvStream, SendStream, quinn};

/// Upper bound on the JWT preamble length (see [`read_jwt_preamble`]).
///
/// Tunnel JWTs run a few hundred bytes. This bound only exists so that a corrupt or hostile
/// length prefix cannot drive a large allocation.
const MAX_JWT_PREAMBLE_LEN: usize = 8 * 1024;

/// QUIC transport settings shared by the client endpoint and the server config.
///
/// The websocket ping frequency maps onto QUIC's own keep-alive. The idle timeout is then set to
/// three times that, so a connection is not torn down between two pings.
///
/// When pings are disabled the idle timeout is disabled too. That matters: quinn defaults it to
/// 30s, which would silently drop an idle tunnel that the websocket and http2 transports keep
/// open indefinitely, since TCP has no equivalent timeout. Matching them is the least surprising
/// behaviour for a user who asked for no periodic traffic.
pub(crate) fn mk_transport_config(keep_alive_interval: Option<Duration>) -> anyhow::Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();

    // TODO: Check performance impact
    transport.send_fairness(false);
    transport.datagram_send_buffer_size(4 * 1024 * 1024);
    transport.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    let Some(interval) = keep_alive_interval else {
        transport.keep_alive_interval(None);
        transport.max_idle_timeout(None);
        return Ok(transport);
    };

    let idle_timeout = interval
        .checked_mul(3)
        .with_context(|| format!("ping frequency {interval:?} is too large to derive a QUIC idle timeout"))?;

    transport.keep_alive_interval(Some(interval));
    transport.max_idle_timeout(Some(
        idle_timeout
            .try_into()
            .with_context(|| format!("ping frequency {interval:?} is too large for a QUIC idle timeout"))?,
    ));

    Ok(transport)
}

/// Bind a UDP socket for a QUIC endpoint, applying `SO_MARK`.
///
/// With no `bind` address, this binds a wildcard dual-stack socket, mirroring what
/// `quinn::Endpoint::client` does: an IPv6 socket with `IPV6_V6ONLY` cleared reaches both
/// families, because `connect_with` rewrites IPv4 peers to their IPv4-mapped form. Some
/// environments refuse dual-stack (or IPv6 outright), so fall back to IPv4-only.
pub(crate) fn bind_udp_socket(bind: Option<SocketAddr>, so_mark: SoMark) -> anyhow::Result<std::net::UdpSocket> {
    let addr = bind.unwrap_or_else(|| SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)));

    let socket = match socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    ) {
        Ok(socket) => socket,
        // Only worth retrying when we picked IPv6 ourselves.
        Err(err) if bind.is_none() => {
            debug!("cannot create an IPv6 UDP socket, falling back to IPv4: {err:?}");
            return bind_udp_socket(Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))), so_mark);
        }
        Err(err) => return Err(err).with_context(|| format!("cannot create a UDP socket for {addr}")),
    };

    if addr.is_ipv6()
        && let Err(err) = socket.set_only_v6(false)
    {
        debug!("cannot make the UDP socket dual-stack, IPv4 servers may be unreachable: {err:?}");
    }

    socket
        .bind(&socket2::SockAddr::from(addr))
        .with_context(|| format!("cannot bind the UDP socket to {addr}"))?;
    so_mark
        .set_mark(SockRef::from(&socket))
        .with_context(|| "cannot set SO_MARK on the UDP socket")?;

    Ok(socket.into())
}

/// Write the tunnel JWT as a length-prefixed preamble: `[u16 big-endian length][JWT bytes]`.
///
/// `ConnectResponse` carries only a status and a subprotocol, so unlike the websocket and http2
/// transports the server cannot answer with a `Cookie` header. Dynamic reverse tunnels need the
/// server to tell the client which destination it resolved, so for those the JWT is sent as the
/// first bytes of the stream instead. QUIC streams are ordered and reliable, so it always
/// arrives before any tunnel payload.
///
/// Both peers decide whether a preamble is present from the same value —
/// [`crate::tunnel::LocalProtocol::is_dynamic_reverse_tunnel`] — so they cannot disagree.
pub async fn write_jwt_preamble(stream: &mut SendStream, jwt: &str) -> anyhow::Result<()> {
    let jwt = jwt.as_bytes();
    let len =
        u16::try_from(jwt.len()).with_context(|| format!("tunnel JWT is too long to send: {} bytes", jwt.len()))?;

    stream
        .write_u16(len)
        .await
        .with_context(|| "cannot send the tunnel JWT length")?;
    stream
        .write_all(jwt)
        .await
        .with_context(|| "cannot send the tunnel JWT")?;
    stream.flush().await?;

    Ok(())
}

/// Read the preamble written by [`write_jwt_preamble`].
pub async fn read_jwt_preamble(stream: &mut RecvStream) -> anyhow::Result<String> {
    let len = stream
        .read_u16()
        .await
        .with_context(|| "cannot read the tunnel JWT length")? as usize;

    if len == 0 || len > MAX_JWT_PREAMBLE_LEN {
        return Err(anyhow!(
            "invalid tunnel JWT length {len} in webtransport preamble, expected 1..={MAX_JWT_PREAMBLE_LEN}"
        ));
    }

    let mut jwt = vec![0u8; len];
    stream
        .read_exact(&mut jwt)
        .await
        .with_context(|| "cannot read the tunnel JWT")?;

    String::from_utf8(jwt).with_context(|| "tunnel JWT is not valid utf-8")
}
