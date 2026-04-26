use crate::executor::TokioExecutorRef;
use crate::restrictions::types::RestrictionsRules;
use crate::tunnel::LocalProtocol;
use crate::tunnel::reverse_socks5::{ReverseSocks5ConnectResult, read_reverse_socks5_connect_result};
use crate::tunnel::server::WsServer;
use crate::tunnel::server::send_socks5_reply_if_needed;
use crate::tunnel::server::utils::{HttpResponse, bad_request, inject_cookie};
use crate::tunnel::transport;
use crate::tunnel::transport::io::TunnelWrite;
use crate::tunnel::transport::websocket::mk_websocket_tunnel;
use fast_socks5::ReplyError;
use fastwebsockets::Role;
use http_body_util::Either;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::header::{HeaderValue, SEC_WEBSOCKET_PROTOCOL};
use hyper::{Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::{Instrument, Span, error, warn};

pub(super) async fn ws_server_upgrade(
    server: WsServer<impl TokioExecutorRef>,
    restrictions: Arc<RestrictionsRules>,
    restrict_path_prefix: Option<String>,
    client_addr: SocketAddr,
    mut req: Request<Incoming>,
) -> HttpResponse {
    if !fastwebsockets::upgrade::is_upgrade_request(&req) {
        warn!("Rejecting connection with bad upgrade request: {}", req.uri());
        return bad_request();
    }

    let mask_frame = server.config.websocket_mask_frame;
    let (remote_addr, local_rx, mut local_tx, need_cookie, reverse_socks5) = match server
        .handle_tunnel_request(restrictions, restrict_path_prefix, client_addr, &req)
        .await
    {
        Ok(ret) => ret,
        Err(err) => return err,
    };

    let (response, fut) = match fastwebsockets::upgrade::upgrade(&mut req) {
        Ok(ret) => ret,
        Err(err) => {
            warn!("Rejecting connection with bad upgrade request: {} {}", err, req.uri());
            return bad_request();
        }
    };

    let reverse_socks5_handshake_timeout = server.config.timeout_connect;
    let reverse_socks5_tcp = reverse_socks5 && matches!(&remote_addr.protocol, LocalProtocol::Tcp { .. });
    let executor = server.executor.clone();
    server.executor.spawn(
        async move {
            let (mut ws_rx, mut ws_tx) = match fut.await {
                Ok(ws) => match mk_websocket_tunnel(ws, Role::Server, mask_frame) {
                    Ok(ws) => ws,
                    Err(err) => {
                        error!("Error during http upgrade request: {:?}", err);
                        return Err(err);
                    }
                },
                Err(err) => {
                    error!("Error during http upgrade request: {:?}", err);
                    return Err(anyhow::Error::from(err));
                }
            };
            if reverse_socks5_tcp {
                match read_reverse_socks5_connect_result(ws_rx.read_handshake_byte(), reverse_socks5_handshake_timeout)
                    .await
                {
                    Ok(ReverseSocks5ConnectResult::Connected) => {
                        if let Err(err) = send_socks5_reply_if_needed(&mut local_tx, ReplyError::Succeeded).await {
                            error!("Cannot reply to socks5 client: {err:?}");
                            let _ = ws_tx.close().await;
                            return Err(err);
                        }
                    }
                    Ok(ReverseSocks5ConnectResult::Failed) => {
                        let _ = send_socks5_reply_if_needed(&mut local_tx, ReplyError::GeneralFailure).await;
                        let _ = ws_tx.close().await;
                        return Ok(());
                    }
                    Err(err) => {
                        warn!("Reverse socks5 handshake failed: {err}");
                        let _ = send_socks5_reply_if_needed(&mut local_tx, ReplyError::GeneralFailure).await;
                        let _ = ws_tx.close().await;
                        return Err(err.into());
                    }
                }
            }

            let (close_tx, close_rx) = oneshot::channel::<()>();

            executor
                .spawn(transport::io::propagate_remote_to_local(local_tx, ws_rx, close_rx).instrument(Span::current()));

            let _ = transport::io::propagate_local_to_remote(
                local_rx,
                ws_tx,
                close_tx,
                server.config.websocket_ping_frequency,
            )
            .await;
            Ok(())
        }
        .instrument(Span::current()),
    );

    let mut response = Response::from_parts(response.into_parts().0, Either::Right(BoxBody::default()));
    if need_cookie && inject_cookie(&mut response, &remote_addr).is_err() {
        return bad_request();
    }

    response
        .headers_mut()
        .insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_static("v1"));

    response
}
