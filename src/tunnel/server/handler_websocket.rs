use crate::restrictions::types::RestrictionsRules;
use crate::tunnel::server::utils::{bad_request, inject_cookie};
use crate::tunnel::server::WsServer;
use crate::tunnel::transport;
use crate::tunnel::transport::websocket::{WebsocketTunnelRead, WebsocketTunnelWrite};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::Either;
use hyper::body::Incoming;
use hyper::header::{HeaderValue, SEC_WEBSOCKET_PROTOCOL};
use hyper::{Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::{error, warn, Instrument, Span};

pub(super) async fn ws_server_upgrade(
    server: WsServer,
    restrictions: Arc<RestrictionsRules>,
    restrict_path_prefix: Option<String>,
    client_addr: SocketAddr,
    mut req: Request<Incoming>,
) -> Response<Either<String, BoxBody<Bytes, anyhow::Error>>> {
    if !fastwebsockets::upgrade::is_upgrade_request(&req) {
        warn!("Rejecting connection with bad upgrade request: {}", req.uri());
        return bad_request();
    }

    let mask_frame = server.config.websocket_mask_frame;
    let (remote_addr, local_rx, local_tx, need_cookie) = match server
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

    tokio::spawn(
        async move {
            let (ws_rx, ws_tx) = match fut.await {
                Ok(mut ws) => {
                    ws.set_auto_pong(false);
                    ws.set_auto_close(false);
                    ws.set_auto_apply_mask(mask_frame);
                    ws.split(tokio::io::split)
                }
                Err(err) => {
                    error!("Error during http upgrade request: {:?}", err);
                    return;
                }
            };
            let (close_tx, close_rx) = oneshot::channel::<()>();

            let (ws_rx, pending_ops) = WebsocketTunnelRead::new(ws_rx);
            tokio::task::spawn(
                transport::io::propagate_remote_to_local(local_tx, ws_rx, close_rx).instrument(Span::current()),
            );

            let _ = transport::io::propagate_local_to_remote(
                local_rx,
                WebsocketTunnelWrite::new(ws_tx, pending_ops),
                close_tx,
                server.config.websocket_ping_frequency,
            )
            .await;
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
