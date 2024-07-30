use crate::restrictions::types::RestrictionsRules;
use crate::tunnel::server::utils::{
    extract_path_prefix, extract_tunnel_info, extract_x_forwarded_for, inject_cookie, validate_tunnel,
};
use crate::tunnel::server::WsServer;
use crate::tunnel::transport::websocket::{WebsocketTunnelRead, WebsocketTunnelWrite};
use crate::tunnel::{transport, RemoteAddr};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, SEC_WEBSOCKET_PROTOCOL};
use hyper::{http, Request, Response, StatusCode};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::{error, info, warn, Instrument, Span};

pub(super) async fn ws_server_upgrade(
    server: WsServer,
    restrictions: Arc<RestrictionsRules>,
    restrict_path_prefix: Option<String>,
    mut client_addr: SocketAddr,
    mut req: Request<Incoming>,
) -> Response<String> {
    if !fastwebsockets::upgrade::is_upgrade_request(&req) {
        warn!("Rejecting connection with bad upgrade request: {}", req.uri());
        return http::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("Invalid upgrade request".to_string())
            .unwrap();
    }

    match extract_x_forwarded_for(&req) {
        Ok(Some((x_forward_for, x_forward_for_str))) => {
            info!("Request X-Forwarded-For: {:?}", x_forward_for);
            Span::current().record("forwarded_for", x_forward_for_str);
            client_addr.set_ip(x_forward_for);
        }
        Ok(_) => {}
        Err(err) => return err,
    };

    let path_prefix = match extract_path_prefix(&req) {
        Ok(p) => p,
        Err(err) => return err,
    };

    if let Some(restrict_path) = restrict_path_prefix {
        if path_prefix != restrict_path {
            warn!(
                "Client requested upgrade path '{}' does not match upgrade path restriction '{}' (mTLS, etc.)",
                path_prefix, restrict_path
            );
            return http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Invalid upgrade request".to_string())
                .unwrap();
        }
    }

    let jwt = match extract_tunnel_info(&req) {
        Ok(jwt) => jwt,
        Err(err) => return err,
    };

    Span::current().record("id", &jwt.claims.id);
    Span::current().record("remote", format!("{}:{}", jwt.claims.r, jwt.claims.rp));

    let remote = match RemoteAddr::try_from(jwt.claims) {
        Ok(remote) => remote,
        Err(err) => {
            warn!("Rejecting connection with bad tunnel info: {} {}", err, req.uri());
            return http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Invalid upgrade request".to_string())
                .unwrap();
        }
    };

    let restriction = match validate_tunnel(&remote, path_prefix, &restrictions) {
        Ok(matched_restriction) => {
            info!("Tunnel accepted due to matched restriction: {}", matched_restriction.name);
            matched_restriction
        }
        Err(err) => return err,
    };

    let req_protocol = remote.protocol.clone();
    let tunnel = match server.run_tunnel(restriction, remote, client_addr).await {
        Ok(ret) => ret,
        Err(err) => {
            warn!("Rejecting connection with bad upgrade request: {} {}", err, req.uri());
            return http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Invalid upgrade request".to_string())
                .unwrap();
        }
    };

    let (remote_addr, local_rx, local_tx) = tunnel;
    info!("connected to {:?} {}:{}", req_protocol, remote_addr.host, remote_addr.port);
    let (response, fut) = match fastwebsockets::upgrade::upgrade(&mut req) {
        Ok(ret) => ret,
        Err(err) => {
            warn!("Rejecting connection with bad upgrade request: {} {}", err, req.uri());
            return http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(format!("Invalid upgrade request: {:?}", err))
                .unwrap();
        }
    };

    tokio::spawn(
        async move {
            let (ws_rx, mut ws_tx) = match fut.await {
                Ok(ws) => ws.split(tokio::io::split),
                Err(err) => {
                    error!("Error during http upgrade request: {:?}", err);
                    return;
                }
            };
            let (close_tx, close_rx) = oneshot::channel::<()>();
            ws_tx.set_auto_apply_mask(server.config.websocket_mask_frame);

            tokio::task::spawn(
                transport::io::propagate_remote_to_local(local_tx, WebsocketTunnelRead::new(ws_rx), close_rx)
                    .instrument(Span::current()),
            );

            let _ =
                transport::io::propagate_local_to_remote(local_rx, WebsocketTunnelWrite::new(ws_tx), close_tx, None)
                    .await;
        }
        .instrument(Span::current()),
    );

    let mut response = Response::from_parts(response.into_parts().0, "".to_string());
    if let Err(response) = inject_cookie(&req_protocol, &mut response, &remote_addr, |s| s) {
        return response;
    }

    response
        .headers_mut()
        .insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_static("v1"));

    response
}
