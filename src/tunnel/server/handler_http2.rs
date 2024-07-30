use crate::restrictions::types::RestrictionsRules;
use crate::tunnel::server::utils::{
    extract_path_prefix, extract_tunnel_info, extract_x_forwarded_for, inject_cookie, validate_tunnel,
};
use crate::tunnel::server::WsServer;
use crate::tunnel::transport::http2::{Http2TunnelRead, Http2TunnelWrite};
use crate::tunnel::{transport, RemoteAddr};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyStream, Either, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::{http, Request, Response, StatusCode};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{info, warn, Instrument, Span};

pub(super) async fn http_server_upgrade(
    server: WsServer,
    restrictions: Arc<RestrictionsRules>,
    restrict_path_prefix: Option<String>,
    mut client_addr: SocketAddr,
    mut req: Request<Incoming>,
) -> Response<Either<String, BoxBody<Bytes, anyhow::Error>>> {
    match extract_x_forwarded_for(&req) {
        Ok(Some((x_forward_for, x_forward_for_str))) => {
            info!("Request X-Forwarded-For: {:?}", x_forward_for);
            Span::current().record("forwarded_for", x_forward_for_str);
            client_addr.set_ip(x_forward_for);
        }
        Ok(_) => {}
        Err(err) => return err.map(Either::Left),
    };

    let path_prefix = match extract_path_prefix(&req) {
        Ok(p) => p,
        Err(err) => return err.map(Either::Left),
    };

    if let Some(restrict_path) = restrict_path_prefix {
        if path_prefix != restrict_path {
            warn!(
                "Client requested upgrade path '{}' does not match upgrade path restriction '{}' (mTLS, etc.)",
                path_prefix, restrict_path
            );
            return http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Either::Left("Invalid upgrade request".to_string()))
                .unwrap();
        }
    }

    let jwt = match extract_tunnel_info(&req) {
        Ok(jwt) => jwt,
        Err(err) => return err.map(Either::Left),
    };

    Span::current().record("id", &jwt.claims.id);
    Span::current().record("remote", format!("{}:{}", jwt.claims.r, jwt.claims.rp));
    let remote = match RemoteAddr::try_from(jwt.claims) {
        Ok(remote) => remote,
        Err(err) => {
            warn!("Rejecting connection with bad tunnel info: {} {}", err, req.uri());
            return http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Either::Left("Invalid upgrade request".to_string()))
                .unwrap();
        }
    };

    let restriction = match validate_tunnel(&remote, path_prefix, &restrictions) {
        Ok(matched_restriction) => {
            info!("Tunnel accepted due to matched restriction: {}", matched_restriction.name);
            matched_restriction
        }
        Err(err) => return err.map(Either::Left),
    };

    let req_protocol = remote.protocol.clone();
    let tunnel = match server.run_tunnel(restriction, remote, client_addr).await {
        Ok(ret) => ret,
        Err(err) => {
            warn!("Rejecting connection with bad upgrade request: {} {}", err, req.uri());
            return http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Either::Left("Invalid upgrade request".to_string()))
                .unwrap();
        }
    };

    let (remote_addr, local_rx, local_tx) = tunnel;
    info!("connected to {:?} {}:{}", req_protocol, remote_addr.host, remote_addr.port);

    let req_content_type = req.headers_mut().remove(CONTENT_TYPE);
    let ws_rx = BodyStream::new(req.into_body());
    let (ws_tx, rx) = mpsc::channel::<Bytes>(1024);
    let body = BoxBody::new(StreamBody::new(
        ReceiverStream::new(rx).map(|s| -> anyhow::Result<Frame<Bytes>> { Ok(Frame::data(s)) }),
    ));

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .body(Either::Right(body))
        .expect("bug: failed to build response");

    tokio::spawn(
        async move {
            let (close_tx, close_rx) = oneshot::channel::<()>();
            tokio::task::spawn(
                transport::io::propagate_remote_to_local(local_tx, Http2TunnelRead::new(ws_rx), close_rx)
                    .instrument(Span::current()),
            );

            let _ =
                transport::io::propagate_local_to_remote(local_rx, Http2TunnelWrite::new(ws_tx), close_tx, None).await;
        }
        .instrument(Span::current()),
    );

    if let Err(response) = inject_cookie(&req_protocol, &mut response, &remote_addr, Either::Left) {
        return response;
    }

    if let Some(content_type) = req_content_type {
        response.headers_mut().insert(CONTENT_TYPE, content_type);
    }

    response
}
