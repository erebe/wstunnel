use crate::restrictions::types::{
    AllowConfig, MatchConfig, RestrictionConfig, RestrictionsRules, ReverseTunnelConfigProtocol, TunnelConfigProtocol,
};
use crate::tunnel::{tunnel_to_jwt_token, JwtTunnelConfig, RemoteAddr, JWT_DECODE, JWT_HEADER_PREFIX};
use crate::LocalProtocol;
use hyper::body::{Body, Incoming};
use hyper::header::{HeaderValue, COOKIE, SEC_WEBSOCKET_PROTOCOL};
use hyper::{http, Request, Response, StatusCode};
use jsonwebtoken::TokenData;
use std::cmp::min;
use std::net::IpAddr;
use std::ops::Deref;
use tracing::{error, info, warn};
use url::Host;
use uuid::Uuid;

/// Checks if the requested (remote) port has been mapped in the configuration to another port.
/// If it is not mapped the original port number is returned.
#[inline]
pub(super) fn find_mapped_port(req_port: u16, restriction: &RestrictionConfig) -> u16 {
    // Determine if the requested port is to be mapped to a different port.
    let remote_port = restriction
        .allow
        .iter()
        .find_map(|allow| {
            if let AllowConfig::ReverseTunnel(allow) = allow {
                return allow.port_mapping.get(&req_port).cloned();
            }
            None
        })
        .unwrap_or(req_port);

    if req_port != remote_port {
        info!("Client requested port {} was mapped to {}", req_port, remote_port);
    }

    remote_port
}

#[inline]
pub(super) fn extract_x_forwarded_for(req: &Request<Incoming>) -> Result<Option<(IpAddr, &str)>, Response<String>> {
    let Some(x_forward_for) = req.headers().get("X-Forwarded-For") else {
        return Ok(None);
    };

    // X-Forwarded-For: <client>, <proxy1>, <proxy2>
    let x_forward_for = x_forward_for.to_str().unwrap_or_default();
    let x_forward_for = x_forward_for.split_once(',').map(|x| x.0).unwrap_or(x_forward_for);
    let ip: Option<IpAddr> = x_forward_for.parse().ok();
    Ok(ip.map(|ip| (ip, x_forward_for)))
}

#[inline]
pub(super) fn extract_path_prefix(req: &Request<Incoming>) -> Result<&str, Response<String>> {
    let path = req.uri().path();
    let min_len = min(path.len(), 1);
    if &path[0..min_len] != "/" {
        warn!("Rejecting connection with bad path prefix in upgrade request: {}", req.uri());
        return Err(http::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("Invalid upgrade request".to_string())
            .unwrap());
    }

    let Some((l, r)) = path[min_len..].split_once('/') else {
        warn!("Rejecting connection with bad upgrade request: {}", req.uri());
        return Err(http::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("Invalid upgrade request".into())
            .unwrap());
    };

    if !r.ends_with("events") {
        warn!("Rejecting connection with bad upgrade request: {}", req.uri());
        return Err(http::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("Invalid upgrade request".into())
            .unwrap());
    }

    Ok(l)
}

#[inline]
pub(super) fn extract_tunnel_info(req: &Request<Incoming>) -> Result<TokenData<JwtTunnelConfig>, Response<String>> {
    let jwt = req
        .headers()
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.split_once(JWT_HEADER_PREFIX))
        .map(|(_prefix, jwt)| jwt)
        .or_else(|| req.headers().get(COOKIE).and_then(|header| header.to_str().ok()))
        .unwrap_or_default();

    let (validation, decode_key) = JWT_DECODE.deref();
    let jwt = match jsonwebtoken::decode(jwt, decode_key, validation) {
        Ok(jwt) => jwt,
        err => {
            warn!(
                "error while decoding jwt for tunnel info {:?} header {:?}",
                err,
                req.headers().get(SEC_WEBSOCKET_PROTOCOL)
            );
            return Err(http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Invalid upgrade request".to_string())
                .unwrap());
        }
    };

    Ok(jwt)
}

#[inline]
pub(super) fn validate_tunnel<'a>(
    remote: &RemoteAddr,
    path_prefix: &str,
    restrictions: &'a RestrictionsRules,
) -> Result<&'a RestrictionConfig, Response<String>> {
    for restriction in &restrictions.restrictions {
        if !restriction.r#match.iter().all(|m| match m {
            MatchConfig::Any => true,
            MatchConfig::PathPrefix(path) => path.is_match(path_prefix),
        }) {
            continue;
        }

        for allow in &restriction.allow {
            match allow {
                AllowConfig::ReverseTunnel(allow) => {
                    if !remote.protocol.is_reverse_tunnel() {
                        continue;
                    }

                    if !allow.port.is_empty() && !allow.port.iter().any(|range| range.contains(&remote.port)) {
                        continue;
                    }

                    if !allow.protocol.is_empty()
                        && !allow
                            .protocol
                            .contains(&ReverseTunnelConfigProtocol::from(&remote.protocol))
                    {
                        continue;
                    }

                    match &remote.host {
                        Host::Domain(_) => {}
                        Host::Ipv4(ip) => {
                            let ip = IpAddr::V4(*ip);
                            for cidr in &allow.cidr {
                                if cidr.contains(&ip) {
                                    return Ok(restriction);
                                }
                            }
                        }
                        Host::Ipv6(ip) => {
                            let ip = IpAddr::V6(*ip);
                            for cidr in &allow.cidr {
                                if cidr.contains(&ip) {
                                    return Ok(restriction);
                                }
                            }
                        }
                    }
                }

                AllowConfig::Tunnel(allow) => {
                    if remote.protocol.is_reverse_tunnel() {
                        continue;
                    }

                    if !allow.port.is_empty() && !allow.port.iter().any(|range| range.contains(&remote.port)) {
                        continue;
                    }

                    if !allow.protocol.is_empty()
                        && !allow.protocol.contains(&TunnelConfigProtocol::from(&remote.protocol))
                    {
                        continue;
                    }

                    match &remote.host {
                        Host::Domain(host) => {
                            if allow.host.is_match(host) {
                                return Ok(restriction);
                            }
                        }
                        Host::Ipv4(ip) => {
                            let ip = IpAddr::V4(*ip);
                            for cidr in &allow.cidr {
                                if cidr.contains(&ip) {
                                    return Ok(restriction);
                                }
                            }
                        }
                        Host::Ipv6(ip) => {
                            let ip = IpAddr::V6(*ip);
                            for cidr in &allow.cidr {
                                if cidr.contains(&ip) {
                                    return Ok(restriction);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    warn!("Rejecting connection with not allowed destination: {:?}", remote);
    Err(http::Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body("Invalid upgrade request".to_string())
        .unwrap())
}

pub(super) fn inject_cookie<B>(
    req_protocol: &LocalProtocol,
    response: &mut http::Response<B>,
    remote_addr: &RemoteAddr,
    mk_body: impl FnOnce(String) -> B,
) -> Result<(), Response<B>>
where
    B: Body,
{
    if matches!(
        req_protocol,
        LocalProtocol::ReverseSocks5 { .. } | LocalProtocol::ReverseHttpProxy { .. }
    ) {
        let Ok(header_val) = HeaderValue::from_str(&tunnel_to_jwt_token(Uuid::from_u128(0), remote_addr)) else {
            error!("Bad header value for reverse socks5: {} {}", remote_addr.host, remote_addr.port);
            return Err(http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(mk_body("Invalid upgrade request".to_string()))
                .unwrap());
        };
        response.headers_mut().insert(COOKIE, header_val);
    }

    Ok(())
}
