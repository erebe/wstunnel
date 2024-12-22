use crate::restrictions::types::{
    AllowConfig, MatchConfig, RestrictionConfig, RestrictionsRules, ReverseTunnelConfigProtocol, TunnelConfigProtocol,
};
use crate::tunnel::transport::{jwt_token_to_tunnel, tunnel_to_jwt_token, JwtTunnelConfig, JWT_HEADER_PREFIX};
use crate::tunnel::RemoteAddr;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::Either;
use hyper::body::{Body, Incoming};
use hyper::header::{HeaderValue, COOKIE, SEC_WEBSOCKET_PROTOCOL};
use hyper::{http, Request, Response, StatusCode};
use jsonwebtoken::TokenData;
use std::cmp::min;
use std::net::IpAddr;
use tracing::{error, info, warn};
use url::Host;
use uuid::Uuid;

pub(super) fn bad_request() -> Response<Either<String, BoxBody<Bytes, anyhow::Error>>> {
    http::Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Either::Left("Invalid request".to_string()))
        .unwrap()
}

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
pub(super) fn extract_x_forwarded_for(req: &Request<Incoming>) -> Result<Option<(IpAddr, &str)>, ()> {
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
pub(super) fn extract_path_prefix(req: &Request<Incoming>) -> Result<&str, ()> {
    let path = req.uri().path();
    let min_len = min(path.len(), 1);
    if &path[0..min_len] != "/" {
        warn!("Rejecting connection with bad path prefix in upgrade request: {}", req.uri());
        return Err(());
    }

    let Some((l, r)) = path[min_len..].split_once('/') else {
        warn!("Rejecting connection with bad upgrade request: {}", req.uri());
        return Err(());
    };

    if !r.ends_with("events") {
        warn!("Rejecting connection with bad upgrade request: {}", req.uri());
        return Err(());
    }

    Ok(l)
}

#[inline]
pub(super) fn extract_tunnel_info(req: &Request<Incoming>) -> Result<TokenData<JwtTunnelConfig>, ()> {
    let jwt = req
        .headers()
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.split_once(JWT_HEADER_PREFIX))
        .map(|(_prefix, jwt)| jwt)
        .or_else(|| req.headers().get(COOKIE).and_then(|header| header.to_str().ok()))
        .unwrap_or_default();

    let jwt = match jwt_token_to_tunnel(jwt) {
        Ok(jwt) => jwt,
        err => {
            warn!(
                "error while decoding jwt for tunnel info {:?} header {:?}",
                err,
                req.headers().get(SEC_WEBSOCKET_PROTOCOL)
            );
            return Err(());
        }
    };

    Ok(jwt)
}

#[inline]
pub(super) fn validate_tunnel<'a>(
    remote: &RemoteAddr,
    path_prefix: &str,
    restrictions: &'a RestrictionsRules,
) -> Result<&'a RestrictionConfig, ()> {
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
    Err(())
}

pub(super) fn inject_cookie(response: &mut http::Response<impl Body>, remote_addr: &RemoteAddr) -> Result<(), ()> {
    let Ok(header_val) = HeaderValue::from_str(&tunnel_to_jwt_token(Uuid::from_u128(0), remote_addr)) else {
        error!("Bad header value for reverse socks5: {} {}", remote_addr.host, remote_addr.port);
        return Err(());
    };
    response.headers_mut().insert(COOKIE, header_val);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::restrictions::types::{AllowReverseTunnelConfig, AllowTunnelConfig};
    use crate::tunnel::LocalProtocol;
    use ipnet::{IpNet, Ipv4Net};
    use regex::Regex;
    use std::net::Ipv6Addr;

    #[test]
    fn test_validate_tunnel() {
        let restrictions = RestrictionsRules {
            restrictions: vec![
                // tunnel
                RestrictionConfig {
                    name: "restrict1".into(),
                    r#match: vec![MatchConfig::Any],
                    allow: vec![AllowConfig::Tunnel(AllowTunnelConfig {
                        protocol: vec![TunnelConfigProtocol::Tcp],
                        port: vec![80..=80],
                        cidr: vec![IpNet::from(Ipv4Net::new([127, 0, 0, 1].into(), 24).unwrap())],
                        host: Regex::new("example.com").unwrap(),
                    })],
                },
                // reverse tunnel
                RestrictionConfig {
                    name: "restrict2".into(),
                    r#match: vec![MatchConfig::Any],
                    allow: vec![AllowConfig::ReverseTunnel(AllowReverseTunnelConfig {
                        protocol: vec![ReverseTunnelConfigProtocol::Tcp],
                        port: vec![80..=80],
                        cidr: vec![IpNet::from(Ipv4Net::new([127, 0, 0, 1].into(), 24).unwrap())],
                        port_mapping: Default::default(),
                    })],
                },
            ],
        };

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert_eq!(
            validate_tunnel(&remote, "/doesnt/matter", &restrictions).unwrap().name,
            restrictions.restrictions[0].name
        );

        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert_eq!(
            validate_tunnel(&remote, "/doesnt/matter", &restrictions).unwrap().name,
            restrictions.restrictions[1].name
        );

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 81,
        };
        assert!(validate_tunnel(&remote, "/doesnt/matter", &restrictions).is_err());

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 1, 1].into()),
            port: 80,
        };
        assert!(validate_tunnel(&remote, "/doesnt/matter", &restrictions).is_err());

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Domain("example.com".into()),
            port: 80,
        };
        assert_eq!(
            validate_tunnel(&remote, "/doesnt/matter", &restrictions).unwrap().name,
            restrictions.restrictions[0].name
        );

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Domain("not.com".into()),
            port: 80,
        };
        assert!(validate_tunnel(&remote, "/doesnt/matter", &restrictions).is_err());

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv6(Ipv6Addr::LOCALHOST),
            port: 80,
        };
        assert!(validate_tunnel(&remote, "/doesnt/matter", &restrictions).is_err());
    }
}
