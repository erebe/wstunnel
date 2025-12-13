use crate::LocalProtocol;
use crate::protocols::tls::CertificateVars;
use crate::restrictions::types::{
    AllowConfig, AllowReverseTunnelConfig, AllowTunnelConfig, MatchConfig, RestrictionConfig, RestrictionsRules,
    ReverseTunnelConfigProtocol, TunnelConfigProtocol,
};
use crate::tunnel::RemoteAddr;
use crate::tunnel::transport::{JWT_HEADER_PREFIX, JwtTunnelConfig, jwt_token_to_tunnel, tunnel_to_jwt_token};
use anyhow::Context;
use bytes::Bytes;
use derive_more::{Display, Error};
use http_body_util::Either;
use http_body_util::combinators::BoxBody;
use hyper::body::{Body, Incoming};
use hyper::header::{AUTHORIZATION, COOKIE, HeaderValue, SEC_WEBSOCKET_PROTOCOL};
use hyper::{Request, Response, StatusCode, http};
use jsonwebtoken::TokenData;
use regex::Regex;
use std::net::IpAddr;
use tracing::{error, info};
use url::Host;
use uuid::Uuid;

pub type HttpResponse = Response<Either<String, BoxBody<Bytes, anyhow::Error>>>;

pub(super) fn bad_request() -> HttpResponse {
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
pub(super) fn extract_authorization(req: &Request<Incoming>) -> Option<&str> {
    req.headers().get(AUTHORIZATION)?.to_str().ok()
}

#[inline]
pub(super) fn extract_x_forwarded_for(req: &Request<Incoming>) -> Option<(IpAddr, &str)> {
    let x_forward_for = req.headers().get("X-Forwarded-For")?;

    // X-Forwarded-For: <client>, <proxy1>, <proxy2>
    let x_forward_for = x_forward_for.to_str().unwrap_or_default();
    let x_forward_for = x_forward_for.split_once(',').map(|x| x.0).unwrap_or(x_forward_for);
    let ip: Option<IpAddr> = x_forward_for.parse().ok();
    ip.map(|ip| (ip, x_forward_for))
}

#[inline]
pub(super) fn extract_path_prefix(path: &str) -> Result<&str, PathPrefixErr> {
    if !path.starts_with('/') {
        return Err(PathPrefixErr::BadPathPrefix);
    }

    let (l, r) = path[1..].split_once('/').ok_or(PathPrefixErr::BadUpgradeRequest)?;

    match r.ends_with("events") {
        true => Ok(l),
        false => Err(PathPrefixErr::BadUpgradeRequest),
    }
}

#[derive(Debug, Display, Error)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(super) enum PathPrefixErr {
    #[display("bad path prefix in upgrade request")]
    BadPathPrefix,
    #[display("bad upgrade request")]
    BadUpgradeRequest,
}

#[inline]
pub(super) fn extract_tunnel_info(req: &Request<Incoming>) -> anyhow::Result<TokenData<JwtTunnelConfig>> {
    let jwt = req
        .headers()
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.split_once(JWT_HEADER_PREFIX))
        .map(|(_prefix, jwt)| jwt)
        .or_else(|| req.headers().get(COOKIE).and_then(|header| header.to_str().ok()))
        .unwrap_or_default();

    jwt_token_to_tunnel(jwt).with_context(|| {
        let msg = format!(
            "error while decoding jwt for tunnel info header {:?}",
            req.headers().get(SEC_WEBSOCKET_PROTOCOL)
        );
        msg
    })
}

fn substitute_vars(pattern: &str, cert_vars: &CertificateVars) -> String {
    let result = pattern
        .replace("${cn}", cert_vars.cn.as_deref().unwrap_or(""))
        .replace("${cert.cn}", cert_vars.cn.as_deref().unwrap_or(""));
    tracing::debug!(
        "Variable substitution: pattern='{}', cn={:?}, result='{}'",
        pattern,
        cert_vars.cn,
        result
    );
    result
    // TODO: Add more variables like ${cert.subject.ou}, etc.
}

impl RestrictionConfig {
    /// Returns true if the parameters match the restriction config
    #[inline]
    fn filter(
        self: &RestrictionConfig,
        path_prefix: &str,
        authorization_header_val: Option<&str>,
        cert_vars: &CertificateVars,
    ) -> bool {
        self.r#match.iter().all(|m| match m {
            MatchConfig::Any => true,
            MatchConfig::PathPrefix(pattern) => {
                let substituted = substitute_vars(pattern, cert_vars);
                Regex::new(&substituted).is_ok_and(|re| re.is_match(path_prefix))
            }
            MatchConfig::Authorization(pattern) => authorization_header_val.is_some_and(|val| {
                let substituted = substitute_vars(pattern, cert_vars);
                Regex::new(&substituted).is_ok_and(|re| re.is_match(val))
            }),
        })
    }
}

impl AllowReverseTunnelConfig {
    #[inline]
    fn is_allowed(&self, remote: &RemoteAddr, cert_vars: &CertificateVars) -> bool {
        if !remote.protocol.is_reverse_tunnel() {
            return false;
        }

        // For ReverseUnix tunnels there is no port or cidr to check
        if let LocalProtocol::ReverseUnix { path } = &remote.protocol {
            let substituted = substitute_vars(&self.unix_path, cert_vars);
            return Regex::new(&substituted)
                .is_ok_and(|re| re.is_match(path.to_str().unwrap_or("####INVALID_UNIX_PATH####")));
        }

        if !self.port.is_empty() && !self.port.iter().any(|range| range.contains(&remote.port)) {
            return false;
        }

        if !self.protocol.is_empty()
            && !self
                .protocol
                .contains(&ReverseTunnelConfigProtocol::from(&remote.protocol))
        {
            return false;
        }

        match &remote.host {
            Host::Domain(_) => false,
            Host::Ipv4(ip) => self.cidr.iter().any(|cidr| cidr.contains(&IpAddr::from(*ip))),
            Host::Ipv6(ip) => self.cidr.iter().any(|cidr| cidr.contains(&IpAddr::from(*ip))),
        }
    }
}

impl AllowTunnelConfig {
    #[inline]
    fn is_allowed(&self, remote: &RemoteAddr, cert_vars: &CertificateVars) -> bool {
        if remote.protocol.is_reverse_tunnel() {
            return false;
        }

        if !self.port.is_empty() && !self.port.iter().any(|range| range.contains(&remote.port)) {
            return false;
        }

        if !self.protocol.is_empty() && !self.protocol.contains(&TunnelConfigProtocol::from(&remote.protocol)) {
            return false;
        }

        match &remote.host {
            Host::Domain(host) => {
                let substituted = substitute_vars(&self.host, cert_vars);
                Regex::new(&substituted).is_ok_and(|re| re.is_match(host))
            }
            Host::Ipv4(ip) => self.cidr.iter().any(|cidr| cidr.contains(&IpAddr::from(*ip))),
            Host::Ipv6(ip) => self.cidr.iter().any(|cidr| cidr.contains(&IpAddr::from(*ip))),
        }
    }
}

impl AllowConfig {
    #[inline]
    fn is_allowed(&self, remote: &RemoteAddr, cert_vars: &CertificateVars) -> bool {
        match self {
            AllowConfig::ReverseTunnel(config) => config.is_allowed(remote, cert_vars),
            AllowConfig::Tunnel(config) => config.is_allowed(remote, cert_vars),
        }
    }
}

/// Validate if the requested tunnel is allowed by the restrictions.
///
/// Restrictions are checked one by one. If one matches the tunnel, the tunnel will be allowed.
/// If no restriction matches, the tunnel will be rejected.
///
/// # Return value:
/// * `Some(restriction)` - Tunnel is allowed. Encapsulates the restriction that allowed the tunnel.
/// * `None` - Tunnel is not allowed.
#[inline]
pub(super) fn validate_tunnel<'a>(
    remote: &RemoteAddr,
    path_prefix: &str,
    authorization: Option<&str>,
    restrictions: &'a RestrictionsRules,
    cert_vars: &CertificateVars,
) -> Option<&'a RestrictionConfig> {
    tracing::debug!(
        "validate_tunnel: remote={:?}, path_prefix='{}', cert_cn={:?}",
        remote,
        path_prefix,
        cert_vars.cn
    );

    restrictions
        .restrictions
        .iter()
        .filter(|restriction| {
            let matches = restriction.filter(path_prefix, authorization, cert_vars);
            tracing::debug!("Restriction '{}': filter_match={}", restriction.name, matches);
            matches
        })
        .find(|restriction| {
            let allowed = restriction
                .allow
                .iter()
                .any(|allow| allow.is_allowed(remote, cert_vars));
            tracing::debug!("Restriction '{}': allow_check={}", restriction.name, allowed);
            allowed
        })
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
    use crate::restrictions::types::{AllowReverseTunnelConfig, AllowTunnelConfig, default_cidr, default_host};
    use crate::tunnel::LocalProtocol;
    use ipnet::{IpNet, Ipv4Net};
    use std::net::Ipv6Addr;
    use std::path::PathBuf;

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
                        host: "example.com".to_string(),
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
                        unix_path: default_host(),
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
            validate_tunnel(&remote, "/doesnt/matter", None, &restrictions, &CertificateVars::default())
                .unwrap()
                .name,
            restrictions.restrictions[0].name
        );

        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert_eq!(
            validate_tunnel(&remote, "/doesnt/matter", None, &restrictions, &CertificateVars::default())
                .unwrap()
                .name,
            restrictions.restrictions[1].name
        );

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 81,
        };
        assert!(validate_tunnel(&remote, "/doesnt/matter", None, &restrictions, &CertificateVars::default()).is_none());

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 1, 1].into()),
            port: 80,
        };
        assert!(validate_tunnel(&remote, "/doesnt/matter", None, &restrictions, &CertificateVars::default()).is_none());

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Domain("example.com".into()),
            port: 80,
        };
        assert_eq!(
            validate_tunnel(&remote, "/doesnt/matter", None, &restrictions, &CertificateVars::default())
                .unwrap()
                .name,
            restrictions.restrictions[0].name
        );

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Domain("not.com".into()),
            port: 80,
        };
        assert!(validate_tunnel(&remote, "/doesnt/matter", None, &restrictions, &CertificateVars::default()).is_none());

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv6(Ipv6Addr::LOCALHOST),
            port: 80,
        };
        assert!(validate_tunnel(&remote, "/doesnt/matter", None, &restrictions, &CertificateVars::default()).is_none());
    }

    #[test]
    fn test_validate_tunnel_with_auth() {
        let restrictions = RestrictionsRules {
            restrictions: vec![RestrictionConfig {
                name: "restrict1".into(),
                r#match: vec![MatchConfig::Authorization("^[Bb]earer +the-bearer-token$".to_string())],
                allow: vec![AllowConfig::Tunnel(AllowTunnelConfig {
                    protocol: vec![],
                    port: vec![],
                    cidr: default_cidr(),
                    host: default_host(),
                })],
            }],
        };

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert_eq!(
            validate_tunnel(
                &remote,
                "/doesnt/matter",
                Some("Bearer the-bearer-token"),
                &restrictions,
                &CertificateVars::default()
            )
            .unwrap()
            .name,
            restrictions.restrictions[0].name
        );
        assert!(
            validate_tunnel(
                &remote,
                "/doesnt/matter",
                Some("Bearer other-bearer-token"),
                &restrictions,
                &CertificateVars::default()
            )
            .is_none()
        );
        assert!(validate_tunnel(&remote, "/doesnt/matter", None, &restrictions, &CertificateVars::default()).is_none());
    }

    #[test]
    fn test_reverse_tunnel_is_allowed() {
        let config = AllowReverseTunnelConfig {
            protocol: vec![ReverseTunnelConfigProtocol::Tcp],
            port: vec![80..=80],
            cidr: vec![IpNet::from(Ipv4Net::new([127, 0, 0, 1].into(), 8).unwrap())],
            port_mapping: Default::default(),
            unix_path: default_host(),
        };

        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert!(config.is_allowed(&remote, &CertificateVars::default()));
        assert!(AllowConfig::from(config.clone()).is_allowed(&remote, &CertificateVars::default()));

        // another ip on the same subnet
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4([127, 0, 1, 1].into()),
            port: 80,
        };
        assert!(config.is_allowed(&remote, &CertificateVars::default()));
        assert!(AllowConfig::from(config.clone()).is_allowed(&remote, &CertificateVars::default()));
    }

    #[test]
    fn test_reverse_tunnel_is_not_allowed() {
        let config = AllowReverseTunnelConfig {
            protocol: vec![ReverseTunnelConfigProtocol::Tcp],
            port: vec![80..=80],
            cidr: vec![IpNet::from(Ipv4Net::new([127, 0, 0, 1].into(), 24).unwrap())],
            port_mapping: Default::default(),
            unix_path: default_host(),
        };

        // wrong IP
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4([127, 0, 1, 1].into()),
            port: 80,
        };
        assert!(!config.is_allowed(&remote, &CertificateVars::default()));
        assert!(!AllowConfig::from(config.clone()).is_allowed(&remote, &CertificateVars::default()));

        // ipv6
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv6(Ipv6Addr::LOCALHOST),
            port: 80,
        };
        assert!(!config.is_allowed(&remote, &CertificateVars::default()));
        assert!(!AllowConfig::from(config.clone()).is_allowed(&remote, &CertificateVars::default()));

        // wrong port
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 81,
        };
        assert!(!config.is_allowed(&remote, &CertificateVars::default()));
        assert!(!AllowConfig::from(config.clone()).is_allowed(&remote, &CertificateVars::default()));

        // wrong protocol - remote
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseUdp { timeout: None },
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert!(!config.is_allowed(&remote, &CertificateVars::default()));
        assert!(!AllowConfig::from(config.clone()).is_allowed(&remote, &CertificateVars::default()));

        // wrong protocol - local
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert!(!config.is_allowed(&remote, &CertificateVars::default()));
        assert!(!AllowConfig::from(config.clone()).is_allowed(&remote, &CertificateVars::default()));

        // host is domain
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Domain("example.com".into()),
            port: 80,
        };
        assert!(!config.is_allowed(&remote, &CertificateVars::default()));
        assert!(!AllowConfig::from(config.clone()).is_allowed(&remote, &CertificateVars::default()));
    }

    #[test]
    fn test_reverse_unix_tunnel_is_allowed() {
        let config = AllowReverseTunnelConfig {
            protocol: vec![ReverseTunnelConfigProtocol::Unix],
            port: vec![],
            cidr: vec![],
            port_mapping: Default::default(),
            unix_path: "^/tmp/tutu$".to_string(),
        };

        // wrong protocol
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4([127, 0, 1, 1].into()),
            port: 80,
        };
        assert!(!config.is_allowed(&remote, &CertificateVars::default()));

        // ReverseUnix is not allowed because wrong path
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseUnix {
                path: PathBuf::from("/tmp/toto"),
            },
            host: Host::Domain("test.com".to_string()),
            port: 12,
        };
        assert!(!config.is_allowed(&remote, &CertificateVars::default()));

        // ReverseUnix is allowed
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseUnix {
                path: PathBuf::from("/tmp/tutu"),
            },
            host: Host::Domain("test.com".to_string()),
            port: 12,
        };
        assert!(config.is_allowed(&remote, &CertificateVars::default()));
    }

    #[test]
    fn test_tunnel_is_allowed() {
        let config = AllowTunnelConfig {
            protocol: vec![TunnelConfigProtocol::Tcp],
            port: vec![80..=80],
            cidr: vec![IpNet::from(Ipv4Net::new([127, 0, 0, 1].into(), 8).unwrap())],
            host: ".*".to_string(),
        };

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert!(config.is_allowed(&remote, &CertificateVars::default()));
        assert!(AllowConfig::from(config.clone()).is_allowed(&remote, &CertificateVars::default()));

        // another ip on the same subnet
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 1, 1].into()),
            port: 80,
        };
        assert!(config.is_allowed(&remote, &CertificateVars::default()));
        assert!(AllowConfig::from(config.clone()).is_allowed(&remote, &CertificateVars::default()));

        // host is domain
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Domain("example.com".into()),
            port: 80,
        };
        assert!(config.is_allowed(&remote, &CertificateVars::default()));
        assert!(AllowConfig::from(config.clone()).is_allowed(&remote, &CertificateVars::default()));
    }

    #[test]
    fn test_tunnel_is_not_allowed() {
        let config = AllowTunnelConfig {
            protocol: vec![TunnelConfigProtocol::Tcp],
            port: vec![80..=80],
            cidr: vec![IpNet::from(Ipv4Net::new([127, 0, 0, 1].into(), 24).unwrap())],
            host: "example.com".to_string(),
        };

        // wrong IP
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 1, 1].into()),
            port: 80,
        };
        assert!(!config.is_allowed(&remote, &CertificateVars::default()));
        assert!(!AllowConfig::from(config.clone()).is_allowed(&remote, &CertificateVars::default()));

        // ipv6
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv6(Ipv6Addr::LOCALHOST),
            port: 80,
        };
        assert!(!config.is_allowed(&remote, &CertificateVars::default()));
        assert!(!AllowConfig::from(config.clone()).is_allowed(&remote, &CertificateVars::default()));

        // wrong port
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 81,
        };
        assert!(!config.is_allowed(&remote, &CertificateVars::default()));
        assert!(!AllowConfig::from(config.clone()).is_allowed(&remote, &CertificateVars::default()));

        // wrong protocol - remote
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert!(!config.is_allowed(&remote, &CertificateVars::default()));
        assert!(!AllowConfig::from(config.clone()).is_allowed(&remote, &CertificateVars::default()));

        // wrong protocol - local
        let remote = RemoteAddr {
            protocol: LocalProtocol::Udp { timeout: None },
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert!(!config.is_allowed(&remote, &CertificateVars::default()));
        assert!(!AllowConfig::from(config.clone()).is_allowed(&remote, &CertificateVars::default()));

        // wrong host
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Domain("not.com".into()),
            port: 80,
        };
        assert!(!config.is_allowed(&remote, &CertificateVars::default()));
        assert!(!AllowConfig::from(config.clone()).is_allowed(&remote, &CertificateVars::default()));
    }

    #[test]
    fn test_extract_path_prefix_happy_path() {
        assert_eq!(extract_path_prefix("/prefix/events"), Ok("prefix"));
        assert_eq!(extract_path_prefix("/prefix/a/events"), Ok("prefix"));
        assert_eq!(extract_path_prefix("/prefix/a/b/events"), Ok("prefix"));
    }

    #[test]
    fn test_extract_path_prefix_no_events_suffix() {
        assert_eq!(extract_path_prefix("/prefix/events/"), Err(PathPrefixErr::BadUpgradeRequest));
        assert_eq!(extract_path_prefix("/prefix"), Err(PathPrefixErr::BadUpgradeRequest));
        assert_eq!(extract_path_prefix("/prefixevents"), Err(PathPrefixErr::BadUpgradeRequest));
        assert_eq!(extract_path_prefix("/prefix/event"), Err(PathPrefixErr::BadUpgradeRequest));
        assert_eq!(extract_path_prefix("/prefix/a"), Err(PathPrefixErr::BadUpgradeRequest));
        assert_eq!(extract_path_prefix("/prefix/a/b"), Err(PathPrefixErr::BadUpgradeRequest));
    }

    #[test]
    fn test_extract_path_prefix_no_slash_prefix() {
        assert_eq!(extract_path_prefix(""), Err(PathPrefixErr::BadPathPrefix));
        assert_eq!(extract_path_prefix("p"), Err(PathPrefixErr::BadPathPrefix));
        assert_eq!(extract_path_prefix("\\"), Err(PathPrefixErr::BadPathPrefix));
        assert_eq!(extract_path_prefix("prefix/events"), Err(PathPrefixErr::BadPathPrefix));
        assert_eq!(extract_path_prefix("prefix/a/events"), Err(PathPrefixErr::BadPathPrefix));
        assert_eq!(extract_path_prefix("prefix/a/b/events"), Err(PathPrefixErr::BadPathPrefix));
    }

    #[test]
    fn test_substitute_vars() {
        let cert_vars = CertificateVars {
            cn: Some("test-cn".to_string()),
        };
        assert_eq!(substitute_vars("${cn}", &cert_vars), "test-cn");
        assert_eq!(substitute_vars("${cert.cn}", &cert_vars), "test-cn");
        assert_eq!(substitute_vars("prefix-${cn}-suffix", &cert_vars), "prefix-test-cn-suffix");
        assert_eq!(substitute_vars("no-vars", &cert_vars), "no-vars");
        assert_eq!(substitute_vars("${cn}", &CertificateVars::default()), "");
    }
}
