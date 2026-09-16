use crate::tunnel::client::TlsClientConfig;
use anyhow::anyhow;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use std::sync::Arc;
use url::{Host, Url};

#[derive(Copy, Clone, Debug)]
pub enum TransportScheme {
    Ws,
    Wss,
    Http,
    Https,
    Wts,
}

impl TransportScheme {
    #[cfg(feature = "clap")] // this is only used inside a clap value parser
    pub const fn values() -> &'static [Self] {
        &[Self::Ws, Self::Wss, Self::Http, Self::Https, Self::Wts]
    }
    pub const fn to_str(self) -> &'static str {
        match self {
            Self::Ws => "ws",
            Self::Wss => "wss",
            Self::Http => "http",
            Self::Https => "https",
            Self::Wts => "wts",
        }
    }

    pub fn alpn_protocols(&self) -> Vec<Vec<u8>> {
        match self {
            Self::Ws => vec![],
            Self::Wss => vec![b"http/1.1".to_vec()],
            Self::Http => vec![],
            Self::Https => vec![b"h2".to_vec()],
            // WebTransport rides HTTP/3, whose ALPN is "h3"
            Self::Wts => vec![web_transport_quinn::ALPN.as_bytes().to_vec()],
        }
    }

    /// WebTransport runs over QUIC, which mandates TLS 1.3. There is no cleartext variant.
    pub const fn is_webtransport(self) -> bool {
        matches!(self, Self::Wts)
    }
}
impl FromStr for TransportScheme {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "https" => Ok(Self::Https),
            "http" => Ok(Self::Http),
            "wss" => Ok(Self::Wss),
            "ws" => Ok(Self::Ws),
            "wts" => Ok(Self::Wts),
            _ => Err(()),
        }
    }
}

impl Display for TransportScheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_str())
    }
}

#[derive(Clone)]
pub enum TransportAddr {
    Wss {
        tls: TlsClientConfig,
        scheme: TransportScheme,
        host: Host,
        port: u16,
    },
    Ws {
        scheme: TransportScheme,
        host: Host,
        port: u16,
    },
    Https {
        scheme: TransportScheme,
        tls: TlsClientConfig,
        host: Host,
        port: u16,
    },
    Http {
        scheme: TransportScheme,
        host: Host,
        port: u16,
    },
    WebTransport {
        scheme: TransportScheme,
        tls: TlsClientConfig,
        host: Host,
        port: u16,
    },
}

impl Debug for TransportAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}://{}:{}", self.scheme(), self.host(), self.port()))
    }
}

impl TransportAddr {
    pub fn new(scheme: TransportScheme, host: Host, port: u16, tls: Option<TlsClientConfig>) -> Option<Self> {
        match scheme {
            TransportScheme::Https => Some(Self::Https {
                scheme: TransportScheme::Https,
                tls: tls?,
                host,
                port,
            }),
            TransportScheme::Http => Some(Self::Http {
                scheme: TransportScheme::Http,
                host,
                port,
            }),
            TransportScheme::Wss => Some(Self::Wss {
                scheme: TransportScheme::Wss,
                tls: tls?,
                host,
                port,
            }),
            TransportScheme::Ws => Some(Self::Ws {
                scheme: TransportScheme::Ws,
                host,
                port,
            }),
            TransportScheme::Wts => Some(Self::WebTransport {
                scheme: TransportScheme::Wts,
                tls: tls?,
                host,
                port,
            }),
        }
    }

    pub const fn tls(&self) -> Option<&TlsClientConfig> {
        match self {
            Self::Wss { tls, .. } => Some(tls),
            Self::Https { tls, .. } => Some(tls),
            Self::WebTransport { tls, .. } => Some(tls),
            Self::Ws { .. } => None,
            Self::Http { .. } => None,
        }
    }

    pub const fn host(&self) -> &Host {
        match self {
            Self::Wss { host, .. } => host,
            Self::Ws { host, .. } => host,
            Self::Https { host, .. } => host,
            Self::Http { host, .. } => host,
            Self::WebTransport { host, .. } => host,
        }
    }

    pub const fn port(&self) -> u16 {
        match self {
            Self::Wss { port, .. } => *port,
            Self::Ws { port, .. } => *port,
            Self::Https { port, .. } => *port,
            Self::Http { port, .. } => *port,
            Self::WebTransport { port, .. } => *port,
        }
    }

    pub const fn scheme(&self) -> &TransportScheme {
        match self {
            Self::Wss { scheme, .. } => scheme,
            Self::Ws { scheme, .. } => scheme,
            Self::Https { scheme, .. } => scheme,
            Self::Http { scheme, .. } => scheme,
            Self::WebTransport { scheme, .. } => scheme,
        }
    }

    /// Returns the authority string (e.g. `example.com:443` or `[::1]:443`).
    pub fn authority(&self) -> String {
        match self.host() {
            Host::Domain(d) => format!("{}:{}", d, self.port()),
            Host::Ipv4(ip) => format!("{}:{}", ip, self.port()),
            Host::Ipv6(ip) => format!("[{}]:{}", ip, self.port()),
        }
    }

    /// Converts this `TransportAddr` into a base `url::Url` with the given path.
    pub fn to_url_with_path(&self, path: &str) -> Result<Url, url::ParseError> {
        let scheme_str = self.scheme().to_str();
        let host_str = match self.host() {
            Host::Domain(d) => d.clone(),
            Host::Ipv4(ip) => ip.to_string(),
            Host::Ipv6(ip) => format!("[{ip}]"),
        };
        let normalized_path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        Url::parse(&format!("{scheme_str}://{host_str}:{}{normalized_path}", self.port()))
    }

    /// Resolve an HTTP `Location` header against this address and current path prefix.
    ///
    /// Handles relative/absolute URLs, RFC 6455 scheme translation (`http` -> `ws`, `https` -> `wss`),
    /// TLS downgrade protection (refusing `wss`/`https` -> `ws`/`http`), and cycle detection via `visited`.
    ///
    /// Returns the new target [`TransportAddr`] and the resolved path prefix.
    pub fn resolve_redirect(
        &self,
        current_path_prefix: &str,
        location: &str,
        visited: &mut HashSet<Url>,
    ) -> anyhow::Result<(Self, String)> {
        let trimmed_location = location.trim();
        if trimmed_location.is_empty() {
            return Err(anyhow!("Empty Location header in redirect"));
        }

        // Construct base URL from current transport address and request path: /{prefix}/events
        let base_path = format!("/{current_path_prefix}/events");
        let base_url = self
            .to_url_with_path(&base_path)
            .map_err(|err| anyhow!("Cannot construct base URL from current address: {err}"))?;

        // Parse target URL relative to base URL (handles absolute, protocol-relative, path-absolute, and relative paths)
        let new_url = base_url
            .join(trimmed_location)
            .map_err(|err| anyhow!("Invalid redirect Location '{location}': {err}"))?;

        // Cycle detection: track visited URLs (normalized without query or fragment)
        let mut normalized_url = new_url.clone();
        normalized_url.set_query(None);
        normalized_url.set_fragment(None);
        if !visited.insert(normalized_url.clone()) {
            return Err(anyhow!("Redirect loop detected: {normalized_url}"));
        }

        // Scheme mapping & TLS downgrade prevention
        let is_secure_original = matches!(
            self.scheme(),
            TransportScheme::Wss | TransportScheme::Https | TransportScheme::Wts
        );
        let new_scheme = match new_url.scheme() {
            "http" => {
                if is_secure_original {
                    return Err(anyhow!(
                        "Refusing to downgrade from secure scheme ({}) to insecure scheme (http)",
                        self.scheme()
                    ));
                }
                match self.scheme() {
                    TransportScheme::Http => TransportScheme::Http,
                    _ => TransportScheme::Ws,
                }
            }
            "https" => match self.scheme() {
                TransportScheme::Http | TransportScheme::Https => TransportScheme::Https,
                _ => TransportScheme::Wss,
            },
            "ws" => {
                if is_secure_original {
                    return Err(anyhow!(
                        "Refusing to downgrade from secure scheme ({}) to insecure scheme (ws)",
                        self.scheme()
                    ));
                }
                TransportScheme::Ws
            }
            "wss" => match self.scheme() {
                TransportScheme::Http | TransportScheme::Https => TransportScheme::Https,
                _ => TransportScheme::Wss,
            },
            other => {
                return Err(anyhow!("Unsupported redirect scheme: '{other}'"));
            }
        };

        // Extract host
        let host = match new_url.host() {
            Some(url::Host::Domain(d)) => Host::Domain(d.to_string()),
            Some(url::Host::Ipv4(ip)) => Host::Ipv4(ip),
            Some(url::Host::Ipv6(ip)) => Host::Ipv6(ip),
            None => return Err(anyhow!("Redirect URL missing host: {new_url}")),
        };

        // Extract port
        let port = new_url.port_or_known_default().unwrap_or(match new_scheme {
            TransportScheme::Ws | TransportScheme::Http => 80,
            TransportScheme::Wss | TransportScheme::Https | TransportScheme::Wts => 443,
        });

        // Determine path prefix:
        // - If redirect path is empty or "/", preserve existing prefix (e.g. server host redirect)
        // - If redirect path ends with "/events", extract prefix preceding it (e.g. "/v2/events" -> "v2")
        // - Otherwise, extract non-empty path segment as prefix
        let path = new_url.path();
        let new_prefix = if path.is_empty() || path == "/" {
            current_path_prefix.to_string()
        } else if let Some(stripped) = path.strip_suffix("/events") {
            let p = stripped.trim_matches('/');
            if p.is_empty() {
                current_path_prefix.to_string()
            } else {
                p.to_string()
            }
        } else {
            let p = path.trim_matches('/');
            if p.is_empty() {
                current_path_prefix.to_string()
            } else {
                p.to_string()
            }
        };

        // TLS configuration: carry over existing TLS configuration if the target requires TLS
        let tls = match self.tls().cloned() {
            Some(tls) => Some(tls),
            None if matches!(new_scheme, TransportScheme::Wss | TransportScheme::Https) => {
                let connector = crate::protocols::tls::tls_connector(
                    false,
                    new_scheme.alpn_protocols(),
                    true,
                    None,
                    None,
                    None,
                )
                .map_err(|err| anyhow!("Cannot create TLS connector for redirected address: {err}"))?;
                Some(TlsClientConfig {
                    tls_sni_disabled: false,
                    tls_sni_override: None,
                    tls_verify_certificate: false,
                    tls_connector: Arc::new(RwLock::new(connector)),
                    tls_certificate_path: None,
                    tls_key_path: None,
                })
            }
            None => None,
        };

        let new_transport_addr = match new_scheme {
            TransportScheme::Wss => TransportAddr::Wss {
                scheme: TransportScheme::Wss,
                tls: tls.ok_or_else(|| anyhow!("TLS configuration required for wss:// redirect"))?,
                host,
                port,
            },
            TransportScheme::Ws => TransportAddr::Ws {
                scheme: TransportScheme::Ws,
                host,
                port,
            },
            TransportScheme::Https => TransportAddr::Https {
                scheme: TransportScheme::Https,
                tls: tls.ok_or_else(|| anyhow!("TLS configuration required for https:// redirect"))?,
                host,
                port,
            },
            TransportScheme::Http => TransportAddr::Http {
                scheme: TransportScheme::Http,
                host,
                port,
            },
            TransportScheme::Wts => {
                return Err(anyhow!("Redirection to webtransport (wts://) is not supported"));
            }
        };

        Ok((new_transport_addr, new_prefix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_tls_config() -> TlsClientConfig {
        let connector = crate::protocols::tls::tls_connector(
            false,
            TransportScheme::Wss.alpn_protocols(),
            true,
            None,
            None,
            None,
        )
        .unwrap();
        TlsClientConfig {
            tls_sni_disabled: false,
            tls_sni_override: None,
            tls_verify_certificate: false,
            tls_connector: Arc::new(RwLock::new(connector)),
            tls_certificate_path: None,
            tls_key_path: None,
        }
    }

    #[test]
    fn test_resolve_redirect_relative_path() {
        let addr = TransportAddr::Ws {
            scheme: TransportScheme::Ws,
            host: Host::Domain("d1.example.com".to_string()),
            port: 80,
        };
        let mut visited = HashSet::new();

        let (new_addr, new_prefix) = addr.resolve_redirect("v1", "/v2/events", &mut visited).unwrap();
        assert_eq!(new_addr.host(), &Host::Domain("d1.example.com".to_string()));
        assert_eq!(new_addr.port(), 80);
        assert_eq!(new_prefix, "v2");
        assert!(matches!(new_addr.scheme(), TransportScheme::Ws));
    }

    #[test]
    fn test_resolve_redirect_domain_and_port() {
        let addr = TransportAddr::Ws {
            scheme: TransportScheme::Ws,
            host: Host::Domain("server2.com".to_string()),
            port: 8000,
        };
        let mut visited = HashSet::new();

        // Testing dynamic server redirect like in Issue #479
        let (new_addr, new_prefix) = addr
            .resolve_redirect("v1", "http://server1.com:8456", &mut visited)
            .unwrap();
        assert_eq!(new_addr.host(), &Host::Domain("server1.com".to_string()));
        assert_eq!(new_addr.port(), 8456);
        assert_eq!(new_prefix, "v1");
        assert!(matches!(new_addr.scheme(), TransportScheme::Ws));
    }

    #[test]
    fn test_resolve_redirect_rfc6455_scheme_translation() {
        let addr = TransportAddr::Wss {
            scheme: TransportScheme::Wss,
            tls: dummy_tls_config(),
            host: Host::Domain("d1.example.com".to_string()),
            port: 443,
        };
        let mut visited = HashSet::new();

        // An HTTPS redirect should map to WSS per RFC 6455
        let (new_addr, new_prefix) = addr
            .resolve_redirect("v1", "https://d2.example.com/custom_prefix/events", &mut visited)
            .unwrap();
        assert_eq!(new_addr.host(), &Host::Domain("d2.example.com".to_string()));
        assert_eq!(new_addr.port(), 443);
        assert_eq!(new_prefix, "custom_prefix");
        assert!(matches!(new_addr.scheme(), TransportScheme::Wss));
    }

    #[test]
    fn test_resolve_redirect_downgrade_protection() {
        let addr = TransportAddr::Wss {
            scheme: TransportScheme::Wss,
            tls: dummy_tls_config(),
            host: Host::Domain("d1.example.com".to_string()),
            port: 443,
        };
        let mut visited = HashSet::new();

        // Redirecting from wss:// to http:// or ws:// must fail
        let err = addr
            .resolve_redirect("v1", "http://insecure.example.com/", &mut visited)
            .unwrap_err();
        assert!(err.to_string().contains("Refusing to downgrade"));

        let err_ws = addr
            .resolve_redirect("v1", "ws://insecure.example.com/", &mut visited)
            .unwrap_err();
        assert!(err_ws.to_string().contains("Refusing to downgrade"));
    }

    #[test]
    fn test_resolve_redirect_cycle_detection() {
        let addr = TransportAddr::Ws {
            scheme: TransportScheme::Ws,
            host: Host::Domain("d1.example.com".to_string()),
            port: 80,
        };
        let mut visited = HashSet::new();

        // First redirect to d2 succeeds
        let (d2_addr, _) = addr
            .resolve_redirect("v1", "http://d2.example.com/v1/events", &mut visited)
            .unwrap();

        // Second redirect to d2 detects loop
        let err = d2_addr
            .resolve_redirect("v1", "http://d2.example.com/v1/events", &mut visited)
            .unwrap_err();
        assert!(err.to_string().contains("Redirect loop detected"));
    }

    #[test]
    fn test_resolve_redirect_protocol_relative() {
        let addr = TransportAddr::Wss {
            scheme: TransportScheme::Wss,
            tls: dummy_tls_config(),
            host: Host::Domain("d1.example.com".to_string()),
            port: 443,
        };
        let mut visited = HashSet::new();

        let (new_addr, new_prefix) = addr
            .resolve_redirect("v1", "//d2.example.com:8443/new_prefix/events", &mut visited)
            .unwrap();
        assert_eq!(new_addr.host(), &Host::Domain("d2.example.com".to_string()));
        assert_eq!(new_addr.port(), 8443);
        assert_eq!(new_prefix, "new_prefix");
        assert!(matches!(new_addr.scheme(), TransportScheme::Wss));
    }
}
