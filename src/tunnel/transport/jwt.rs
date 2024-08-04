use crate::tunnel::{LocalProtocol, RemoteAddr};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ops::Deref;
use url::Host;
use uuid::Uuid;

pub static JWT_HEADER_PREFIX: &str = "authorization.bearer.";
static JWT_SECRET: &[u8; 15] = b"champignonfrais";
static JWT_KEY: Lazy<(Header, EncodingKey)> =
    Lazy::new(|| (Header::new(Algorithm::HS256), EncodingKey::from_secret(JWT_SECRET)));

static JWT_DECODE: Lazy<(Validation, DecodingKey)> = Lazy::new(|| {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims = HashSet::with_capacity(0);
    (validation, DecodingKey::from_secret(JWT_SECRET))
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtTunnelConfig {
    pub id: String,       // tunnel id
    pub p: LocalProtocol, // protocol to use
    pub r: String,        // remote host
    pub rp: u16,          // remote port
}

impl JwtTunnelConfig {
    fn new(request_id: Uuid, dest: &RemoteAddr) -> Self {
        Self {
            id: request_id.to_string(),
            p: match dest.protocol {
                LocalProtocol::Tcp { .. } => dest.protocol.clone(),
                LocalProtocol::Udp { .. } => dest.protocol.clone(),
                LocalProtocol::Stdio => LocalProtocol::Tcp { proxy_protocol: false },
                LocalProtocol::Socks5 { .. } => LocalProtocol::Tcp { proxy_protocol: false },
                LocalProtocol::HttpProxy { .. } => dest.protocol.clone(),
                LocalProtocol::ReverseTcp => LocalProtocol::ReverseTcp,
                LocalProtocol::ReverseUdp { .. } => dest.protocol.clone(),
                LocalProtocol::ReverseSocks5 { .. } => dest.protocol.clone(),
                LocalProtocol::TProxyTcp => LocalProtocol::Tcp { proxy_protocol: false },
                LocalProtocol::TProxyUdp { timeout } => LocalProtocol::Udp { timeout },
                LocalProtocol::Unix { .. } => LocalProtocol::Tcp { proxy_protocol: false },
                LocalProtocol::ReverseUnix { .. } => dest.protocol.clone(),
                LocalProtocol::ReverseHttpProxy { .. } => dest.protocol.clone(),
            },
            r: dest.host.to_string(),
            rp: dest.port,
        }
    }
}

pub fn tunnel_to_jwt_token(request_id: Uuid, tunnel: &RemoteAddr) -> String {
    let cfg = JwtTunnelConfig::new(request_id, tunnel);
    let (alg, secret) = JWT_KEY.deref();
    jsonwebtoken::encode(alg, &cfg, secret).unwrap_or_default()
}

pub fn jwt_token_to_tunnel(token: &str) -> anyhow::Result<TokenData<JwtTunnelConfig>> {
    let (validation, decode_key) = JWT_DECODE.deref();
    let jwt: TokenData<JwtTunnelConfig> = jsonwebtoken::decode(token, decode_key, validation)?;
    Ok(jwt)
}

impl TryFrom<JwtTunnelConfig> for RemoteAddr {
    type Error = anyhow::Error;
    fn try_from(jwt: JwtTunnelConfig) -> anyhow::Result<Self> {
        Ok(Self {
            protocol: jwt.p,
            host: Host::parse(&jwt.r)?,
            port: jwt.rp,
        })
    }
}
