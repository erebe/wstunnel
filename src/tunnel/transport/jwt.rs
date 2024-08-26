use crate::tunnel::{LocalProtocol, RemoteAddr};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ops::Deref;
use std::sync::LazyLock;
use std::time::SystemTime;
use url::Host;
use uuid::Uuid;

pub static JWT_HEADER_PREFIX: &str = "authorization.bearer.";
static JWT_KEY: LazyLock<(Header, EncodingKey)> = LazyLock::new(|| {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_ne_bytes();
    (Header::new(Algorithm::HS256), EncodingKey::from_secret(&now))
});

static JWT_DECODE: LazyLock<(Validation, DecodingKey)> = LazyLock::new(|| {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims = HashSet::with_capacity(0);
    validation.insecure_disable_signature_validation();
    (validation, DecodingKey::from_secret(b"champignonfrais"))
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
                LocalProtocol::ReverseTcp => dest.protocol.clone(),
                LocalProtocol::ReverseUdp { .. } => dest.protocol.clone(),
                LocalProtocol::ReverseSocks5 { .. } => dest.protocol.clone(),
                LocalProtocol::ReverseUnix { .. } => dest.protocol.clone(),
                LocalProtocol::ReverseHttpProxy { .. } => dest.protocol.clone(),
                LocalProtocol::TProxyTcp => unreachable!("cannot use tproxy tcp as destination protocol"),
                LocalProtocol::TProxyUdp { .. } => unreachable!("cannot use tproxy udp as destination protocol"),
                LocalProtocol::Stdio { .. } => unreachable!("cannot use stdio as destination protocol"),
                LocalProtocol::Unix { .. } => unreachable!("canont use unix as destination protocol"),
                LocalProtocol::Socks5 { .. } => unreachable!("cannot use socks5 as destination protocol"),
                LocalProtocol::HttpProxy { .. } => unreachable!("cannot use http proxy as destination protocol"),
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
