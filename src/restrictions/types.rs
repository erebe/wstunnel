use crate::LocalProtocol;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use regex::Regex;
use serde::{Deserialize, Deserializer};
use std::ops::RangeInclusive;

#[derive(Debug, Clone, Deserialize)]
pub struct RestrictionsRules {
    pub restrictions: Vec<RestrictionConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RestrictionConfig {
    pub name: String,
    pub r#match: MatchConfig,
    pub allow: Vec<AllowConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub enum MatchConfig {
    Any,
    #[serde(with = "serde_regex")]
    PathPrefix(Regex),
}

#[derive(Debug, Clone, Deserialize)]
pub enum AllowConfig {
    ReverseTunnel(AllowReverseTunnelConfig),
    Tunnel(AllowTunnelConfig),
}

#[derive(Debug, Clone, Deserialize)]
pub struct AllowTunnelConfig {
    #[serde(default)]
    pub protocol: Vec<TunnelConfigProtocol>,

    #[serde(deserialize_with = "deserialize_port_range")]
    #[serde(default = "default_port")]
    pub port: RangeInclusive<u16>,

    #[serde(with = "serde_regex")]
    #[serde(default = "default_host")]
    pub host: Regex,

    #[serde(default = "default_cidr")]
    pub cidr: Vec<IpNet>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AllowReverseTunnelConfig {
    #[serde(default)]
    pub protocol: Vec<ReverseTunnelConfigProtocol>,

    #[serde(deserialize_with = "deserialize_port_range")]
    #[serde(default = "default_port")]
    pub port: RangeInclusive<u16>,

    #[serde(default = "default_cidr")]
    pub cidr: Vec<IpNet>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub enum TunnelConfigProtocol {
    Tcp,
    Udp,
    Unknown,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub enum ReverseTunnelConfigProtocol {
    Tcp,
    Udp,
    Socks5,
    Unix,
    Unknown,
}

pub fn default_port() -> RangeInclusive<u16> {
    RangeInclusive::new(1, 65535)
}

pub fn default_host() -> Regex {
    Regex::new("^.*$").unwrap()
}

pub fn default_cidr() -> Vec<IpNet> {
    vec![IpNet::V4(Ipv4Net::default()), IpNet::V6(Ipv6Net::default())]
}

fn deserialize_port_range<'de, D>(deserializer: D) -> Result<RangeInclusive<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let range = if let Some((l, r)) = s.split_once("..") {
        RangeInclusive::new(
            l.parse().map_err(serde::de::Error::custom)?,
            r.parse().map_err(serde::de::Error::custom)?,
        )
    } else {
        let port = s.parse::<u16>().map_err(serde::de::Error::custom)?;
        RangeInclusive::new(port, port)
    };

    Ok(range)
}

impl From<&LocalProtocol> for ReverseTunnelConfigProtocol {
    fn from(value: &LocalProtocol) -> Self {
        match value {
            LocalProtocol::Tcp { .. }
            | LocalProtocol::Udp { .. }
            | LocalProtocol::Stdio
            | LocalProtocol::Socks5 { .. }
            | LocalProtocol::TProxyTcp { .. }
            | LocalProtocol::TProxyUdp { .. }
            | LocalProtocol::Unix { .. } => ReverseTunnelConfigProtocol::Unknown,
            LocalProtocol::ReverseTcp => ReverseTunnelConfigProtocol::Tcp,
            LocalProtocol::ReverseUdp { .. } => ReverseTunnelConfigProtocol::Udp,
            LocalProtocol::ReverseSocks5 => ReverseTunnelConfigProtocol::Socks5,
            LocalProtocol::ReverseUnix { .. } => ReverseTunnelConfigProtocol::Unix,
        }
    }
}
impl From<&LocalProtocol> for TunnelConfigProtocol {
    fn from(value: &LocalProtocol) -> Self {
        match value {
            LocalProtocol::ReverseTcp
            | LocalProtocol::ReverseUdp { .. }
            | LocalProtocol::ReverseSocks5
            | LocalProtocol::ReverseUnix { .. }
            | LocalProtocol::Stdio
            | LocalProtocol::Socks5 { .. }
            | LocalProtocol::TProxyTcp { .. }
            | LocalProtocol::TProxyUdp { .. }
            | LocalProtocol::Unix { .. } => TunnelConfigProtocol::Unknown,
            LocalProtocol::Tcp { .. } => TunnelConfigProtocol::Tcp,
            LocalProtocol::Udp { .. } => TunnelConfigProtocol::Udp,
        }
    }
}
