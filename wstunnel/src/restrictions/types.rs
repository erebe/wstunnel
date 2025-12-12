use crate::tunnel::LocalProtocol;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use regex::Regex;
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::ops::RangeInclusive;

#[derive(Debug, Clone, Deserialize)]
pub struct RestrictionsRules {
    pub restrictions: Vec<RestrictionConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RestrictionConfig {
    pub name: String,
    #[serde(deserialize_with = "deserialize_non_empty_vec")]
    pub r#match: Vec<MatchConfig>,
    pub allow: Vec<AllowConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub enum MatchConfig {
    Any,
    #[serde(with = "serde_regex")]
    PathPrefix(Regex),
    #[serde(with = "serde_regex")]
    Authorization(Regex),
}

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(derive_more::From))]
pub enum AllowConfig {
    ReverseTunnel(AllowReverseTunnelConfig),
    Tunnel(AllowTunnelConfig),
}

#[derive(Debug, Clone, Deserialize)]
pub struct AllowTunnelConfig {
    #[serde(default)]
    pub protocol: Vec<TunnelConfigProtocol>,

    #[serde(deserialize_with = "deserialize_port_range")]
    #[serde(default)]
    pub port: Vec<RangeInclusive<u16>>,

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
    #[serde(default)]
    pub port: Vec<RangeInclusive<u16>>,

    #[serde(deserialize_with = "deserialize_port_mapping")]
    #[serde(default)]
    pub port_mapping: HashMap<u16, u16>,

    #[serde(default = "default_cidr")]
    pub cidr: Vec<IpNet>,

    #[serde(with = "serde_regex")]
    #[serde(default = "default_host")]
    pub unix_path: Regex,
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
    HttpProxy,
    Unknown,
}

pub fn default_host() -> Regex {
    Regex::new("^.*$").unwrap()
}

pub fn default_cidr() -> Vec<IpNet> {
    vec![IpNet::V4(Ipv4Net::default()), IpNet::V6(Ipv6Net::default())]
}

fn deserialize_port_range<'de, D>(deserializer: D) -> Result<Vec<RangeInclusive<u16>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = Vec::<String>::deserialize(deserializer)?;
    let ranges = s
        .into_iter()
        .map(|s| {
            let range: Result<RangeInclusive<u16>, D::Error> = if let Some((l, r)) = s.split_once("..") {
                Ok(RangeInclusive::new(
                    l.parse().map_err(<D::Error as serde::de::Error>::custom)?,
                    r.parse().map_err(<D::Error as serde::de::Error>::custom)?,
                ))
            } else {
                let port = s.parse::<u16>().map_err(serde::de::Error::custom)?;
                Ok(RangeInclusive::new(port, port))
            };
            range
        })
        .collect::<Vec<_>>()
        .into_iter()
        .collect::<Result<Vec<RangeInclusive<u16>>, D::Error>>()?;

    Ok(ranges)
}

fn deserialize_port_mapping<'de, D>(deserializer: D) -> Result<HashMap<u16, u16>, D::Error>
where
    D: Deserializer<'de>,
{
    let mappings: Vec<String> = Deserialize::deserialize(deserializer)?;
    mappings
        .into_iter()
        .map(|port_mapping| {
            let port_mapping_parts: Vec<&str> = port_mapping.split(':').collect();
            if port_mapping_parts.len() != 2 {
                Err(serde::de::Error::custom(format!("Invalid port_mapping entry: {port_mapping}")))
            } else {
                let orig_port = port_mapping_parts[0].parse::<u16>().map_err(serde::de::Error::custom)?;
                let target_port = port_mapping_parts[1].parse::<u16>().map_err(serde::de::Error::custom)?;
                Ok((orig_port, target_port))
            }
        })
        .collect()
}

fn deserialize_non_empty_vec<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let vec = <Vec<T>>::deserialize(d)?;
    if vec.is_empty() {
        Err(serde::de::Error::custom("List must not be empty"))
    } else {
        Ok(vec)
    }
}

impl From<&LocalProtocol> for ReverseTunnelConfigProtocol {
    fn from(value: &LocalProtocol) -> Self {
        match value {
            LocalProtocol::Tcp { .. }
            | LocalProtocol::Udp { .. }
            | LocalProtocol::Stdio { .. }
            | LocalProtocol::Socks5 { .. }
            | LocalProtocol::TProxyTcp
            | LocalProtocol::TProxyUdp { .. }
            | LocalProtocol::HttpProxy { .. }
            | LocalProtocol::Unix { .. } => Self::Unknown,
            LocalProtocol::ReverseTcp => Self::Tcp,
            LocalProtocol::ReverseUdp { .. } => Self::Udp,
            LocalProtocol::ReverseSocks5 { .. } => Self::Socks5,
            LocalProtocol::ReverseUnix { .. } => Self::Unix,
            LocalProtocol::ReverseHttpProxy { .. } => Self::HttpProxy,
        }
    }
}
impl From<&LocalProtocol> for TunnelConfigProtocol {
    fn from(value: &LocalProtocol) -> Self {
        match value {
            LocalProtocol::ReverseTcp
            | LocalProtocol::ReverseUdp { .. }
            | LocalProtocol::ReverseSocks5 { .. }
            | LocalProtocol::ReverseUnix { .. }
            | LocalProtocol::Stdio { .. }
            | LocalProtocol::Socks5 { .. }
            | LocalProtocol::TProxyTcp
            | LocalProtocol::TProxyUdp { .. }
            | LocalProtocol::HttpProxy { .. }
            | LocalProtocol::ReverseHttpProxy { .. }
            | LocalProtocol::Unix { .. } => Self::Unknown,
            LocalProtocol::Tcp { .. } => Self::Tcp,
            LocalProtocol::Udp { .. } => Self::Udp,
        }
    }
}
