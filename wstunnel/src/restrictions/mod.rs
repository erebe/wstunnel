use ipnet::IpNet;
use regex::Regex;
use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::path::Path;
use std::str::FromStr;
use std::vec;

use types::RestrictionsRules;

use crate::restrictions::types::{default_cidr, default_host};

pub mod config_reloader;
pub mod types;

impl RestrictionsRules {
    pub fn from_config_file(config_path: &Path) -> anyhow::Result<Self> {
        let restrictions: Self = serde_yaml::from_reader(BufReader::new(File::open(config_path)?))?;
        Ok(restrictions)
    }

    pub fn from_path_prefix(path_prefixes: &[String], restrict_to: &[(String, u16)]) -> anyhow::Result<Self> {
        let tunnels_restrictions = if restrict_to.is_empty() {
            let r = types::AllowConfig::Tunnel(types::AllowTunnelConfig {
                protocol: vec![],
                port: vec![],
                host: default_host(),
                cidr: default_cidr(),
            });
            let reverse_tunnel = types::AllowConfig::ReverseTunnel(types::AllowReverseTunnelConfig {
                protocol: vec![],
                port: vec![],
                port_mapping: Default::default(),
                cidr: default_cidr(),
            });

            vec![r, reverse_tunnel]
        } else {
            restrict_to
                .iter()
                .map(|(host, port)| {
                    let tunnels = if let Ok(ip) = IpAddr::from_str(host) {
                        vec![
                            types::AllowConfig::Tunnel(types::AllowTunnelConfig {
                                protocol: vec![],
                                port: vec![RangeInclusive::new(*port, *port)],
                                host: Regex::new("^$")?,
                                cidr: vec![IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 })?],
                            }),
                            types::AllowConfig::ReverseTunnel(types::AllowReverseTunnelConfig {
                                protocol: vec![],
                                port: vec![RangeInclusive::new(*port, *port)],
                                port_mapping: Default::default(),
                                cidr: vec![IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 })?],
                            }),
                        ]
                    } else {
                        vec![
                            types::AllowConfig::Tunnel(types::AllowTunnelConfig {
                                protocol: vec![],
                                port: vec![RangeInclusive::new(*port, *port)],
                                host: Regex::new(&format!("^{}$", regex::escape(host)))?,
                                cidr: default_cidr(),
                            }),
                            types::AllowConfig::ReverseTunnel(types::AllowReverseTunnelConfig {
                                protocol: vec![],
                                port: vec![],
                                port_mapping: Default::default(),
                                cidr: default_cidr(),
                            }),
                        ]
                    };

                    Ok(tunnels)
                })
                .collect::<Result<Vec<_>, anyhow::Error>>()?
                .into_iter()
                .flatten()
                .collect()
        };

        let restrictions = if path_prefixes.is_empty() {
            // if no path prefixes are provided, we allow all
            let r = types::RestrictionConfig {
                name: "Allow All".to_string(),
                r#match: vec![types::MatchConfig::Any],
                allow: tunnels_restrictions,
            };
            vec![r]
        } else {
            path_prefixes
                .iter()
                .map(|path_prefix| {
                    let reg = Regex::new(&format!("^{}$", regex::escape(path_prefix)))?;
                    Ok(types::RestrictionConfig {
                        name: format!("Allow path prefix {}", path_prefix),
                        r#match: vec![types::MatchConfig::PathPrefix(reg)],
                        allow: tunnels_restrictions.clone(),
                    })
                })
                .collect::<Result<Vec<_>, anyhow::Error>>()?
        };

        Ok(Self { restrictions })
    }
}
