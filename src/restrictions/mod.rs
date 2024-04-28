use crate::restrictions::types::{default_cidr, default_host};
use regex::Regex;
use std::fs::File;
use std::io::BufReader;
use std::ops::RangeInclusive;
use std::path::Path;
use types::RestrictionsRules;

pub mod types;

impl RestrictionsRules {
    pub fn from_config_file(config_path: &Path) -> anyhow::Result<RestrictionsRules> {
        let restrictions: RestrictionsRules = serde_yaml::from_reader(BufReader::new(File::open(config_path)?))?;
        Ok(restrictions)
    }

    pub fn from_path_prefix(
        path_prefixes: &[String],
        restrict_to: &[(String, u16)],
    ) -> anyhow::Result<RestrictionsRules> {
        let mut tunnels_restrictions = if restrict_to.is_empty() {
            let r = types::AllowConfig::Tunnel(types::AllowTunnelConfig {
                protocol: vec![],
                port: vec![],
                host: default_host(),
                cidr: default_cidr(),
            });
            vec![r]
        } else {
            restrict_to
                .iter()
                .map(|(host, port)| {
                    let reg = Regex::new(&format!("^{}$", regex::escape(host)))?;
                    Ok(types::AllowConfig::Tunnel(types::AllowTunnelConfig {
                        protocol: vec![],
                        port: vec![RangeInclusive::new(*port, *port)],
                        host: reg,
                        cidr: default_cidr(),
                    }))
                })
                .collect::<Result<Vec<_>, anyhow::Error>>()?
        };

        tunnels_restrictions.push(types::AllowConfig::ReverseTunnel(types::AllowReverseTunnelConfig {
            protocol: vec![],
            port: vec![],
            cidr: default_cidr(),
        }));

        let restrictions = if path_prefixes.is_empty() {
            // if no path prefixes are provided, we allow all
            let reg = Regex::new(".").unwrap();
            let r = types::RestrictionConfig {
                name: "Allow All".to_string(),
                r#match: types::MatchConfig::PathPrefix(reg),
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
                        r#match: types::MatchConfig::PathPrefix(reg),
                        allow: tunnels_restrictions.clone(),
                    })
                })
                .collect::<Result<Vec<_>, anyhow::Error>>()?
        };

        Ok(RestrictionsRules { restrictions })
    }
}
