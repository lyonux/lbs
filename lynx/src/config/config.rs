use anyhow::{Context, Result};
use lbs_core::prelude::Protocol;
use lbs_core::prelude::Rule;
use lbs_core::prelude::Target;
use serde::{Deserialize, Deserializer, Serialize, de};
use std::collections::HashMap;
use std::path::Path;

/// Port mapping: source port (as string for TOML) -> list of targets
/// This helper type handles deserialization of string port keys to u16
#[derive(Debug, Clone, Serialize, Default)]
pub struct PortMapping {
    inner: HashMap<u16, Vec<Target>>,
}

impl PortMapping {
    pub fn iter(&self) -> impl Iterator<Item = (&u16, &Vec<Target>)> {
        self.inner.iter()
    }

    pub fn get(&self, key: &u16) -> Option<&Vec<Target>> {
        self.inner.get(key)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<'de> Deserialize<'de> for PortMapping {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize as a map of String -> Vec<Target>
        let raw_map = HashMap::<String, Vec<Target>>::deserialize(deserializer)?;

        // Convert string keys to u16
        let mut inner = HashMap::new();
        for (key_str, value) in raw_map {
            let port = key_str
                .parse::<u16>()
                .map_err(|_| de::Error::custom(format!("Invalid port number: {}", key_str)))?;
            inner.insert(port, value);
        }

        Ok(PortMapping { inner })
    }
}

/// Protocol-specific rules
pub type ProtocolRules = HashMap<String, PortMapping>;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub tcp: ProtocolRules,

    #[serde(default)]
    pub udp: ProtocolRules,
}

impl Config {
    /// Load configuration from a TOML file
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = tokio::fs::read_to_string(path.as_ref())
            .await
            .with_context(|| format!("Failed to read config file: {}", path.as_ref().display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.as_ref().display()))?;

        Ok(config)
    }

    /// Get all unique rules as a flattened list for comparison
    pub fn get_all_rules(&self) -> Vec<Rule> {
        let mut rules = Vec::new();

        for (vip, port_map) in &self.tcp {
            for (port, targets) in port_map.iter() {
                for target in targets {
                    rules.push(Rule {
                        protocol: Protocol::Tcp,
                        vip: vip.clone(),
                        vip_port: *port,
                        target: target.clone(),
                    });
                }
            }
        }

        for (vip, port_map) in &self.udp {
            for (port, targets) in port_map.iter() {
                for target in targets {
                    rules.push(Rule {
                        protocol: Protocol::Udp,
                        vip: vip.clone(),
                        vip_port: *port,
                        target: target.clone(),
                    });
                }
            }
        }

        rules
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        for (vip, port_map) in &self.tcp {
            self.validate_ip(vip)?;
            for (port, targets) in port_map.iter() {
                if targets.is_empty() {
                    anyhow::bail!("TCP rule for {}:{} has no targets", vip, port);
                }
                for target in targets {
                    self.validate_ip(&target.address)?;
                }
            }
        }

        for (vip, port_map) in &self.udp {
            self.validate_ip(vip)?;
            for (port, targets) in port_map.iter() {
                if targets.is_empty() {
                    anyhow::bail!("UDP rule for {}:{} has no targets", vip, port);
                }
                for target in targets {
                    self.validate_ip(&target.address)?;
                }
            }
        }

        Ok(())
    }

    fn validate_ip(&self, ip: &str) -> Result<()> {
        ip.parse::<std::net::IpAddr>()
            .with_context(|| format!("Invalid IP address: {}", ip))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let toml = r#"
            [tcp."172.16.111.111"]
            80 = ["192.168.111.111:80"]

            [udp."172.16.111.111"]
            80 = ["192.168.111.111:80"]
        "#;

        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.tcp.len(), 1);
        assert_eq!(config.udp.len(), 1);
    }

    #[test]
    fn test_target_parse() {
        let target = Target::parse("192.168.111.111:80").unwrap();
        assert_eq!(target.address, "192.168.111.111");
        assert_eq!(target.port, 80);
    }
}
