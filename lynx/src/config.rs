use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize, de};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;

/// Represents a target endpoint with address and port
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
pub struct Target {
    pub address: String,
    pub port: u16,
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.address, self.port)
    }
}

impl Target {
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid target format: {}", s);
        }
        let port = parts[0]
            .parse::<u16>()
            .with_context(|| format!("Invalid port in target: {}", s))?;
        let address = parts[1].to_string();
        Ok(Target { address, port })
    }
}

impl<'de> Deserialize<'de> for Target {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Try to deserialize as a string first
        struct TargetVisitor;

        impl<'de> de::Visitor<'de> for TargetVisitor {
            type Value = Target;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string in the format \"address:port\" or a struct with address and port fields")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Target::parse(s).map_err(|e| de::Error::custom(e.to_string()))
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: de::MapAccess<'de>,
            {
                let mut address = None;
                let mut port = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "address" => {
                            if address.is_some() {
                                return Err(de::Error::duplicate_field("address"));
                            }
                            address = Some(map.next_value()?);
                        }
                        "port" => {
                            if port.is_some() {
                                return Err(de::Error::duplicate_field("port"));
                            }
                            port = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(de::Error::unknown_field(&key, &["address", "port"]));
                        }
                    }
                }

                let address = address.ok_or_else(|| de::Error::missing_field("address"))?;
                let port = port.ok_or_else(|| de::Error::missing_field("port"))?;

                Ok(Target { address, port })
            }
        }

        deserializer.deserialize_any(TargetVisitor)
    }
}

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

/// Individual rule representation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Rule {
    pub protocol: Protocol,
    pub vip: String,
    pub vip_port: u16,
    pub target: Target,
}

impl std::fmt::Display for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}:{} -> {}",
            self.protocol, self.vip, self.vip_port, self.target
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
        }
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
