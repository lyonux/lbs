use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize, de};
use std::fmt;

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
    Any,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Any => write!(f, "ANY"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_parse() {
        let target = Target::parse("192.168.111.111:80").unwrap();
        assert_eq!(target.address, "192.168.111.111");
        assert_eq!(target.port, 80);
    }
}
