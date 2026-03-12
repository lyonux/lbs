use anyhow::{Context, Result};

/// Network interface information
#[derive(Debug, Clone)]
pub struct Interface {
    pub name: String,
    pub index: u32,
}

/// Detect the primary network interface by checking routing table
pub async fn detect_primary_interface() -> Result<Interface> {
    // Try multiple methods to detect the primary interface
    tokio::task::spawn_blocking(|| {
        // Method 1: Try to read from /proc/net/route
        if let Ok(iface) = get_interface_from_route() {
            return Ok(iface);
        }

        // Method 2: Fallback to common interface names
        for name in ["eth0", "ens3", "ens4", "enp0s3", "enp1s0", "enp0s31s6"] {
            if interface_exists(name) {
                let index = nix::net::if_::if_nametoindex(name)?;
                return Ok(Interface { name: name.to_string(), index });
            }
        }

        anyhow::bail!("Could not detect primary network interface")
    })
    .await?
}

/// Get the primary interface from /proc/net/route
fn get_interface_from_route() -> Result<Interface> {
    let route_content = std::fs::read_to_string("/proc/net/route")
        .context("Failed to read /proc/net/route")?;

    for line in route_content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 8 {
            let iface_name = parts[0];
            let dest = u32::from_str_radix(parts[1], 16).unwrap_or(0);
            // Look for default route (destination 0)
            if dest == 0 {
                let index = nix::net::if_::if_nametoindex(iface_name)
                    .with_context(|| format!("Failed to get interface index for {}", iface_name))?;
                return Ok(Interface {
                    name: iface_name.to_string(),
                    index,
                });
            }
        }
    }

    anyhow::bail!("No default route found in /proc/net/route")
}

/// Check if an interface exists
fn interface_exists(name: &str) -> bool {
    nix::net::if_::if_nametoindex(name).is_ok()
}

/// Get all available network interfaces
pub async fn get_all_interfaces() -> Result<Vec<String>> {
    tokio::task::spawn_blocking(|| {
        let mut interfaces = Vec::new();

        let entries = std::fs::read_dir("/sys/class/net/")
            .context("Failed to read /sys/class/net directory")?;

        for entry in entries {
            let entry = entry?;
            let name = entry.file_name()
                .to_string_lossy()
                .to_string();
            interfaces.push(name);
        }

        interfaces.sort();
        Ok(interfaces)
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_all_interfaces() {
        let interfaces = get_all_interfaces().await;
        assert!(interfaces.is_ok());
        let interfaces = interfaces.unwrap();
        assert!(!interfaces.is_empty());
        println!("Available interfaces: {:?}", interfaces);
    }
}
