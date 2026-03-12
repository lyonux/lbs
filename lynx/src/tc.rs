use crate::config::{Protocol, Rule};
use crate::network::Interface;
use anyhow::{Context, Result};
use std::collections::HashSet;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

/// Traffic Control (tc) rule manager
pub struct TcManager {
    interface: Interface,
    current_rules: HashSet<Rule>,
    qdisc_initialized: bool,
}

impl TcManager {
    pub fn new(interface: Interface) -> Self {
        Self {
            interface,
            current_rules: HashSet::new(),
            qdisc_initialized: false,
        }
    }

    /// Initialize the HTB qdisc on the interface
    async fn ensure_qdisc(&mut self) -> Result<()> {
        if self.qdisc_initialized {
            return Ok(());
        }

        info!(
            "Initializing HTB qdisc on interface {}",
            self.interface.name
        );

        // Check if qdisc already exists
        let check_output = Command::new("tc")
            .args(["qdisc", "show", "dev", &self.interface.name])
            .output()
            .await
            .context("Failed to execute tc qdisc show command")?;

        let stdout = String::from_utf8_lossy(&check_output.stdout);
        if stdout.contains("qdisc htb 1:") {
            debug!("HTB qdisc already exists on {}", self.interface.name);
            self.qdisc_initialized = true;
            return Ok(());
        }

        // Add HTB qdisc
        let output = Command::new("tc")
            .args([
                "qdisc",
                "add",
                "dev",
                &self.interface.name,
                "root",
                "handle",
                "1:",
                "htb",
            ])
            .output()
            .await
            .context("Failed to execute tc qdisc add command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to add HTB qdisc: {}", stderr);
        }

        self.qdisc_initialized = true;
        info!(
            "Successfully initialized HTB qdisc on {}",
            self.interface.name
        );
        Ok(())
    }

    /// Get the tc filter rule specification for a given rule
    fn get_filter_rule_spec(&self, rule: &Rule) -> Vec<String> {
        let protocol_lower = rule.protocol.to_string().to_lowercase();

        // Build the tc filter command
        // tc filter add dev <iface> parent 1: protocol ip u32 \
        //   match ip dsfield 0xa8 0xfc \
        //   match ip src <target_ip>/32 \
        //   match ip df \
        //   match ip ihl 0x05 0x0F \
        //   match ip sport <target_port> 0xFFFF \
        //   action nat egress <target_ip> <vip> \
        //   pipe action pedit munge ip dsfield set 0 \
        //   pipe action pedit ex munge tcp sport set <vip_port> \
        //   pipe action pedit ex munge udp sport set <vip_port> \
        //   pipe action csum ip4h tcp udp

        // Note: tc command line syntax requires careful spacing
        // The "match ip ..." lines need to be properly formatted
        vec![
            "filter".to_string(),
            "add".to_string(),
            "dev".to_string(),
            self.interface.name.clone(),
            "parent".to_string(),
            "1:".to_string(),
            "protocol".to_string(),
            "ip".to_string(),
            "u32".to_string(),
            "match".to_string(),
            "ip".to_string(),
            "dsfield".to_string(),
            "0xa8".to_string(),
            "0xfc".to_string(),
            "match".to_string(),
            "ip".to_string(),
            "src".to_string(),
            format!("{}/32", rule.target.address),
            "match".to_string(),
            "ip".to_string(),
            "df".to_string(),
            "match".to_string(),
            "ip".to_string(),
            "ihl".to_string(),
            "0x05".to_string(),
            "0x0F".to_string(),
            "match".to_string(),
            "ip".to_string(),
            "sport".to_string(),
            rule.target.port.to_string(),
            "0xFFFF".to_string(),
            "action".to_string(),
            "nat".to_string(),
            "egress".to_string(),
            rule.target.address.clone(),
            rule.vip.clone(),
            "pipe".to_string(),
            "action".to_string(),
            "pedit".to_string(),
            "munge".to_string(),
            "ip".to_string(),
            "dsfield".to_string(),
            "set".to_string(),
            "0".to_string(),
            "pipe".to_string(),
            "action".to_string(),
            "pedit".to_string(),
            "ex".to_string(),
            "munge".to_string(),
            protocol_lower.clone(),
            "sport".to_string(),
            "set".to_string(),
            rule.vip_port.to_string(),
            "pipe".to_string(),
            "action".to_string(),
            "csum".to_string(),
            "ip4h".to_string(),
            "tcp".to_string(),
            "udp".to_string(),
        ]
    }

    /// Check if a tc filter rule exists for the given rule
    async fn rule_exists(&self, rule: &Rule) -> Result<bool> {
        let output = Command::new("tc")
            .args([
                "filter",
                "show",
                "dev",
                &self.interface.name,
                "parent",
                "1:",
            ])
            .output()
            .await
            .context("Failed to execute tc filter show command")?;

        if !output.status.success() {
            return Ok(false);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Check if a filter with matching source IP and port exists
        let has_match = stdout.contains(&format!("match ip sport {} 0xffff", rule.target.port))
            && stdout.contains(&rule.target.address);

        Ok(has_match)
    }

    /// Add a tc filter rule
    async fn add_rule(&self, rule: &Rule) -> Result<()> {
        info!("Adding tc rule: {}", rule);

        let mut cmd = Command::new("tc");
        cmd.args(self.get_filter_rule_spec(rule));

        let output = cmd
            .output()
            .await
            .context("Failed to execute tc filter add command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Check if error is about rule already existing
            if stderr.contains("File exists") || stderr.contains("exists") {
                debug!("tc rule already exists: {}", rule);
                return Ok(());
            }
            anyhow::bail!("Failed to add tc rule: {}", stderr);
        }

        debug!("Successfully added tc rule: {}", rule);
        Ok(())
    }

    /// Delete a tc filter rule
    async fn delete_rule(&self, rule: &Rule) -> Result<()> {
        info!("Deleting tc rule: {}", rule);

        // Deleting tc filters is tricky - we need to get the handle
        // For now, we'll flush and recreate
        let output = Command::new("tc")
            .args([
                "filter",
                "del",
                "dev",
                &self.interface.name,
                "parent",
                "1:",
                "protocol",
                "ip",
                "u32",
            ])
            .output()
            .await
            .context("Failed to execute tc filter del command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("No such file or directory") {
                warn!("Failed to delete tc rule: {}", stderr);
            }
        } else {
            debug!("Successfully deleted tc rule: {}", rule);
        }

        Ok(())
    }

    /// Apply a set of rules, adding new ones and removing old ones
    pub async fn apply_rules(&mut self, rules: &[Rule]) -> Result<()> {
        let new_rules: HashSet<Rule> = rules.iter().cloned().collect();

        // Find rules to add (present in new but not in current)
        let to_add: Vec<_> = new_rules.difference(&self.current_rules).cloned().collect();

        // Find rules to remove (present in current but not in new)
        let to_remove: Vec<_> = self.current_rules.difference(&new_rules).cloned().collect();

        info!(
            "Applying tc rules: {} to add, {} to remove",
            to_add.len(),
            to_remove.len()
        );

        // Ensure qdisc is initialized
        self.ensure_qdisc().await?;

        for rule in &to_add {
            if let Err(e) = self.add_rule(rule).await {
                error!("Failed to add tc rule {}: {}", rule, e);
            }
        }
        for rule in &to_remove {
            if let Err(e) = self.delete_rule(rule).await {
                error!("Failed to delete tc rule {}: {}", rule, e);
            }
        }

        // Update current rules
        self.current_rules = new_rules;

        Ok(())
    }

    /// Flush all tc filters on the interface
    async fn flush_filters(&self) -> Result<()> {
        debug!("Flushing tc filters on {}", self.interface.name);

        let output = Command::new("tc")
            .args(["filter", "del", "dev", &self.interface.name, "parent", "1:"])
            .output()
            .await
            .context("Failed to execute tc filter del command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "no such file" errors
            if !stderr.contains("No such file or directory") {
                warn!("Failed to flush tc filters: {}", stderr);
            }
        }

        Ok(())
    }

    /// Get current tc filter rules
    pub async fn get_current_rules(&self) -> Result<Vec<String>> {
        let output = Command::new("tc")
            .args([
                "filter",
                "show",
                "dev",
                &self.interface.name,
                "parent",
                "1:",
            ])
            .output()
            .await
            .context("Failed to execute tc filter show command")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let rules: Vec<String> = stdout.lines().map(|s| s.to_string()).collect();

        Ok(rules)
    }

    /// Initialize tc rules
    pub async fn initialize(&mut self) -> Result<()> {
        info!("Initializing tc manager");

        // Ensure qdisc is set up
        self.ensure_qdisc().await?;

        // Start with empty rules
        self.current_rules = HashSet::new();

        Ok(())
    }

    /// Cleanup all managed rules
    pub async fn cleanup(&mut self) -> Result<()> {
        info!("Cleaning up tc rules");

        self.flush_filters().await?;
        self.current_rules.clear();
        self.qdisc_initialized = false;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_filter_rule_spec() {
        let interface = Interface {
            name: "ens3".to_string(),
            index: 2,
        };
        let manager = TcManager::new(interface);

        let rule = Rule {
            protocol: Protocol::Tcp,
            vip: "172.16.192.111".to_string(),
            vip_port: 898,
            target: crate::config::Target {
                address: "192.168.2.94".to_string(),
                port: 898,
            },
        };

        let spec = manager.get_filter_rule_spec(&rule);
        assert!(spec.iter().any(|s| s.contains("192.168.2.94")));
        assert!(spec.iter().any(|s| s.contains("172.16.192.111")));
    }
}
