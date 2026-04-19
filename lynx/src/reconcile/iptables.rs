use anyhow::{Context, Result};
use lbs_core::prelude::Rule;
use std::collections::HashSet;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

/// DSCP mark value for traffic control
const DSCP_MARK: u8 = 0x2a;
const DSCP_RESTORE: u8 = 0x00;

/// iptables rule manager
pub struct IptablesManager {
    current_rules: HashSet<Rule>,
    mangle_initialized: bool,
}

impl IptablesManager {
    pub fn new() -> Self {
        Self {
            current_rules: HashSet::new(),
            mangle_initialized: false,
        }
    }

    /// Initialize mangle table rules for DSCP marking
    async fn ensure_mangle_rules(&mut self) -> Result<()> {
        if self.mangle_initialized {
            return Ok(());
        }

        info!("Initializing mangle table rules");

        // Check if INPUT rule for DSCP already exists
        let input_check = Command::new("iptables")
            .args([
                "-t",
                "mangle",
                "-C",
                "INPUT",
                "-m",
                "dscp",
                "--dscp",
                &format!("0x{:02x}", DSCP_MARK),
                "-j",
                "MARK",
                "--set-xmark",
                &format!("0x{:02x}", DSCP_MARK),
            ])
            .output()
            .await;

        let rule_exists = input_check.as_ref().map_or(false, |o| o.status.success());

        if !rule_exists {
            // Add INPUT chain rules for DSCP marking
            let dscp_mark = format!("0x{:02x}", DSCP_MARK);
            let dscp_mark_full = format!("0x{:02x}", DSCP_MARK);
            let dscp_restore = format!("0x{:02x}", DSCP_RESTORE);

            let rules: Vec<Vec<String>> = vec![
                // Mark packets with DSCP value
                vec![
                    "-t",
                    "mangle",
                    "-A",
                    "INPUT",
                    "-m",
                    "dscp",
                    "--dscp",
                    &dscp_mark,
                    "-j",
                    "MARK",
                    "--set-xmark",
                    &dscp_mark_full,
                ]
                .iter()
                .map(|s| s.to_string())
                .collect(),
                // Reset DSCP to 0 after marking
                vec![
                    "-t",
                    "mangle",
                    "-A",
                    "INPUT",
                    "-m",
                    "dscp",
                    "--dscp",
                    &dscp_mark,
                    "-j",
                    "DSCP",
                    "--set-dscp",
                    &dscp_restore,
                ]
                .iter()
                .map(|s| s.to_string())
                .collect(),
                // Save mark to connection
                vec![
                    "-t",
                    "mangle",
                    "-A",
                    "INPUT",
                    "-j",
                    "CONNMARK",
                    "--save-mark",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ];

            for rule_args in rules {
                let output = Command::new("iptables")
                    .args(&rule_args)
                    .output()
                    .await
                    .context("Failed to execute iptables mangle command")?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!("Failed to add mangle rule: {}", stderr);
                }
            }
        }

        // Check if OUTPUT rule for CONNMARK restore already exists
        let output_check = Command::new("iptables")
            .args([
                "-t",
                "mangle",
                "-C",
                "OUTPUT",
                "-j",
                "CONNMARK",
                "--restore-mark",
            ])
            .output()
            .await;

        let output_exists = output_check.as_ref().map_or(false, |o| o.status.success());

        if !output_exists {
            // Add OUTPUT chain rules for restoring connection marks
            let dscp_mark = format!("0x{:02x}", DSCP_MARK);

            let rules: Vec<Vec<String>> = vec![
                // Restore mark from connection
                vec![
                    "-t",
                    "mangle",
                    "-A",
                    "OUTPUT",
                    "-j",
                    "CONNMARK",
                    "--restore-mark",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect(),
                // Set DSCP based on mark
                vec![
                    "-t",
                    "mangle",
                    "-A",
                    "OUTPUT",
                    "-m",
                    "mark",
                    "--mark",
                    &dscp_mark,
                    "-j",
                    "DSCP",
                    "--set-dscp",
                    &dscp_mark,
                ]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ];

            for rule_args in rules {
                let output = Command::new("iptables")
                    .args(&rule_args)
                    .output()
                    .await
                    .context("Failed to execute iptables mangle command")?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!("Failed to add mangle rule: {}", stderr);
                }
            }
        }

        self.mangle_initialized = true;
        info!("Mangle table rules initialized");
        Ok(())
    }

    /// Build the iptables arguments for a NAT OUTPUT rule
    fn build_nat_args(&self, rule: &Rule) -> Vec<String> {
        let protocol = rule.protocol.to_string().to_lowercase();
        vec![
            "-t".to_string(),
            "nat".to_string(),
            "-A".to_string(),
            "OUTPUT".to_string(),
            "-d".to_string(),
            format!("{}/32", rule.vip),
            "-p".to_string(),
            protocol.clone(),
            "-m".to_string(),
            protocol,
            "--dport".to_string(),
            rule.vip_port.to_string(),
            "-j".to_string(),
            "DNAT".to_string(),
            "--to-destination".to_string(),
            rule.target.to_string(),
        ]
    }

    /// Check if a NAT OUTPUT rule exists
    async fn rule_exists(&self, rule: &Rule) -> Result<bool> {
        let mut args = self.build_nat_args(rule);
        args[2] = "-C".to_string(); // Change -A to -C for check

        let output = Command::new("iptables")
            .args(&args)
            .output()
            .await
            .context("Failed to execute iptables command")?;

        Ok(output.status.success())
    }

    /// Add a NAT OUTPUT rule
    async fn add_rule(&self, rule: &Rule) -> Result<()> {
        let args = self.build_nat_args(rule);

        info!("Adding iptables nat rule: {}", rule);

        let output = Command::new("iptables")
            .args(&args)
            .output()
            .await
            .context("Failed to execute iptables -A command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to add iptables rule: {}", stderr);
        }

        debug!("Successfully added iptables nat rule: {}", rule);
        Ok(())
    }

    /// Delete a NAT OUTPUT rule
    async fn delete_rule(&self, rule: &Rule) -> Result<()> {
        let mut args = self.build_nat_args(rule);
        args[2] = "-D".to_string(); // Change -A to -D for delete

        info!("Deleting iptables nat rule: {}", rule);

        let output = Command::new("iptables")
            .args(&args)
            .output()
            .await
            .context("Failed to execute iptables -D command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Don't error if rule doesn't exist
            if !stderr.contains("No chain/target/match") {
                warn!("Failed to delete iptables rule: {}", stderr);
            }
        } else {
            debug!("Successfully deleted iptables nat rule: {}", rule);
        }

        Ok(())
    }

    /// Apply a set of rules, adding new ones and removing old ones
    pub async fn apply_rules(&mut self, rules: &[Rule]) -> Result<()> {
        // Ensure mangle rules are set up first
        self.ensure_mangle_rules().await?;

        let new_rules: HashSet<Rule> = rules.iter().cloned().collect();

        // Find rules to add (present in new but not in current)
        let to_add: Vec<_> = new_rules.difference(&self.current_rules).cloned().collect();

        // Find rules to remove (present in current but not in new)
        let to_remove: Vec<_> = self.current_rules.difference(&new_rules).cloned().collect();

        info!(
            "Applying iptables nat rules: {} to add, {} to remove",
            to_add.len(),
            to_remove.len()
        );

        match self.delete_rules(&to_remove).await {
            Ok(()) => {}
            Err(e) => {
                warn!("Failed to delete rules: {}", e);
            }
        }

        match self.add_rules(&to_add).await {
            Ok(()) => {}
            Err(e) => {
                warn!("Failed to add rules: {}", e);
            }
        }

        Ok(())
    }

    /// Add a set of rules, adding new ones and removing old ones
    pub async fn add_rules(&mut self, to_add: &[Rule]) -> Result<()> {
        info!("Applying iptables nat rules: {} to add", to_add.len());

        // Then add new rules
        for rule in to_add {
            // Check if rule already exists before adding
            if !self.rule_exists(rule).await? {
                if let Err(e) = self.add_rule(rule).await {
                    error!("Failed to add rule {}: {}", rule, e);
                    return Err(e);
                }
            } else {
                debug!("Rule {} already exists, skipping", rule);
            }
        }

        self.current_rules.extend(to_add.iter().cloned());

        Ok(())
    }

    /// Delete a set of rules, removing them from iptables
    pub async fn delete_rules(&mut self, to_remove: &[Rule]) -> Result<()> {
        info!("Applying iptables nat rules: {} to remove", to_remove.len());

        // First remove old rules
        for rule in to_remove {
            if let Err(e) = self.delete_rule(rule).await {
                warn!("Failed to delete rule {}: {}", rule, e);
            }
        }

        // Update current rules
        self.current_rules.retain(|r| !to_remove.contains(r));

        Ok(())
    }

    /// Get current iptables NAT OUTPUT rules
    async fn get_current_rules(&self) -> Result<Vec<String>> {
        let output = Command::new("iptables")
            .args(["-t", "nat", "-S", "OUTPUT"])
            .output()
            .await
            .context("Failed to execute iptables -S command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to get current iptables rules: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let rules: Vec<String> = stdout.lines().map(|s| s.to_string()).collect();

        Ok(rules)
    }

    /// Initialize iptables rules (load from system state)
    pub async fn initialize(&mut self) -> Result<()> {
        info!("Initializing iptables manager");

        // Initialize mangle table
        self.ensure_mangle_rules().await?;

        // Get current rules from iptables
        let _existing_rules = self.get_current_rules().await?;

        // Parse existing rules to populate current_rules
        // For now, we'll start with an empty set and let apply_rules handle it
        self.current_rules = HashSet::new();

        Ok(())
    }

    /// Cleanup all managed rules
    pub async fn cleanup(&mut self) -> Result<()> {
        info!("Cleaning up iptables rules");

        info!("Deleted rule: ========1 {}", self.current_rules.len());
        for rule in &self.current_rules {
            if let Err(e) = self.delete_rule(rule).await {
                warn!("Failed to delete rule {} during cleanup: {}", rule, e);
            }
            info!("Deleted rule: ======== {}", rule);
        }

        self.current_rules.clear();
        Ok(())
    }
}
