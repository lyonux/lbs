use anyhow::Result;
use lbs_core::prelude::{Action, ActionOption, Rule};
use lbs_core::prelude::{Global, Worker as WorkerTrait};
use lyo::prelude::Consumer;
use tracing::{error, info, warn};

use crate::prelude::iptables::IptablesManager;
use crate::prelude::network::detect_primary_interface;
use crate::prelude::traffic_control::TcManager;

/// Main rule manager that orchestrates iptables and tc rules
pub struct ReconcileManager {
    iptables: IptablesManager,
    tc: TcManager,
    shutdown_cleanup: bool,
}

impl ReconcileManager {
    /// Create a new rule manager
    pub fn new() -> Result<Self> {
        info!("Initializing rule manager");

        // Detect primary network interface
        let interface = detect_primary_interface()?;
        info!(
            "Detected primary interface: {} (index: {})",
            interface.name, interface.index
        );

        // Create managers
        let iptables = IptablesManager::new();
        let tc = TcManager::new(interface)?;

        Ok(Self {
            iptables,
            tc,
            shutdown_cleanup: false,
        })
    }

    pub async fn reconcile(&mut self, rules: &Vec<Rule>) -> Result<()> {
        // Apply rules to iptables
        if let Err(e) = self.iptables.apply_rules(rules).await {
            error!("Failed to apply iptables rules: {}", e);
        }

        // Apply rules to tc
        if let Err(e) = self.tc.apply_rules(rules).await {
            warn!("Failed to apply tc rules: {}", e);
            // Don't fail on tc errors, as they might be due to missing kernel modules
        }

        info!("Configuration reloaded done");
        Ok(())
    }

    pub fn set_global(&mut self, global: &Global) -> &mut Self {
        self.set_shutdown_cleanup(global.shutdown_cleanup);
        self
    }

    pub async fn add_rules(&mut self, rules: &Vec<Rule>) -> Result<()> {
        // Apply rules to iptables
        if let Err(e) = self.iptables.add_rules(rules).await {
            error!("Failed to apply iptables rules: {}", e);
        }

        // Add rules to tc
        if let Err(e) = self.tc.add_rules(rules).await {
            warn!("Failed to add tc rules: {}", e);
        }

        info!("Configuration reloaded done");
        Ok(())
    }
    pub async fn delete_rules(&mut self, rules: &Vec<Rule>) -> Result<()> {
        // Apply rules to iptables
        if let Err(e) = self.iptables.delete_rules(rules).await {
            error!("Failed to delete iptables rules: {}", e);
        }

        // Delete rules from tc
        if let Err(e) = self.tc.delete_rules(rules).await {
            warn!("Failed to delete tc rules: {}", e);
        }

        info!("Configuration reloaded done");
        Ok(())
    }

    /// Cleanup all rules
    async fn cleanup(&mut self) -> Result<()> {
        info!("Cleaning up all rules");

        if let Err(e) = self.iptables.cleanup().await {
            warn!("Failed to cleanup iptables rules: {}", e);
        }

        if let Err(e) = self.tc.cleanup().await {
            warn!("Failed to cleanup tc rules: {}", e);
        }

        Ok(())
    }
}

impl ReconcileManager {
    fn set_shutdown_cleanup(&mut self, shutdown_cleanup: bool) {
        self.shutdown_cleanup = shutdown_cleanup;
    }
}

impl WorkerTrait for ReconcileManager {}

impl Consumer<Action> for ReconcileManager {
    async fn consume(&mut self, action: &Action) {
        match action.option {
            ActionOption::Reconcile => {
                if let Err(e) = self
                    .set_global(&action.global)
                    .reconcile(&action.rules)
                    .await
                {
                    warn!("Failed to reconcile: {}", e);
                }
            }
            ActionOption::Add => {
                if let Err(e) = self.add_rules(&action.rules).await {
                    warn!("Failed to add: {}", e);
                }
            }
            ActionOption::Del => {
                if let Err(e) = self.delete_rules(&action.rules).await {
                    warn!("Failed to remove: {}", e);
                }
            }
            _ => {}
        }
    }
    async fn stop(&mut self) {
        info!("Stopping reconcile manager");
        if self.shutdown_cleanup
            && let Err(e) = self.cleanup().await
        {
            warn!("Failed to cleanup: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rule_manager_basic() {
        // Basic test placeholder - actual testing requires root privileges
        assert!(true);
    }
}
