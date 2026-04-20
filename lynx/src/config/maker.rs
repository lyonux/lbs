use anyhow::{Context, Result, anyhow};
use lbs_core::prelude::Action;
use lbs_core::prelude::ActionOption;
use lbs_core::prelude::Maker as MakerTrait;
use std::result::Result::Ok;
use tokio::signal;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::time::Duration;
use tracing::{error, info};

use crate::prelude::config::Config;
use crate::prelude::config::GlobalConfig;
use crate::prelude::watcher::ConfigWatcher;
use std::path::PathBuf;
use std::sync::Arc;

const DEBOUNCE_DELAY: Duration = Duration::from_millis(32);

/// Main rule manager that orchestrates iptables and tc rules
pub struct Manager {
    config_path: PathBuf,
    current_config: Option<Arc<tokio::sync::RwLock<Config>>>,
    action_tx: UnboundedSender<Action>,
}

pub struct Maker {
    action_rx: UnboundedReceiver<Action>,
}

impl Maker {
    pub fn new(action_rx: UnboundedReceiver<Action>) -> Self {
        Self { action_rx }
    }
}

impl MakerTrait for Maker {}

impl lyo::prelude::Producer<Action> for Maker {
    async fn produce(&mut self) -> Result<Action> {
        self.action_rx
            .recv()
            .await
            .ok_or_else(|| anyhow!("Action channel closed"))
    }
}

impl Manager {
    /// Create a new rule manager
    pub fn new(config_path: PathBuf) -> (Self, Maker) {
        info!("Initializing rule manager");

        let current_config = None;
        // Create action channel for rule updates
        let (action_tx, action_rx) = tokio::sync::mpsc::unbounded_channel();

        (
            Self {
                config_path,
                current_config,
                action_tx,
            },
            Maker::new(action_rx),
        )
    }

    /// Run the rule manager (main loop)
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting rule manager main loop");

        // Create config watcher
        let mut watcher =
            ConfigWatcher::new([&self.config_path]).context("Failed to create config watcher")?;

        // Create shutdown watch channel (allows multiple receivers)
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        // Spawn a task to handle graceful shutdown (Ctrl+C)
        tokio::spawn(async move {
            if signal::ctrl_c().await.is_ok() {
                info!("Received shutdown signal (Ctrl+C)");
                let _ = shutdown_tx.send(true);
            }
        });

        loop {
            tokio::select! {
                // Wait for config file changes (producer)
                _ = watcher.reload_rx().recv() => {
                    // debounce
                    let delay = tokio::time::sleep(DEBOUNCE_DELAY);
                    tokio::pin!(delay);
                    loop {
                        tokio::select! {
                            _ = &mut delay => {
                                break;
                            }
                            _ = watcher.reload_rx().recv() => {
                                delay.as_mut().reset(tokio::time::Instant::now() + DEBOUNCE_DELAY);
                            }
                        }
                    }

                    // Reload the configuration asynchronously
                    let act = self.reload_config().await;
                    match act {
                        Ok(act) => {
                            let _ = self.action_tx.send(act);
                        }
                        Err(e) => {
                            error!("Failed to reload config: {}", e);
                        }
                    }

                }

                // Wait for shutdown signal
                _ = shutdown_rx.changed() => {
                    info!("Shutting down gracefully");
                    break;
                }
            }
        }

        Ok(())
    }
}

impl Manager {
    /// Load configuration from file
    async fn load_config(path: &PathBuf) -> Result<Config> {
        Config::from_file(path).await
    }

    /// Reload configuration and apply changes
    async fn reload_config(&mut self) -> Result<Action> {
        // Load new configuration
        let new_config = Self::load_config(&self.config_path)
            .await
            .context("Failed to load configuration")?;

        // Validate configuration
        if let Err(e) = new_config.validate() {
            error!("Configuration validation failed: {}", e);
            return Err(e.context("Configuration validation failed"));
        }

        // Get rules from new configuration
        let new_rules = new_config.get_all_rules();
        let new_global = new_config.clone().get_global();

        info!("New configuration has {} rules", new_rules.len());

        // Get current rules for comparison
        if let Some(config) = &self.current_config {
            let current_config = config.read().await;
            let _current_rules = current_config.get_all_rules();
        }

        // Determine action based on rules comparison
        let act = Action::new(new_rules, new_global, ActionOption::Reconcile);

        // Update current configuration
        if let Some(config) = &self.current_config {
            let mut config_guard = config.write().await;
            *config_guard = new_config;
        } else {
            self.current_config = Some(Arc::new(tokio::sync::RwLock::new(new_config)));
        }

        info!("Configuration reloaded successfully");

        Ok(act)
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
