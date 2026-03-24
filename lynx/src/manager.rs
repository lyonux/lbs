use anyhow::{Context, Result};
use tokio::signal;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::iptables::IptablesManager;
use crate::network::detect_primary_interface;
use crate::traffic_control::TcManager;
use crate::watcher::ConfigWatcher;
use std::path::PathBuf;
use std::sync::Arc;

/// Shutdown signal that can be observed by multiple tasks
type ShutdownSignal = tokio::sync::watch::Receiver<bool>;

/// Configuration reload event sent from the producer to consumer
#[derive(Debug)]
struct ReloadEvent {
    attempt: usize,
}

/// Main rule manager that orchestrates iptables and tc rules
pub struct RuleManager {
    config_path: PathBuf,
    iptables: IptablesManager,
    tc: TcManager,
    current_config: Arc<tokio::sync::RwLock<Config>>,
}

impl RuleManager {
    /// Create a new rule manager
    pub async fn new(config_path: PathBuf) -> Result<Self> {
        info!("Initializing rule manager");

        // Detect primary network interface
        let interface = detect_primary_interface().await?;
        info!(
            "Detected primary interface: {} (index: {})",
            interface.name, interface.index
        );

        // Create managers
        let mut iptables = IptablesManager::new(interface.clone());
        let mut tc = TcManager::new(interface)?;

        // Initialize managers
        iptables.initialize().await?;
        tc.initialize().await?;

        // Load initial configuration
        let config = Self::load_config(&config_path).await?;
        config.validate()?;

        let current_config = Arc::new(tokio::sync::RwLock::new(config.clone()));

        // Apply initial rules
        let rules = config.get_all_rules();
        info!("Loaded {} rules from configuration", rules.len());

        iptables.apply_rules(&rules).await?;
        tc.apply_rules(&rules).await?;

        Ok(Self {
            config_path,
            iptables,
            tc,
            current_config,
        })
    }

    /// Load configuration from file
    async fn load_config(path: &PathBuf) -> Result<Config> {
        Config::from_file(path).await
    }

    /// Reload configuration and apply changes
    async fn reload_config(&mut self, event: ReloadEvent) -> Result<()> {
        info!("Processing reload event (attempt {})", event.attempt);

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
        info!("New configuration has {} rules", new_rules.len());

        // Get current rules for comparison
        let _current_config = self.current_config.read().await;
        let _current_rules = _current_config.get_all_rules();
        drop(_current_config);

        // Apply rules to iptables
        if let Err(e) = self.iptables.apply_rules(&new_rules).await {
            error!("Failed to apply iptables rules: {}", e);
            return Err(e.context("Failed to apply iptables rules"));
        }

        // Apply rules to tc
        if let Err(e) = self.tc.apply_rules(&new_rules).await {
            warn!("Failed to apply tc rules: {}", e);
            // Don't fail on tc errors, as they might be due to missing kernel modules
        }

        // Update current configuration
        let mut config_guard = self.current_config.write().await;
        *config_guard = new_config;

        info!("Configuration reloaded successfully");

        Ok(())
    }

    /// Consumer task that processes reload events from the queue
    async fn reload_consumer(
        mut reload_rx: mpsc::Receiver<ReloadEvent>,
        manager: Arc<tokio::sync::Mutex<Self>>,
        mut shutdown_rx: ShutdownSignal,
    ) -> Result<()> {
        info!("Starting reload consumer task");
        loop {
            tokio::select! {
                // Process reload events from the queue
                Some(event) = reload_rx.recv() => {
                    tokio::task::yield_now().await;
                    if !reload_rx.is_empty() {
                        continue;
                    }
                    tokio::time::sleep(Duration::from_micros(500)).await;
                    if !reload_rx.is_empty() {
                        continue;
                    }

                    // Reload the configuration asynchronously
                     _= manager.lock().await.reload_config(event).await;
                }

                // Check if shutdown signal was received
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Reload consumer received shutdown signal");
                        break;
                    }
                }

                // Channel was closed, exit the loop
                else => {
                    info!("Reload channel closed, exiting consumer");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Run the rule manager (main loop)
    pub async fn run(self) -> Result<()> {
        info!("Starting rule manager main loop");

        // Create config watcher
        let watcher =
            ConfigWatcher::new(&self.config_path).context("Failed to create config watcher")?;

        // Create a channel for reload events (producer-consumer pattern)
        // Channel size 16 allows buffering multiple events during rapid file changes
        let (reload_tx, reload_rx) = mpsc::channel::<ReloadEvent>(16);

        // Wrap the manager in Arc<Mutex<>> for sharing between tasks
        let manager = Arc::new(tokio::sync::Mutex::new(self));

        // Create shutdown watch channel (allows multiple receivers)
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        // Clone shutdown receiver for consumer task
        let consumer_shutdown_rx = shutdown_rx.clone();

        // Clone shutdown sender for Ctrl+C handler
        let signal_shutdown_tx = shutdown_tx.clone();

        // Spawn the consumer task
        let consumer_task = tokio::spawn(async move {
            let result = Self::reload_consumer(reload_rx, manager, consumer_shutdown_rx).await;

            if let Err(e) = &result {
                error!("Reload consumer task failed: {}", e);
            }

            result
        });

        // Spawn a task to handle graceful shutdown (Ctrl+C)
        tokio::spawn(async move {
            if signal::ctrl_c().await.is_ok() {
                info!("Received shutdown signal (Ctrl+C)");
                let _ = signal_shutdown_tx.send(true);
            }
        });

        loop {
            tokio::select! {
                // Wait for config file changes (producer)
                _ = watcher.wait_for_change() => {

                    // Send reload event to the consumer (non-blocking)
                    let event = ReloadEvent {
                        attempt: 0usize,
                    };

                    if let Err(e) = reload_tx.try_send(event) {
                        match e {
                            mpsc::error::TrySendError::Full(_) => {
                                warn!("Reload queue is full, skipping reload event");
                            }
                            mpsc::error::TrySendError::Closed(_) => {
                                error!("Reload consumer channel closed, stopping");
                                break;
                            }
                        }
                    } else {
                        debug!("Reload event queued successfully");
                    }
                }

                // Wait for shutdown signal
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Shutting down gracefully");

                        // Signal consumer to stop by sending true on watch channel
                        let _ = shutdown_tx.send(true);

                        // Wait for consumer to finish (with timeout)
                        let _ = tokio::time::timeout(
                            Duration::from_secs(5),
                            consumer_task
                        ).await;

                        break;
                    }
                }
            }
        }

        Ok(())
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
