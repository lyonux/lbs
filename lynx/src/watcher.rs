use anyhow::{Context, Result};
use notify::{EventKind, RecursiveMode, Watcher, recommended_watcher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Notify;
use tracing::{debug, info, warn};
use tracing_subscriber::reload;

/// Configuration file watcher
pub struct ConfigWatcher {
    _watcher: notify::RecommendedWatcher,
    reload_notify: Arc<Notify>,
    config_path: PathBuf,
}

impl ConfigWatcher {
    /// Create a new watcher for the given configuration file
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self> {
        let config_path = config_path
            .as_ref()
            .canonicalize()
            .unwrap_or_else(|_| config_path.as_ref().to_path_buf());

        let reload_notify = Arc::new(Notify::new());
        let reload_notify_clone = reload_notify.clone();
        let config_path_clone = config_path.clone();

        // Create the watcher with a callback
        let mut watcher = recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            match res {
                Ok(event) => {
                    debug!(
                        "Received file system event: kind={:?}, paths={:?}",
                        event.kind, event.paths
                    );

                    // Check if the event is for our config file
                    for path in &event.paths {
                        // Try to canonicalize the path for comparison
                        let path_canonical = path.canonicalize().unwrap_or_else(|_| path.clone());

                        if path_canonical == config_path_clone || path == &config_path_clone {
                            match event.kind {
                                EventKind::Create(_)
                                | EventKind::Modify(_)
                                | EventKind::Remove(_) => {
                                    info!("Configuration file changed: {:?}", path);
                                    reload_notify_clone.notify_one();
                                }
                                _ => {
                                    debug!("Ignoring event kind: {:?}", event.kind);
                                }
                            }
                            break;
                        }
                    }
                }
                Err(e) => {
                    warn!("Watch error: {:?}", e);
                }
            }
        })
        .context("Failed to create file watcher")?;

        // Watch both the parent directory and, if it exists, the file itself
        let parent = config_path.parent().unwrap_or_else(|| Path::new("/"));

        debug!("Watching parent directory: {}", parent.display());
        watcher
            .watch(parent, RecursiveMode::NonRecursive)
            .with_context(|| format!("Failed to watch directory: {}", parent.display()))?;

        // Also try to watch the file directly if it exists
        if config_path.exists() {
            debug!("Watching file directly: {}", config_path.display());
            let _ = watcher.watch(&config_path, RecursiveMode::NonRecursive);
        }

        info!("Watching configuration file: {}", config_path.display());

        Ok(Self {
            _watcher: watcher,
            reload_notify,
            config_path,
        })
    }

    /// Wait for the next reload notification
    pub async fn wait_for_change(&self) {
        debug!("Waiting for configuration change...");
        self.reload_notify.notified().await;
        debug!("Configuration change detected");
    }

    /// Get the path being watched
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_config_watcher() {
        // Test would require real file system
        // Placeholder for future testing
    }
}
