use anyhow::{Context, Result};
use notify::{Event, EventKind, RecursiveMode, Watcher, recommended_watcher};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Configuration file watcher
pub struct ConfigWatcher {
    _watcher: notify::RecommendedWatcher,
    reload_rx: mpsc::UnboundedReceiver<notify::Event>,
}

impl ConfigWatcher {
    /// Create a new watcher for the given configuration files.
    pub fn new<P: AsRef<Path>, I>(path_list: I) -> Result<Self>
    where
        P: AsRef<Path>,
        I: IntoIterator<Item = P>,
    {
        let paths: Vec<PathBuf> = path_list
            .into_iter()
            .map(|p| p.as_ref().to_path_buf())
            .collect();

        let watched: HashSet<PathBuf> = paths.iter().map(|p| Self::canonicalize_or(p)).collect();

        let (tx, rx) = mpsc::unbounded_channel::<Event>();
        let mut watcher = recommended_watcher(Self::make_watch_callback(watched, tx.clone()))
            .context("Failed to create file watcher")?;

        for path in &paths {
            Self::register_path(&mut watcher, path, &tx)?;
        }

        Ok(Self {
            _watcher: watcher,
            reload_rx: rx,
        })
    }

    pub fn reload_rx(&mut self) -> &mut mpsc::UnboundedReceiver<notify::Event> {
        &mut self.reload_rx
    }
}

impl ConfigWatcher {
    /// Canonicalize a path, falling back to the original on failure.
    fn canonicalize_or(path: &Path) -> PathBuf {
        path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
    }

    /// Check if the event kind is one we care about (create/modify/remove).
    fn is_reload_event(kind: &EventKind) -> bool {
        matches!(
            kind,
            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
        )
    }

    /// Check if any path in the event matches our watched set.
    fn path_matches(event_paths: &[PathBuf], watched: &HashSet<PathBuf>) -> bool {
        event_paths
            .iter()
            .any(|p| watched.contains(p) || watched.contains(&Self::canonicalize_or(p)))
    }

    /// Build the watcher callback that filters and forwards reload events.
    fn make_watch_callback(
        watched: HashSet<PathBuf>,
        tx: mpsc::UnboundedSender<Event>,
    ) -> impl FnMut(Result<Event, notify::Error>) + Send {
        move |res: Result<Event, notify::Error>| {
            let event = match res {
                Ok(e) => e,
                Err(e) => {
                    warn!("Watch error: {:?}", e);
                    return;
                }
            };

            debug!(
                "Received file system event: kind={:?}, paths={:?}",
                &event.kind, &event.paths
            );

            if !Self::path_matches(&event.paths, &watched) || !Self::is_reload_event(&event.kind) {
                return;
            }

            info!("Configuration file changed: {:?}", event.paths);

            if let Err(e) = tx.send(event) {
                warn!("Failed to send reload event: {:?}", e);
            }
        }
    }

    /// Register a single path: watch its parent directory (and the file itself if it exists),
    /// then emit an initial reload event.
    fn register_path(
        watcher: &mut notify::RecommendedWatcher,
        path: &Path,
        tx: &mpsc::UnboundedSender<Event>,
    ) -> Result<()> {
        let parent = path.parent().unwrap_or(Path::new("/"));
        debug!("Watching parent directory: {}", parent.display());
        watcher
            .watch(parent, RecursiveMode::NonRecursive)
            .with_context(|| format!("Failed to watch directory: {}", parent.display()))?;

        if path.exists() {
            debug!("Watching file directly: {}", path.display());
            if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
                warn!("Failed to watch file directly {}: {:?}", path.display(), e);
            }
        }

        tx.send(
            Event::new(EventKind::Create(notify::event::CreateKind::File))
                .add_path(path.to_path_buf()),
        )?;

        info!("Watching configuration file: {}", path.display());
        Ok(())
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
