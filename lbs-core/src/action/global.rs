use serde::{Deserialize, Serialize};

/// Global configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Global {
    #[serde(default = "default_log_level")]
    pub log_level: String,

    #[serde(default)]
    pub shutdown_cleanup: bool,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for Global {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            shutdown_cleanup: false,
        }
    }
}
