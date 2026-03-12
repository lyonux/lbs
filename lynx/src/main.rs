mod config;
mod iptables;
mod manager;
mod network;
mod tc;
mod watcher;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::{Level, info};
use tracing_subscriber::EnvFilter;

/// Lynx - Network rule processor using tokio ecosystem
#[derive(Parser, Debug)]
#[command(name = "lynx")]
#[command(author = "lynx contributors")]
#[command(version = "0.1.0")]
#[command(about = "Network rule processor using tokio ecosystem", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long = "config", value_name = "FILE")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("Starting Lynx network rule processor");
    info!("Loading configuration from: {}", args.config.display());

    // Create and run the manager
    let manager = manager::RuleManager::new(args.config).await?;

    // Run the manager (this will block until shutdown)
    manager.run().await?;

    Ok(())
}
