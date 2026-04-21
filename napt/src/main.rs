use anyhow::Result;
use clap::Parser;
use napt::config::config::Config;
use napt::config::maker::Manager;
use napt::prelude::reconcile::ReconcileManager;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Napt - Network rule processor using tokio ecosystem
#[derive(Parser, Debug)]
#[command(name = "napt")]
#[command(author = "napt contributors")]
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

    // Load global config early for log level
    let global = Config::load_global(&args.config).unwrap_or_default();

    // Initialize tracing with configured log level
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&global.log_level)),
        )
        .init();

    info!("Starting Napt network rule processor");
    info!("Loading configuration from: {}", args.config.display());

    let (mut manager, maker) = Manager::new(args.config);
    let reconcile = ReconcileManager::new()?;

    let mut ctl = lbs_core::prelude::Controller::new(reconcile, maker);

    let _ = tokio::spawn(async move { manager.run().await });
    let _ = tokio::spawn(async move { ctl.run().await }).await;

    Ok(())
}
