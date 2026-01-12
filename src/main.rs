//! Mihomo Rust - CLI Entry Point
//!
//! High-performance Rust implementation of mihomo with 100% API compatibility.
//!
//! Supports Go-style CLI arguments for compatibility with clash-verge-rev:
//! - `-ext-ctl-pipe` (Go style) and `--ext-ctl-pipe` (standard) both work
//! - `-ext-ctl-unix` (Go style) and `--ext-ctl-unix` (standard) both work
//! - `-ext-ctl` (Go style) and `--ext-ctl` (standard) both work
//! - `-secret` (Go style) and `--secret` (standard) both work
//! - `-ext-ui` (Go style) and `--ext-ui` (standard) both work

// Use mimalloc as global allocator for better p99 latency
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use clap::Parser;
use mihomo_rust::{Config, Gateway, VERSION};
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Go-style long options that use single dash (Go's flag package behavior)
/// These need to be converted to double-dash for clap compatibility
const GO_STYLE_LONG_OPTIONS: &[&str] = &[
    "-ext-ctl-pipe",
    "-ext-ctl-unix",
    "-ext-ctl",
    "-secret",
    "-ext-ui",
    "-config",
    "-directory",
    "-test",
];

/// Convert Go-style CLI arguments to standard double-dash format
///
/// Go's flag package uses single dash for long options: -ext-ctl-pipe
/// Rust's clap uses double dash for long options: --ext-ctl-pipe
///
/// This function converts single-dash long options to double-dash format
/// so that clap can parse them correctly.
fn normalize_args() -> Vec<String> {
    std::env::args()
        .map(|arg| {
            // Check if this is a Go-style long option (single dash, multiple chars)
            if arg.starts_with('-') && !arg.starts_with("--") {
                for go_opt in GO_STYLE_LONG_OPTIONS {
                    if arg == *go_opt {
                        // Convert -ext-ctl-pipe to --ext-ctl-pipe
                        return format!("-{}", arg);
                    }
                }
            }
            arg
        })
        .collect()
}

#[derive(Parser, Debug)]
#[command(name = "mihomo-rust")]
#[command(author = "Tsang")]
#[command(version = VERSION)]
#[command(about = "High-performance Rust implementation of mihomo")]
struct Args {
    /// Path to configuration file
    #[arg(short = 'c', short_alias = 'f', long = "config", default_value = "config.yaml")]
    config: PathBuf,

    /// Configuration directory
    #[arg(short = 'd', long = "directory")]
    directory: Option<PathBuf>,

    /// External controller address (overrides config)
    #[arg(long = "ext-ctl")]
    external_controller: Option<String>,

    /// External controller secret (overrides config)
    #[arg(long = "secret")]
    secret: Option<String>,

    /// External UI directory
    #[arg(long = "ext-ui")]
    external_ui: Option<PathBuf>,

    /// Enable geodata mode
    #[arg(short = 'm', long = "geodata-mode")]
    geodata_mode: bool,

    /// External controller via Named Pipe (Windows)
    #[cfg(windows)]
    #[arg(long = "ext-ctl-pipe")]
    ext_ctl_pipe: Option<String>,

    /// External controller via Unix Socket
    #[cfg(unix)]
    #[arg(long = "ext-ctl-unix")]
    ext_ctl_unix: Option<String>,

    /// Test configuration and exit
    #[arg(short = 't', long = "test")]
    test: bool,
}

fn main() -> anyhow::Result<()> {
    // Install aws-lc-rs as the default crypto provider for rustls
    // This provides asm-optimized crypto primitives for better TLS performance
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Build optimized tokio runtime for low-latency proxy workloads
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_cpus::get().max(2))
        .max_blocking_threads(32)
        .enable_all()
        // Reduce I/O polling overhead - check for new events every 61 ticks
        .event_interval(61)
        // Reduce cross-thread work stealing frequency for better cache locality
        .global_queue_interval(31)
        .thread_name("mihomo-worker")
        .build()?;

    runtime.block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env()
            .add_directive("mihomo_rust=info".parse()?)
            .add_directive("tower_http=debug".parse()?))
        .init();

    // Parse arguments with Go-style compatibility
    let normalized_args = normalize_args();
    let args = Args::parse_from(normalized_args);

    info!("Mihomo Rust v{}", VERSION);
    info!("Loading configuration from: {}", args.config.display());

    // Handle directory option - change working directory if specified
    if let Some(ref dir) = args.directory {
        info!("Using configuration directory: {}", dir.display());
        // Set the working directory for config file resolution
        if dir.is_dir() {
            std::env::set_current_dir(dir)?;
        }
    }

    // Load configuration
    let mut config = match Config::load(args.config.to_str().unwrap_or("config.yaml")) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    // Apply CLI overrides
    if let Some(ext_ctl) = args.external_controller {
        config.external_controller = Some(ext_ctl);
    }

    if let Some(secret) = args.secret {
        config.secret = Some(secret);
    }

    // Apply IPC overrides
    #[cfg(windows)]
    if let Some(pipe) = args.ext_ctl_pipe {
        info!("Named Pipe configured: {}", pipe);
        config.external_controller_pipe = Some(pipe);
    }

    #[cfg(unix)]
    if let Some(unix_path) = args.ext_ctl_unix {
        info!("Unix Socket configured: {}", unix_path);
        config.external_controller_unix = Some(unix_path);
    }

    // Log geodata mode if enabled
    if args.geodata_mode {
        info!("Geodata mode enabled");
    }

    // Log external UI if specified
    if let Some(ref ui_path) = args.external_ui {
        info!("External UI directory: {}", ui_path.display());
        // TODO: Serve static files from this directory
    }

    // Test mode
    if args.test {
        info!("Configuration test passed");
        return Ok(());
    }

    // Create and run gateway
    let gateway = match Gateway::new(config).await {
        Ok(g) => g,
        Err(e) => {
            error!("Failed to initialize gateway: {}", e);
            std::process::exit(1);
        }
    };

    // Run gateway
    if let Err(e) = gateway.run().await {
        error!("Gateway error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
