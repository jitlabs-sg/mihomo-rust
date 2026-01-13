//! Go mihomo process manager
//!
//! Manages the lifecycle of the Go mihomo child process:
//! - Starting/stopping the process
//! - Health checks
//! - Auto-restart on crash
//! - Graceful shutdown

use crate::{Error, Result};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::{Child, Command};
use tokio::sync::{watch, Mutex, RwLock};
use tokio::time::{interval, sleep, timeout};
use tracing::{debug, error, info, warn};

/// Health check interval
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(10);

/// Health check timeout
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Restart delay after crash
const RESTART_DELAY: Duration = Duration::from_secs(2);

/// Maximum restart attempts before giving up
const MAX_RESTART_ATTEMPTS: u32 = 5;

/// Process state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Process not started
    Stopped,
    /// Process is starting
    Starting,
    /// Process is running and healthy
    Running,
    /// Process is unhealthy (failed health checks)
    Unhealthy,
    /// Process has crashed and is restarting
    Restarting,
    /// Process has failed too many times
    Failed,
}

impl std::fmt::Display for ProcessState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessState::Stopped => write!(f, "stopped"),
            ProcessState::Starting => write!(f, "starting"),
            ProcessState::Running => write!(f, "running"),
            ProcessState::Unhealthy => write!(f, "unhealthy"),
            ProcessState::Restarting => write!(f, "restarting"),
            ProcessState::Failed => write!(f, "failed"),
        }
    }
}

/// Configuration for Go process manager
#[derive(Debug, Clone)]
pub struct GoProcessConfig {
    /// Path to mihomo executable
    pub executable: PathBuf,
    /// Path to configuration file
    pub config_path: PathBuf,
    /// Listen port (for health checks)
    pub listen_port: u16,
    /// Working directory
    pub work_dir: Option<PathBuf>,
    /// Enable auto-restart
    pub auto_restart: bool,
    /// Maximum restart attempts
    pub max_restarts: u32,
}

impl Default for GoProcessConfig {
    fn default() -> Self {
        GoProcessConfig {
            executable: PathBuf::from("mihomo"),
            config_path: PathBuf::from("go-fallback-config.yaml"),
            listen_port: 17890,
            work_dir: None,
            auto_restart: true,
            max_restarts: MAX_RESTART_ATTEMPTS,
        }
    }
}

/// Go mihomo process manager
pub struct GoProcessManager {
    config: GoProcessConfig,
    state: RwLock<ProcessState>,
    child: Mutex<Option<Child>>,
    restart_count: AtomicU32,
    shutdown: AtomicBool,
    state_tx: watch::Sender<ProcessState>,
    state_rx: watch::Receiver<ProcessState>,
}

impl GoProcessManager {
    /// Create a new process manager
    pub fn new(config: GoProcessConfig) -> Self {
        let (state_tx, state_rx) = watch::channel(ProcessState::Stopped);

        GoProcessManager {
            config,
            state: RwLock::new(ProcessState::Stopped),
            child: Mutex::new(None),
            restart_count: AtomicU32::new(0),
            shutdown: AtomicBool::new(false),
            state_tx,
            state_rx,
        }
    }

    /// Create with default config
    pub fn with_defaults(executable: PathBuf, config_path: PathBuf, port: u16) -> Self {
        Self::new(GoProcessConfig {
            executable,
            config_path,
            listen_port: port,
            ..Default::default()
        })
    }

    /// Get current process state
    pub async fn state(&self) -> ProcessState {
        *self.state.read().await
    }

    /// Subscribe to state changes
    pub fn subscribe(&self) -> watch::Receiver<ProcessState> {
        self.state_rx.clone()
    }

    /// Set state and notify subscribers
    async fn set_state(&self, new_state: ProcessState) {
        let mut state = self.state.write().await;
        if *state != new_state {
            debug!("Go process state: {} -> {}", *state, new_state);
            *state = new_state;
            let _ = self.state_tx.send(new_state);
        }
    }

    /// Start the Go mihomo process
    pub async fn start(&self) -> Result<()> {
        // Check if already running
        if matches!(self.state().await, ProcessState::Running | ProcessState::Starting) {
            return Ok(());
        }

        self.set_state(ProcessState::Starting).await;
        self.shutdown.store(false, Ordering::SeqCst);

        // Validate executable exists
        if !self.config.executable.exists() {
            error!("Go mihomo executable not found: {:?}", self.config.executable);
            self.set_state(ProcessState::Failed).await;
            return Err(Error::config(format!(
                "mihomo executable not found: {:?}",
                self.config.executable
            )));
        }

        // Validate config exists
        if !self.config.config_path.exists() {
            error!("Go fallback config not found: {:?}", self.config.config_path);
            self.set_state(ProcessState::Failed).await;
            return Err(Error::config(format!(
                "Config file not found: {:?}",
                self.config.config_path
            )));
        }

        // Build command
        let mut cmd = Command::new(&self.config.executable);
        cmd.arg("-f")
            .arg(&self.config.config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true); // Ensure child is killed when dropped

        if let Some(ref work_dir) = self.config.work_dir {
            cmd.current_dir(work_dir);
        }

        info!(
            "Starting Go mihomo: {:?} -f {:?}",
            self.config.executable, self.config.config_path
        );

        // Spawn process
        let child = cmd.spawn().map_err(|e| {
            error!("Failed to spawn Go mihomo: {}", e);
            self.shutdown.store(true, Ordering::SeqCst);
            Error::internal(format!("Failed to spawn Go mihomo: {}", e))
        })?;

        let pid = child.id().unwrap_or(0);
        info!("Go mihomo started with PID: {}", pid);

        // Store child process
        {
            let mut child_guard = self.child.lock().await;
            *child_guard = Some(child);
        }

        // Wait a moment for process to initialize
        sleep(Duration::from_millis(500)).await;

        // Verify process is still running
        if self.is_process_alive().await {
            self.set_state(ProcessState::Running).await;
            self.restart_count.store(0, Ordering::SeqCst);
            info!("Go mihomo is running");
            Ok(())
        } else {
            self.set_state(ProcessState::Failed).await;
            Err(Error::internal("Go mihomo exited immediately after start"))
        }
    }

    /// Stop the Go mihomo process
    pub async fn stop(&self) -> Result<()> {
        self.shutdown.store(true, Ordering::SeqCst);

        let mut child_guard = self.child.lock().await;
        if let Some(ref mut child) = *child_guard {
            info!("Stopping Go mihomo...");

            // Try graceful shutdown first
            #[cfg(unix)]
            {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;
                if let Some(pid) = child.id() {
                    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                }
            }

            // Wait for graceful shutdown with timeout
            match timeout(Duration::from_secs(5), child.wait()).await {
                Ok(Ok(status)) => {
                    info!("Go mihomo exited with status: {}", status);
                }
                Ok(Err(e)) => {
                    warn!("Error waiting for Go mihomo: {}", e);
                }
                Err(_) => {
                    // Timeout - force kill
                    warn!("Go mihomo didn't exit gracefully, forcing kill");
                    let _ = child.kill().await;
                }
            }

            *child_guard = None;
        }

        self.set_state(ProcessState::Stopped).await;
        info!("Go mihomo stopped");
        Ok(())
    }

    /// Check if the child process is alive
    async fn is_process_alive(&self) -> bool {
        let mut child_guard = self.child.lock().await;
        if let Some(ref mut child) = *child_guard {
            match child.try_wait() {
                Ok(None) => true,  // Still running
                Ok(Some(_)) => false,  // Exited
                Err(_) => false,  // Error checking
            }
        } else {
            false
        }
    }

    /// Perform a health check
    pub async fn health_check(&self) -> bool {
        // First check if process is alive
        if !self.is_process_alive().await {
            return false;
        }

        // Try to connect to the proxy port
        let addr = format!("127.0.0.1:{}", self.config.listen_port);
        match timeout(
            HEALTH_CHECK_TIMEOUT,
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(_)) => {
                debug!("Go mihomo health check passed");
                true
            }
            Ok(Err(e)) => {
                warn!("Go mihomo health check failed: {}", e);
                false
            }
            Err(_) => {
                warn!("Go mihomo health check timed out");
                false
            }
        }
    }

    /// Start the health check and auto-restart loop
    pub async fn run_health_loop(self: Arc<Self>) {
        let mut interval = interval(HEALTH_CHECK_INTERVAL);

        loop {
            interval.tick().await;

            if self.shutdown.load(Ordering::SeqCst) {
                break;
            }

            let state = self.state().await;
            if state == ProcessState::Failed {
                continue; // Don't check failed processes
            }

            if state == ProcessState::Running {
                let healthy = self.health_check().await;
                if !healthy {
                    self.set_state(ProcessState::Unhealthy).await;

                    // Attempt restart if enabled
                    if self.config.auto_restart {
                        let restart_count = self.restart_count.fetch_add(1, Ordering::SeqCst) + 1;

                        if restart_count <= self.config.max_restarts {
                            warn!(
                                "Go mihomo unhealthy, restarting ({}/{})",
                                restart_count, self.config.max_restarts
                            );
                            self.set_state(ProcessState::Restarting).await;
                            sleep(RESTART_DELAY).await;

                            if let Err(e) = self.restart().await {
                                error!("Failed to restart Go mihomo: {}", e);
                            }
                        } else {
                            error!(
                                "Go mihomo exceeded max restart attempts ({})",
                                self.config.max_restarts
                            );
                            self.set_state(ProcessState::Failed).await;
                        }
                    }
                } else {
                    // Reset restart count on successful health check
                    self.restart_count.store(0, Ordering::SeqCst);
                }
            }
        }
    }

    /// Restart the process
    async fn restart(&self) -> Result<()> {
        self.stop().await?;
        sleep(Duration::from_millis(500)).await;
        self.start().await
    }

    /// Force restart (resets restart counter)
    pub async fn force_restart(&self) -> Result<()> {
        self.restart_count.store(0, Ordering::SeqCst);
        self.restart().await
    }

    /// Get restart count
    pub fn restart_count(&self) -> u32 {
        self.restart_count.load(Ordering::SeqCst)
    }

    /// Get the listen port
    pub fn listen_port(&self) -> u16 {
        self.config.listen_port
    }

    /// Get the proxy address string
    pub fn proxy_address(&self) -> String {
        format!("127.0.0.1:{}", self.config.listen_port)
    }
}

impl Drop for GoProcessManager {
    fn drop(&mut self) {
        // Note: Child process will be killed on drop due to kill_on_drop(true)
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_config_default() {
        let config = GoProcessConfig::default();
        assert_eq!(config.listen_port, 17890);
        assert!(config.auto_restart);
        assert_eq!(config.max_restarts, MAX_RESTART_ATTEMPTS);
    }

    #[test]
    fn test_process_state_display() {
        assert_eq!(ProcessState::Stopped.to_string(), "stopped");
        assert_eq!(ProcessState::Running.to_string(), "running");
        assert_eq!(ProcessState::Failed.to_string(), "failed");
    }

    #[tokio::test]
    async fn test_manager_initial_state() {
        let config = GoProcessConfig::default();
        let manager = GoProcessManager::new(config);
        assert_eq!(manager.state().await, ProcessState::Stopped);
        assert_eq!(manager.restart_count(), 0);
    }

    #[tokio::test]
    async fn test_manager_start_missing_executable() {
        let config = GoProcessConfig {
            executable: PathBuf::from("/nonexistent/mihomo"),
            ..Default::default()
        };
        let manager = GoProcessManager::new(config);

        let result = manager.start().await;
        assert!(result.is_err());
        assert_eq!(manager.state().await, ProcessState::Failed);
    }

    #[test]
    fn test_proxy_address() {
        let manager = GoProcessManager::with_defaults(
            PathBuf::from("mihomo"),
            PathBuf::from("config.yaml"),
            17890,
        );
        assert_eq!(manager.proxy_address(), "127.0.0.1:17890");
    }
}
