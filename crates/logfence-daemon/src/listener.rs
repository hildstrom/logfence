//! Unix domain socket listener and connection acceptor.
//!
//! [`Listener`] binds the configured socket path, sets permissions, and
//! spawns a [`session::run_session`] task for each accepted connection.
//! A semaphore limits the number of concurrent sessions to
//! [`DaemonConfig::max_connections`].

use std::{os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};

use tokio::{
    net::UnixListener,
    sync::{watch, Semaphore},
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{
    config::DaemonConfig,
    forwarder::Forwarder,
    metrics::MetricsStore,
    session::{run_session, SessionConfig},
    validator::Validator,
};

// ── Shutdown drain timeout ────────────────────────────────────────────────────

const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

// ── Listener ──────────────────────────────────────────────────────────────────

/// Accepts client connections on a Unix domain socket and spawns sessions.
#[allow(
    clippy::struct_field_names,
    reason = "listener field is the natural name for a UnixListener inside Listener"
)]
pub struct Listener {
    listener: UnixListener,
    semaphore: Arc<Semaphore>,
    cfg: DaemonConfig,
    forwarder: Forwarder,
    local_hostname: Arc<str>,
}

impl Listener {
    /// Bind the socket at `cfg.listen_socket`, apply permissions, and return a
    /// ready [`Listener`].
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` if the socket cannot be bound or if permissions
    /// cannot be set.
    pub fn bind(cfg: DaemonConfig, forwarder: Forwarder) -> std::io::Result<Self> {
        let path = Path::new(&cfg.listen_socket);

        // Remove a stale socket file if present.
        if path.exists() {
            std::fs::remove_file(path)?;
        }

        let listener = UnixListener::bind(path)?;
        apply_socket_permissions(path, &cfg.socket_mode)?;

        let semaphore = Arc::new(Semaphore::new(cfg.max_connections));
        let local_hostname = detect_hostname();
        info!(socket = %cfg.listen_socket, "listening for client connections");

        Ok(Self {
            listener,
            semaphore,
            cfg,
            forwarder,
            local_hostname,
        })
    }

    /// Run the accept loop until `shutdown` is cancelled, then drain active
    /// sessions before returning.
    ///
    /// Each accepted connection is dispatched to a Tokio task. When
    /// `max_connections` is reached, new connections queue on the semaphore
    /// until an existing session finishes. On cancellation, the accept loop
    /// stops and the function waits up to 30 seconds for all sessions to finish.
    pub async fn run(
        self,
        shutdown: CancellationToken,
        validator_rx: watch::Receiver<Arc<Validator>>,
        metrics: Arc<MetricsStore>,
    ) {
        let Self {
            listener,
            semaphore,
            cfg,
            forwarder,
            local_hostname,
        } = self;

        loop {
            // Acquire a connection permit, cancelling if shutdown fires first.
            let permit = tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                result = semaphore.clone().acquire_owned() => if let Ok(p) = result { p } else {
                    error!("connection semaphore closed — shutting down accept loop");
                    return;
                },
            };

            let (stream, addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    error!(error = %e, "accept() failed");
                    drop(permit);
                    continue;
                }
            };

            let peer = addr
                .as_pathname()
                .map_or_else(|| "<anonymous>".to_owned(), |p| p.display().to_string());
            info!(peer = %peer, "accepted connection");

            let session_cfg = SessionConfig {
                framing: cfg.framing,
                max_message_size: cfg.max_message_size,
                sender_mode: cfg.sender,
                local_hostname: Arc::clone(&local_hostname),
            };
            let vr = validator_rx.clone();
            let fwd = forwarder.clone();
            let m = Arc::clone(&metrics);

            tokio::spawn(async move {
                run_session(stream, session_cfg, vr, fwd, m).await;
                info!(peer = %peer, "connection closed");
                drop(permit);
            });
        }

        info!("shutting down; waiting for active sessions to finish");
        let total = u32::try_from(cfg.max_connections).unwrap_or(u32::MAX);
        match tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, semaphore.acquire_many(total)).await {
            Ok(Ok(_)) => info!("all sessions finished; shutdown complete"),
            Ok(Err(_)) => {} // semaphore was closed; no active sessions to drain
            Err(_) => warn!("graceful shutdown timed out; forcing exit"),
        };
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Read the local hostname from `/etc/hostname` (Linux / RHEL / Ubuntu).
///
/// Returns `"-"` (the RFC 5424 nil value) when the file is absent or empty,
/// which covers macOS in development environments.
fn detect_hostname() -> Arc<str> {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_owned())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "-".to_owned())
        .into()
}

fn apply_socket_permissions(path: &Path, mode_str: &str) -> std::io::Result<()> {
    let trimmed = mode_str.trim_start_matches('0');
    let trimmed = if trimmed.is_empty() { "0" } else { trimmed };
    let mode = u32::from_str_radix(trimmed, 8).unwrap_or_else(|_| {
        warn!(mode = %mode_str, "invalid socket_mode; using 0660");
        0o660
    });
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}
