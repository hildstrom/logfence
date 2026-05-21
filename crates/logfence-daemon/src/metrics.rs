//! Atomic message counters and optional Unix socket stats endpoint.
//!
//! [`MetricsStore`] is cheaply cloneable via `Arc` and safe to share across
//! Tokio tasks. Call [`MetricsStore::snapshot`] to read a consistent view of
//! all counters, then log or serialize the resulting [`Snapshot`].
//!
//! When compiled with `--features metrics`, [`serve_stats_socket`] binds a
//! Unix stream socket and writes a JSON [`Snapshot`] to each connecting client.

use std::{
    fmt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use serde::Serialize;

// ── MetricsStore ──────────────────────────────────────────────────────────────

/// Shared atomic counters tracking messages processed by the daemon.
#[derive(Default)]
pub struct MetricsStore {
    received: AtomicU64,
    forwarded: AtomicU64,
    dropped: AtomicU64,
    errors: AtomicU64,
}

impl MetricsStore {
    /// Create a new zeroed store, wrapped in an `Arc`.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Increment the received counter (one message arrived from a client).
    pub fn inc_received(&self) {
        self.received.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the forwarded counter (one message passed validation and was sent to rsyslog).
    pub fn inc_forwarded(&self) {
        self.forwarded.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the dropped counter (one message failed validation and was discarded).
    pub fn inc_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the errors counter (one forwarding attempt to rsyslog failed).
    pub fn inc_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Read all counters atomically and return a [`Snapshot`].
    ///
    /// Individual loads use `Relaxed` ordering; the snapshot is not guaranteed
    /// to be globally consistent across all four counters, but is accurate
    /// enough for operational monitoring.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            received: self.received.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

// ── Snapshot ──────────────────────────────────────────────────────────────────

/// A point-in-time view of the daemon's message counters.
#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    /// Total messages received from clients (before validation).
    pub received: u64,
    /// Messages that passed validation and were forwarded to rsyslog.
    pub forwarded: u64,
    /// Messages that failed validation and were discarded.
    pub dropped: u64,
    /// Messages that passed validation but could not be forwarded to rsyslog.
    pub errors: u64,
}

impl fmt::Display for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "received={} forwarded={} dropped={} errors={}",
            self.received, self.forwarded, self.dropped, self.errors
        )
    }
}

// ── Stats socket (metrics feature) ───────────────────────────────────────────

/// Bind a Unix stream socket at `path` and serve one-shot stats responses.
///
/// Each connecting client receives a single JSON line containing the current
/// [`Snapshot`] and the connection is then closed. The loop exits when
/// `shutdown` is cancelled.
///
/// Only compiled when the `metrics` Cargo feature is enabled.
/// Shut down the read half of an accepted metrics connection and return only
/// the write half.
///
/// The metrics socket is write-only from the daemon's perspective: logfenced
/// never reads from it.  Calling `shutdown(SHUT_RD)` makes that invariant
/// explicit at the OS level; keeping only `OwnedWriteHalf` enforces it at the
/// type level.
#[cfg(feature = "metrics")]
fn metrics_write_half(
    stream: tokio::net::UnixStream,
) -> std::io::Result<tokio::net::unix::OwnedWriteHalf> {
    let std_stream = stream.into_std()?;
    std_stream.shutdown(std::net::Shutdown::Read)?;
    let stream = tokio::net::UnixStream::from_std(std_stream)?;
    let (_, write_half) = stream.into_split();
    Ok(write_half)
}

#[cfg(feature = "metrics")]
pub async fn serve_stats_socket(
    path: String,
    store: Arc<MetricsStore>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    use tokio::{io::AsyncWriteExt, net::UnixListener};
    use tracing::{error, info};

    let _ = std::fs::remove_file(&path);
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, socket = %path, "failed to bind metrics socket");
            return;
        }
    };
    info!(socket = %path, "metrics socket listening");

    loop {
        let stream = tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            result = listener.accept() => match result {
                Ok((s, _)) => s,
                Err(e) => {
                    error!(error = %e, "metrics socket accept failed");
                    continue;
                }
            },
        };

        // Enforce write-only direction before doing anything with the socket.
        let mut write_half = match metrics_write_half(stream) {
            Ok(w) => w,
            Err(e) => {
                error!(error = %e, "failed to enforce write-only on metrics connection");
                continue;
            }
        };

        let snapshot = store.snapshot();
        let line = match serde_json::to_string(&snapshot) {
            Ok(s) => format!("{s}\n"),
            Err(e) => {
                error!(error = %e, "failed to serialize metrics snapshot");
                continue;
            }
        };
        if let Err(e) = write_half.write_all(line.as_bytes()).await {
            error!(error = %e, "failed to write metrics response");
        }
    }

    let _ = std::fs::remove_file(&path);
    info!("metrics socket closed");
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "unwrap is appropriate in test assertions"
)]
mod tests {
    use super::*;

    #[test]
    fn counters_start_at_zero() {
        let store = MetricsStore::new();
        let snap = store.snapshot();
        assert_eq!(snap.received, 0);
        assert_eq!(snap.forwarded, 0);
        assert_eq!(snap.dropped, 0);
        assert_eq!(snap.errors, 0);
    }

    #[test]
    fn inc_received_increments_only_received() {
        let store = MetricsStore::new();
        store.inc_received();
        store.inc_received();
        let snap = store.snapshot();
        assert_eq!(snap.received, 2);
        assert_eq!(snap.forwarded, 0);
        assert_eq!(snap.dropped, 0);
        assert_eq!(snap.errors, 0);
    }

    #[test]
    fn inc_all_counters_independently() {
        let store = MetricsStore::new();
        store.inc_received();
        store.inc_forwarded();
        store.inc_dropped();
        store.inc_errors();
        let snap = store.snapshot();
        assert_eq!(snap.received, 1);
        assert_eq!(snap.forwarded, 1);
        assert_eq!(snap.dropped, 1);
        assert_eq!(snap.errors, 1);
    }

    #[test]
    fn snapshot_display_format() {
        let snap = Snapshot {
            received: 10,
            forwarded: 7,
            dropped: 2,
            errors: 1,
        };
        assert_eq!(
            snap.to_string(),
            "received=10 forwarded=7 dropped=2 errors=1"
        );
    }

    #[test]
    fn arc_clone_shares_store() {
        let store = MetricsStore::new();
        let clone = Arc::clone(&store);
        store.inc_received();
        clone.inc_forwarded();
        let snap = store.snapshot();
        assert_eq!(snap.received, 1);
        assert_eq!(snap.forwarded, 1);
    }

    #[cfg(feature = "metrics")]
    #[tokio::test]
    async fn stats_socket_serves_json() {
        use std::time::Duration;
        use tokio::io::AsyncReadExt;
        use tokio_util::sync::CancellationToken;

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("stats.sock").to_string_lossy().into_owned();

        let store = MetricsStore::new();
        store.inc_received();
        store.inc_forwarded();

        let shutdown = CancellationToken::new();
        let path_clone = sock_path.clone();
        let store_clone = Arc::clone(&store);
        let token_clone = shutdown.child_token();
        tokio::spawn(async move {
            serve_stats_socket(path_clone, store_clone, token_clone).await;
        });

        // Give the socket a moment to bind.
        tokio::time::sleep(Duration::from_millis(20)).await;

        let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let mut buf = String::new();
        tokio::time::timeout(Duration::from_secs(1), client.read_to_string(&mut buf))
            .await
            .unwrap()
            .unwrap();

        let snap: serde_json::Value = serde_json::from_str(buf.trim()).unwrap();
        assert_eq!(snap["received"], 1);
        assert_eq!(snap["forwarded"], 1);
        assert_eq!(snap["dropped"], 0);
        assert_eq!(snap["errors"], 0);

        shutdown.cancel();
    }
}
