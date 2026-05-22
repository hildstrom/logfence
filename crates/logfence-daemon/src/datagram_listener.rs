//! Unix datagram socket listener.
//!
//! [`DatagramListener`] binds a `SOCK_DGRAM` Unix domain socket and processes
//! each incoming datagram as a complete RFC 5424 syslog message.  There is no
//! framing — the datagram boundary is the message boundary — which matches the
//! standard `imuxsock` input mode used by rsyslog.  This makes logfenced a
//! drop-in man-in-the-middle between existing syslog clients and rsyslog.
//!
//! ## Receive loop design
//!
//! The design separates receiving from processing with two phases per wakeup:
//!
//! **Phase 1 — tight drain (no `.await`).**  After `readable()` fires, an inner
//! loop calls [`try_recv_from`] until `WouldBlock`, copying each datagram into
//! an owned [`Bytes`] buffer and collecting `(bytes, peer)` pairs into a local
//! batch.  There is no scheduler interaction in this loop; the kernel buffer is
//! emptied as fast as possible.
//!
//! **Phase 2 — round-robin dispatch.**  The batch is distributed across a fixed
//! pool of worker tasks, one item per worker channel per step.  [`try_send`] is
//! used for the fast path (channel has space); a blocking [`send`] fallback
//! handles the rare case where a worker channel is full.  Workers process
//! datagrams in parallel as soon as items arrive in their channels.
//!
//! **Worker pool.**  `max_connections` long-lived Tokio tasks each own a
//! dedicated bounded channel.  Workers call [`process_datagram`] directly —
//! there is no [`tokio::spawn`] per message and no semaphore acquisition in the
//! hot path.  On graceful shutdown the receive loop drops all channel senders,
//! causing workers to drain their remaining items and exit naturally.
//!
//! A 1 MB kernel receive buffer ([`RECV_BUFFER_SIZE`]) absorbs bursts without
//! dropping datagrams when workers temporarily fall behind.

use std::{io, path::Path, sync::Arc, time::Duration};

use bytes::Bytes;
use serde_json::json;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use logfence_proto::syslog::SyslogMessage;

use crate::{
    config::DaemonConfig,
    forwarder::Forwarder,
    listener::{apply_socket_permissions, detect_hostname},
    metrics::MetricsStore,
    session::{handle_message, report_rejection, SessionConfig},
    validator::Validator,
};

// ── Constants ─────────────────────────────────────────────────────────────────

const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-worker channel buffer depth.
///
/// Each of the `max_connections` worker tasks owns a bounded channel of this
/// capacity.  Total in-flight capacity across all workers is
/// `max_connections × WORKER_CHANNEL_CAP` datagrams.
const WORKER_CHANNEL_CAP: usize = 256;

/// Kernel receive buffer size for the datagram listen socket.
///
/// 1 MB absorbs bursts when workers temporarily fall behind, matching the
/// receive buffer set on the mock rsyslog socket in benchmarks.
const RECV_BUFFER_SIZE: usize = 1024 * 1024;

// ── DatagramListener ──────────────────────────────────────────────────────────

/// Receives syslog messages as Unix datagrams and forwards validated ones to
/// rsyslog.
///
/// `DatagramListener` is cheaply constructed — the underlying socket is bound
/// at construction time and held until [`run`](Self::run) returns.
pub struct DatagramListener {
    socket: tokio::net::UnixDatagram,
    cfg: DaemonConfig,
    forwarder: Forwarder,
    local_hostname: Arc<str>,
}

impl DatagramListener {
    /// Bind the socket at `cfg.listen_socket`, apply permissions, set a 1 MB
    /// receive buffer, enforce read-only direction (`SHUT_WR`), and return a
    /// ready [`DatagramListener`].
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` if the socket cannot be bound, if permissions
    /// cannot be set, if the receive buffer cannot be resized, or if the
    /// directional shutdown fails.
    pub fn bind(cfg: DaemonConfig, forwarder: Forwarder) -> std::io::Result<Self> {
        let path = Path::new(&cfg.listen_socket);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let socket = tokio::net::UnixDatagram::bind(path)?;
        apply_socket_permissions(path, &cfg.socket_mode)?;

        // Set a 1 MB receive buffer to absorb bursts without dropping datagrams
        // when workers temporarily fall behind.
        socket2::SockRef::from(&socket).set_recv_buffer_size(RECV_BUFFER_SIZE)?;

        // Enforce read-only direction: logfenced never sends on the listen socket.
        socket.shutdown(std::net::Shutdown::Write)?;

        let local_hostname = detect_hostname();
        info!(socket = %cfg.listen_socket, "listening for client datagrams");
        Ok(Self {
            socket,
            cfg,
            forwarder,
            local_hostname,
        })
    }

    /// Receive datagrams until `shutdown` is cancelled, dispatching each to a
    /// worker task, then drain in-flight work before returning.
    ///
    /// The receive loop has two phases per wakeup: a tight non-blocking drain
    /// that collects all queued datagrams into a local batch, followed by
    /// round-robin dispatch of that batch to the fixed worker pool.  Workers
    /// process datagrams in parallel; there is no per-message spawn overhead.
    pub async fn run(
        self,
        shutdown: CancellationToken,
        validator_rx: watch::Receiver<Arc<Validator>>,
        metrics: Arc<MetricsStore>,
    ) {
        let Self {
            socket,
            cfg,
            forwarder,
            local_hostname,
        } = self;

        let mut buf = vec![0u8; cfg.max_message_size];
        let num_workers = cfg.max_connections;

        // Template SessionConfig for workers; `peer` is overwritten per message.
        let base_cfg = SessionConfig {
            framing: cfg.framing,
            max_message_size: cfg.max_message_size,
            sender_mode: cfg.sender,
            local_hostname: Arc::clone(&local_hostname),
            peer: Arc::from("<anonymous>"),
        };

        // Spawn a fixed pool of worker tasks, each with its own bounded channel.
        // Long-lived workers eliminate per-message tokio::spawn and semaphore
        // overhead; the channel provides backpressure when workers fall behind.
        let mut senders: Vec<mpsc::Sender<(Bytes, Arc<str>)>> = Vec::with_capacity(num_workers);
        let mut join_set: JoinSet<()> = JoinSet::new();

        for _ in 0..num_workers {
            let (tx, rx) = mpsc::channel::<(Bytes, Arc<str>)>(WORKER_CHANNEL_CAP);
            senders.push(tx);
            join_set.spawn(run_worker(
                rx,
                base_cfg.clone(),
                validator_rx.clone(),
                forwarder.clone(),
                Arc::clone(&metrics),
            ));
        }

        let mut worker_idx = 0usize;
        // Reused across drain cycles; avoids per-wakeup allocation.
        let mut batch: Vec<(Bytes, Arc<str>)> = Vec::with_capacity(64);

        'recv: loop {
            // ── Wait for the socket to become readable or for shutdown ─────────
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                result = socket.readable() => {
                    if let Err(e) = result {
                        error!(error = %e, "socket readability poll failed");
                        continue;
                    }
                }
            };

            // ── Phase 1: tight drain — no `.await`, empties the kernel buffer ──
            loop {
                let (n, addr) = match socket.try_recv_from(&mut buf) {
                    Ok(pair) => pair,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        error!(error = %e, "recv_from() failed on datagram socket");
                        break;
                    }
                };

                let peer: Arc<str> = addr
                    .as_pathname()
                    .map_or_else(|| "<anonymous>".into(), |p| p.display().to_string().into());
                batch.push((Bytes::copy_from_slice(&buf[..n]), peer));
            }

            // ── Phase 2: dispatch batch round-robin to worker channels ─────────
            // try_send is non-blocking for the common case (channel has space).
            // Falls back to send().await when a worker channel is full, which
            // yields to the scheduler and lets workers consume queued items.
            for item in batch.drain(..) {
                let item = match senders[worker_idx].try_send(item) {
                    Ok(()) => {
                        worker_idx = (worker_idx + 1) % num_workers;
                        continue;
                    }
                    Err(mpsc::error::TrySendError::Full(item)) => item,
                    Err(mpsc::error::TrySendError::Closed(_)) => break 'recv,
                };
                if senders[worker_idx].send(item).await.is_err() {
                    break 'recv;
                }
                worker_idx = (worker_idx + 1) % num_workers;
            }
        }

        // ── Graceful drain ────────────────────────────────────────────────────
        // Dropping all senders closes each worker's channel; workers drain
        // remaining items and exit their recv loop naturally.
        drop(senders);
        info!("datagram listener shutting down; waiting for in-flight tasks");
        if tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, async {
            while let Some(result) = join_set.join_next().await {
                if let Err(e) = result {
                    error!(error = %e, "datagram worker task failed");
                }
            }
        })
        .await
        .is_ok()
        {
            info!("all datagram workers finished; shutdown complete");
        } else {
            warn!("graceful shutdown timed out; forcing exit");
        }
    }
}

// ── Worker task ───────────────────────────────────────────────────────────────

/// Long-lived worker that processes datagrams from its dedicated channel.
///
/// Runs until its channel is closed (all senders dropped during shutdown),
/// draining any remaining items before returning.
async fn run_worker(
    mut rx: mpsc::Receiver<(Bytes, Arc<str>)>,
    base_cfg: SessionConfig,
    validator_rx: watch::Receiver<Arc<Validator>>,
    forwarder: Forwarder,
    metrics: Arc<MetricsStore>,
) {
    while let Some((msg_bytes, peer)) = rx.recv().await {
        let msg_cfg = SessionConfig {
            peer,
            ..base_cfg.clone()
        };
        process_datagram(msg_bytes, msg_cfg, &validator_rx, &forwarder, &metrics).await;
    }
}

// ── Per-datagram processing ───────────────────────────────────────────────────

/// Validate and forward one received datagram.
///
/// Called from a worker task; takes shared references to avoid per-message
/// Arc clones of the validator, forwarder, and metrics handles.
async fn process_datagram(
    msg_bytes: Bytes,
    msg_cfg: SessionConfig,
    validator_rx: &watch::Receiver<Arc<Validator>>,
    forwarder: &Forwarder,
    metrics: &MetricsStore,
) {
    let Ok(raw) = std::str::from_utf8(&msg_bytes) else {
        warn!(peer = %msg_cfg.peer, "dropping datagram with invalid UTF-8");
        let payload = json!({
            "event": "message_dropped",
            "peer": msg_cfg.peer.as_ref(),
            "error": "invalid UTF-8 encoding",
        });
        report_rejection(forwarder, &msg_cfg.local_hostname, payload).await;
        return;
    };

    let msg = match SyslogMessage::parse(raw) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, peer = %msg_cfg.peer, "dropping datagram with parse error");
            let payload = json!({
                "event": "message_dropped",
                "peer": msg_cfg.peer.as_ref(),
                "error": format!("syslog parse error: {e}"),
            });
            report_rejection(forwarder, &msg_cfg.local_hostname, payload).await;
            return;
        }
    };

    handle_message(msg, validator_rx, forwarder, metrics, &msg_cfg).await;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "unwrap is appropriate in test assertions"
)]
mod tests {
    use std::time::Duration;

    use tokio::net::UnixDatagram;
    use tokio::sync::watch;

    use logfence_proto::syslog::{Facility, Priority, Severity, SyslogMessage};

    use super::*;
    use crate::{
        config::{ForwardTransport, FramingMode, RsyslogConfig, SenderMode, ValidationMode},
        forwarder::Forwarder,
        metrics::MetricsStore,
        validator::Validator,
    };

    fn sample_msg() -> SyslogMessage {
        SyslogMessage {
            priority: Priority(Facility::Local0, Severity::Info),
            timestamp: None,
            hostname: None,
            app_name: Some("test".into()),
            proc_id: None,
            msg_id: None,
            structured_data: "-".into(),
            msg: r#"{"action":"login"}"#.into(),
        }
    }

    fn make_forwarder(rsyslog_sock: &str) -> Forwarder {
        Forwarder::from_config(&RsyslogConfig {
            transport: ForwardTransport::UnixDgram,
            socket: rsyslog_sock.to_owned(),
        })
        .unwrap()
    }

    fn make_validator() -> Arc<Validator> {
        Arc::new(Validator::from_values(ValidationMode::Off, &[]).unwrap())
    }

    fn make_daemon_cfg(listen: &str) -> DaemonConfig {
        DaemonConfig {
            listen_socket: listen.to_owned(),
            socket_mode: "0600".to_owned(),
            socket_group: None,
            max_connections: 4,
            max_message_size: 65_536,
            listen_transport: crate::config::ListenTransport::UnixDgram,
            framing: FramingMode::OctetCount,
            sender: SenderMode::Original,
        }
    }

    #[tokio::test]
    async fn datagram_listener_forwards_valid_message() {
        let dir = tempfile::tempdir().unwrap();
        let listen_path = dir.path().join("logfenced.sock");
        let rsyslog_path = dir.path().join("rsyslog.sock");

        let rsyslog_rx = UnixDatagram::bind(&rsyslog_path).unwrap();
        let forwarder = make_forwarder(rsyslog_path.to_str().unwrap());
        let cfg = make_daemon_cfg(listen_path.to_str().unwrap());
        let listener = DatagramListener::bind(cfg, forwarder).unwrap();

        let (_, validator_rx) = watch::channel(make_validator());
        let metrics = MetricsStore::new();
        let shutdown = CancellationToken::new();

        let listener_task = tokio::spawn({
            let tok = shutdown.child_token();
            async move { listener.run(tok, validator_rx, metrics).await }
        });

        // Send one datagram containing a complete RFC 5424 message.
        let wire = sample_msg().to_string();
        let sender = UnixDatagram::unbound().unwrap();
        sender.send_to(wire.as_bytes(), &listen_path).await.unwrap();

        // The forwarded message must arrive at the mock rsyslog receiver.
        let mut buf = vec![0u8; 65_536];
        let n = tokio::time::timeout(Duration::from_secs(1), rsyslog_rx.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), wire);

        shutdown.cancel();
        listener_task.await.unwrap();
    }

    #[tokio::test]
    async fn datagram_listener_drops_invalid_message_and_reports() {
        let dir = tempfile::tempdir().unwrap();
        let listen_path = dir.path().join("logfenced.sock");
        let rsyslog_path = dir.path().join("rsyslog.sock");

        let rsyslog_rx = UnixDatagram::bind(&rsyslog_path).unwrap();

        // Strict validator requiring "action" field.
        let validator = Arc::new(
            Validator::from_values(
                ValidationMode::Strict,
                &[serde_json::json!({
                    "type": "object",
                    "required": ["action"],
                })],
            )
            .unwrap(),
        );
        let forwarder = make_forwarder(rsyslog_path.to_str().unwrap());
        let cfg = make_daemon_cfg(listen_path.to_str().unwrap());
        let listener = DatagramListener::bind(cfg, forwarder).unwrap();

        let (_, validator_rx) = watch::channel(validator);
        let metrics = MetricsStore::new();
        let shutdown = CancellationToken::new();

        let listener_task = tokio::spawn({
            let tok = shutdown.child_token();
            async move { listener.run(tok, validator_rx, metrics).await }
        });

        // Message missing the required "action" field.
        let bad_msg = SyslogMessage {
            priority: Priority(Facility::Local0, Severity::Info),
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            msg_id: None,
            structured_data: "-".into(),
            msg: r#"{"other":"value"}"#.into(),
        };
        let wire = bad_msg.to_string();
        let sender = UnixDatagram::unbound().unwrap();
        sender.send_to(wire.as_bytes(), &listen_path).await.unwrap();

        // A rejection report must arrive; the original message must not.
        let mut buf = vec![0u8; 65_536];
        let n = tokio::time::timeout(Duration::from_secs(1), rsyslog_rx.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let report = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(
            report.contains("message_dropped"),
            "expected rejection report, got: {report}"
        );
        let second =
            tokio::time::timeout(Duration::from_millis(100), rsyslog_rx.recv(&mut buf)).await;
        assert!(second.is_err(), "invalid message must not be forwarded");

        shutdown.cancel();
        listener_task.await.unwrap();
    }

    #[tokio::test]
    async fn datagram_listener_reports_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let listen_path = dir.path().join("logfenced.sock");
        let rsyslog_path = dir.path().join("rsyslog.sock");

        let rsyslog_rx = UnixDatagram::bind(&rsyslog_path).unwrap();
        let forwarder = make_forwarder(rsyslog_path.to_str().unwrap());
        let cfg = make_daemon_cfg(listen_path.to_str().unwrap());
        let listener = DatagramListener::bind(cfg, forwarder).unwrap();

        let (_, validator_rx) = watch::channel(make_validator());
        let metrics = MetricsStore::new();
        let shutdown = CancellationToken::new();

        let listener_task = tokio::spawn({
            let tok = shutdown.child_token();
            async move { listener.run(tok, validator_rx, metrics).await }
        });

        let sender = UnixDatagram::unbound().unwrap();
        sender
            .send_to(b"not a syslog message at all", &listen_path)
            .await
            .unwrap();

        let mut buf = vec![0u8; 65_536];
        let n = tokio::time::timeout(Duration::from_secs(1), rsyslog_rx.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let report = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(
            report.contains("message_dropped"),
            "expected parse-error rejection report, got: {report}"
        );

        shutdown.cancel();
        listener_task.await.unwrap();
    }

    #[tokio::test]
    async fn datagram_listener_removes_stale_socket_on_bind() {
        let dir = tempfile::tempdir().unwrap();
        let listen_path = dir.path().join("logfenced.sock");
        let rsyslog_path = dir.path().join("rsyslog.sock");

        // Pre-create a file at the socket path to simulate a stale socket.
        std::fs::write(&listen_path, b"stale").unwrap();
        assert!(listen_path.exists());

        let _rsyslog_rx = UnixDatagram::bind(&rsyslog_path).unwrap();
        let forwarder = make_forwarder(rsyslog_path.to_str().unwrap());
        let cfg = make_daemon_cfg(listen_path.to_str().unwrap());

        // bind() should remove the stale file and succeed.
        DatagramListener::bind(cfg, forwarder).unwrap();
    }

    #[tokio::test]
    async fn datagram_listener_successive_binds_succeed() {
        let dir = tempfile::tempdir().unwrap();
        let listen_path = dir.path().join("successive.sock");
        let rsyslog_path = dir.path().join("rsyslog.sock");

        let _rsyslog_rx = UnixDatagram::bind(&rsyslog_path).unwrap();
        let forwarder1 = make_forwarder(rsyslog_path.to_str().unwrap());
        let forwarder2 = make_forwarder(rsyslog_path.to_str().unwrap());
        let cfg1 = make_daemon_cfg(listen_path.to_str().unwrap());
        let cfg2 = make_daemon_cfg(listen_path.to_str().unwrap());

        let l1 = DatagramListener::bind(cfg1, forwarder1).unwrap();
        // Drop l1 (socket file remains on disk).
        drop(l1);
        // Second bind should clean up the stale socket and succeed.
        DatagramListener::bind(cfg2, forwarder2).unwrap();
    }

    #[tokio::test]
    async fn stream_listener_still_works_alongside_datagram_type() {
        let dir = tempfile::tempdir().unwrap();
        let stream_sock = dir.path().join("stream.sock");
        let rsyslog_path = dir.path().join("rsyslog.sock");

        let _rsyslog_rx = UnixDatagram::bind(&rsyslog_path).unwrap();
        let forwarder = make_forwarder(rsyslog_path.to_str().unwrap());
        let stream_cfg = DaemonConfig {
            listen_socket: stream_sock.to_str().unwrap().to_owned(),
            socket_mode: "0600".to_owned(),
            socket_group: None,
            max_connections: 4,
            max_message_size: 65_536,
            listen_transport: crate::config::ListenTransport::UnixStream,
            framing: FramingMode::OctetCount,
            sender: SenderMode::Original,
        };
        let _stream_listener = crate::listener::Listener::bind(stream_cfg, forwarder).unwrap();
        let client = tokio::net::UnixStream::connect(&stream_sock).await.unwrap();
        drop(client);
    }

    #[tokio::test]
    async fn both_directionality_enforcements_coexist() {
        let dir = tempfile::tempdir().unwrap();
        let listen_path = dir.path().join("coexist.sock");
        let rsyslog_path = dir.path().join("rsyslog.sock");

        let rsyslog_rx = UnixDatagram::bind(&rsyslog_path).unwrap();
        let forwarder = make_forwarder(rsyslog_path.to_str().unwrap());
        let cfg = make_daemon_cfg(listen_path.to_str().unwrap());
        let listener = DatagramListener::bind(cfg, forwarder).unwrap();

        let (_, validator_rx) = watch::channel(make_validator());
        let metrics = MetricsStore::new();
        let shutdown = CancellationToken::new();
        let listener_task = tokio::spawn({
            let tok = shutdown.child_token();
            async move { listener.run(tok, validator_rx, metrics).await }
        });

        let wire = sample_msg().to_string();
        let sender = UnixDatagram::unbound().unwrap();
        sender.send_to(wire.as_bytes(), &listen_path).await.unwrap();

        let mut buf = vec![0u8; 65_536];
        let n = tokio::time::timeout(Duration::from_secs(1), rsyslog_rx.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), wire);

        shutdown.cancel();
        listener_task.await.unwrap();
    }
}
