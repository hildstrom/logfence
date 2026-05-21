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
//! The receive loop is deliberately thin.  After each [`recv_from`] the bytes
//! are copied into an owned [`Bytes`] buffer and all subsequent work (UTF-8
//! validation, syslog parsing, schema validation, forwarding) is dispatched to
//! a Tokio task via [`process_datagram`].  The loop returns to [`recv_from`]
//! as quickly as possible, draining the kernel receive buffer at the highest
//! possible rate.
//!
//! A 1 MB kernel receive buffer ([`RECV_BUFFER_SIZE`]) absorbs bursts without
//! dropping datagrams when the processing tasks temporarily fall behind.
//!
//! A semaphore bounded by [`DaemonConfig::max_connections`] limits the number
//! of concurrently active processing tasks, providing backpressure when the
//! pipeline is saturated.  On graceful shutdown the loop stops accepting new
//! datagrams and waits up to 30 seconds for in-flight tasks to complete.

use std::{path::Path, sync::Arc, time::Duration};

use bytes::Bytes;
use serde_json::json;
use tokio::sync::{watch, Semaphore};
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

/// Kernel receive buffer size for the datagram listen socket.
///
/// 1 MB absorbs bursts when processing tasks temporarily fall behind, matching
/// the receive buffer set on the mock rsyslog socket in benchmarks.
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
        // when processing tasks temporarily fall behind.
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
    /// processing task, then drain in-flight tasks before returning.
    ///
    /// The receive loop copies each datagram into an owned buffer and immediately
    /// spawns a task for all subsequent work, returning to [`recv_from`] as fast
    /// as possible.  A semaphore bounded by [`DaemonConfig::max_connections`]
    /// limits concurrent tasks; if the limit is reached the loop blocks until a
    /// task finishes before calling [`recv_from`] again.
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
        let semaphore = Arc::new(Semaphore::new(cfg.max_connections));

        loop {
            // ── Step 1: receive the next datagram ─────────────────────────────
            let (n, addr) = tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                result = socket.recv_from(&mut buf) => match result {
                    Ok(pair) => pair,
                    Err(e) => {
                        error!(error = %e, "recv_from() failed on datagram socket");
                        continue;
                    }
                },
            };

            let peer: Arc<str> = addr
                .as_pathname()
                .map_or_else(|| "<anonymous>".to_owned(), |p| p.display().to_string())
                .into();

            // Copy bytes into an owned buffer so `buf` is free for the next recv.
            let msg_bytes = Bytes::copy_from_slice(&buf[..n]);

            // ── Step 2: acquire a processing permit (backpressure) ────────────
            //
            // Also cancels on shutdown so the loop does not block indefinitely
            // when all permits are held during a clean shutdown.
            let permit = tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                result = semaphore.clone().acquire_owned() => if let Ok(p) = result { p } else {
                    error!("datagram processing semaphore closed — shutting down");
                    return;
                },
            };

            // ── Step 3: spawn processing task ─────────────────────────────────
            let vr = validator_rx.clone();
            let fwd = forwarder.clone();
            let m = Arc::clone(&metrics);
            let msg_cfg = SessionConfig {
                framing: cfg.framing,
                max_message_size: cfg.max_message_size,
                sender_mode: cfg.sender,
                local_hostname: Arc::clone(&local_hostname),
                peer,
            };

            tokio::spawn(async move {
                process_datagram(msg_bytes, msg_cfg, vr, fwd, m).await;
                drop(permit);
            });
        }

        // ── Graceful drain ────────────────────────────────────────────────────
        info!("datagram listener shutting down; waiting for in-flight tasks");
        let total = u32::try_from(cfg.max_connections).unwrap_or(u32::MAX);
        match tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, semaphore.acquire_many(total)).await {
            Ok(Ok(_)) => info!("all datagram tasks finished; shutdown complete"),
            Ok(Err(_)) => {} // semaphore closed; no tasks in flight
            Err(_) => warn!("graceful shutdown timed out; forcing exit"),
        };
    }
}

// ── Per-datagram processing ───────────────────────────────────────────────────

/// Validate and forward one received datagram.
///
/// Called from a spawned Tokio task per datagram so the receive loop is not
/// blocked on parsing, validation, or forwarding.
async fn process_datagram(
    msg_bytes: Bytes,
    msg_cfg: SessionConfig,
    validator_rx: watch::Receiver<Arc<Validator>>,
    forwarder: Forwarder,
    metrics: Arc<MetricsStore>,
) {
    let Ok(raw) = std::str::from_utf8(&msg_bytes) else {
        warn!(peer = %msg_cfg.peer, "dropping datagram with invalid UTF-8");
        let payload = json!({
            "event": "message_dropped",
            "peer": msg_cfg.peer.as_ref(),
            "error": "invalid UTF-8 encoding",
        });
        report_rejection(&forwarder, &msg_cfg.local_hostname, payload).await;
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
            report_rejection(&forwarder, &msg_cfg.local_hostname, payload).await;
            return;
        }
    };

    handle_message(msg, &validator_rx, &forwarder, &metrics, &msg_cfg).await;
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
            max_connections: 256,
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
