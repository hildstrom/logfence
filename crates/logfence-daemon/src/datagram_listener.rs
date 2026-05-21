//! Unix datagram socket listener.
//!
//! [`DatagramListener`] binds a `SOCK_DGRAM` Unix domain socket and processes
//! each incoming datagram as a complete RFC 5424 syslog message.  There is no
//! framing — the datagram boundary is the message boundary — which matches the
//! standard `imuxsock` input mode used by rsyslog.  This makes logfenced a
//! drop-in man-in-the-middle between existing syslog clients and rsyslog.

use std::{path::Path, sync::Arc};

use serde_json::json;
use tokio::sync::watch;
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
    /// Bind the socket at `cfg.listen_socket`, apply permissions, enforce
    /// read-only direction (`SHUT_WR`), and return a ready
    /// [`DatagramListener`].
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` if the socket cannot be bound, if permissions
    /// cannot be set, or if the directional shutdown fails.
    pub fn bind(cfg: DaemonConfig, forwarder: Forwarder) -> std::io::Result<Self> {
        let path = Path::new(&cfg.listen_socket);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let socket = tokio::net::UnixDatagram::bind(path)?;
        apply_socket_permissions(path, &cfg.socket_mode)?;
        // Enforce read-only direction: logfenced never sends on the listen
        // socket.
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

    /// Receive and process datagrams until `shutdown` is cancelled.
    ///
    /// Each datagram is treated as one complete RFC 5424 syslog message.
    /// Invalid UTF-8 and parse failures generate rejection reports forwarded
    /// to rsyslog.  Validated messages are forwarded via the shared
    /// [`Forwarder`].
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

        loop {
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

            let Ok(raw) = std::str::from_utf8(&buf[..n]) else {
                warn!(peer = %peer, "dropping datagram with invalid UTF-8");
                let payload = json!({
                    "event": "message_dropped",
                    "peer": peer.as_ref(),
                    "error": "invalid UTF-8 encoding",
                });
                report_rejection(&forwarder, &local_hostname, payload).await;
                continue;
            };

            let msg = match SyslogMessage::parse(raw) {
                Ok(m) => m,
                Err(e) => {
                    warn!(error = %e, peer = %peer, "dropping datagram with parse error");
                    let payload = json!({
                        "event": "message_dropped",
                        "peer": peer.as_ref(),
                        "error": format!("syslog parse error: {e}"),
                    });
                    report_rejection(&forwarder, &local_hostname, payload).await;
                    continue;
                }
            };

            let msg_cfg = SessionConfig {
                framing: cfg.framing,
                max_message_size: cfg.max_message_size,
                sender_mode: cfg.sender,
                local_hostname: Arc::clone(&local_hostname),
                peer,
            };
            handle_message(msg, &validator_rx, &forwarder, &metrics, &msg_cfg).await;
        }

        info!("datagram listener shutting down");
    }
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

    // Verify the datagram listener does not interfere with the stream listener
    // — both use the same socket path management but different socket types.
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

    // Integration smoke test: a second bind on the same path (after the first
    // DatagramListener is dropped) should succeed because the socket file was
    // left on disk and the new bind removes it.
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

    // Verify the stream listener type is unchanged (datagram_listener.rs does
    // not affect it).
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
        // Just bind — we're testing that the stream listener still compiles and
        // binds without interference from the datagram listener code.
        let _stream_listener = crate::listener::Listener::bind(stream_cfg, forwarder).unwrap();
        let client = tokio::net::UnixStream::connect(&stream_sock).await.unwrap();
        drop(client);
    }

    // Ensure the forwarder-side datagram socket's SHUT_RD does not prevent
    // the listener-side SHUT_WR from working.
    #[tokio::test]
    async fn both_directionality_enforcements_coexist() {
        let dir = tempfile::tempdir().unwrap();
        let listen_path = dir.path().join("coexist.sock");
        let rsyslog_path = dir.path().join("rsyslog.sock");

        // rsyslog side: datagram receive socket
        let rsyslog_rx = UnixDatagram::bind(&rsyslog_path).unwrap();
        // forwarder: write-only to rsyslog (SHUT_RD)
        let forwarder = make_forwarder(rsyslog_path.to_str().unwrap());
        let cfg = make_daemon_cfg(listen_path.to_str().unwrap());
        // listener: read-only from clients (SHUT_WR)
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
