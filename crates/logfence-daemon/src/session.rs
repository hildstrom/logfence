//! Per-connection session handler.
//!
//! Each accepted client connection is handled by [`run_session`], which reads
//! framed syslog messages from the stream, validates them, and forwards valid
//! ones to rsyslog via the shared [`Forwarder`].

use std::sync::Arc;

use bytes::BytesMut;
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::net::unix::OwnedReadHalf;
use tokio::net::UnixStream;
use tokio::sync::watch;
use tokio_util::codec::Decoder;
use tracing::{debug, error, warn};

use logfence_proto::frame::{DelimiterCodec, FrameError, OctetCountCodec};

use crate::{
    config::{FramingMode, SenderMode},
    forwarder::Forwarder,
    metrics::MetricsStore,
    validator::Validator,
};

// ── Session config ────────────────────────────────────────────────────────────

/// Per-session configuration derived from [`crate::config::DaemonConfig`].
#[derive(Clone)]
pub struct SessionConfig {
    /// Framing mode for the incoming stream.
    pub framing: FramingMode,
    /// Maximum accepted message size in bytes.
    pub max_message_size: usize,
    /// Sender identity mode for forwarded messages.
    pub sender_mode: SenderMode,
    /// Local hostname reported as sender when `sender_mode` is `Logfenced`.
    pub local_hostname: Arc<str>,
    /// Socket path (or `"<anonymous>"`) of the connecting client, used in
    /// rejection reports forwarded to rsyslog.
    pub peer: Arc<str>,
}

// ── Sender rewrite ────────────────────────────────────────────────────────────

/// Escape characters that are not allowed unescaped in RFC 5424 SD-PARAM values.
fn escape_sd_param(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' | '\\' | ']' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Replace sender identity fields with logfenced's own identity and preserve
/// the original hostname, `app_name`, and `proc_id` in RFC 5424 STRUCTURED-DATA.
fn rewrite_sender(
    msg: logfence_proto::syslog::SyslogMessage,
    local_hostname: &str,
) -> logfence_proto::syslog::SyslogMessage {
    let orig_hostname = escape_sd_param(msg.hostname.as_deref().unwrap_or("-"));
    let orig_app = escape_sd_param(msg.app_name.as_deref().unwrap_or("-"));
    let orig_pid = escape_sd_param(msg.proc_id.as_deref().unwrap_or("-"));

    let src_element = format!(
        r#"[logfence-src@65944 hostname="{orig_hostname}" app="{orig_app}" pid="{orig_pid}"]"#
    );
    let new_sd = if msg.structured_data == "-" {
        src_element
    } else {
        format!("{} {src_element}", msg.structured_data)
    };

    logfence_proto::syslog::SyslogMessage {
        priority: msg.priority,
        timestamp: msg.timestamp,
        hostname: Some(local_hostname.to_owned()),
        app_name: Some("logfenced".to_owned()),
        proc_id: Some(std::process::id().to_string()),
        msg_id: msg.msg_id,
        structured_data: new_sd,
        msg: msg.msg,
    }
}

// ── Session ───────────────────────────────────────────────────────────────────

/// Handle one client connection until EOF or an unrecoverable error.
///
/// `validator_rx` carries the current validator; updating the watch channel
/// causes subsequent messages in this session to use the new validator.
pub async fn run_session(
    stream: UnixStream,
    cfg: SessionConfig,
    validator_rx: watch::Receiver<Arc<Validator>>,
    forwarder: Forwarder,
    metrics: Arc<MetricsStore>,
) {
    // Enforce read-only direction on this socket: logfenced only reads from
    // client connections and must never write back.  Dropping the write half
    // calls shutdown(SHUT_WR) at the OS level, making any accidental write
    // attempt fail immediately.
    let (read_half, _write_half) = stream.into_split();
    match cfg.framing {
        FramingMode::OctetCount => {
            let codec = OctetCountCodec::new(cfg.max_message_size);
            run_with_codec(read_half, codec, cfg, validator_rx, forwarder, metrics).await;
        }
        FramingMode::Newline => {
            let codec = DelimiterCodec::newline(cfg.max_message_size);
            run_with_codec(read_half, codec, cfg, validator_rx, forwarder, metrics).await;
        }
    }
}

async fn run_with_codec<C>(
    mut stream: OwnedReadHalf,
    mut codec: C,
    cfg: SessionConfig,
    validator_rx: watch::Receiver<Arc<Validator>>,
    forwarder: Forwarder,
    metrics: Arc<MetricsStore>,
) where
    C: Decoder<Item = logfence_proto::syslog::SyslogMessage, Error = FrameError>,
{
    let mut buf = BytesMut::with_capacity(4096);

    loop {
        // Try to decode a complete message from the buffer first.
        match codec.decode(&mut buf) {
            Ok(Some(msg)) => {
                handle_message(msg, &validator_rx, &forwarder, &metrics, &cfg).await;
                continue;
            }
            Ok(None) => {} // Need more bytes.
            Err(e) => {
                handle_frame_error(e, &forwarder, &cfg).await;
                // Clear the buffer so we don't get stuck on bad bytes.
                // The connection stays open; the next read may recover.
                buf.clear();
            }
        }

        // Read more data from the stream.
        let n = match stream.read_buf(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                error!(error = %e, "I/O error reading from client");
                return;
            }
        };

        if n == 0 {
            // EOF — drain any remaining complete messages.
            loop {
                match codec.decode_eof(&mut buf) {
                    Ok(Some(msg)) => {
                        handle_message(msg, &validator_rx, &forwarder, &metrics, &cfg).await;
                    }
                    Ok(None) => break,
                    Err(e) => {
                        handle_frame_error(e, &forwarder, &cfg).await;
                        break;
                    }
                }
            }
            debug!("client disconnected");
            return;
        }
    }
}

/// Build and forward a rejection notice to rsyslog.
///
/// The notice is a syslog message from logfenced itself (facility=syslog,
/// severity=warning) whose MSG field is a JSON object describing why the
/// client's message was dropped.
pub(crate) async fn report_rejection(
    forwarder: &Forwarder,
    local_hostname: &str,
    payload: serde_json::Value,
) {
    use logfence_proto::syslog::{Facility, Priority, Severity};
    let report = logfence_proto::syslog::SyslogMessage {
        priority: Priority(Facility::Syslog, Severity::Warning),
        timestamp: None,
        hostname: Some(local_hostname.to_owned()),
        app_name: Some("logfenced".to_owned()),
        proc_id: Some(std::process::id().to_string()),
        msg_id: None,
        structured_data: "-".to_owned(),
        msg: payload.to_string(),
    };
    if let Err(e) = forwarder.forward(&report).await {
        error!(error = %e, "failed to report rejection to rsyslog");
    }
}

pub(crate) async fn handle_message(
    msg: logfence_proto::syslog::SyslogMessage,
    validator_rx: &watch::Receiver<Arc<Validator>>,
    forwarder: &Forwarder,
    metrics: &MetricsStore,
    cfg: &SessionConfig,
) {
    metrics.inc_received();

    // Clone the Arc so the watch borrow is released before any await point.
    let validator = Arc::clone(&*validator_rx.borrow());
    if let Err(e) = validator.validate(&msg) {
        warn!(error = %e, "dropping invalid message");
        metrics.inc_dropped();
        let payload = json!({
            "event": "message_dropped",
            "peer": cfg.peer.as_ref(),
            "sender_hostname": msg.hostname.as_deref().unwrap_or("-"),
            "sender_app": msg.app_name.as_deref().unwrap_or("-"),
            "sender_pid": msg.proc_id.as_deref().unwrap_or("-"),
            "error": e.to_string(),
        });
        report_rejection(forwarder, &cfg.local_hostname, payload).await;
        return;
    }
    let prepared = validator.prepare_for_forwarding(&msg);
    let to_forward = match cfg.sender_mode {
        SenderMode::Original => prepared,
        SenderMode::Logfenced => {
            std::borrow::Cow::Owned(rewrite_sender(prepared.into_owned(), &cfg.local_hostname))
        }
    };
    if let Err(e) = forwarder.forward(&to_forward).await {
        error!(error = %e, "failed to forward message to rsyslog");
        metrics.inc_errors();
    } else {
        debug!(msg = %to_forward, "forwarded message");
        metrics.inc_forwarded();
    }
}

async fn handle_frame_error(e: FrameError, forwarder: &Forwarder, cfg: &SessionConfig) {
    // Returns Some(description) for dropped-message errors that should be
    // reported to rsyslog, or None for infrastructure errors (I/O).
    let problem: Option<String> = match &e {
        FrameError::MessageTooLarge { max, got } => {
            warn!(max, got, "dropping oversized message");
            Some(format!("oversized message: got {got} bytes, max {max}"))
        }
        FrameError::InvalidOctetCount => {
            warn!("dropping message with invalid octet count");
            Some("invalid octet count".to_owned())
        }
        FrameError::InvalidUtf8 => {
            warn!("dropping message with invalid UTF-8");
            Some("invalid UTF-8 encoding".to_owned())
        }
        FrameError::OctetCountPrefixTooLong => {
            warn!("dropping message with excessively long octet count prefix");
            Some("octet count prefix too long".to_owned())
        }
        FrameError::Parse(inner) => {
            warn!(error = %inner, "dropping message with parse error");
            Some(format!("syslog parse error: {inner}"))
        }
        FrameError::Io(inner) => {
            error!(error = %inner, "I/O error in framing codec");
            None // infrastructure error — not a dropped message
        }
    };
    if let Some(problem) = problem {
        let payload = json!({
            "event": "message_dropped",
            "peer": cfg.peer.as_ref(),
            "error": problem,
        });
        report_rejection(forwarder, &cfg.local_hostname, payload).await;
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

    use tokio::io::AsyncWriteExt;
    use tokio::net::{UnixDatagram, UnixListener, UnixStream};
    use tokio::sync::watch;

    use logfence_proto::syslog::{Facility, Priority, Severity, SyslogMessage};
    use serde_json::json;

    use super::*;
    use crate::{
        config::{
            CeeCookieMode, ForwardTransport, FramingMode, RsyslogConfig, SenderMode, ValidationMode,
        },
        forwarder::Forwarder,
        metrics::MetricsStore,
        validator::Validator,
    };

    fn make_session_cfg(framing: FramingMode) -> SessionConfig {
        SessionConfig {
            framing,
            max_message_size: 65536,
            sender_mode: SenderMode::Original,
            local_hostname: Arc::from("-"),
            peer: Arc::from("<test>"),
        }
    }

    fn sample_msg_wire() -> String {
        let msg = SyslogMessage {
            priority: Priority(Facility::Local0, Severity::Info),
            timestamp: None,
            hostname: None,
            app_name: Some("test".into()),
            proc_id: None,
            msg_id: None,
            structured_data: "-".into(),
            msg: r#"{"action":"login"}"#.into(),
        };
        msg.to_string()
    }

    fn make_forwarder(rsyslog_sock: &str) -> Forwarder {
        let cfg = RsyslogConfig {
            transport: ForwardTransport::UnixDgram,
            socket: rsyslog_sock.to_owned(),
            ..Default::default()
        };
        Forwarder::from_config(&cfg, None).unwrap()
    }

    fn make_validator(mode: ValidationMode) -> Arc<Validator> {
        let schemas = if mode == ValidationMode::Off {
            vec![]
        } else {
            vec![json!({
                "type": "object",
                "required": ["action"],
                "properties": { "action": { "type": "string" } }
            })]
        };
        Arc::new(Validator::from_values(mode, &schemas).unwrap())
    }

    #[tokio::test]
    async fn session_forwards_valid_octet_count_message() {
        let dir = tempfile::tempdir().unwrap();
        let rsyslog_sock = dir.path().join("rsyslog.sock");
        let client_sock = dir.path().join("logfenced.sock");

        let receiver = UnixDatagram::bind(&rsyslog_sock).unwrap();
        let listener = UnixListener::bind(&client_sock).unwrap();
        let forwarder = make_forwarder(rsyslog_sock.to_str().unwrap());
        let (_, validator_rx) = watch::channel(make_validator(ValidationMode::Off));
        let metrics = MetricsStore::new();

        let wire = sample_msg_wire();
        let frame = format!("{} {wire}", wire.len());

        let session_task = tokio::spawn({
            async move {
                let (stream, _) = listener.accept().await.unwrap();
                run_session(
                    stream,
                    make_session_cfg(FramingMode::OctetCount),
                    validator_rx,
                    forwarder,
                    metrics,
                )
                .await;
            }
        });

        let mut client = UnixStream::connect(&client_sock).await.unwrap();
        client.write_all(frame.as_bytes()).await.unwrap();
        drop(client);

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), wire);
        session_task.await.unwrap();
    }

    #[tokio::test]
    async fn session_forwards_valid_newline_message() {
        let dir = tempfile::tempdir().unwrap();
        let rsyslog_sock = dir.path().join("rsyslog.sock");
        let client_sock = dir.path().join("logfenced.sock");

        let receiver = UnixDatagram::bind(&rsyslog_sock).unwrap();
        let listener = UnixListener::bind(&client_sock).unwrap();
        let forwarder = make_forwarder(rsyslog_sock.to_str().unwrap());
        let (_, validator_rx) = watch::channel(make_validator(ValidationMode::Off));
        let metrics = MetricsStore::new();

        let wire = sample_msg_wire();
        let frame = format!("{wire}\n");

        let session_task = tokio::spawn({
            async move {
                let (stream, _) = listener.accept().await.unwrap();
                run_session(
                    stream,
                    make_session_cfg(FramingMode::Newline),
                    validator_rx,
                    forwarder,
                    metrics,
                )
                .await;
            }
        });

        let mut client = UnixStream::connect(&client_sock).await.unwrap();
        client.write_all(frame.as_bytes()).await.unwrap();
        drop(client);

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), wire);
        session_task.await.unwrap();
    }

    #[tokio::test]
    async fn session_drops_invalid_json_message() {
        let dir = tempfile::tempdir().unwrap();
        let rsyslog_sock = dir.path().join("rsyslog.sock");
        let client_sock = dir.path().join("logfenced.sock");

        let receiver = UnixDatagram::bind(&rsyslog_sock).unwrap();
        let listener = UnixListener::bind(&client_sock).unwrap();
        let forwarder = make_forwarder(rsyslog_sock.to_str().unwrap());
        let (_, validator_rx) = watch::channel(make_validator(ValidationMode::Strict));
        let metrics = MetricsStore::new();

        let bad_msg = SyslogMessage {
            priority: Priority(Facility::Local0, Severity::Info),
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            msg_id: None,
            structured_data: "-".into(),
            msg: r#"{"other":"field"}"#.into(),
        };
        let wire = bad_msg.to_string();
        let frame = format!("{} {wire}", wire.len());

        let metrics_ref = Arc::clone(&metrics);
        let session_task = tokio::spawn({
            async move {
                let (stream, _) = listener.accept().await.unwrap();
                run_session(
                    stream,
                    make_session_cfg(FramingMode::OctetCount),
                    validator_rx,
                    forwarder,
                    metrics_ref,
                )
                .await;
            }
        });

        let mut client = UnixStream::connect(&client_sock).await.unwrap();
        client.write_all(frame.as_bytes()).await.unwrap();
        drop(client);
        session_task.await.unwrap();

        let snap = metrics.snapshot();
        assert_eq!(snap.received, 1, "counter: received");
        assert_eq!(snap.dropped, 1, "counter: dropped");
        assert_eq!(snap.forwarded, 0, "counter: forwarded");

        // The invalid message itself must not arrive, but logfenced must send
        // one rejection-report datagram to rsyslog.
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let report = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(
            report.contains("message_dropped"),
            "expected rejection report, got: {report}"
        );
        // No further datagram should arrive.
        let second =
            tokio::time::timeout(Duration::from_millis(100), receiver.recv(&mut buf)).await;
        assert!(second.is_err(), "unexpected second datagram");
    }

    #[tokio::test]
    async fn session_increments_forwarded_counter() {
        let dir = tempfile::tempdir().unwrap();
        let rsyslog_sock = dir.path().join("rsyslog.sock");
        let client_sock = dir.path().join("logfenced.sock");

        let _receiver = UnixDatagram::bind(&rsyslog_sock).unwrap(); // keep fd alive
        let listener = UnixListener::bind(&client_sock).unwrap();
        let forwarder = make_forwarder(rsyslog_sock.to_str().unwrap());
        let (_, validator_rx) = watch::channel(make_validator(ValidationMode::Off));
        let metrics = MetricsStore::new();

        let wire = sample_msg_wire();
        let frame = format!("{} {wire}", wire.len());

        let metrics_ref = Arc::clone(&metrics);
        let session_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            run_session(
                stream,
                make_session_cfg(FramingMode::OctetCount),
                validator_rx,
                forwarder,
                metrics_ref,
            )
            .await;
        });

        let mut client = UnixStream::connect(&client_sock).await.unwrap();
        client.write_all(frame.as_bytes()).await.unwrap();
        drop(client);
        session_task.await.unwrap();

        let snap = metrics.snapshot();
        assert_eq!(snap.received, 1);
        assert_eq!(snap.forwarded, 1);
        assert_eq!(snap.dropped, 0);
        assert_eq!(snap.errors, 0);
    }

    #[tokio::test]
    async fn session_uses_reloaded_validator() {
        let dir = tempfile::tempdir().unwrap();
        let rsyslog_sock = dir.path().join("rsyslog.sock");
        let client_sock = dir.path().join("logfenced.sock");

        let receiver = UnixDatagram::bind(&rsyslog_sock).unwrap();
        let listener = UnixListener::bind(&client_sock).unwrap();
        let forwarder = make_forwarder(rsyslog_sock.to_str().unwrap());
        let (validator_tx, validator_rx) = watch::channel(make_validator(ValidationMode::Off));
        let metrics = MetricsStore::new();

        let session_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            run_session(
                stream,
                make_session_cfg(FramingMode::OctetCount),
                validator_rx,
                forwarder,
                metrics,
            )
            .await;
        });

        let mut client = UnixStream::connect(&client_sock).await.unwrap();

        // Message 1: {"event":"boot"} — passes Off-mode validator.
        let msg1 = SyslogMessage {
            priority: Priority(Facility::Local0, Severity::Info),
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            msg_id: None,
            structured_data: "-".into(),
            msg: r#"{"event":"boot"}"#.into(),
        };
        let wire1 = msg1.to_string();
        let frame1 = format!("{} {wire1}", wire1.len());
        client.write_all(frame1.as_bytes()).await.unwrap();

        // Wait for message 1 to arrive at the mock rsyslog receiver.
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), wire1);

        // Reload to Strict mode requiring "action" field — {"event":"boot"} will be dropped.
        validator_tx
            .send(make_validator(ValidationMode::Strict))
            .unwrap();

        // Message 2: same payload — now rejected by the reloaded strict validator.
        client.write_all(frame1.as_bytes()).await.unwrap();
        drop(client);
        session_task.await.unwrap();

        // The rejection must produce one error-report datagram to rsyslog.
        let n = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let report = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(
            report.contains("message_dropped"),
            "expected rejection report after reload, got: {report}"
        );
        // No further datagram (the invalid message itself must not be forwarded).
        let second =
            tokio::time::timeout(Duration::from_millis(100), receiver.recv(&mut buf)).await;
        assert!(
            second.is_err(),
            "unexpected second datagram after rejection report"
        );
    }

    // ── CEE cookie tests ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn session_cee_input_required_rejects_plain_json() {
        let dir = tempfile::tempdir().unwrap();
        let rsyslog_sock = dir.path().join("rsyslog.sock");
        let client_sock = dir.path().join("logfenced.sock");

        let receiver = UnixDatagram::bind(&rsyslog_sock).unwrap();
        let listener = UnixListener::bind(&client_sock).unwrap();
        let forwarder = make_forwarder(rsyslog_sock.to_str().unwrap());
        let validator = Arc::new(
            Validator::new(ValidationMode::Off, vec![]).with_input_cee(CeeCookieMode::Always),
        );
        let (_, validator_rx) = watch::channel(validator);
        let metrics = MetricsStore::new();

        let msg = SyslogMessage {
            priority: Priority(Facility::Local0, Severity::Info),
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            msg_id: None,
            structured_data: "-".into(),
            msg: r#"{"event":"no-cookie"}"#.into(), // no @cee: prefix
        };
        let wire = msg.to_string();
        let frame = format!("{} {wire}", wire.len());

        let metrics_ref = Arc::clone(&metrics);
        let session_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            run_session(
                stream,
                make_session_cfg(FramingMode::OctetCount),
                validator_rx,
                forwarder,
                metrics_ref,
            )
            .await;
        });

        let mut client = UnixStream::connect(&client_sock).await.unwrap();
        client.write_all(frame.as_bytes()).await.unwrap();
        drop(client);
        session_task.await.unwrap();

        let snap = metrics.snapshot();
        assert_eq!(snap.received, 1);
        assert_eq!(snap.dropped, 1);
        assert_eq!(snap.forwarded, 0);

        // One rejection-report datagram must arrive at rsyslog; the original
        // message must not be forwarded.
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let report = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(
            report.contains("message_dropped"),
            "expected rejection report, got: {report}"
        );
        let second =
            tokio::time::timeout(Duration::from_millis(100), receiver.recv(&mut buf)).await;
        assert!(second.is_err(), "plain JSON should have been dropped");
    }

    #[tokio::test]
    async fn session_cee_output_always_adds_cookie() {
        let dir = tempfile::tempdir().unwrap();
        let rsyslog_sock = dir.path().join("rsyslog.sock");
        let client_sock = dir.path().join("logfenced.sock");

        let receiver = UnixDatagram::bind(&rsyslog_sock).unwrap();
        let listener = UnixListener::bind(&client_sock).unwrap();
        let forwarder = make_forwarder(rsyslog_sock.to_str().unwrap());
        let validator = Arc::new(
            Validator::new(ValidationMode::Off, vec![]).with_output_cee(CeeCookieMode::Always),
        );
        let (_, validator_rx) = watch::channel(validator);
        let metrics = MetricsStore::new();

        let msg = SyslogMessage {
            priority: Priority(Facility::Local0, Severity::Info),
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            msg_id: None,
            structured_data: "-".into(),
            msg: r#"{"event":"plain"}"#.into(),
        };
        let wire = msg.to_string();
        let frame = format!("{} {wire}", wire.len());

        let session_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            run_session(
                stream,
                make_session_cfg(FramingMode::OctetCount),
                validator_rx,
                forwarder,
                metrics,
            )
            .await;
        });

        let mut client = UnixStream::connect(&client_sock).await.unwrap();
        client.write_all(frame.as_bytes()).await.unwrap();
        drop(client);
        session_task.await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let forwarded = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(
            forwarded.contains(r#"@cee:{"event":"plain"}"#),
            "forwarded message should have @cee: prefix: {forwarded}"
        );
    }

    // ── Sender rewrite tests ──────────────────────────────────────────────────

    fn make_msg_with_sender(
        hostname: Option<&str>,
        app: Option<&str>,
        pid: Option<&str>,
    ) -> SyslogMessage {
        SyslogMessage {
            priority: Priority(Facility::Local0, Severity::Info),
            timestamp: None,
            hostname: hostname.map(str::to_owned),
            app_name: app.map(str::to_owned),
            proc_id: pid.map(str::to_owned),
            msg_id: Some("test-id".into()),
            structured_data: "-".into(),
            msg: r#"{"event":"test"}"#.into(),
        }
    }

    #[test]
    fn rewrite_sender_replaces_identity_fields() {
        let msg = make_msg_with_sender(Some("orighost"), Some("myapp"), Some("1234"));
        let rewritten = rewrite_sender(msg, "logfencedhost");

        assert_eq!(rewritten.hostname.as_deref(), Some("logfencedhost"));
        assert_eq!(rewritten.app_name.as_deref(), Some("logfenced"));
        assert!(
            rewritten.proc_id.is_some(),
            "proc_id should be set to logfenced PID"
        );
    }

    #[test]
    fn rewrite_sender_preserves_original_in_sd() {
        let msg = make_msg_with_sender(Some("orighost"), Some("myapp"), Some("1234"));
        let rewritten = rewrite_sender(msg, "logfencedhost");

        assert!(
            rewritten.structured_data.contains(r#"hostname="orighost""#),
            "SD should preserve original hostname: {}",
            rewritten.structured_data
        );
        assert!(
            rewritten.structured_data.contains(r#"app="myapp""#),
            "SD should preserve original app_name: {}",
            rewritten.structured_data
        );
        assert!(
            rewritten.structured_data.contains(r#"pid="1234""#),
            "SD should preserve original proc_id: {}",
            rewritten.structured_data
        );
        assert!(
            rewritten.structured_data.contains("[logfence-src@65944 "),
            "SD should contain logfence-src@65944 element: {}",
            rewritten.structured_data
        );
    }

    #[test]
    fn rewrite_sender_nil_fields_become_dash_in_sd() {
        let msg = make_msg_with_sender(None, None, None);
        let rewritten = rewrite_sender(msg, "logfencedhost");

        assert!(
            rewritten.structured_data.contains(r#"hostname="-""#),
            "nil hostname should become dash: {}",
            rewritten.structured_data
        );
        assert!(
            rewritten.structured_data.contains(r#"app="-""#),
            "nil app_name should become dash: {}",
            rewritten.structured_data
        );
        assert!(
            rewritten.structured_data.contains(r#"pid="-""#),
            "nil proc_id should become dash: {}",
            rewritten.structured_data
        );
    }

    #[test]
    fn rewrite_sender_appends_to_existing_sd() {
        let mut msg = make_msg_with_sender(Some("host"), Some("app"), Some("42"));
        msg.structured_data = r#"[myid@123 key="val"]"#.into();
        let rewritten = rewrite_sender(msg, "logfencedhost");

        assert!(
            rewritten
                .structured_data
                .starts_with(r#"[myid@123 key="val"]"#),
            "existing SD should be preserved: {}",
            rewritten.structured_data
        );
        assert!(
            rewritten.structured_data.contains("[logfence-src@65944 "),
            "logfence-src@65944 SD element should be appended: {}",
            rewritten.structured_data
        );
    }

    #[test]
    fn rewrite_sender_preserves_msg_id_and_payload() {
        let msg = make_msg_with_sender(Some("host"), Some("app"), None);
        let rewritten = rewrite_sender(msg, "logfencedhost");

        assert_eq!(
            rewritten.msg_id.as_deref(),
            Some("test-id"),
            "msg_id must not change"
        );
        assert_eq!(
            rewritten.msg, r#"{"event":"test"}"#,
            "msg payload must not change"
        );
    }

    #[test]
    fn rewrite_sender_escapes_special_chars_in_sd_params() {
        let msg = make_msg_with_sender(Some(r#"host"with"quotes"#), Some(r"app\back"), None);
        let rewritten = rewrite_sender(msg, "logfencedhost");

        assert!(
            rewritten
                .structured_data
                .contains(r#"hostname="host\"with\"quotes""#),
            "quotes in hostname should be escaped: {}",
            rewritten.structured_data
        );
        assert!(
            rewritten.structured_data.contains(r#"app="app\\back""#),
            "backslash in app_name should be escaped: {}",
            rewritten.structured_data
        );
    }

    #[test]
    fn session_sender_logfenced_rewrites_forwarded_message() {
        // Build a message directly and verify rewrite_sender produces the right output.
        let msg = make_msg_with_sender(Some("client-host"), Some("client-app"), Some("999"));
        let rewritten = rewrite_sender(msg, "daemon-host");

        assert_eq!(rewritten.hostname.as_deref(), Some("daemon-host"));
        assert_eq!(rewritten.app_name.as_deref(), Some("logfenced"));
        assert!(rewritten
            .structured_data
            .contains(r#"hostname="client-host""#));
        assert!(rewritten.structured_data.contains(r#"app="client-app""#));
        assert!(rewritten.structured_data.contains(r#"pid="999""#));
    }
}
