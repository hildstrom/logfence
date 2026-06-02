//! End-to-end integration tests: spawn logfenced as a child process, send
//! messages via the client library, and assert the mock rsyslog listener
//! receives the correct forwarded output.
#![cfg(unix)]
#![allow(
    clippy::expect_used,
    reason = "expect is appropriate in integration test setup and assertions"
)]

use std::{
    path::PathBuf,
    process::{Child, Command},
    time::Duration,
};

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use tempfile::TempDir;
use tokio::{
    io::AsyncReadExt,
    net::{UnixDatagram, UnixListener},
};

use logfence_client::{builder::CEE_COOKIE, MessageBuilder, Transport, UnixTransport};
use logfence_proto::syslog::{Facility, Priority, Severity, SyslogMessage};

// ── Test fixture ──────────────────────────────────────────────────────────────

/// Holds all resources for one integration test: temp directory, daemon
/// process, and the mock rsyslog datagram socket.
struct Fixture {
    /// Keeps the temp directory alive for the duration of the test.
    dir: TempDir,
    listen_path: PathBuf,
    rsyslog_path: PathBuf,
    config_path: PathBuf,
    receiver: UnixDatagram,
    daemon: Child,
}

impl Fixture {
    /// Start logfenced with base `[daemon]` / `[rsyslog]` sections plus `extra`
    /// appended verbatim (use it for `[validation]`, `[logging]`, etc.).
    async fn start(extra: &str) -> Self {
        Self::start_with(extra, 256).await
    }

    /// Like `start`, but appends `daemon_extra` inside the `[daemon]` section.
    async fn start_with_daemon_extra(daemon_extra: &str, extra: &str) -> Self {
        let dir = tempfile::tempdir().expect("create temp dir");
        let listen_path = dir.path().join("logfenced.sock");
        let rsyslog_path = dir.path().join("rsyslog.sock");
        let config_path = dir.path().join("config.toml");

        let receiver =
            UnixDatagram::bind(&rsyslog_path).expect("bind mock rsyslog datagram socket");
        // A 1 MB receive buffer prevents ENOBUFS under burst forwarding. macOS
        // defaults to ~8 KB; Linux defaults are larger but an explicit buffer
        // still improves throughput on both platforms.
        socket2::SockRef::from(&receiver)
            .set_recv_buffer_size(1024 * 1024)
            .expect("set recv buffer size");

        let config = format!(
            "[daemon]\nlisten_socket = \"{listen}\"\nsocket_mode = \"0600\"\n\
             max_connections = 256\n{daemon_extra}\
             [rsyslog]\ntransport = \"unix_dgram\"\nsocket = \"{rsyslog}\"\n\n{extra}",
            listen = listen_path.display(),
            rsyslog = rsyslog_path.display(),
        );
        std::fs::write(&config_path, &config).expect("write config file");

        let daemon = Command::new(env!("CARGO_BIN_EXE_logfenced"))
            .args([
                "--config",
                config_path.to_str().expect("config path is UTF-8"),
            ])
            .env("RUST_LOG", "error")
            .spawn()
            .expect("spawn logfenced");

        let f = Self {
            dir,
            listen_path,
            rsyslog_path,
            config_path,
            receiver,
            daemon,
        };
        f.wait_ready().await;
        f
    }

    /// Like `start`, but sets `max_connections` in `[daemon]`.
    async fn start_with(extra: &str, max_connections: usize) -> Self {
        let dir = tempfile::tempdir().expect("create temp dir");
        let listen_path = dir.path().join("logfenced.sock");
        let rsyslog_path = dir.path().join("rsyslog.sock");
        let config_path = dir.path().join("config.toml");

        // Bind the mock rsyslog socket before starting the daemon so the first
        // forwarded datagram is not silently discarded by the kernel.
        let receiver =
            UnixDatagram::bind(&rsyslog_path).expect("bind mock rsyslog datagram socket");
        // A 1 MB receive buffer prevents ENOBUFS under burst forwarding. macOS
        // defaults to ~8 KB; Linux defaults are larger but an explicit buffer
        // still improves throughput on both platforms.
        socket2::SockRef::from(&receiver)
            .set_recv_buffer_size(1024 * 1024)
            .expect("set recv buffer size");

        let config = format!(
            "[daemon]\nlisten_socket = \"{listen}\"\nsocket_mode = \"0600\"\n\
             max_connections = {max_connections}\n\
             [rsyslog]\ntransport = \"unix_dgram\"\nsocket = \"{rsyslog}\"\n\n{extra}",
            listen = listen_path.display(),
            rsyslog = rsyslog_path.display(),
        );
        std::fs::write(&config_path, &config).expect("write config file");

        let daemon = Command::new(env!("CARGO_BIN_EXE_logfenced"))
            .args([
                "--config",
                config_path.to_str().expect("config path is UTF-8"),
            ])
            // Suppress daemon's own tracing output to keep test logs readable.
            .env("RUST_LOG", "error")
            .spawn()
            .expect("spawn logfenced");

        let f = Self {
            dir,
            listen_path,
            rsyslog_path,
            config_path,
            receiver,
            daemon,
        };
        f.wait_ready().await;
        f
    }

    /// Poll until the daemon's listen socket appears (up to 5 s).
    async fn wait_ready(&self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !self.listen_path.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "logfenced did not bind its listen socket within 5 s"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Brief additional pause so the accept() loop has started.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    fn send_sighup(&self) {
        Command::new("kill")
            .args(["-HUP", &self.daemon.id().to_string()])
            .status()
            .expect("send SIGHUP to daemon");
    }

    fn send_sigterm(&self) {
        Command::new("kill")
            .args(["-TERM", &self.daemon.id().to_string()])
            .status()
            .expect("send SIGTERM to daemon");
    }

    /// Try to receive one forwarded message with a 2 s timeout.
    /// Returns `None` on timeout or I/O error.
    async fn try_recv(&self) -> Option<String> {
        self.try_recv_timeout(Duration::from_secs(2)).await
    }

    /// Try to receive one forwarded message with a custom timeout.
    /// Returns `None` on timeout or I/O error.
    async fn try_recv_timeout(&self, timeout: Duration) -> Option<String> {
        let mut buf = vec![0u8; 65_536];
        tokio::time::timeout(timeout, self.receiver.recv(&mut buf))
            .await
            .ok()
            .and_then(std::result::Result::ok)
            .map(|n| String::from_utf8_lossy(&buf[..n]).into_owned())
    }

    /// Receive and assert the next datagram is a rejection report that logfenced
    /// sent in response to an invalid message.
    async fn recv_rejection(&self) -> String {
        let msg = self
            .try_recv()
            .await
            .expect("expected a rejection report at rsyslog, got timeout");
        assert!(
            msg.contains("message_dropped"),
            "expected rejection report, got: {msg}"
        );
        msg
    }

    /// Send SIGTERM and wait up to 5 s for the process to exit cleanly.
    async fn shutdown(mut self) {
        self.send_sigterm();
        for _ in 0..100 {
            match self.daemon.try_wait() {
                Ok(Some(_)) => return,
                _ => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        let _ = self.daemon.kill();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Best-effort cleanup for the case where the test panics before shutdown.
        let _ = self.daemon.kill();
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn send_event(listen_path: &PathBuf, event: &str) {
    send_event_on(listen_path, event, None).await;
}

async fn send_event_on(listen_path: &PathBuf, event: &str, transport: Option<&UnixTransport>) {
    let owned;
    let t = if let Some(t) = transport {
        t
    } else {
        owned = UnixTransport::new(listen_path, 65_536);
        &owned
    };
    MessageBuilder::new(Facility::Local0, Severity::Info)
        .app_name("itest")
        .kv("event", event)
        .expect("kv")
        .send(t)
        .await
        .expect("send message to daemon");
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// A valid JSON message is forwarded to rsyslog unchanged.
#[tokio::test]
async fn happy_path() {
    let f = Fixture::start("[validation]\nmode = \"off\"\n").await;

    send_event(&f.listen_path, "hello").await;

    let raw = f
        .try_recv()
        .await
        .expect("mock rsyslog should receive the forwarded message");

    assert!(
        raw.starts_with('<'),
        "expected RFC 5424 syslog line, got: {raw}"
    );
    assert!(
        raw.contains(r#""event":"hello""#),
        "JSON payload missing from forwarded message: {raw}"
    );

    f.shutdown().await;
}

/// In strict schema mode, messages that do not conform to any schema are
/// dropped; messages that do conform are forwarded.
#[tokio::test]
async fn schema_rejects_invalid_and_passes_valid() {
    let schema_dir = tempfile::tempdir().expect("schema temp dir");
    let schema_path = schema_dir.path().join("schema.json");
    std::fs::write(
        &schema_path,
        r#"{"type":"object","required":["event"],
            "properties":{"event":{"type":"string"}}}"#,
    )
    .expect("write schema file");

    let f = Fixture::start(&format!(
        "[validation]\nmode = \"strict\"\nschemas = [\"{}\"]",
        schema_path.display()
    ))
    .await;

    // Message missing the required "event" field → must be dropped.
    let transport = UnixTransport::new(&f.listen_path, 65_536);
    MessageBuilder::new(Facility::Local0, Severity::Info)
        .kv("other", "value")
        .expect("kv")
        .send(&transport)
        .await
        .expect("send non-conforming message");

    // The daemon drops the invalid message and sends a rejection report to rsyslog.
    f.recv_rejection().await;

    // Message with the required "event" field → must be forwarded.
    send_event(&f.listen_path, "audit").await;
    let raw = f
        .try_recv()
        .await
        .expect("conforming message should be forwarded");
    assert!(raw.contains(r#""event":"audit""#));

    f.shutdown().await;
}

/// SIGHUP causes the daemon to reload its config file and apply the updated
/// schema; no existing connections are dropped during the reload.
#[tokio::test]
async fn sighup_reloads_schema() {
    let f = Fixture::start("[validation]\nmode = \"off\"\n").await;

    // Baseline: in "off" mode a message without "event" passes validation.
    let transport = UnixTransport::new(&f.listen_path, 65_536);
    MessageBuilder::new(Facility::Local0, Severity::Info)
        .kv("other", "baseline")
        .expect("kv")
        .send(&transport)
        .await
        .expect("send baseline message");
    assert!(
        f.try_recv().await.is_some(),
        "baseline message should be forwarded in validation=off mode"
    );

    // Write a strict schema and overwrite the config file.
    let schema_path = f.dir.path().join("schema.json");
    std::fs::write(
        &schema_path,
        r#"{"type":"object","required":["event"],
            "properties":{"event":{"type":"string"}}}"#,
    )
    .expect("write updated schema");

    let new_config = format!(
        "[daemon]\nlisten_socket = \"{listen}\"\nsocket_mode = \"0600\"\n\
         [rsyslog]\ntransport = \"unix_dgram\"\nsocket = \"{rsyslog}\"\n\
         [validation]\nmode = \"strict\"\nschemas = [\"{schema}\"]\n",
        listen = f.listen_path.display(),
        rsyslog = f.rsyslog_path.display(),
        schema = schema_path.display(),
    );
    std::fs::write(&f.config_path, &new_config).expect("overwrite config file");

    // Signal the daemon to reload; give it time to apply the new schema.
    f.send_sighup();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // After reload: message without "event" must now be dropped.
    MessageBuilder::new(Facility::Local0, Severity::Info)
        .kv("other", "after-reload")
        .expect("kv")
        .send(&transport)
        .await
        .expect("send non-conforming after reload");
    // The daemon drops the invalid message and sends a rejection report to rsyslog.
    f.recv_rejection().await;

    // Message with the required "event" field must now pass.
    send_event(&f.listen_path, "post-reload").await;
    let raw = f
        .try_recv()
        .await
        .expect("conforming message should be forwarded after reload");
    assert!(raw.contains(r#""event":"post-reload""#));

    f.shutdown().await;
}

/// When `max_connections` is saturated, the overflow connection's message is
/// queued until a permit becomes available — no panic, no data loss.
#[tokio::test]
async fn max_connections_backpressure() {
    let f = Fixture::start_with("[validation]\nmode = \"off\"\n", 3).await;

    // Open 3 transports and send one message each to hold all permits.
    let t0 = UnixTransport::new(&f.listen_path, 65_536);
    let t1 = UnixTransport::new(&f.listen_path, 65_536);
    let t2 = UnixTransport::new(&f.listen_path, 65_536);

    send_event_on(&f.listen_path, "hold0", Some(&t0)).await;
    send_event_on(&f.listen_path, "hold1", Some(&t1)).await;
    send_event_on(&f.listen_path, "hold2", Some(&t2)).await;

    // Drain the 3 forwarded messages so the socket buffer stays clear.
    for _ in 0..3 {
        f.try_recv().await.expect("permit-holder message forwarded");
    }

    // 4th connection: data is buffered in the kernel write buffer but the
    // semaphore is exhausted, so the message cannot be forwarded yet.
    let t3 = UnixTransport::new(&f.listen_path, 65_536);
    send_event_on(&f.listen_path, "overflow", Some(&t3)).await;

    assert!(
        f.try_recv_timeout(Duration::from_millis(300))
            .await
            .is_none(),
        "overflow message should not be forwarded while all permits are held"
    );

    // Drop t0 — the session reads EOF and releases its permit.
    drop(t0);

    // The overflow connection can now be accepted; its message must arrive.
    let raw = f
        .try_recv()
        .await
        .expect("overflow message forwarded after permit released");
    assert!(
        raw.contains(r#""event":"overflow""#),
        "unexpected payload: {raw}"
    );

    f.shutdown().await;
}

// ── logger interoperability tests ─────────────────────────────────────────────

/// Return the path to the util-linux `logger` binary, or `None` if not found.
/// Used to skip tests at runtime on minimal Linux environments without util-linux.
#[cfg(target_os = "linux")]
fn find_logger() -> Option<std::path::PathBuf> {
    for candidate in ["/usr/bin/logger", "/bin/logger"] {
        let p = std::path::Path::new(candidate);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    None
}

/// A well-formed RFC 5424 message with a JSON body sent via `logger --socket`
/// is forwarded to rsyslog unchanged.
///
/// `logger --octet-count` uses RFC 6587 §3.4.1 framing, which matches
/// logfenced's default `framing = "octet_count"` mode.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn logger_json_message_forwarded() {
    let Some(logger) = find_logger() else {
        // util-linux not present in this environment; nothing to test.
        return;
    };

    let f = Fixture::start("[validation]\nmode = \"off\"\n").await;

    let status = Command::new(&logger)
        .args([
            "--socket",
            f.listen_path.to_str().expect("socket path is UTF-8"),
            "--rfc5424",
            "--octet-count",
            "--tag",
            "itest",
            r#"{"event":"logger_test"}"#,
        ])
        .status()
        .expect("run logger");
    assert!(status.success(), "logger exited with non-zero status");

    let raw = f
        .try_recv()
        .await
        .expect("forwarded message should arrive at mock rsyslog");
    assert!(
        raw.contains(r#""event":"logger_test""#),
        "JSON payload missing from forwarded message: {raw}"
    );

    f.shutdown().await;
}

/// A non-JSON message body sent via `logger --socket` is dropped by the daemon.
///
/// The validator requires a JSON object in the message body regardless of
/// validation mode; plain-text bodies are always rejected.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn logger_non_json_message_dropped() {
    let Some(logger) = find_logger() else {
        // util-linux not present in this environment; nothing to test.
        return;
    };

    let f = Fixture::start("[validation]\nmode = \"off\"\n").await;

    let status = Command::new(&logger)
        .args([
            "--socket",
            f.listen_path.to_str().expect("socket path is UTF-8"),
            "--rfc5424",
            "--octet-count",
            "--tag",
            "itest",
            "this is not valid json",
        ])
        .status()
        .expect("run logger");
    assert!(status.success(), "logger exited with non-zero status");

    // The daemon drops the invalid message and sends a rejection report to rsyslog.
    f.recv_rejection().await;

    f.shutdown().await;
}

// ── CEE cookie tests ──────────────────────────────────────────────────────────

/// With `input_cee = "always"`, plain-JSON messages (no `@cee:` prefix) are
/// dropped by the daemon.
#[tokio::test]
async fn cee_input_required_rejects_plain_json() {
    let f = Fixture::start("[validation]\nmode = \"off\"\ninput_cee = \"always\"\n").await;

    send_event(&f.listen_path, "no-cookie").await;

    // The daemon drops the message and sends a rejection report to rsyslog.
    f.recv_rejection().await;

    f.shutdown().await;
}

/// With `input_cee = "always"`, CEE-prefixed messages are forwarded.
#[tokio::test]
async fn cee_input_required_accepts_cee_message() {
    let f = Fixture::start("[validation]\nmode = \"off\"\ninput_cee = \"always\"\n").await;

    let t = UnixTransport::new(&f.listen_path, 65_536);
    MessageBuilder::new(Facility::Local0, Severity::Info)
        .app_name("itest")
        .cee_cookie(true)
        .kv("event", "cee-hello")
        .expect("kv")
        .send(&t)
        .await
        .expect("send CEE message");

    let raw = f
        .try_recv()
        .await
        .expect("CEE message should be forwarded when input_cee = always");
    assert!(
        raw.contains(r#""event":"cee-hello""#),
        "JSON payload missing from forwarded message: {raw}"
    );

    f.shutdown().await;
}

/// With `input_cee = "optional"`, both plain-JSON and CEE-prefixed messages
/// are forwarded.
#[tokio::test]
async fn cee_input_optional_accepts_both() {
    let f = Fixture::start("[validation]\nmode = \"off\"\ninput_cee = \"optional\"\n").await;

    // Plain JSON — must be forwarded.
    send_event(&f.listen_path, "plain").await;
    let raw = f
        .try_recv()
        .await
        .expect("plain JSON should be forwarded when input_cee = optional");
    assert!(raw.contains(r#""event":"plain""#));

    // CEE-prefixed — must also be forwarded.
    let t = UnixTransport::new(&f.listen_path, 65_536);
    MessageBuilder::new(Facility::Local0, Severity::Info)
        .app_name("itest")
        .cee_cookie(true)
        .kv("event", "with-cookie")
        .expect("kv")
        .send(&t)
        .await
        .expect("send CEE message");
    let raw = f
        .try_recv()
        .await
        .expect("CEE message should be forwarded when input_cee = optional");
    assert!(raw.contains(r#""event":"with-cookie""#));

    f.shutdown().await;
}

/// With `output_cee = "always"`, plain-JSON messages have `@cee:` added before
/// forwarding to rsyslog.
#[tokio::test]
async fn cee_output_always_adds_cookie() {
    let f = Fixture::start("[validation]\nmode = \"off\"\noutput_cee = \"always\"\n").await;

    send_event(&f.listen_path, "needs-cookie").await;

    let raw = f
        .try_recv()
        .await
        .expect("message should be forwarded with @cee: added");
    assert!(
        raw.contains(&format!("{CEE_COOKIE}{{\"event\":\"needs-cookie\"}}")),
        "forwarded message should have @cee: prefix: {raw}"
    );

    f.shutdown().await;
}

/// With `output_cee = "never"` (default) and a CEE input, the `@cee:` prefix
/// is stripped before forwarding.
#[tokio::test]
async fn cee_output_never_strips_cookie() {
    let f = Fixture::start(
        "[validation]\nmode = \"off\"\ninput_cee = \"optional\"\noutput_cee = \"never\"\n",
    )
    .await;

    let t = UnixTransport::new(&f.listen_path, 65_536);
    MessageBuilder::new(Facility::Local0, Severity::Info)
        .app_name("itest")
        .cee_cookie(true)
        .kv("event", "strip-me")
        .expect("kv")
        .send(&t)
        .await
        .expect("send CEE message");

    let raw = f.try_recv().await.expect("message should be forwarded");
    assert!(
        !raw.contains(CEE_COOKIE),
        "forwarded message should not contain @cee: when output_cee = never: {raw}"
    );
    assert!(
        raw.contains(r#""event":"strip-me""#),
        "JSON payload missing from forwarded message: {raw}"
    );

    f.shutdown().await;
}

// ── Canonical JSON tests ──────────────────────────────────────────────────────

/// Send a syslog message whose MSG field is `json_body` verbatim (bypassing
/// the `MessageBuilder` so we can supply unsorted JSON).
async fn send_raw_json(listen_path: &std::path::PathBuf, json_body: &str) {
    let msg = SyslogMessage {
        priority: Priority(Facility::Local0, Severity::Info),
        timestamp: None,
        hostname: None,
        app_name: Some("itest".into()),
        proc_id: None,
        msg_id: None,
        structured_data: "-".into(),
        msg: json_body.to_owned(),
    };
    let t = UnixTransport::new(listen_path, 65_536);
    t.send(&msg).await.expect("send raw JSON message");
}

/// With `canonical_json = true`, unsorted object keys are sorted before forwarding.
#[tokio::test]
async fn canonical_json_sorts_object_keys() {
    let f = Fixture::start("[validation]\nmode = \"off\"\ncanonical_json = true\n").await;

    send_raw_json(&f.listen_path, r#"{"z":3,"a":1,"m":2}"#).await;

    let raw = f.try_recv().await.expect("message should be forwarded");
    assert!(
        raw.contains(r#"{"a":1,"m":2,"z":3}"#),
        "expected sorted JSON keys in forwarded message: {raw}"
    );

    f.shutdown().await;
}

/// With `canonical_json = true`, nested object keys are also sorted.
#[tokio::test]
async fn canonical_json_sorts_nested_keys() {
    let f = Fixture::start("[validation]\nmode = \"off\"\ncanonical_json = true\n").await;

    send_raw_json(&f.listen_path, r#"{"b":{"y":2,"x":1},"a":0}"#).await;

    let raw = f.try_recv().await.expect("message should be forwarded");
    assert!(
        raw.contains(r#"{"a":0,"b":{"x":1,"y":2}}"#),
        "expected nested keys sorted in forwarded message: {raw}"
    );

    f.shutdown().await;
}

// ── C API integration tests ───────────────────────────────────────────────────

/// Send a message through the C API and verify the daemon forwards it to rsyslog.
///
/// `lf_send` embeds a Tokio runtime and calls `block_on` internally; it must
/// not be invoked from within an async context. The send runs on a dedicated
/// OS thread and the result is joined back before the async assertions.
#[tokio::test]
#[allow(
    unsafe_code,
    reason = "calls logfence-client-c unsafe extern C functions at the FFI boundary"
)]
async fn c_api_valid_json_forwarded() {
    use std::ffi::CString;

    use logfence_client_c::{lf_client_free, lf_client_new, lf_send, LF_OK};

    let f = Fixture::start("[validation]\nmode = \"off\"\n").await;
    let sock = f
        .listen_path
        .to_str()
        .expect("socket path is UTF-8")
        .to_owned();

    let rc = std::thread::spawn(move || {
        let path = CString::new(sock).expect("valid socket path CString");
        // SAFETY: path is a valid NUL-terminated CString.
        let client = unsafe { lf_client_new(path.as_ptr(), 65_536) };
        assert!(!client.is_null(), "lf_client_new should succeed");
        let json =
            CString::new(r#"{"event":"c-api-ok","user":"alice"}"#).expect("valid JSON CString");
        // SAFETY: client is valid; json is a valid CString; NULL attr uses defaults.
        let rc = unsafe { lf_send(client, 16, 6, std::ptr::null(), json.as_ptr()) };
        // SAFETY: client was returned by lf_client_new and has not been freed.
        unsafe { lf_client_free(client) };
        rc
    })
    .join()
    .expect("C API thread should not panic");

    assert_eq!(rc, LF_OK, "lf_send should return LF_OK (got {rc})");

    let raw = f
        .try_recv()
        .await
        .expect("daemon should forward the C API message to mock rsyslog");
    assert!(
        raw.contains(r#""event":"c-api-ok""#),
        "JSON payload missing from forwarded message: {raw}"
    );

    f.shutdown().await;
}

/// A message delivered via the C API that does not satisfy the active JSON
/// Schema must be dropped by the daemon and never reach rsyslog.
///
/// This verifies the full path: C API → logfenced validation → drop.
/// `lf_send` returns `LF_OK` (the message was accepted by the daemon socket),
/// but the daemon silently discards it because it fails the schema.
#[tokio::test]
#[allow(
    unsafe_code,
    reason = "calls logfence-client-c unsafe extern C functions at the FFI boundary"
)]
async fn c_api_schema_rejects_noncompliant_json() {
    use std::ffi::CString;

    use logfence_client_c::{lf_client_free, lf_client_new, lf_send, LF_OK};

    let schema_dir = tempfile::tempdir().expect("schema temp dir");
    let schema_path = schema_dir.path().join("schema.json");
    std::fs::write(
        &schema_path,
        r#"{"type":"object","required":["event"],
            "properties":{"event":{"type":"string"}}}"#,
    )
    .expect("write schema file");

    let f = Fixture::start(&format!(
        "[validation]\nmode = \"strict\"\nschemas = [\"{}\"]",
        schema_path.display()
    ))
    .await;

    let sock = f
        .listen_path
        .to_str()
        .expect("socket path is UTF-8")
        .to_owned();

    // Send a JSON object that is missing the required "event" field.
    let rc = std::thread::spawn(move || {
        let path = CString::new(sock).expect("valid socket path CString");
        // SAFETY: path is a valid NUL-terminated CString.
        let client = unsafe { lf_client_new(path.as_ptr(), 65_536) };
        assert!(!client.is_null(), "lf_client_new should succeed");
        let json =
            CString::new(r#"{"user":"alice","action":"login"}"#).expect("valid JSON CString");
        // SAFETY: client is valid; json is a valid CString; NULL attr uses defaults.
        let rc = unsafe { lf_send(client, 16, 6, std::ptr::null(), json.as_ptr()) };
        // SAFETY: client was returned by lf_client_new and has not been freed.
        unsafe { lf_client_free(client) };
        rc
    })
    .join()
    .expect("C API thread should not panic");

    // The message reached the daemon socket (transport succeeded).
    assert_eq!(rc, LF_OK, "lf_send should return LF_OK (got {rc})");

    // The daemon dropped it and sent a rejection report to rsyslog.
    f.recv_rejection().await;

    f.shutdown().await;
}

/// With `canonical_json = false` (default), unsorted JSON is forwarded as-is.
#[tokio::test]
async fn canonical_json_disabled_preserves_original_order() {
    let f = Fixture::start("[validation]\nmode = \"off\"\n").await;

    send_raw_json(&f.listen_path, r#"{"z":3,"a":1,"m":2}"#).await;

    let raw = f.try_recv().await.expect("message should be forwarded");
    assert!(
        raw.contains(r#"{"z":3,"a":1,"m":2}"#),
        "expected original JSON order preserved when canonical_json = false: {raw}"
    );

    f.shutdown().await;
}

// ── Concurrent connections test ────────────────────────────────────────────────

/// 100 simultaneous client connections each send one message; all 100 messages
/// must arrive at the mock rsyslog listener.
#[tokio::test]
async fn concurrent_connections() {
    const CONN_COUNT: usize = 100;

    let f = Fixture::start("[validation]\nmode = \"off\"\n").await;

    let listen_path = f.listen_path.clone();
    let handles: Vec<_> = (0..CONN_COUNT)
        .map(|i| {
            let path = listen_path.clone();
            tokio::spawn(async move {
                let t = UnixTransport::new(&path, 65_536);
                MessageBuilder::new(Facility::Local0, Severity::Info)
                    .kv("seq", i as u64)
                    .expect("kv")
                    .send(&t)
                    .await
                    .expect("concurrent send");
            })
        })
        .collect();

    // Drain the mock rsyslog socket concurrently with the senders. Running both
    // sides in parallel keeps the receive buffer clear regardless of platform
    // defaults, and mirrors how real rsyslog behaves.
    let ((), received) = tokio::join!(
        async {
            for h in handles {
                h.await.expect("send task panicked");
            }
        },
        async {
            let mut n = 0usize;
            while n < CONN_COUNT {
                if f.try_recv().await.is_none() {
                    break;
                }
                n += 1;
            }
            n
        },
    );

    assert_eq!(
        received, CONN_COUNT,
        "expected {CONN_COUNT} forwarded messages, got {received}"
    );

    f.shutdown().await;
}

// ── Sender mode tests ──────────────────────────────────────────────────────────

/// With `sender = "logfenced"`, the forwarded message uses logfenced's identity
/// and the original sender is preserved in RFC 5424 STRUCTURED-DATA.
#[tokio::test]
async fn sender_logfenced_rewrites_sender_fields() {
    let f = Fixture::start_with_daemon_extra(
        "sender = \"logfenced\"\n",
        "[validation]\nmode = \"off\"\n",
    )
    .await;

    send_event(&f.listen_path, "sender-test").await;

    let raw = f
        .try_recv()
        .await
        .expect("mock rsyslog should receive the forwarded message");

    assert!(
        raw.contains(" logfenced "),
        "forwarded message should have 'logfenced' as app_name: {raw}"
    );
    assert!(
        raw.contains("[logfence-src@65944 "),
        "forwarded message should contain logfence-src@65944 SD element: {raw}"
    );
    assert!(
        raw.contains(r#"app="itest""#),
        "original app_name 'itest' should be preserved in SD: {raw}"
    );

    f.shutdown().await;
}

/// With `sender = "original"` (default), sender fields pass through unchanged.
#[tokio::test]
async fn sender_original_preserves_sender_fields() {
    let f = Fixture::start("[validation]\nmode = \"off\"\n").await;

    send_event(&f.listen_path, "original-sender").await;

    let raw = f
        .try_recv()
        .await
        .expect("mock rsyslog should receive the forwarded message");

    assert!(
        raw.contains(" itest "),
        "original app_name 'itest' should appear in forwarded message: {raw}"
    );
    assert!(
        !raw.contains("[logfence-src@65944 "),
        "logfence-src@65944 SD element must not appear with sender = original: {raw}"
    );

    f.shutdown().await;
}

// ── Stream output tests ───────────────────────────────────────────────────────

/// When logfenced is configured with `unix_stream` rsyslog output, sending N
/// messages should result in exactly N RFC 6587 frames arriving at the mock
/// rsyslog stream listener — no drops, no duplicates.
///
/// This also implicitly verifies that stream output backpressure propagates
/// correctly: the session task's `write_all` blocks when the downstream
/// connection is slow, which in turn pauses `read_buf` from the client, keeping
/// the client's own `write_all` blocked rather than dropping messages.
#[tokio::test]
async fn stream_output_delivers_all_messages() {
    const N: u64 = 200;

    let dir = tempfile::tempdir().expect("temp dir");
    let listen_path = dir.path().join("logfenced.sock");
    let rsyslog_path = dir.path().join("rsyslog.sock");
    let config_path = dir.path().join("config.toml");

    // Mock rsyslog: accept one stream connection and count incoming bytes.
    let rsyslog_listener = UnixListener::bind(&rsyslog_path).expect("bind rsyslog stream listener");
    let bytes_received = Arc::new(AtomicU64::new(0));
    let bytes_clone = Arc::clone(&bytes_received);
    tokio::spawn(async move {
        let (mut conn, _) = rsyslog_listener
            .accept()
            .await
            .expect("accept rsyslog conn");
        let mut buf = vec![0u8; 65_536];
        loop {
            match conn.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    bytes_clone.fetch_add(n as u64, Ordering::Relaxed);
                }
            }
        }
    });

    let config = format!(
        "[daemon]\nlisten_socket = \"{listen}\"\nsocket_mode = \"0600\"\n\
         max_connections = 256\n\
         [rsyslog]\ntransport = \"unix_stream\"\nsocket = \"{rsyslog}\"\n\
         [validation]\nmode = \"off\"\n",
        listen = listen_path.display(),
        rsyslog = rsyslog_path.display(),
    );
    std::fs::write(&config_path, &config).expect("write config");

    let mut daemon = Command::new(env!("CARGO_BIN_EXE_logfenced"))
        .args(["--config", config_path.to_str().expect("path is UTF-8")])
        .env("RUST_LOG", "error")
        .spawn()
        .expect("spawn logfenced");

    // Wait for daemon to bind its listen socket.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !listen_path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "logfenced did not bind its listen socket within 5 s"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send a single warmup message and measure its RFC 6587 frame size.
    let transport = UnixTransport::new(&listen_path, 65_536);
    send_event_on(&listen_path, "warmup", Some(&transport)).await;
    let deadline2 = std::time::Instant::now() + Duration::from_secs(2);
    while bytes_received.load(Ordering::Relaxed) == 0 {
        assert!(
            std::time::Instant::now() < deadline2,
            "warmup message did not arrive at mock rsyslog"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let bytes_per_msg = bytes_received.load(Ordering::Relaxed);

    // Send N messages with the same payload so bytes_per_msg stays constant.
    let baseline = bytes_received.load(Ordering::Relaxed);
    for _ in 0..N {
        send_event_on(&listen_path, "warmup", Some(&transport)).await;
    }
    drop(transport);

    // Spin until all N messages have been received or the deadline expires.
    let target = baseline + N * bytes_per_msg;
    let deadline3 = std::time::Instant::now() + Duration::from_secs(5);
    while bytes_received.load(Ordering::Relaxed) < target {
        assert!(
            std::time::Instant::now() < deadline3,
            "only {} of {} expected bytes arrived at mock rsyslog within 5 s",
            bytes_received.load(Ordering::Relaxed),
            target,
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        bytes_received.load(Ordering::Relaxed),
        target,
        "expected exactly {target} bytes ({bytes_per_msg} warmup + {N} × {bytes_per_msg})",
    );

    // Clean shutdown.
    Command::new("kill")
        .args(["-TERM", &daemon.id().to_string()])
        .status()
        .expect("send SIGTERM");
    for _ in 0..100 {
        match daemon.try_wait() {
            Ok(Some(_)) => break,
            _ => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    let _ = daemon.kill();
}
