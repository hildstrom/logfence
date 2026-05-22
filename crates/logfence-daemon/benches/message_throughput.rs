//! Throughput benchmarks for the logfenced message pipeline.
//!
//! Benchmarks are divided into three categories:
//!
//! **No schema, stream** (`no_schema` group): `[validation] mode = "off"` —
//! the daemon only checks that the payload is a JSON object.  Measures raw
//! transport and framing cost with a minimal single-field message.  Uses a
//! Unix stream socket as the daemon input (`listen_transport = "unix_stream"`).
//!
//! **No schema, datagram** (`no_schema_dgram` group): same validation policy
//! as `no_schema` but uses a Unix datagram socket as the daemon input
//! (`listen_transport = "unix_dgram"`).  Clients send via
//! [`UnixDatagramTransport`]; there is no framing overhead.  The daemon
//! receive loop drains all queued datagrams per readability event but remains
//! serialised, so concurrency effects differ from the stream case.
//!
//! **With schema** (`with_schema` group): `[validation] mode = "strict"` with
//! a ten-field JSON Schema.  Measures the combined cost of stream transport,
//! framing, JSON parsing, and `jsonschema` evaluation against a realistic
//! message shape.
//!
//! Each benchmark sends 1 000 messages per iteration.  The three load variants
//! distribute those messages across 1, 4, or 100 senders to exercise
//! single-sender throughput and concurrent fan-in at increasing scales.
//!
//! ## Measurement methodology
//!
//! Each iteration uses [`Bencher::iter_custom`] with explicit timing:
//!
//! 1. Snapshot the forwarded-message counter before sending.
//! 2. Start the wall-clock timer.
//! 3. Send all messages into the daemon.
//! 4. Spin-poll until the mock rsyslog drainer has received
//!    `snapshot + TOTAL_MSGS` messages.
//! 5. Stop the timer.
//!
//! This makes every benchmark a true end-to-end measurement: the timer stops
//! only after every forwarded datagram has been received by the mock rsyslog
//! socket, not merely after the last client send returns.
//!
//! All benchmarks are intentionally coarse — they catch regressions of ≥10 %
//! rather than nanosecond noise.
//!
//! Run all benchmarks:
//!   cargo bench -p logfence-daemon
//!
//! Run one category:
//!   cargo bench -p logfence-daemon -- `no_schema`/
//!   cargo bench -p logfence-daemon -- `no_schema_dgram`/
//!   cargo bench -p logfence-daemon -- `with_schema`/
#![cfg(unix)]
#![allow(
    clippy::expect_used,
    reason = "expect is appropriate in benchmark setup"
)]

use std::{
    path::PathBuf,
    process::{Child, Command},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use tempfile::TempDir;

use logfence_client::{MessageBuilder, UnixDatagramTransport, UnixTransport};
use logfence_proto::syslog::{Facility, Severity};

// ── Validation schema and message ─────────────────────────────────────────────

/// JSON Schema used by every `with_schema` benchmark.
///
/// Requires exactly the ten fields produced by [`validated_message_builder`],
/// each with its correct type. `additionalProperties: false` ensures the
/// schema is strict — no extra keys are permitted.
///
/// The resulting validated JSON message body is:
/// `{"auth_method":"password","duration_ms":42,"event":"user_login",
///   "region":"us-east-1","request_id":"req-00000001","service":"api-gateway",
///   "session_id":"s-abc123def456","source_ip":"10.0.0.1","success":true,
///   "user":"alice"}`
const VALIDATION_SCHEMA: &str = r#"{
    "type": "object",
    "required": [
        "auth_method", "duration_ms", "event",   "region",     "request_id",
        "service",     "session_id",  "source_ip","success",    "user"
    ],
    "properties": {
        "auth_method": { "type": "string"  },
        "duration_ms": { "type": "integer" },
        "event":       { "type": "string"  },
        "region":      { "type": "string"  },
        "request_id":  { "type": "string"  },
        "service":     { "type": "string"  },
        "session_id":  { "type": "string"  },
        "source_ip":   { "type": "string"  },
        "success":     { "type": "boolean" },
        "user":        { "type": "string"  }
    },
    "additionalProperties": false
}"#;

/// Returns a fresh [`MessageBuilder`] pre-loaded with ten key-value pairs that
/// satisfy [`VALIDATION_SCHEMA`].
///
/// Keys are listed in the alphabetical order that `BTreeMap` serialises them,
/// so the resulting JSON body is deterministic across all calls.
fn validated_message_builder() -> MessageBuilder {
    MessageBuilder::new(Facility::Local0, Severity::Info)
        .kv("auth_method", "password")
        .expect("kv")
        .kv("duration_ms", 42_u64)
        .expect("kv")
        .kv("event", "user_login")
        .expect("kv")
        .kv("region", "us-east-1")
        .expect("kv")
        .kv("request_id", "req-00000001")
        .expect("kv")
        .kv("service", "api-gateway")
        .expect("kv")
        .kv("session_id", "s-abc123def456")
        .expect("kv")
        .kv("source_ip", "10.0.0.1")
        .expect("kv")
        .kv("success", true)
        .expect("kv")
        .kv("user", "alice")
        .expect("kv")
}

// ── Bench fixture ─────────────────────────────────────────────────────────────

struct BenchSetup {
    _dir: TempDir,
    pub listen_path: PathBuf,
    daemon: Child,
    stop: Arc<AtomicBool>,
    drainer: Option<thread::JoinHandle<()>>,
    /// Running count of messages received by the mock rsyslog socket.
    ///
    /// Incremented by the drainer thread on every successful `recv`.  Benchmarks
    /// snapshot this counter before sending, then spin-poll until it reaches
    /// `snapshot + TOTAL_MSGS` to confirm end-to-end delivery.
    pub forwarded: Arc<AtomicU64>,
}

impl BenchSetup {
    /// Start logfenced with `[validation] mode = "off"`, Unix stream input.
    fn start() -> Self {
        Self::start_inner(None, false)
    }

    /// Start logfenced with `[validation] mode = "off"`, Unix datagram input.
    fn start_dgram() -> Self {
        Self::start_inner(None, true)
    }

    /// Start logfenced with `[validation] mode = "strict"` and
    /// [`VALIDATION_SCHEMA`] compiled in, Unix stream input.
    fn start_validated() -> Self {
        Self::start_inner(Some(VALIDATION_SCHEMA), false)
    }

    /// Shared startup logic.
    ///
    /// `schema_json` — when `Some`, writes the schema to `schema.json` and
    /// enables strict validation.
    /// `dgram_input` — when `true`, configures `listen_transport = "unix_dgram"`.
    fn start_inner(schema_json: Option<&str>, dgram_input: bool) -> Self {
        let dir = tempfile::tempdir().expect("create temp dir");
        let listen_path = dir.path().join("logfenced.sock");
        let rsyslog_path = dir.path().join("rsyslog.sock");
        let config_path = dir.path().join("config.toml");

        // Bind mock rsyslog socket with std (sync) so the drainer thread can use it.
        let rsyslog_sock = std::os::unix::net::UnixDatagram::bind(&rsyslog_path)
            .expect("bind mock rsyslog socket");
        rsyslog_sock
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("set socket read timeout");
        // A 1 MB receive buffer prevents overflow between drainer thread iterations
        // under high message rates. macOS defaults to ~8 KB; Linux defaults are
        // larger but an explicit buffer improves throughput on both platforms.
        socket2::SockRef::from(&rsyslog_sock)
            .set_recv_buffer_size(1024 * 1024)
            .expect("set recv buffer size");

        let validation_section = match schema_json {
            Some(schema) => {
                let schema_path = dir.path().join("schema.json");
                std::fs::write(&schema_path, schema).expect("write schema file");
                format!(
                    "[validation]\nmode = \"strict\"\nschemas = [\"{}\"]\n",
                    schema_path.display()
                )
            }
            None => "[validation]\nmode = \"off\"\n".to_owned(),
        };

        let listen_transport_line = if dgram_input {
            "listen_transport = \"unix_dgram\"\n"
        } else {
            ""
        };

        let config = format!(
            "[daemon]\nlisten_socket = \"{listen}\"\nsocket_mode = \"0600\"\n\
             {listen_transport}\
             [rsyslog]\ntransport = \"unix_dgram\"\nsocket = \"{rsyslog}\"\n\
             {validation_section}",
            listen = listen_path.display(),
            listen_transport = listen_transport_line,
            rsyslog = rsyslog_path.display(),
        );
        std::fs::write(&config_path, &config).expect("write config");

        let daemon = Command::new(env!("CARGO_BIN_EXE_logfenced"))
            .args(["--config", config_path.to_str().expect("UTF-8 path")])
            .env("RUST_LOG", "error")
            .spawn()
            .expect("spawn logfenced");

        // Poll until the listen socket appears (up to 5 s).
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !listen_path.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "logfenced did not bind its listen socket within 5 s"
            );
            thread::sleep(Duration::from_millis(20));
        }
        thread::sleep(Duration::from_millis(50));

        // Background thread drains forwarded datagrams and counts them.
        // The forwarded count lets benchmark iterations wait for true end-to-end
        // delivery rather than stopping as soon as the last client send returns.
        let forwarded = Arc::new(AtomicU64::new(0));
        let forwarded_clone = Arc::clone(&forwarded);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);
        let drainer = thread::spawn(move || {
            let mut buf = vec![0u8; 65_536];
            while !stop_clone.load(Ordering::Relaxed) {
                // Timeout (50 ms) or error: re-check stop flag and continue.
                if rsyslog_sock.recv(&mut buf).is_ok() {
                    forwarded_clone.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        Self {
            _dir: dir,
            listen_path,
            daemon,
            stop,
            drainer: Some(drainer),
            forwarded,
        }
    }

    /// Block until the forwarded counter reaches `target`.
    ///
    /// Used by benchmark iterations to confirm that every message sent during
    /// the iteration has propagated all the way through the daemon and arrived
    /// at the mock rsyslog socket before the timer is stopped.
    fn wait_for(&self, target: u64) {
        while self.forwarded.load(Ordering::Relaxed) < target {
            thread::sleep(Duration::from_micros(50));
        }
    }
}

impl Drop for BenchSetup {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.drainer.take() {
            let _ = h.join();
        }
        let _ = self.daemon.kill();
    }
}

// ── No-schema stream benchmarks ───────────────────────────────────────────────

/// One persistent stream connection sending 1 000 messages per iteration.
///
/// Measures the end-to-end cost of encoding syslog frames and writing them
/// through the Unix stream socket into the daemon. Validation is off;
/// message body is `{"event":"bench"}`.
fn bench_load_1x1000(c: &mut Criterion) {
    const TOTAL_MSGS: u64 = 1_000;

    let setup = BenchSetup::start();
    let rt = tokio::runtime::Runtime::new().expect("build tokio runtime");
    let transport = UnixTransport::new(&setup.listen_path, 65_536);

    let baseline = setup.forwarded.load(Ordering::Relaxed);
    rt.block_on(async {
        MessageBuilder::new(Facility::Local0, Severity::Info)
            .kv("event", "warmup")
            .expect("kv")
            .send(&transport)
            .await
            .expect("warmup send");
    });
    setup.wait_for(baseline + 1);

    let mut group = c.benchmark_group("no_schema");
    group.throughput(Throughput::Elements(TOTAL_MSGS));

    group.bench_function("load_1x1000", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let baseline = setup.forwarded.load(Ordering::Relaxed);
                let target = baseline + TOTAL_MSGS;
                let start = Instant::now();
                rt.block_on(async {
                    for _ in 0..TOTAL_MSGS {
                        MessageBuilder::new(Facility::Local0, Severity::Info)
                            .kv("event", "bench")
                            .expect("kv")
                            .send(&transport)
                            .await
                            .expect("bench send");
                    }
                });
                setup.wait_for(target);
                total += start.elapsed();
            }
            total
        });
    });

    group.finish();
}

/// 4 persistent stream connections round-robined across 1 000 messages per
/// iteration (250 messages per connection).
///
/// Exercises the daemon under light concurrent fan-in: each of the 4 open
/// Unix stream connections contributes 250 messages per benchmark iteration,
/// interleaved to keep all sessions active throughout the measurement.
/// Validation is off; message body is `{"event":"load"}`.
fn bench_load_4x250(c: &mut Criterion) {
    const CONNS: usize = 4;
    const MSGS_PER_CONN: u64 = 250;
    const TOTAL_MSGS: u64 = CONNS as u64 * MSGS_PER_CONN;

    let setup = BenchSetup::start();
    let rt = tokio::runtime::Runtime::new().expect("build tokio runtime");

    let transports: Vec<UnixTransport> = (0..CONNS)
        .map(|_| UnixTransport::new(&setup.listen_path, 65_536))
        .collect();

    let baseline = setup.forwarded.load(Ordering::Relaxed);
    rt.block_on(async {
        for t in &transports {
            MessageBuilder::new(Facility::Local0, Severity::Info)
                .kv("event", "warmup")
                .expect("kv")
                .send(t)
                .await
                .expect("warmup");
        }
    });
    setup.wait_for(baseline + CONNS as u64);

    let mut group = c.benchmark_group("no_schema");
    group.throughput(Throughput::Elements(TOTAL_MSGS));

    group.bench_function("load_4x250", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let baseline = setup.forwarded.load(Ordering::Relaxed);
                let target = baseline + TOTAL_MSGS;
                let start = Instant::now();
                rt.block_on(async {
                    for _ in 0..MSGS_PER_CONN {
                        for t in &transports {
                            MessageBuilder::new(Facility::Local0, Severity::Info)
                                .kv("event", "load")
                                .expect("kv")
                                .send(t)
                                .await
                                .expect("load send");
                        }
                    }
                });
                setup.wait_for(target);
                total += start.elapsed();
            }
            total
        });
    });

    group.finish();
}

/// 100 persistent stream connections round-robined across 1 000 messages per
/// iteration (10 messages per connection).
///
/// Exercises the daemon under heavy concurrent fan-in: 100 simultaneous
/// Unix stream sessions interleaved across 10 rounds. This stresses
/// the Tokio scheduler and the semaphore-bounded accept loop.
/// Validation is off; message body is `{"event":"load"}`.
fn bench_load_100x10(c: &mut Criterion) {
    const CONNS: usize = 100;
    const MSGS_PER_CONN: u64 = 10;
    const TOTAL_MSGS: u64 = CONNS as u64 * MSGS_PER_CONN;

    let setup = BenchSetup::start();
    let rt = tokio::runtime::Runtime::new().expect("build tokio runtime");

    let transports: Vec<UnixTransport> = (0..CONNS)
        .map(|_| UnixTransport::new(&setup.listen_path, 65_536))
        .collect();

    let baseline = setup.forwarded.load(Ordering::Relaxed);
    rt.block_on(async {
        for t in &transports {
            MessageBuilder::new(Facility::Local0, Severity::Info)
                .kv("event", "warmup")
                .expect("kv")
                .send(t)
                .await
                .expect("warmup");
        }
    });
    setup.wait_for(baseline + CONNS as u64);

    let mut group = c.benchmark_group("no_schema");
    group.throughput(Throughput::Elements(TOTAL_MSGS));

    group.bench_function("load_100x10", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let baseline = setup.forwarded.load(Ordering::Relaxed);
                let target = baseline + TOTAL_MSGS;
                let start = Instant::now();
                rt.block_on(async {
                    for _ in 0..MSGS_PER_CONN {
                        for t in &transports {
                            MessageBuilder::new(Facility::Local0, Severity::Info)
                                .kv("event", "load")
                                .expect("kv")
                                .send(t)
                                .await
                                .expect("load send");
                        }
                    }
                });
                setup.wait_for(target);
                total += start.elapsed();
            }
            total
        });
    });

    group.finish();
}

// ── No-schema datagram benchmarks ─────────────────────────────────────────────
//
// These benchmarks are the datagram-input counterparts of the no_schema group.
// The daemon is configured with `listen_transport = "unix_dgram"` and clients
// use UnixDatagramTransport.  There is no framing overhead.  The daemon receive
// loop is single-threaded so messages are processed serially regardless of
// sender count.
//
// The datagram input has no stream-socket backpressure: the client's send_to()
// calls succeed immediately as long as the daemon's 1 MB kernel receive buffer
// is not full.  Without explicit synchronisation, the benchmark would measure
// the kernel buffer fill rate rather than the daemon's processing rate.  The
// iter_custom approach below closes this gap by waiting for every forwarded
// message to arrive at the mock rsyslog socket before stopping the timer.

/// One datagram sender sending 1 000 messages per iteration.
///
/// Measures the end-to-end cost of sending raw RFC 5424 datagrams through the
/// Unix datagram socket into the daemon. Validation is off;
/// message body is `{"event":"bench"}`.
fn bench_load_1x1000_dgram(c: &mut Criterion) {
    const TOTAL_MSGS: u64 = 1_000;

    let setup = BenchSetup::start_dgram();
    let rt = tokio::runtime::Runtime::new().expect("build tokio runtime");
    let transport = UnixDatagramTransport::new(&setup.listen_path, 65_536);

    let baseline = setup.forwarded.load(Ordering::Relaxed);
    rt.block_on(async {
        MessageBuilder::new(Facility::Local0, Severity::Info)
            .kv("event", "warmup")
            .expect("kv")
            .send(&transport)
            .await
            .expect("warmup send");
    });
    setup.wait_for(baseline + 1);

    let mut group = c.benchmark_group("no_schema_dgram");
    group.throughput(Throughput::Elements(TOTAL_MSGS));

    group.bench_function("load_1x1000", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let baseline = setup.forwarded.load(Ordering::Relaxed);
                let target = baseline + TOTAL_MSGS;
                let start = Instant::now();
                rt.block_on(async {
                    for _ in 0..TOTAL_MSGS {
                        MessageBuilder::new(Facility::Local0, Severity::Info)
                            .kv("event", "bench")
                            .expect("kv")
                            .send(&transport)
                            .await
                            .expect("bench send");
                    }
                });
                setup.wait_for(target);
                total += start.elapsed();
            }
            total
        });
    });

    group.finish();
}

/// 4 datagram senders interleaved across 1 000 messages per iteration
/// (250 messages per sender).
///
/// Each sender is an independent [`UnixDatagramTransport`].  The daemon
/// receive loop is single-threaded so messages are processed serially
/// regardless of sender count.
/// Validation is off; message body is `{"event":"load"}`.
fn bench_load_4x250_dgram(c: &mut Criterion) {
    const SENDERS: usize = 4;
    const MSGS_PER_SENDER: u64 = 250;
    const TOTAL_MSGS: u64 = SENDERS as u64 * MSGS_PER_SENDER;

    let setup = BenchSetup::start_dgram();
    let rt = tokio::runtime::Runtime::new().expect("build tokio runtime");

    let transports: Vec<UnixDatagramTransport> = (0..SENDERS)
        .map(|_| UnixDatagramTransport::new(&setup.listen_path, 65_536))
        .collect();

    let baseline = setup.forwarded.load(Ordering::Relaxed);
    rt.block_on(async {
        for t in &transports {
            MessageBuilder::new(Facility::Local0, Severity::Info)
                .kv("event", "warmup")
                .expect("kv")
                .send(t)
                .await
                .expect("warmup");
        }
    });
    setup.wait_for(baseline + SENDERS as u64);

    let mut group = c.benchmark_group("no_schema_dgram");
    group.throughput(Throughput::Elements(TOTAL_MSGS));

    group.bench_function("load_4x250", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let baseline = setup.forwarded.load(Ordering::Relaxed);
                let target = baseline + TOTAL_MSGS;
                let start = Instant::now();
                rt.block_on(async {
                    for _ in 0..MSGS_PER_SENDER {
                        for t in &transports {
                            MessageBuilder::new(Facility::Local0, Severity::Info)
                                .kv("event", "load")
                                .expect("kv")
                                .send(t)
                                .await
                                .expect("load send");
                        }
                    }
                });
                setup.wait_for(target);
                total += start.elapsed();
            }
            total
        });
    });

    group.finish();
}

/// 100 datagram senders interleaved across 1 000 messages per iteration
/// (10 messages per sender).
///
/// Each sender is an independent [`UnixDatagramTransport`].  The daemon
/// receive loop is single-threaded so messages are processed serially
/// regardless of sender count.
/// Validation is off; message body is `{"event":"load"}`.
fn bench_load_100x10_dgram(c: &mut Criterion) {
    const SENDERS: usize = 100;
    const MSGS_PER_SENDER: u64 = 10;
    const TOTAL_MSGS: u64 = SENDERS as u64 * MSGS_PER_SENDER;

    let setup = BenchSetup::start_dgram();
    let rt = tokio::runtime::Runtime::new().expect("build tokio runtime");

    let transports: Vec<UnixDatagramTransport> = (0..SENDERS)
        .map(|_| UnixDatagramTransport::new(&setup.listen_path, 65_536))
        .collect();

    let baseline = setup.forwarded.load(Ordering::Relaxed);
    rt.block_on(async {
        for t in &transports {
            MessageBuilder::new(Facility::Local0, Severity::Info)
                .kv("event", "warmup")
                .expect("kv")
                .send(t)
                .await
                .expect("warmup");
        }
    });
    setup.wait_for(baseline + SENDERS as u64);

    let mut group = c.benchmark_group("no_schema_dgram");
    group.throughput(Throughput::Elements(TOTAL_MSGS));

    group.bench_function("load_100x10", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let baseline = setup.forwarded.load(Ordering::Relaxed);
                let target = baseline + TOTAL_MSGS;
                let start = Instant::now();
                rt.block_on(async {
                    for _ in 0..MSGS_PER_SENDER {
                        for t in &transports {
                            MessageBuilder::new(Facility::Local0, Severity::Info)
                                .kv("event", "load")
                                .expect("kv")
                                .send(t)
                                .await
                                .expect("load send");
                        }
                    }
                });
                setup.wait_for(target);
                total += start.elapsed();
            }
            total
        });
    });

    group.finish();
}

// ── With-validation benchmarks ────────────────────────────────────────────────
//
// Each benchmark below is a direct duplicate of its no-validation counterpart
// above, differing only in:
//   - BenchSetup::start_validated() enabling strict JSON Schema validation
//   - validated_message_builder() producing a ten-field message body
//
// Compare pairs (e.g. no_schema/load_1x1000 vs with_schema/load_1x1000) to
// isolate the cost of JSON parsing and jsonschema evaluation from transport
// and framing overhead.

/// One persistent stream connection, strict validation enabled, 1 000 messages
/// per iteration.
///
/// Message body is the ten-field JSON object produced by
/// [`validated_message_builder`]. Compare with `no_schema/load_1x1000` to
/// isolate schema-validation overhead on a single connection.
fn bench_load_1x1000_validated(c: &mut Criterion) {
    const TOTAL_MSGS: u64 = 1_000;

    let setup = BenchSetup::start_validated();
    let rt = tokio::runtime::Runtime::new().expect("build tokio runtime");
    let transport = UnixTransport::new(&setup.listen_path, 65_536);

    let baseline = setup.forwarded.load(Ordering::Relaxed);
    rt.block_on(async {
        validated_message_builder()
            .send(&transport)
            .await
            .expect("warmup send");
    });
    setup.wait_for(baseline + 1);

    let mut group = c.benchmark_group("with_schema");
    group.throughput(Throughput::Elements(TOTAL_MSGS));

    group.bench_function("load_1x1000", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let baseline = setup.forwarded.load(Ordering::Relaxed);
                let target = baseline + TOTAL_MSGS;
                let start = Instant::now();
                rt.block_on(async {
                    for _ in 0..TOTAL_MSGS {
                        validated_message_builder()
                            .send(&transport)
                            .await
                            .expect("bench send");
                    }
                });
                setup.wait_for(target);
                total += start.elapsed();
            }
            total
        });
    });

    group.finish();
}

/// 4 persistent stream connections, strict validation enabled, round-robined
/// across 1 000 messages per iteration (250 per connection).
///
/// Compare with `no_schema/load_4x250` to isolate schema-validation overhead
/// under light concurrent fan-in.
fn bench_load_4x250_validated(c: &mut Criterion) {
    const CONNS: usize = 4;
    const MSGS_PER_CONN: u64 = 250;
    const TOTAL_MSGS: u64 = CONNS as u64 * MSGS_PER_CONN;

    let setup = BenchSetup::start_validated();
    let rt = tokio::runtime::Runtime::new().expect("build tokio runtime");

    let transports: Vec<UnixTransport> = (0..CONNS)
        .map(|_| UnixTransport::new(&setup.listen_path, 65_536))
        .collect();

    let baseline = setup.forwarded.load(Ordering::Relaxed);
    rt.block_on(async {
        for t in &transports {
            validated_message_builder().send(t).await.expect("warmup");
        }
    });
    setup.wait_for(baseline + CONNS as u64);

    let mut group = c.benchmark_group("with_schema");
    group.throughput(Throughput::Elements(TOTAL_MSGS));

    group.bench_function("load_4x250", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let baseline = setup.forwarded.load(Ordering::Relaxed);
                let target = baseline + TOTAL_MSGS;
                let start = Instant::now();
                rt.block_on(async {
                    for _ in 0..MSGS_PER_CONN {
                        for t in &transports {
                            validated_message_builder()
                                .send(t)
                                .await
                                .expect("load send");
                        }
                    }
                });
                setup.wait_for(target);
                total += start.elapsed();
            }
            total
        });
    });

    group.finish();
}

/// 100 persistent stream connections, strict validation enabled, round-robined
/// across 1 000 messages per iteration (10 per connection).
///
/// Compare with `no_schema/load_100x10` to isolate schema-validation overhead
/// under heavy concurrent fan-in.
fn bench_load_100x10_validated(c: &mut Criterion) {
    const CONNS: usize = 100;
    const MSGS_PER_CONN: u64 = 10;
    const TOTAL_MSGS: u64 = CONNS as u64 * MSGS_PER_CONN;

    let setup = BenchSetup::start_validated();
    let rt = tokio::runtime::Runtime::new().expect("build tokio runtime");

    let transports: Vec<UnixTransport> = (0..CONNS)
        .map(|_| UnixTransport::new(&setup.listen_path, 65_536))
        .collect();

    let baseline = setup.forwarded.load(Ordering::Relaxed);
    rt.block_on(async {
        for t in &transports {
            validated_message_builder().send(t).await.expect("warmup");
        }
    });
    setup.wait_for(baseline + CONNS as u64);

    let mut group = c.benchmark_group("with_schema");
    group.throughput(Throughput::Elements(TOTAL_MSGS));

    group.bench_function("load_100x10", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let baseline = setup.forwarded.load(Ordering::Relaxed);
                let target = baseline + TOTAL_MSGS;
                let start = Instant::now();
                rt.block_on(async {
                    for _ in 0..MSGS_PER_CONN {
                        for t in &transports {
                            validated_message_builder()
                                .send(t)
                                .await
                                .expect("load send");
                        }
                    }
                });
                setup.wait_for(target);
                total += start.elapsed();
            }
            total
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    // No-schema stream benchmarks
    bench_load_1x1000,
    bench_load_4x250,
    bench_load_100x10,
    // No-schema datagram benchmarks
    bench_load_1x1000_dgram,
    bench_load_4x250_dgram,
    bench_load_100x10_dgram,
    // With-schema stream benchmarks
    bench_load_1x1000_validated,
    bench_load_4x250_validated,
    bench_load_100x10_validated,
);
criterion_main!(benches);
