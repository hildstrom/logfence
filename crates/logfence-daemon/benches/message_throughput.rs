//! Throughput benchmarks for the logfenced message pipeline.
//!
//! Benchmark groups are named `<prefix>_<input>_<output>`, where:
//!
//! - `input` is `stream` (Unix stream socket) or `dgram` (Unix datagram socket)
//! - `output` is `stream` (Unix stream socket) or `dgram` (Unix datagram socket)
//!
//! **`no_schema_stream_dgram`** — `[validation] mode = "off"`, Unix stream
//! input, datagram forwarding to mock rsyslog.  Baseline for raw transport cost.
//!
//! **`no_schema_stream_stream`** — `[validation] mode = "off"`, Unix stream
//! input, stream forwarding to mock rsyslog.  Adds RFC 6587 framing on output.
//!
//! **`no_schema_dgram_dgram`** — `[validation] mode = "off"`, Unix datagram
//! input, datagram forwarding to mock rsyslog.
//!
//! **`no_schema_dgram_stream`** — `[validation] mode = "off"`, Unix datagram
//! input, stream forwarding to mock rsyslog.
//!
//! **`with_schema_stream_dgram`** — `[validation] mode = "strict"` with a
//! ten-field JSON Schema, Unix stream input, datagram output.  Measures the
//! combined cost of transport, JSON parsing, and schema evaluation.
//!
//! Each benchmark sends 1 000 messages per iteration.  The three load variants
//! distribute those messages across 1, 4, or 100 senders to exercise
//! single-sender throughput and concurrent fan-in at increasing scales.
//!
//! ## Measurement methodology
//!
//! Each iteration uses [`Bencher::iter_custom`] with explicit timing:
//!
//! 1. Snapshot the forwarded counter before sending.
//! 2. Start the wall-clock timer.
//! 3. Send all messages into the daemon.
//! 4. For datagram output: spin-poll until the mock rsyslog drainer has
//!    received `snapshot + TOTAL_MSGS` datagrams (counted individually).
//!    For stream output: spin-poll until the drainer has received
//!    `snapshot + TOTAL_MSGS × bytes_per_msg` bytes (measured from warmup).
//! 5. Stop the timer.
//!
//! This makes every benchmark a true end-to-end measurement: the timer stops
//! only after every forwarded message has been received by the mock rsyslog
//! socket, not merely after the last client send returns.
//!
//! All benchmarks are intentionally coarse — they catch regressions of ≥10 %
//! rather than nanosecond noise.
//!
//! Run all benchmarks:
//!   cargo bench -p logfence-daemon
//!
//! Run one group:
//!   cargo bench -p logfence-daemon -- `no_schema_stream_dgram`/
//!   cargo bench -p logfence-daemon -- `no_schema_stream_stream`/
//!   cargo bench -p logfence-daemon -- `no_schema_dgram_dgram`/
//!   cargo bench -p logfence-daemon -- `no_schema_dgram_stream`/
//!   cargo bench -p logfence-daemon -- `with_schema_stream_dgram`/
#![cfg(unix)]
#![allow(
    clippy::expect_used,
    reason = "expect is appropriate in benchmark setup"
)]

use std::{
    io,
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

// ── Drainer helpers ───────────────────────────────────────────────────────────

/// Bind a Unix datagram socket at `path` and spawn a thread that counts each
/// received datagram in `forwarded`.  Stops when `stop` is set.
fn spawn_dgram_drainer(
    path: &std::path::Path,
    forwarded: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    let sock =
        std::os::unix::net::UnixDatagram::bind(path).expect("bind mock rsyslog datagram socket");
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .expect("set socket read timeout");
    socket2::SockRef::from(&sock)
        .set_recv_buffer_size(1024 * 1024)
        .expect("set recv buffer size");
    thread::spawn(move || {
        let mut buf = vec![0u8; 65_536];
        while !stop.load(Ordering::Relaxed) {
            if sock.recv(&mut buf).is_ok() {
                forwarded.fetch_add(1, Ordering::Relaxed);
            }
        }
    })
}

/// Bind a Unix stream listener at `path` and spawn a single polling thread that
/// accepts multiple connections and reads all of them in one loop, summing
/// received bytes into `forwarded`.
///
/// A single thread with non-blocking reads avoids the thundering-herd problem
/// of spawning one thread per connection with a 50 ms read timeout: with up to
/// 256 worker connections from the daemon, per-connection threads would all
/// wake simultaneously on their timeouts, adding ~1 ms overhead per iteration.
fn spawn_stream_drainer(
    path: &std::path::Path,
    forwarded: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    use std::io::Read;
    let listener =
        std::os::unix::net::UnixListener::bind(path).expect("bind mock rsyslog stream listener");
    listener.set_nonblocking(true).expect("set nonblocking");
    thread::spawn(move || {
        let mut conns: Vec<std::os::unix::net::UnixStream> = Vec::new();
        let mut buf = vec![0u8; 65_536];
        while !stop.load(Ordering::Relaxed) {
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(true).expect("set nonblocking");
                        conns.push(stream);
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => return,
                }
            }
            let mut i = 0;
            let mut had_data = false;
            while i < conns.len() {
                match conns[i].read(&mut buf) {
                    Ok(0) => {
                        conns.swap_remove(i);
                    }
                    Ok(n) => {
                        forwarded.fetch_add(n as u64, Ordering::Relaxed);
                        had_data = true;
                        i += 1;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        i += 1;
                    }
                    Err(_) => {
                        conns.swap_remove(i);
                    }
                }
            }
            if !had_data {
                thread::sleep(Duration::from_micros(50));
            }
        }
    })
}

// ── Bench fixture ─────────────────────────────────────────────────────────────

struct BenchSetup {
    _dir: TempDir,
    pub listen_path: PathBuf,
    daemon: Child,
    stop: Arc<AtomicBool>,
    drainer: Option<thread::JoinHandle<()>>,
    /// For datagram output: count of messages received by the mock rsyslog
    /// socket.  For stream output: total bytes received.  Benchmarks snapshot
    /// this counter before sending and spin-poll until it reaches the expected
    /// target to confirm end-to-end delivery.
    pub forwarded: Arc<AtomicU64>,
    /// Bytes per forwarded message on the output side.
    ///
    /// Zero for datagram output (message count is used instead).  For stream
    /// output this is measured from the first warmup message: the benchmark
    /// function sets it after warmup so subsequent `wait_for` calls can convert
    /// a message count into an expected byte total.
    pub bytes_per_msg: u64,
}

impl BenchSetup {
    /// Stream input → datagram output, no schema.
    fn start() -> Self {
        Self::start_inner(None, false, false)
    }

    /// Stream input → stream output, no schema.
    fn start_stream_stream() -> Self {
        Self::start_inner(None, false, true)
    }

    /// Datagram input → datagram output, no schema.
    fn start_dgram() -> Self {
        Self::start_inner(None, true, false)
    }

    /// Datagram input → stream output, no schema.
    fn start_dgram_stream() -> Self {
        Self::start_inner(None, true, true)
    }

    /// Stream input → datagram output, strict schema.
    fn start_validated() -> Self {
        Self::start_inner(Some(VALIDATION_SCHEMA), false, false)
    }

    fn start_inner(schema_json: Option<&str>, dgram_input: bool, stream_output: bool) -> Self {
        let dir = tempfile::tempdir().expect("create temp dir");
        let listen_path = dir.path().join("logfenced.sock");
        let rsyslog_path = dir.path().join("rsyslog.sock");
        let config_path = dir.path().join("config.toml");

        let forwarded = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let (rsyslog_transport_cfg, drainer) = if stream_output {
            let d = spawn_stream_drainer(&rsyslog_path, Arc::clone(&forwarded), Arc::clone(&stop));
            ("transport = \"unix_stream\"", d)
        } else {
            let d = spawn_dgram_drainer(&rsyslog_path, Arc::clone(&forwarded), Arc::clone(&stop));
            ("transport = \"unix_dgram\"", d)
        };

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
             [rsyslog]\n{rsyslog_transport}\nsocket = \"{rsyslog}\"\n\
             {validation_section}",
            listen = listen_path.display(),
            listen_transport = listen_transport_line,
            rsyslog_transport = rsyslog_transport_cfg,
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

        Self {
            _dir: dir,
            listen_path,
            daemon,
            stop,
            drainer: Some(drainer),
            forwarded,
            bytes_per_msg: 0,
        }
    }

    /// Block until the forwarded counter reaches `target`.
    ///
    /// For datagram output `target` is a message count; for stream output it
    /// is a byte total.  Benchmarks compute the appropriate target before
    /// calling this method.
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

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Measure `bytes_per_msg` for a stream output setup by sending one message
/// and counting the bytes that arrive at the drainer.
///
/// Returns the number of bytes per forwarded message.  The `send` closure
/// must send exactly one message.
fn measure_bytes_per_msg(setup: &BenchSetup, send: impl FnOnce()) -> u64 {
    let pre = setup.forwarded.load(Ordering::Relaxed);
    send();
    while setup.forwarded.load(Ordering::Relaxed) == pre {
        thread::sleep(Duration::from_micros(50));
    }
    // Brief pause to let the full framed message arrive in the drainer's buffer.
    thread::sleep(Duration::from_millis(1));
    setup.forwarded.load(Ordering::Relaxed) - pre
}

// ── no_schema_stream_dgram — stream input, datagram output ────────────────────

/// One persistent stream connection → datagram output, 1 000 messages/iter.
fn bench_load_1x1000_stream_dgram(c: &mut Criterion) {
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

    let mut group = c.benchmark_group("no_schema_stream_dgram");
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

/// 4 persistent stream connections → datagram output, 250 msgs/conn/iter.
fn bench_load_4x250_stream_dgram(c: &mut Criterion) {
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

    let mut group = c.benchmark_group("no_schema_stream_dgram");
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

/// 100 persistent stream connections → datagram output, 10 msgs/conn/iter.
fn bench_load_100x10_stream_dgram(c: &mut Criterion) {
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

    let mut group = c.benchmark_group("no_schema_stream_dgram");
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

// ── no_schema_stream_stream — stream input, stream output ─────────────────────

/// One persistent stream connection → stream output, 1 000 messages/iter.
fn bench_load_1x1000_stream_stream(c: &mut Criterion) {
    const TOTAL_MSGS: u64 = 1_000;

    let mut setup = BenchSetup::start_stream_stream();
    let rt = tokio::runtime::Runtime::new().expect("build tokio runtime");
    let transport = UnixTransport::new(&setup.listen_path, 65_536);

    // Send one warmup message using the bench event string to get an accurate
    // bytes_per_msg measurement, then use that to compute wait targets.
    setup.bytes_per_msg = measure_bytes_per_msg(&setup, || {
        rt.block_on(async {
            MessageBuilder::new(Facility::Local0, Severity::Info)
                .kv("event", "bench")
                .expect("kv")
                .send(&transport)
                .await
                .expect("warmup send");
        });
    });

    let mut group = c.benchmark_group("no_schema_stream_stream");
    group.throughput(Throughput::Elements(TOTAL_MSGS));
    group.bench_function("load_1x1000", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let baseline = setup.forwarded.load(Ordering::Relaxed);
                let target = baseline + TOTAL_MSGS * setup.bytes_per_msg;
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

/// 4 persistent stream connections → stream output, 250 msgs/conn/iter.
fn bench_load_4x250_stream_stream(c: &mut Criterion) {
    const CONNS: usize = 4;
    const MSGS_PER_CONN: u64 = 250;
    const TOTAL_MSGS: u64 = CONNS as u64 * MSGS_PER_CONN;

    let mut setup = BenchSetup::start_stream_stream();
    let rt = tokio::runtime::Runtime::new().expect("build tokio runtime");
    let transports: Vec<UnixTransport> = (0..CONNS)
        .map(|_| UnixTransport::new(&setup.listen_path, 65_536))
        .collect();

    // Measure bytes_per_msg from the first connection using the bench event.
    setup.bytes_per_msg = measure_bytes_per_msg(&setup, || {
        rt.block_on(async {
            MessageBuilder::new(Facility::Local0, Severity::Info)
                .kv("event", "load")
                .expect("kv")
                .send(&transports[0])
                .await
                .expect("warmup send");
        });
    });

    // Warm up the remaining connections.
    let baseline = setup.forwarded.load(Ordering::Relaxed);
    rt.block_on(async {
        for t in transports.iter().skip(1) {
            MessageBuilder::new(Facility::Local0, Severity::Info)
                .kv("event", "load")
                .expect("kv")
                .send(t)
                .await
                .expect("warmup");
        }
    });
    setup.wait_for(baseline + (CONNS as u64 - 1) * setup.bytes_per_msg);

    let mut group = c.benchmark_group("no_schema_stream_stream");
    group.throughput(Throughput::Elements(TOTAL_MSGS));
    group.bench_function("load_4x250", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let baseline = setup.forwarded.load(Ordering::Relaxed);
                let target = baseline + TOTAL_MSGS * setup.bytes_per_msg;
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

/// 100 persistent stream connections → stream output, 10 msgs/conn/iter.
fn bench_load_100x10_stream_stream(c: &mut Criterion) {
    const CONNS: usize = 100;
    const MSGS_PER_CONN: u64 = 10;
    const TOTAL_MSGS: u64 = CONNS as u64 * MSGS_PER_CONN;

    let mut setup = BenchSetup::start_stream_stream();
    let rt = tokio::runtime::Runtime::new().expect("build tokio runtime");
    let transports: Vec<UnixTransport> = (0..CONNS)
        .map(|_| UnixTransport::new(&setup.listen_path, 65_536))
        .collect();

    setup.bytes_per_msg = measure_bytes_per_msg(&setup, || {
        rt.block_on(async {
            MessageBuilder::new(Facility::Local0, Severity::Info)
                .kv("event", "load")
                .expect("kv")
                .send(&transports[0])
                .await
                .expect("warmup send");
        });
    });

    let baseline = setup.forwarded.load(Ordering::Relaxed);
    rt.block_on(async {
        for t in transports.iter().skip(1) {
            MessageBuilder::new(Facility::Local0, Severity::Info)
                .kv("event", "load")
                .expect("kv")
                .send(t)
                .await
                .expect("warmup");
        }
    });
    setup.wait_for(baseline + (CONNS as u64 - 1) * setup.bytes_per_msg);

    let mut group = c.benchmark_group("no_schema_stream_stream");
    group.throughput(Throughput::Elements(TOTAL_MSGS));
    group.bench_function("load_100x10", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let baseline = setup.forwarded.load(Ordering::Relaxed);
                let target = baseline + TOTAL_MSGS * setup.bytes_per_msg;
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

// ── no_schema_dgram_dgram — datagram input, datagram output ───────────────────

/// One datagram sender → datagram output, 1 000 messages/iter.
fn bench_load_1x1000_dgram_dgram(c: &mut Criterion) {
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

    let mut group = c.benchmark_group("no_schema_dgram_dgram");
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

/// 4 datagram senders → datagram output, 250 msgs/sender/iter.
fn bench_load_4x250_dgram_dgram(c: &mut Criterion) {
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

    let mut group = c.benchmark_group("no_schema_dgram_dgram");
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

/// 100 datagram senders → datagram output, 10 msgs/sender/iter.
fn bench_load_100x10_dgram_dgram(c: &mut Criterion) {
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

    let mut group = c.benchmark_group("no_schema_dgram_dgram");
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

// ── no_schema_dgram_stream — datagram input, stream output ────────────────────

/// One datagram sender → stream output, 1 000 messages/iter.
fn bench_load_1x1000_dgram_stream(c: &mut Criterion) {
    const TOTAL_MSGS: u64 = 1_000;

    let mut setup = BenchSetup::start_dgram_stream();
    let rt = tokio::runtime::Runtime::new().expect("build tokio runtime");
    let transport = UnixDatagramTransport::new(&setup.listen_path, 65_536);

    setup.bytes_per_msg = measure_bytes_per_msg(&setup, || {
        rt.block_on(async {
            MessageBuilder::new(Facility::Local0, Severity::Info)
                .kv("event", "bench")
                .expect("kv")
                .send(&transport)
                .await
                .expect("warmup send");
        });
    });

    let mut group = c.benchmark_group("no_schema_dgram_stream");
    group.throughput(Throughput::Elements(TOTAL_MSGS));
    group.bench_function("load_1x1000", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let baseline = setup.forwarded.load(Ordering::Relaxed);
                let target = baseline + TOTAL_MSGS * setup.bytes_per_msg;
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

/// 4 datagram senders → stream output, 250 msgs/sender/iter.
fn bench_load_4x250_dgram_stream(c: &mut Criterion) {
    const SENDERS: usize = 4;
    const MSGS_PER_SENDER: u64 = 250;
    const TOTAL_MSGS: u64 = SENDERS as u64 * MSGS_PER_SENDER;

    let mut setup = BenchSetup::start_dgram_stream();
    let rt = tokio::runtime::Runtime::new().expect("build tokio runtime");
    let transports: Vec<UnixDatagramTransport> = (0..SENDERS)
        .map(|_| UnixDatagramTransport::new(&setup.listen_path, 65_536))
        .collect();

    setup.bytes_per_msg = measure_bytes_per_msg(&setup, || {
        rt.block_on(async {
            MessageBuilder::new(Facility::Local0, Severity::Info)
                .kv("event", "load")
                .expect("kv")
                .send(&transports[0])
                .await
                .expect("warmup send");
        });
    });

    let baseline = setup.forwarded.load(Ordering::Relaxed);
    rt.block_on(async {
        for t in transports.iter().skip(1) {
            MessageBuilder::new(Facility::Local0, Severity::Info)
                .kv("event", "load")
                .expect("kv")
                .send(t)
                .await
                .expect("warmup");
        }
    });
    setup.wait_for(baseline + (SENDERS as u64 - 1) * setup.bytes_per_msg);

    let mut group = c.benchmark_group("no_schema_dgram_stream");
    group.throughput(Throughput::Elements(TOTAL_MSGS));
    group.bench_function("load_4x250", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let baseline = setup.forwarded.load(Ordering::Relaxed);
                let target = baseline + TOTAL_MSGS * setup.bytes_per_msg;
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

/// 100 datagram senders → stream output, 10 msgs/sender/iter.
fn bench_load_100x10_dgram_stream(c: &mut Criterion) {
    const SENDERS: usize = 100;
    const MSGS_PER_SENDER: u64 = 10;
    const TOTAL_MSGS: u64 = SENDERS as u64 * MSGS_PER_SENDER;

    let mut setup = BenchSetup::start_dgram_stream();
    let rt = tokio::runtime::Runtime::new().expect("build tokio runtime");
    let transports: Vec<UnixDatagramTransport> = (0..SENDERS)
        .map(|_| UnixDatagramTransport::new(&setup.listen_path, 65_536))
        .collect();

    setup.bytes_per_msg = measure_bytes_per_msg(&setup, || {
        rt.block_on(async {
            MessageBuilder::new(Facility::Local0, Severity::Info)
                .kv("event", "load")
                .expect("kv")
                .send(&transports[0])
                .await
                .expect("warmup send");
        });
    });

    let baseline = setup.forwarded.load(Ordering::Relaxed);
    rt.block_on(async {
        for t in transports.iter().skip(1) {
            MessageBuilder::new(Facility::Local0, Severity::Info)
                .kv("event", "load")
                .expect("kv")
                .send(t)
                .await
                .expect("warmup");
        }
    });
    setup.wait_for(baseline + (SENDERS as u64 - 1) * setup.bytes_per_msg);

    let mut group = c.benchmark_group("no_schema_dgram_stream");
    group.throughput(Throughput::Elements(TOTAL_MSGS));
    group.bench_function("load_100x10", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let baseline = setup.forwarded.load(Ordering::Relaxed);
                let target = baseline + TOTAL_MSGS * setup.bytes_per_msg;
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

// ── with_schema_stream_dgram — stream input, datagram output, strict schema ───

/// One stream connection, strict validation, datagram output, 1 000 msgs/iter.
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

    let mut group = c.benchmark_group("with_schema_stream_dgram");
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

/// 4 stream connections, strict validation, datagram output, 250 msgs/conn/iter.
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

    let mut group = c.benchmark_group("with_schema_stream_dgram");
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

/// 100 stream connections, strict validation, datagram output, 10 msgs/conn/iter.
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

    let mut group = c.benchmark_group("with_schema_stream_dgram");
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
    // stream input, datagram output
    bench_load_1x1000_stream_dgram,
    bench_load_4x250_stream_dgram,
    bench_load_100x10_stream_dgram,
    // stream input, stream output
    bench_load_1x1000_stream_stream,
    bench_load_4x250_stream_stream,
    bench_load_100x10_stream_stream,
    // datagram input, datagram output
    bench_load_1x1000_dgram_dgram,
    bench_load_4x250_dgram_dgram,
    bench_load_100x10_dgram_dgram,
    // datagram input, stream output
    bench_load_1x1000_dgram_stream,
    bench_load_4x250_dgram_stream,
    bench_load_100x10_dgram_stream,
    // stream input, datagram output, strict schema
    bench_load_1x1000_validated,
    bench_load_4x250_validated,
    bench_load_100x10_validated,
);
criterion_main!(benches);
