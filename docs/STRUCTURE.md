# Project File Structure

```
logfence/
├── Cargo.toml                        Workspace manifest: member crates, shared dependency
│                                     versions, and workspace-wide lint configuration.
├── Cargo.lock                        Locked dependency tree — committed to version control
│                                     so builds are reproducible across machines and CI.
├── deny.toml                         cargo-deny policy: allowed SPDX licenses, security
│                                     advisory checks, and crates.io-only source enforcement.
├── CLAUDE.md                         Project overview, goals, and AI-assisted development
│                                     instructions. Target OS list and high-level design.
├── LICENSE-APACHE                    Apache License, Version 2.0.
├── LICENSE-MIT                       MIT License.
├── README.md                         Project README: overview, quick start, and performance
│                                     summary table.
├── get-rust.sh                       Convenience script that installs the Rust toolchain
│                                     via rustup on a fresh system.
├── .gitignore                        Excludes the Cargo build cache (target/).
├── .claudeignore                     Excludes exported conversation transcripts (*.claude.txt)
│                                     from Claude Code's context window.
│
├── crates/                           All library and binary crates live here.
│   │
│   ├── logfence-proto/               Shared, dependency-free protocol crate. Used by both
│   │   │                             logfence-client and logfence-daemon. Has no knowledge
│   │   │                             of schemas, config, or application logic.
│   │   ├── Cargo.toml
│   │   ├── README.md                 Crate README for crates.io and GitHub: types,
│   │   │                             codecs, and usage snippet.
│   │   └── src/
│   │       ├── lib.rs                Re-exports the two modules (syslog, frame).
│   │       ├── syslog.rs             RFC 5424 types: Facility, Severity, Priority,
│   │       │                         SyslogMessage. Includes parser and Display (wire format).
│   │       └── frame.rs              RFC 6587 framing codecs: OctetCountCodec (octet-count,
│   │                                 §3.4.1) and DelimiterCodec (newline/NUL, §3.4.2).
│   │                                 Both implement tokio_util::codec::{Decoder, Encoder}.
│   │
│   ├── logfence-client/              Application-facing client library. Depends on
│   │   │                             logfence-proto. Does not depend on logfence-daemon.
│   │   ├── Cargo.toml
│   │   ├── README.md                 Crate README for crates.io and GitHub: MessageBuilder
│   │   │                             API, stream and datagram examples, retry config.
│   │   └── src/
│   │       ├── lib.rs                Re-exports the public API modules.
│   │       ├── builder.rs            MessageBuilder fluent API — assembles a SyslogMessage
│   │       │                         with typed kv() calls and validates the JSON payload.
│   │       │                         Also exports now_rfc3339() timestamp helper.
│   │       ├── transport.rs          Transport trait + UnixTransport (stream, octet-count framing)
│       │                         and UnixDatagramTransport (datagram, no framing) impls.
│   │       └── error.rs              ClientError and BuildError types.
│   │
│   ├── logfence-client-c/            C API wrapper for logfence-client. Depends on
│   │   │                             logfence-proto and logfence-client. All unsafe
│   │   │                             FFI code lives here; the Rust client stays safe.
│   │   │                             Compiles to both a cdylib (.so/.dylib) and a
│   │   │                             staticlib (.a) for linking from C programs.
│   │   ├── Cargo.toml                Package manifest with explicit lint table
│   │   │                             (does not inherit workspace lints — unsafe_code
│   │   │                             must be allowed at the FFI boundary).
│   │   ├── README.md                 Crate README for crates.io and GitHub: C API
│   │   │                             functions, build/link instructions, C example,
│   │   │                             thread safety, and error codes.
│   │   ├── include/
│   │   │   └── logfence.h            Hand-written C header. Declares LfClient (opaque
│   │   │                             handle), LfMsgAttr (optional header attributes),
│   │   │                             LF_FACILITY_*/LF_SEVERITY_* constants, error codes,
│   │   │                             and the four public functions: lf_client_new,
│   │   │                             lf_client_free, lf_send, lf_strerror.
│   │   └── src/
│   │       └── lib.rs                Four exported functions (no_mangle, unsafe extern C):
│   │                                 lf_client_new — creates opaque LfClient wrapping
│   │                                   UnixTransport + tokio Runtime.
│   │                                 lf_client_free — drops the heap-allocated handle.
│   │                                 lf_send — blocking send: validates facility/severity,
│   │                                   validates json_body as a JSON object, constructs
│   │                                   SyslogMessage directly, and calls Runtime::block_on
│   │                                   over Transport::send. Accepts an optional LfMsgAttr
│   │                                   for RFC 5424 header fields (hostname, app_name,
│   │                                   msg_id, proc_id, timestamp, cee_cookie).
│   │                                 lf_strerror — maps error codes to static strings.
│   │
│   └── logfence-daemon/              The logfenced binary. Depends on logfence-proto.
│       ├── Cargo.toml
│       ├── README.md                 Crate README for crates.io and GitHub: features,
│       │                             install, config, signals, platforms, performance.
│       ├── src/
│       │   ├── main.rs               Entry point: clap CLI, file-aware logging setup,
│       │   │                         schema loading, signal handling (SIGTERM/SIGHUP/
│       │   │                         SIGUSR1), forwarder, listener dispatch (stream or
│       │   │                         datagram based on listen_transport), metrics wiring.
│       │   ├── config.rs             Config structs and TOML loading/validation.
│       │   │                         DaemonConfig, RsyslogConfig, ValidationConfig,
│       │   │                         LoggingConfig, MetricsConfig, FramingMode,
│       │   │                         ListenTransport, ForwardTransport enums.
│       │   ├── listener.rs           UnixListener accept loop with Semaphore-bounded
│       │   │                         concurrency. Sets socket permissions from config.
│       │   │                         Drains active sessions on graceful shutdown.
│       │   ├── datagram_listener.rs  UnixDatagram receive loop. Each datagram is one
│       │   │                         complete RFC 5424 message; no framing needed.
│       │   │                         Selected at runtime via listen_transport = "unix_dgram".
│       │   ├── session.rs            Per-connection codec loop: read frames → validate →
│       │   │                         forward. Increments MetricsStore counters.
│       │   │                         Hot-reloads validator via watch::Receiver.
│       │   │                         pub(crate) report_rejection() and handle_message()
│       │   │                         shared with datagram_listener.
│       │   ├── validator.rs          JSON-object check + JSON Schema validation via
│       │   │                         jsonschema. Strict / warn / off modes.
│       │   ├── forwarder.rs          Arc-backed Forwarder forwards to rsyslog via
│       │   │                         unix_dgram or unix_stream.
│       │   └── metrics.rs            AtomicU64 counters (received/forwarded/dropped/
│       │                             errors) + Snapshot (Display + Serialize).
│       │                             serve_stats_socket: Unix socket stats endpoint,
│       │                             enabled at runtime via metrics.enabled = true.
│       ├── benches/
│       │   └── message_throughput.rs 15 Criterion benchmarks in five groups
│       │                             (no_schema_stream_dgram, no_schema_stream_stream,
│       │                             no_schema_dgram_dgram, no_schema_dgram_stream,
│       │                             with_schema_stream_dgram), each with 1, 4, and
│       │                             100 concurrent connections/senders sending
│       │                             1 000 messages per iteration. Uses a background
│       │                             drainer thread and SO_RCVBUF=1 MB on the mock
│       │                             rsyslog socket to handle high message rates on
│       │                             all platforms.
│       └── tests/
│           └── integration_test.rs  20 end-to-end tests that spawn logfenced as a
│                                     child process and communicate via real Unix sockets.
│                                     Uses env!("CARGO_BIN_EXE_logfenced") so Cargo builds
│                                     the binary automatically before tests run.
│
├── config/
│   └── logfenced.example.toml        Fully commented reference configuration. Copy to
│                                     /etc/logfenced/logfenced.toml to deploy. Documents
│                                     every supported key and its default value.
│
├── schemas/                          Bundled example JSON Schema files for use in
│                                     [validation] schemas = [...] config entries.
│
├── packaging/
│   ├── logfenced.service             systemd service unit for Linux (RHEL/Ubuntu).
│   │                                 Runs as the logfence system user with a hardened
│   │                                 filesystem sandbox (ProtectSystem, PrivateTmp, etc.).
│   ├── logfenced.sysusers            systemd-sysusers drop-in that creates the logfence
│   │                                 system user and group at package install time.
│   │                                 Install to /usr/lib/sysusers.d/logfenced.conf.
│   └── com.logfence.logfenced.plist  launchd service definition for macOS.
│                                     Runs as _logfence; install to
│                                     /Library/LaunchDaemons/.
│
├── docs/
│   ├── BENCHMARK.md                  Benchmark results: throughput figures for all six
│   │                                 Criterion benchmarks with 95% CI, validation overhead
│   │                                 comparison table, and methodology notes.
│   ├── DEVENV.md                     Developer environment reference: toolchain, MSRV,
│   │                                 lint rationale, CI jobs, and local dev commands.
│   ├── JALOP.md                      Comparison of logfence and JALoP (Journal of Audit
│   │                                 Log Protocol): scope, threat model, and how the two
│   │                                 projects relate and can be deployed together.
│   ├── STRUCTURE.md                  This file.
│   ├── logo-full.svg                 Full project logo (wordmark + icon).
│   ├── logo-square.svg               Square project logo (icon only).
│   └── diagrams/
│       ├── README.md                 Index of all diagrams with descriptions.
│       ├── puml.sh                   Shell script to render all .puml files to SVG
│       │                             via the PlantUML CLI.
│       ├── 01-system-context.puml    Component — Application → logfence-client →
│       │                             logfenced → rsyslog with socket types noted.
│       ├── 02-crate-dependencies.puml Package/Component — the four crates, their key
│       │                             contents, and dependency edges.
│       ├── 03-daemon-modules.puml    Component — all seven modules inside logfenced and
│       │                             their call relationships.
│       ├── 04-key-types.puml         Class — key structs, enums, and traits across all
│       │                             crates with relationships.
│       ├── 05-message-sequence.puml  Sequence — full message lifecycle from
│       │                             MessageBuilder.send() through validation and
│       │                             forwarding to rsyslog.
│       ├── 06-sighup-reload.puml     Sequence — SIGHUP hot-reload: config reload →
│       │                             watch channel update → active sessions pick up the
│       │                             new validator without dropping connections.
│       ├── 07-validation-pipeline.puml Activity/Flowchart — every decision in
│       │                             validate() and prepare_for_forwarding(): CEE cookie
│       │                             check, JSON parse, schema matching, canonical JSON,
│       │                             output CEE, forwarding.
│       ├── 08-concurrency-model.puml Component — Tokio tasks, Semaphore,
│       │                             CancellationToken, watch channel, Arc<Forwarder>,
│       │                             and AtomicU64 metrics.
│       └── *.svg                     Pre-rendered SVG output for each .puml file.
│
└── .github/
    └── workflows/
        ├── ci.yml                    GitHub Actions CI pipeline. Seven jobs: fmt, clippy,
        │                             test-ubuntu (24.04), test-rhel (UBI10 container),
        │                             test-macos (26), msrv (Rust 1.86), security
        │                             (cargo-deny). All actions pinned to full SHA hashes.
        └── release.yml               Release workflow triggered by v* tags. Builds and
                                      packages logfenced for x86_64/aarch64 on Linux (musl)
                                      and macOS (26), attaches tarballs to GitHub Release.
```
