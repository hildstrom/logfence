<img src="docs/logo-full.svg" alt="logfence" width="480"/>

**logfence** is a validating syslog filter daemon for Linux and macOS. It sits
between your applications and [rsyslog](https://www.rsyslog.com), enforcing that
every syslog field is valid and every log message is
well-formed JSON — and optionally that it conforms to a JSON Schema — before
the message is forwarded. Invalid messages are dropped and the rejection is
reported to rsyslog. Valid messages are forwarded unchanged (or with optional
normalization). No message reaches rsyslog unless it has passed inspection.

This project is based on ideas from [MITRE's CEE](https://cee.mitre.org)
and the [JALoP Reference Implementation](https://github.com/JALoP/JALoP).
The goal is to combine the simplicity and performance of CEE + rsyslog with
the separation of the JALoP RI.

The scope of this project is intentionally narrow.

---

## Why logfence

Applications that log to rsyslog share the same transport as every other
process on the host. A compromised or misbehaving process can inject malformed,
malicious, or schema-violating log entries that confuse downstream consumers,
trigger parsing bugs in SIEM pipelines, or obscure audit trails. logfence
provides a narrow, auditable chokepoint: only messages that satisfy your schema
policy cross the boundary.

- **Isolation** — logfence communicates over host-local Unix domain sockets
  only. It never opens a network port.
- **Enforcement** — messages that fail JSON parsing or schema validation are
  dropped before they reach rsyslog.
- **Transparency** — valid messages are forwarded as standard RFC 5424 syslog
  frames, fully compatible with existing rsyslog configuration.
- **Safety** — implemented in Rust with Tokio; no unsafe code, no garbage
  collector pauses, minimal dependencies.

---

## Features

**Validation**
- All syslog fields are validated
- Requires the MSG field to be a valid JSON object
- Optional strict JSON Schema enforcement (draft 7 and 2019-09)
- Multiple schemas with linear-scan matching (first match wins)
- Discriminator-field routing: O(1) map lookup by a nominated JSON field
  (e.g. `"service"`), with linear-scan fallback for unrecognised values
- Three enforcement modes: `strict` (drop), `warn` (log and forward), `off`
  (JSON-only check)

**Message Transformation**
- MITRE CEE cookie (`@cee:`) support: configurable per-direction policy
  (`never` / `optional` / `always`) for both incoming and outgoing messages
- Canonical JSON output: re-serialize with all object keys sorted
  lexicographically at every nesting level before forwarding (optional;
  off by default for maximum throughput)
- Configurable sender identity: forward messages with the original sender
  fields unchanged (`original`, default) or replace them with logfenced's
  own identity (`logfenced`); original hostname, app name, and PID are
  preserved in RFC 5424 STRUCTURED-DATA as `[logfence.src ...]` so no
  audit information is lost

**Operations**
- Hot reload: send `SIGHUP` to reload config and recompile schemas without
  dropping any connections
- Metrics: atomic counters for received, forwarded, dropped, and error counts;
  query with `SIGUSR1` (logged) or via an optional Unix stream stats socket
  (enabled with `metrics.enabled = true` in config)
- Configurable maximum connections (semaphore-bounded), message size, socket
  permissions, and socket group
- Structured daemon logging via `tracing` to stderr or a file

**Transport**
- Accepts connections on a Unix stream socket with RFC 6587 octet-count or
  newline framing, or a Unix datagram socket (one datagram per message; drop-in
  for rsyslog's standard `imuxsock` datagram input)
- Forwards to rsyslog via Unix datagram socket (default) or Unix stream socket
- Socket directionality enforced at both the OS level (`SHUT_RD`/`SHUT_WR`) and
  the type level (`OwnedReadHalf`/`OwnedWriteHalf`) on every socket

---

## Architecture

```
Application
  │  logfence-client (Rust library)
  │  MessageBuilder → JSON key-value pairs → RFC 5424 frame
  │  Unix stream socket (octet-count framed)  ─── or ───  Unix datagram socket
  ▼
logfenced (daemon)
  │  Decode → Validate (JSON + Schema) → Transform → Forward
  │  (invalid messages dropped; rejection reported to rsyslog)
  │  Unix datagram or stream socket  (RFC 5424 wire format)
  ▼
rsyslog
```

logfence is composed of four crates:

| Crate | Role |
|---|---|
| `logfence-proto` | RFC 5424 types (`SyslogMessage`, `Facility`, `Severity`) and framing codecs (`OctetCountCodec`, `DelimiterCodec`) |
| `logfence-client` | `MessageBuilder` fluent API, `UnixTransport` (stream), and `UnixDatagramTransport` for applications sending structured log messages |
| `logfence-client-c` | Simple `logfence-client` C API wrapper for C applications sending structured log messages |
| `logfence-daemon` | The `logfenced` daemon: config, validation, forwarding, metrics, signal handling |

See [docs/diagrams/README.md](docs/diagrams/README.md) for architecture
diagrams covering system context, crate dependencies, daemon module
organisation, key types, message sequence, SIGHUP hot-reload, the validation
pipeline flowchart, and the concurrency model.

---

## Configuration

Copy `config/logfenced.example.toml` to `/etc/logfenced/logfenced.toml` and
adjust for your environment. The key sections are:

```toml
[daemon]
listen_socket = "/run/logfenced/logfenced.sock"
max_connections = 256

[rsyslog]
transport = "unix_dgram"
socket = "/run/syslog"

[validation]
mode = "strict"
schemas = ["/etc/logfenced/schemas/audit.schema.json"]

# Optional discriminator routing (O(1) schema selection by field value)
# discriminator = "service"
# [validation.schema_map]
# api-gateway = "/etc/logfenced/schemas/api-gateway.schema.json"
```

---

## Performance

On a Linux aarch64 VM (9 cores, 8 GB RAM) all benchmarks send 1 000 messages
per Criterion iteration and measure true end-to-end throughput: the timer stops
only after every forwarded message has been received by the mock rsyslog socket.

**Unix stream input** (`listen_transport = "unix_stream"`, persistent connections):

| Benchmark | No schema | With schema | Overhead |
|---|---|---|---|
| 1 connection | 831 Kelem/s | 398 Kelem/s | 2.1× |
| 4 connections | 957 Kelem/s | 629 Kelem/s | 1.5× |
| 100 connections | 760 Kelem/s | 539 Kelem/s | 1.4× |

Schema validation costs roughly 2× on a single connection. The overhead drops
to 1.4× at 100 connections as the Tokio scheduler overlaps validation work
across concurrent sessions.

**Unix datagram input** (`listen_transport = "unix_dgram"`, no schema):

| Benchmark | Senders | Median thrpt |
|---|---|---|
| 1 sender × 1 000 msgs | 1 | 383 Kelem/s |
| 4 senders × 250 msgs | 4 | 380 Kelem/s |
| 100 senders × 10 msgs | 100 | 377 Kelem/s |

Datagram throughput is roughly 2–2.5× lower than stream throughput and nearly
flat across sender counts. The receive loop is serialised (one `try_recv_from`
syscall per message is unavoidable), but a fixed worker pool processes
validated messages in parallel, recovering the per-message spawn overhead of
an older design. This is the right choice when logfenced acts as a drop-in
man-in-the-middle for existing syslog clients.

Full benchmark details and methodology: [docs/BENCHMARK.md](docs/BENCHMARK.md)

---

## Target Platforms

- Red Hat Enterprise Linux
- Ubuntu
- macOS

---

## rsyslog Considerations

- RELP
- disk caching
- plugins

---

## License

See [LICENSE](LICENSE).

