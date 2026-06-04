<img src="docs/logo-full.svg" alt="logfence" width="480"/>

**logfence** is a validating syslog filter daemon for Linux and macOS. It sits
between your applications and [rsyslog](https://www.rsyslog.com), enforcing that
every syslog field is valid and every log message is
well-formed JSON — and optionally that it conforms to a JSON Schema — before
the message is forwarded. Invalid messages are dropped and the rejection is
reported to rsyslog. Valid messages are forwarded unchanged (or with optional
normalization). No message reaches rsyslog unless it has passed inspection.

This project is based on ideas from [MITRE's Common Event Expression (CEE)](https://cee.mitre.org)
and the [Journal, Audit, and Logging Protocol (JALoP) Reference Implementation](https://github.com/JALoP/JALoP).
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

## Features

**Validation**
- All syslog fields are validated
- Requires the MSG field to be a valid JSON object
- Optional strict JSON Schema enforcement (draft 4, 6, 7, 2019-09, and 2020-12)
- Multiple schemas with linear-scan matching (first match wins)
- Discriminator-field schema routing: O(1) map lookup by a nominated JSON field
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
  preserved in RFC 5424 STRUCTURED-DATA as `[logfence-src@65944 ...]` so no
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

## Backpressure and Reliability

logfence is designed to avoid dropping messages under load. The strategy differs
by transport type.

**Stream transports (client → logfenced and logfenced → rsyslog)**

Stream writes use `write_all`, which suspends the writing task when the
receiver's socket buffer is full. Backpressure propagates end-to-end
automatically: a slow rsyslog slows logfenced's forwarding, which eventually
slows the session tasks handling incoming client connections. No message is
dropped due to a full buffer.

**Datagram transports (client → logfenced and logfenced → rsyslog)**

Datagrams are send-and-forget from the OS's perspective; when the receiver's
socket buffer is full the kernel returns `ENOBUFS` rather than blocking. Both
`logfence-client` and the logfenced forwarder handle this with a configurable
retry schedule:

| Attempt | Delay before attempt |
|---------|----------------------|
| 1 (immediate) | — |
| 2 | 100 µs |
| 3 | 200 µs |
| 4 | 400 µs |
| … | doubles each attempt |
| 24+ | 1 s (cap) |

Errors that are not buffer-full conditions (e.g. `ENOENT`, `EPERM`) are
returned immediately without retrying.

**logfenced configuration** (`[rsyslog]` section):

```toml
# Total send attempts; 0 = unlimited (default: 4).
dgram_max_attempts = 4

# What to do when attempts are exhausted: "drop" (default) or "terminate".
# "terminate" initiates a graceful daemon shutdown.
# Ignored when dgram_max_attempts = 0.
dgram_exhausted = "drop"
```

**logfence-client** (`UnixDatagramTransport`):

```rust
let transport = UnixDatagramTransport::new(path, 65_536)
    .max_attempts(0);  // retry indefinitely
```

### Linux kernel tuning

On Linux the number of datagrams that may be queued on a Unix datagram socket is
bounded by the `net.unix.max_dgram_qlen` kernel parameter — *not* by the socket
buffer size (`SO_RCVBUF`). The default is often `10`, so only about eleven
datagrams can be pending at once no matter how large the receive buffer is.

For datagram deployments under high concurrency this queue is the limiting
factor: when many clients burst-send at the same time, the queue can fill faster
than the receiver drains it. The retry schedule above then engages, and if the
queue stays full past the attempt budget a message is dropped. Stream transports
are unaffected, because they apply end-to-end backpressure instead of queueing.

Raise the limit to widen the queue before deploying datagram transport at scale:

```bash
# Apply now
sudo sysctl net.unix.max_dgram_qlen=512

# Persist across reboots
echo 'net.unix.max_dgram_qlen=512' | sudo tee /etc/sysctl.d/10-logfence.conf
```

A value of `512` comfortably absorbs bursts from a few hundred concurrent
senders; size it to your expected peak fan-in.

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

Benchmark groups are named `<prefix>_<input>_<output>`.

**Stream input, datagram output** (`no_schema_stream_dgram` / `with_schema_stream_dgram`):

| Benchmark | No schema | With schema | Schema overhead |
|---|---|---|---|
| 1 connection | 812 Kelem/s | 401 Kelem/s | 2.0× |
| 4 connections | 958 Kelem/s | 636 Kelem/s | 1.5× |
| 100 connections | 758 Kelem/s | 542 Kelem/s | 1.4× |

Schema validation costs roughly 2× on a single connection. The overhead drops
to 1.4× at 100 connections as the Tokio scheduler overlaps validation work
across concurrent sessions.

**Stream input, stream output** (`no_schema_stream_stream`, no schema):

| Benchmark | Median thrpt |
|---|---|
| 1 connection × 1 000 msgs | 933 Kelem/s |
| 4 connections × 250 msgs | 1098 Kelem/s |
| 100 connections × 10 msgs | 889 Kelem/s |

Stream output is ~15% faster than datagram output at every connection count.
Each session task holds its own independent persistent connection, so writes
proceed in parallel with no mutex contention between sessions.

**Datagram input, datagram output** (`no_schema_dgram_dgram`, no schema):

| Benchmark | Median thrpt |
|---|---|
| 1 sender × 1 000 msgs | 375 Kelem/s |
| 4 senders × 250 msgs | 380 Kelem/s |
| 100 senders × 10 msgs | 374 Kelem/s |

**Datagram input, stream output** (`no_schema_dgram_stream`, no schema):

| Benchmark | Median thrpt |
|---|---|
| 1 sender × 1 000 msgs | 322 Kelem/s |
| 4 senders × 250 msgs | 320 Kelem/s |
| 100 senders × 10 msgs | 305 Kelem/s |

Datagram input throughput is roughly 2–2.5× lower than stream input and nearly
flat across sender counts. The receive loop requires one `try_recv_from` syscall
per datagram — that boundary is inherent to the protocol. A fixed worker pool
processes validated messages in parallel after the drain loop. The output
transport adds ~16–23% overhead on the datagram path; the receive loop remains
the bottleneck regardless.

Full benchmark details and methodology: [docs/BENCHMARK.md](docs/BENCHMARK.md)

---

## Target Platforms

- Red Hat Enterprise Linux 10
- Ubuntu 24.04 LTS
- macOS 26

---

## rsyslog Considerations

- RELP
- disk caching
- plugins like [mmhashchainsigs](https://github.com/hildstrom/mmhashchainsigs)

---

## License

See [LICENSE](LICENSE).

