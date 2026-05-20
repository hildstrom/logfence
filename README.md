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
  (`--features metrics`)
- Configurable maximum connections (semaphore-bounded), message size, socket
  permissions, and socket group
- Structured daemon logging via `tracing` to stderr or a file

**Transport**
- Accepts connections on a Unix stream socket with RFC 6587 octet-count or
  newline framing
- Forwards to rsyslog via Unix datagram socket (default) or Unix stream socket

---

## Architecture

```
Application
  │  logfence-client (Rust library)
  │  MessageBuilder → JSON key-value pairs → RFC 5424 frame
  │  Unix stream socket  (octet-count framed)
  ▼
logfenced (daemon)
  │  Decode → Validate (JSON + Schema) → Transform → Forward
  │  Unix datagram or stream socket  (RFC 5424 wire format)
  ▼
rsyslog
```

logfence is composed of four crates:

| Crate | Role |
|---|---|
| `logfence-proto` | RFC 5424 types (`SyslogMessage`, `Facility`, `Severity`) and framing codecs (`OctetCountCodec`, `DelimiterCodec`) |
| `logfence-client` | `MessageBuilder` fluent API and `UnixTransport` for applications sending structured log messages |
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

On a Linux VM (9 cores, 8 GB RAM) all benchmarks send 1 000 messages per
Criterion iteration using persistent Unix stream connections.

| Benchmark | No schema | With schema | Overhead |
|---|---|---|---|
| 1 connection | 920 Kelem/s | 447 Kelem/s | 2.1× |
| 4 connections | 1 231 Kelem/s | 708 Kelem/s | 1.7× |
| 100 connections | 1 084 Kelem/s | 707 Kelem/s | 1.5× |

Schema validation (JSON parse + `jsonschema` evaluation) costs roughly 2× on a
single connection. The overhead drops to 1.5× at 100 connections as the Tokio
scheduler overlaps validation work across concurrent sessions.

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

