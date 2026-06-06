# logfence-daemon (logfenced)

Validating syslog filter daemon that sits between applications and
[rsyslog](https://www.rsyslog.com). Only messages with valid syslog fields and
well-formed JSON payloads (optionally conforming to a JSON Schema) are
forwarded. Invalid messages are dropped and the rejection is reported to
rsyslog.

Part of the [logfence](https://github.com/hildstrom/logfence) project.

## Features

- All syslog fields validated per RFC 5424
- JSON object requirement on the MSG field
- Optional JSON Schema enforcement (drafts 4, 6, 7, 2019-09, 2020-12)
- Discriminator-field routing for O(1) schema selection
- Three enforcement modes: `strict` (drop), `warn` (log and forward), `off`
- MITRE CEE cookie (`@cee:`) policies for incoming and outgoing messages
- Canonical JSON output (sorted keys)
- Configurable sender identity forwarding
- Hot reload via `SIGHUP` (config and schemas, no connection drops)
- Metrics via `SIGUSR1` or optional Unix stream stats socket
- Unix stream and datagram transports for both input and output
- Semaphore-bounded connection limits

## Installation

```bash
cargo install logfence-daemon
```

Or build from source:

```bash
cargo build --release -p logfence-daemon
```

The binary is named `logfenced`.

## Configuration

Copy `config/logfenced.example.toml` to `/etc/logfenced/logfenced.toml` and
adjust for your environment:

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
```

See the [example config](../../config/logfenced.example.toml) for all options.

## Usage

```bash
logfenced --config /etc/logfenced/logfenced.toml
```

### Signals

| Signal | Action |
|---|---|
| `SIGTERM` / `SIGINT` | Graceful shutdown (drains active sessions) |
| `SIGHUP` | Hot reload config and recompile schemas |
| `SIGUSR1` | Log current metrics snapshot |

### systemd / launchd

Service units are provided in the `packaging/` directory:
- `packaging/logfenced.service` -- systemd unit for Linux
- `packaging/com.logfence.logfenced.plist` -- launchd plist for macOS

## Target platforms

- Red Hat Enterprise Linux 10
- Ubuntu 24.04 LTS
- macOS 26

## Performance

On a Linux aarch64 VM (9 cores, 8 GB RAM), stream input throughput reaches
812--1098 Kelem/s without schema validation and 401--636 Kelem/s with schema
validation. Datagram input throughput is 305--380 Kelem/s. Full results and
methodology: [docs/BENCHMARK.md](../../docs/BENCHMARK.md).

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or
[MIT license](../../LICENSE-MIT) at your option.
