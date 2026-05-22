# Benchmark Results

Benchmarks measure end-to-end message throughput: client encode → Unix socket
→ daemon decode → validate → forward to mock rsyslog Unix datagram socket →
**received by mock rsyslog drainer**.  Each iteration sends 1 000 messages.
Results are reported by Criterion as elements/second (one element = one syslog
message).

Run environment: Linux aarch64, release build (`cargo bench -p logfence-daemon`).

Test System: M4 Max MacBook Pro (16 cores, 128 GB RAM), Apple Container
implementation for Mac (lightweight Linux VM, 9 cores, 8 GB RAM).

## Measurement methodology

Each benchmark function uses Criterion's `iter_custom` for explicit timing:

1. Snapshot the `forwarded` counter (messages received by mock rsyslog) before
   sending.
2. Start the wall-clock timer.
3. Send all `TOTAL_MSGS` messages into the daemon.
4. Spin-poll (`50 µs` interval) until `forwarded ≥ snapshot + TOTAL_MSGS`.
5. Stop the timer.

This is a true end-to-end measurement: the timer stops only after every
forwarded datagram has been received by the mock rsyslog socket, not merely
after the last client `send` returns.

**Why this matters for the datagram benchmarks.**  The daemon's listen socket
has a 1 MB kernel receive buffer.  With 1 000 messages of ~150 bytes each
(~150 KB total), all client `send_to()` calls complete immediately without
waiting for the daemon to process anything — the kernel buffer absorbs the
whole burst.  Without explicit synchronisation the benchmark would measure
kernel buffer fill rate, not daemon processing throughput.  The `iter_custom`
approach closes that gap.

The stream benchmarks benefit from the same treatment even though Unix stream
sockets provide implicit backpressure.  The combined kernel send/receive buffer
capacity (~400 KB on Linux) exceeds one 150 KB iteration, so individual
iterations can complete before all messages are forwarded; explicit
synchronisation removes that ambiguity.

## no_schema

`[validation] mode = "off"` — daemon checks that the payload is a JSON object
but performs no schema validation.  Input: Unix stream socket with RFC 6587
octet-count framing.  Message body: `{"event":"bench"}` or `{"event":"load"}`
(single field).

| Benchmark | Connections | Msgs/conn | Median thrpt | 95% CI |
|---|---|---|---|---|
| `load_1x1000` | 1 | 1 000 | 830.78 Kelem/s | 828.6 – 833.0 |
| `load_4x250` | 4 | 250 | 956.62 Kelem/s | 954.2 – 958.9 |
| `load_100x10` | 100 | 10 | 759.64 Kelem/s | 756.6 – 762.8 |

## no_schema_dgram

`[validation] mode = "off"` — same validation policy as `no_schema`.  Input:
Unix datagram socket (`listen_transport = "unix_dgram"`); clients use
`UnixDatagramTransport` with no framing.  The receive loop waits for a single
readability event and then drains all queued datagrams via `try_recv_from`
before returning to the scheduler, amortising the per-wakeup cost across
bursts.  The loop remains serialised (no parallel session tasks), so the fan-in
benchmarks do not benefit from the concurrent session scaling seen in the stream
group.  Message body: `{"event":"bench"}` or `{"event":"load"}`.

| Benchmark | Senders | Msgs/sender | Median thrpt | 95% CI |
|---|---|---|---|---|
| `load_1x1000` | 1 | 1 000 | 311.30 Kelem/s | 310.3 – 312.2 |
| `load_4x250` | 4 | 250 | 309.80 Kelem/s | 309.2 – 310.4 |
| `load_100x10` | 100 | 10 | 307.64 Kelem/s | 307.0 – 308.3 |

## with_schema

`[validation] mode = "strict"` with a ten-field JSON Schema
(`additionalProperties: false`).  Input: Unix stream socket.  Message body:
ten-field JSON object (`auth_method`, `duration_ms`, `event`, `region`,
`request_id`, `service`, `session_id`, `source_ip`, `success`, `user`).

| Benchmark | Connections | Msgs/conn | Median thrpt | 95% CI |
|---|---|---|---|---|
| `load_1x1000` | 1 | 1 000 | 398.30 Kelem/s | 397.6 – 399.0 |
| `load_4x250` | 4 | 250 | 628.50 Kelem/s | 627.4 – 629.5 |
| `load_100x10` | 100 | 10 | 539.31 Kelem/s | 536.6 – 541.8 |

## Schema validation overhead (stream)

| Benchmark | no_schema | with_schema | Overhead |
|---|---|---|---|
| `load_1x1000` | 830.78 Kelem/s | 398.30 Kelem/s | 2.1× |
| `load_4x250` | 956.62 Kelem/s | 628.50 Kelem/s | 1.5× |
| `load_100x10` | 759.64 Kelem/s | 539.31 Kelem/s | 1.4× |

Schema validation (JSON parse + `jsonschema` evaluation) costs roughly 2× on a
single connection.  Concurrency recovers a significant portion of that penalty:
the overhead drops to 1.5× at 4 connections and 1.4× at 100 connections, as
the Tokio scheduler overlaps validation work across concurrent sessions.

The `with_schema` throughput peaks at 4 connections (629 Kelem/s) and falls
back at 100 connections (539 Kelem/s).  At 100 connections with only 10
messages each, the per-connection task-spawn and scheduling overhead grows
relative to the validation work, so the scheduler benefit from parallelism is
partially offset by that overhead.

## Stream vs datagram input

| Benchmark | no_schema (stream) | no_schema_dgram | Ratio |
|---|---|---|---|
| `load_1x1000` | 830.78 Kelem/s | 311.30 Kelem/s | 2.7× |
| `load_4x250` | 956.62 Kelem/s | 309.80 Kelem/s | 3.1× |
| `load_100x10` | 759.64 Kelem/s | 307.64 Kelem/s | 2.5× |

The datagram path is roughly 2.5–3× slower than the stream path under
comparable loads.  Two structural differences drive this:

**Per-message syscall on receive.**  With a stream socket, a single `read()`
syscall can return tens of kilobytes covering dozens of framed messages.  The
codec decodes all of them from its buffer without touching the OS again,
amortising I/O overhead across many messages.  With datagrams, each message
requires its own `try_recv_from()` syscall — the datagram boundary is the
syscall boundary — so syscall overhead scales linearly with message count.  The
drain loop amortises the *scheduler* cost (one `readable()` wakeup covers the
full queued burst) but cannot collapse multiple datagrams into a single syscall.

**Flat fan-in.**  The stream listener spawns a separate Tokio task per
connection, so 4 or 100 sessions execute concurrently and overlap I/O and
validation work.  The datagram listener is a single receive loop that handles
messages serially regardless of how many senders are active.  As a result,
the datagram group's throughput is nearly flat across all three load variants
(308–311 Kelem/s) while the stream group peaks at 957 Kelem/s at 4 connections.

**The datagrams figures are close to the true processing rate.**  Because
the daemon's receive loop is the bottleneck for the datagram path (not the
kernel buffer fill rate), and the benchmark explicitly waits for forwarding to
complete, the ~310 Kelem/s figure reflects the daemon's actual serialised
processing throughput for datagram input.

**Note on the 100-connection stream case.**  Stream throughput at 100
connections (760 Kelem/s) is lower than at 4 connections (957 Kelem/s).  With
only 10 messages per connection, each connection's session task spends a large
fraction of its lifetime on task-spawn and scheduling overhead rather than on
message I/O, causing the Tokio scheduler to become the bottleneck before the
connection count scales throughput further.

The appropriate transport choice depends on the deployment context.  Unix stream
input delivers higher throughput for applications that maintain a persistent
connection to logfenced.  Unix datagram input is the correct choice when
logfenced is acting as a drop-in man-in-the-middle for existing syslog clients
that already send to `/run/syslog` or a similar datagram socket — the lower
throughput ceiling is generally not a concern for that workload.
