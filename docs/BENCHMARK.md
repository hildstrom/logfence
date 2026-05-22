# Benchmark Results

Benchmarks measure end-to-end message throughput: client encode → Unix socket
→ daemon decode → validate → forward to mock rsyslog socket →
**received by mock rsyslog drainer**.  Each iteration sends 1 000 messages.
Results are reported by Criterion as elements/second (one element = one syslog
message).

Run environment: Linux aarch64, release build (`cargo bench -p logfence-daemon`).

Test System: M4 Max MacBook Pro (16 cores, 128 GB RAM), Apple Container
implementation for Mac (lightweight Linux VM, 9 cores, 8 GB RAM).

## Measurement methodology

Each benchmark function uses Criterion's `iter_custom` for explicit timing:

1. Snapshot the forwarded counter (messages or bytes received by mock rsyslog)
   before sending.
2. Start the wall-clock timer.
3. Send all `TOTAL_MSGS` messages into the daemon.
4. For **datagram output**: spin-poll (`50 µs` interval) until the drainer's
   message count reaches `snapshot + TOTAL_MSGS`.
   For **stream output**: spin-poll until the drainer's byte total reaches
   `snapshot + TOTAL_MSGS × bytes_per_msg`, where `bytes_per_msg` is measured
   from the first warmup message (one `write_all` frame = octet-count prefix +
   syslog wire message).
5. Stop the timer.

This is a true end-to-end measurement: the timer stops only after every
forwarded message has been received by the mock rsyslog socket, not merely
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
capacity (~400 KB on Linux) can exceed one 150 KB iteration, so individual
iterations can complete before all messages are forwarded.

## no_schema_stream_dgram

Stream input (`listen_transport = "unix_stream"`), datagram output to mock
rsyslog (`[rsyslog] transport = "unix_dgram"`).  `[validation] mode = "off"`.
Message body: `{"event":"bench"}` or `{"event":"load"}`.

| Benchmark | Connections | Msgs/conn | Median thrpt | 95% CI |
|---|---|---|---|---|
| `load_1x1000` | 1 | 1 000 | 811.70 Kelem/s | 809.3 – 813.9 |
| `load_4x250` | 4 | 250 | 957.81 Kelem/s | 954.8 – 960.7 |
| `load_100x10` | 100 | 10 | 757.89 Kelem/s | 753.0 – 762.8 |

## no_schema_stream_stream

Stream input, stream output to mock rsyslog (`[rsyslog] transport =
"unix_stream"`; RFC 6587 octet-count framing).  `[validation] mode = "off"`.

| Benchmark | Connections | Msgs/conn | Median thrpt | 95% CI |
|---|---|---|---|---|
| `load_1x1000` | 1 | 1 000 | 836.36 Kelem/s | 831.8 – 841.6 |
| `load_4x250` | 4 | 250 | 512.38 Kelem/s | 511.0 – 513.6 |
| `load_100x10` | 100 | 10 | 391.68 Kelem/s | 389.8 – 393.6 |

## no_schema_dgram_dgram

Datagram input (`listen_transport = "unix_dgram"`), datagram output.
`[validation] mode = "off"`.  Message body: `{"event":"bench"}` or
`{"event":"load"}`.

| Benchmark | Senders | Msgs/sender | Median thrpt | 95% CI |
|---|---|---|---|---|
| `load_1x1000` | 1 | 1 000 | 375.04 Kelem/s | 373.8 – 376.2 |
| `load_4x250` | 4 | 250 | 379.91 Kelem/s | 378.5 – 381.2 |
| `load_100x10` | 100 | 10 | 373.99 Kelem/s | 372.9 – 375.1 |

## no_schema_dgram_stream

Datagram input, stream output.  `[validation] mode = "off"`.

| Benchmark | Senders | Msgs/sender | Median thrpt | 95% CI |
|---|---|---|---|---|
| `load_1x1000` | 1 | 1 000 | 342.27 Kelem/s | 339.9 – 344.6 |
| `load_4x250` | 4 | 250 | 348.35 Kelem/s | 346.6 – 350.1 |
| `load_100x10` | 100 | 10 | 358.67 Kelem/s | 356.8 – 360.5 |

## with_schema_stream_dgram

Stream input, datagram output, `[validation] mode = "strict"` with a ten-field
JSON Schema (`additionalProperties: false`).  Message body: ten-field JSON
object (`auth_method`, `duration_ms`, `event`, `region`, `request_id`,
`service`, `session_id`, `source_ip`, `success`, `user`).

| Benchmark | Connections | Msgs/conn | Median thrpt | 95% CI |
|---|---|---|---|---|
| `load_1x1000` | 1 | 1 000 | 401.08 Kelem/s | 399.8 – 402.3 |
| `load_4x250` | 4 | 250 | 635.93 Kelem/s | 634.7 – 637.1 |
| `load_100x10` | 100 | 10 | 542.09 Kelem/s | 538.9 – 545.1 |

## Schema validation overhead (stream input, datagram output)

| Benchmark | no_schema | with_schema | Overhead |
|---|---|---|---|
| `load_1x1000` | 811.70 Kelem/s | 401.08 Kelem/s | 2.0× |
| `load_4x250` | 957.81 Kelem/s | 635.93 Kelem/s | 1.5× |
| `load_100x10` | 757.89 Kelem/s | 542.09 Kelem/s | 1.4× |

Schema validation (JSON parse + `jsonschema` evaluation) costs roughly 2× on a
single connection.  Concurrency recovers a significant portion of that penalty:
the overhead drops to 1.5× at 4 connections and 1.4× at 100 connections, as
the Tokio scheduler overlaps validation work across concurrent sessions.

## Stream output vs datagram output (stream input)

| Benchmark | stream_dgram | stream_stream | Ratio |
|---|---|---|---|
| `load_1x1000` | 811.70 Kelem/s | 836.36 Kelem/s | 1.0× (stream_stream faster) |
| `load_4x250` | 957.81 Kelem/s | 512.38 Kelem/s | 1.9× |
| `load_100x10` | 757.89 Kelem/s | 391.68 Kelem/s | 1.9× |

On a single connection, stream output is slightly faster than datagram output
(836 vs 812 Kelem/s).  A persistent stream connection requires no per-message
socket address resolution, and `write_all` on a connected socket is marginally
cheaper than `send_to` on an unconnected one.

With 4 or 100 concurrent input connections, stream output falls to roughly half
the datagram throughput.  The cause is the `Mutex<Option<OwnedWriteHalf>>` in
the stream forwarder: all session tasks share a single write half, so output
writes are fully serialised regardless of how many input connections are
processing messages concurrently.  Datagram output has no such lock; each
`send_to()` goes directly to the kernel without mutual exclusion.

Use `unix_stream` output when the downstream rsyslog instance is configured for
`imtcp` or `imuxsock` (stream-mode) or when a single persistent connection is
preferred.  Use `unix_dgram` output (the default) for maximum throughput when
logfenced is acting as a drop-in filter in front of a standard rsyslog
datagram socket.

## Input transport comparison (datagram output, no schema)

| Benchmark | stream_dgram | dgram_dgram | Ratio |
|---|---|---|---|
| `load_1x1000` | 811.70 Kelem/s | 375.04 Kelem/s | 2.2× |
| `load_4x250` | 957.81 Kelem/s | 379.91 Kelem/s | 2.5× |
| `load_100x10` | 757.89 Kelem/s | 373.99 Kelem/s | 2.0× |

The datagram input path is roughly 2–2.5× slower than the stream input path.
Two structural differences drive this:

**Per-message syscall on receive.**  With a stream socket, a single `read()`
syscall can return tens of kilobytes covering dozens of framed messages.  The
codec decodes all of them from its buffer without touching the OS again,
amortising I/O overhead across many messages.  With datagrams, each message
requires its own `try_recv_from()` syscall — the datagram boundary is the
syscall boundary — so syscall overhead scales linearly with message count.
The tight drain loop amortises the *scheduler* cost (one `readable()` wakeup
covers the full queued burst) but cannot collapse multiple datagrams into a
single syscall without platform-specific APIs (`recvmmsg`).

**Parallel processing.**  The stream listener spawns a separate Tokio task per
connection, so 4 or 100 sessions execute concurrently and overlap I/O and
validation work.  The datagram listener's receive loop is serialised at the
syscall level: all datagrams arrive on one socket, dispatched round-robin to
a fixed pool of worker tasks.  As a result, the datagram group's throughput
is nearly flat across all three load variants (374–380 Kelem/s) while the
stream group peaks at 958 Kelem/s at 4 connections.

## Stream output overhead on datagram input

| Benchmark | dgram_dgram | dgram_stream | Overhead |
|---|---|---|---|
| `load_1x1000` | 375.04 Kelem/s | 342.27 Kelem/s | 1.10× |
| `load_4x250` | 379.91 Kelem/s | 348.35 Kelem/s | 1.09× |
| `load_100x10` | 373.99 Kelem/s | 358.67 Kelem/s | 1.04× |

On the datagram input path the output transport has minimal impact (~4–10%
overhead for stream vs datagram output).  The bottleneck remains the serialised
datagram receive loop, not the output write path.  The framing overhead of
RFC 6587 octet-count formatting and the stream write mutex are small compared
to the per-datagram `try_recv_from` syscall cost.

The slight improvement at 100 senders reflects the benchmark structure: with
100 concurrent async senders in the benchmark harness the sends are more
interleaved, keeping the daemon's receive buffer fuller and reducing idle
cycles in the drain loop.

## Transport selection summary

| Input | Output | Best use case |
|---|---|---|
| `unix_stream` | `unix_dgram` | High throughput; rsyslog using datagram socket (`imuxsock`) |
| `unix_stream` | `unix_stream` | Single persistent connection; rsyslog using stream socket |
| `unix_dgram` | `unix_dgram` | Drop-in for existing datagram syslog clients |
| `unix_dgram` | `unix_stream` | Drop-in clients with stream-mode rsyslog downstream |
