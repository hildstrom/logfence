# Benchmark Results

Benchmarks measure end-to-end message throughput: client encode → Unix socket
→ daemon decode → validate → forward to mock rsyslog Unix datagram socket.
Each iteration sends 1 000 messages.  Results are reported by Criterion as
elements/second (one element = one syslog message).

Run environment: Linux, release build (`cargo bench -p logfence-daemon`).

Test System: M4 Max MacBook Pro (16 cores, 128 GB RAM), Apple Container
implementation for Mac (lightweight Linux VM, 9 cores, 8 GB RAM).

## no_schema

`[validation] mode = "off"` — daemon checks that the payload is a JSON object
but performs no schema validation.  Input: Unix stream socket with RFC 6587
octet-count framing.  Message body: `{"event":"bench"}` or `{"event":"load"}`
(single field).

| Benchmark | Connections | Msgs/conn | Median thrpt | 95% CI |
|---|---|---|---|---|
| `load_1x1000` | 1 | 1 000 | 913.07 Kelem/s | 910.5 – 915.5 |
| `load_4x250` | 4 | 250 | 1 232.8 Kelem/s | 1 228.8 – 1 236.7 |
| `load_100x10` | 100 | 10 | 1 092.6 Kelem/s | 1 083.6 – 1 102.0 |

## no_schema_dgram

`[validation] mode = "off"` — same validation policy as `no_schema`.  Input:
Unix datagram socket (`listen_transport = "unix_dgram"`); clients use
`UnixDatagramTransport` with no framing.  The daemon's single receive loop
processes one datagram at a time, so the fan-in benchmarks do not benefit from
the parallel session scaling seen in the stream group.  Message body:
`{"event":"bench"}` or `{"event":"load"}`.

| Benchmark | Senders | Msgs/sender | Median thrpt | 95% CI |
|---|---|---|---|---|
| `load_1x1000` | 1 | 1 000 | 297.07 Kelem/s | 294.9 – 299.4 |
| `load_4x250` | 4 | 250 | 304.28 Kelem/s | 302.2 – 306.3 |
| `load_100x10` | 100 | 10 | 308.84 Kelem/s | 306.3 – 311.4 |

## with_schema

`[validation] mode = "strict"` with a ten-field JSON Schema
(`additionalProperties: false`).  Input: Unix stream socket.  Message body:
ten-field JSON object (`auth_method`, `duration_ms`, `event`, `region`,
`request_id`, `service`, `session_id`, `source_ip`, `success`, `user`).

| Benchmark | Connections | Msgs/conn | Median thrpt | 95% CI |
|---|---|---|---|---|
| `load_1x1000` | 1 | 1 000 | 442.46 Kelem/s | 439.6 – 445.3 |
| `load_4x250` | 4 | 250 | 702.51 Kelem/s | 700.9 – 704.1 |
| `load_100x10` | 100 | 10 | 723.61 Kelem/s | 721.7 – 725.5 |

## Schema validation overhead (stream)

| Benchmark | no_schema | with_schema | Overhead |
|---|---|---|---|
| `load_1x1000` | 913.07 Kelem/s | 442.46 Kelem/s | 2.1× |
| `load_4x250` | 1 232.8 Kelem/s | 702.51 Kelem/s | 1.8× |
| `load_100x10` | 1 092.6 Kelem/s | 723.61 Kelem/s | 1.5× |

Schema validation (JSON parse + `jsonschema` evaluation) costs roughly 2× on a
single connection.  Concurrency recovers a significant portion of that penalty:
the overhead drops to 1.8× at 4 connections and 1.5× at 100 connections, as
the Tokio scheduler overlaps validation work across concurrent sessions.

The 4-connection and 100-connection `with_schema` benchmarks converge to nearly
the same throughput (~703–724 Kelem/s), indicating that schema validation is
the bottleneck at that point rather than connection fan-in.

## Stream vs datagram input

| Benchmark | no_schema (stream) | no_schema_dgram | Ratio |
|---|---|---|---|
| `load_1x1000` | 913.07 Kelem/s | 297.07 Kelem/s | 3.1× |
| `load_4x250` | 1 232.8 Kelem/s | 304.28 Kelem/s | 4.1× |
| `load_100x10` | 1 092.6 Kelem/s | 308.84 Kelem/s | 3.5× |

The datagram path is roughly 3–4× slower than the stream path.  Two structural
differences drive this:

**Per-message syscall on receive.**  With a stream socket, a single `read()`
syscall can return tens of kilobytes covering dozens of framed messages.  The
codec decodes all of them from its buffer without touching the OS again,
amortising I/O overhead across many messages.  With datagrams, each message
requires its own `recv_from()` syscall — the datagram boundary is the syscall
boundary — so syscall overhead scales linearly with message count rather than
being amortised.

Note that the output datagram socket (daemon → rsyslog) does not face this
constraint in the stream-input benchmarks: the mock rsyslog socket has a 1 MB
receive buffer and a dedicated drainer thread, so the daemon's `send_to()` calls
return immediately without waiting for the receiver.  The output datagram is
non-blocking in practice; it is not the bottleneck.  The datagram *input* path
has no equivalent buffering benefit because the daemon cannot batch `recv_from`
calls.

**Flat fan-in.**  The stream listener spawns a separate Tokio task per
connection, so 4 or 100 sessions execute concurrently and overlap I/O and
validation work.  The datagram listener is a single receive loop that handles
one message at a time, regardless of how many senders are active.  As a result,
the datagram group's throughput is nearly flat across all three load variants
(297–309 Kelem/s) while the stream group scales from 913 to 1 233 Kelem/s.

The appropriate transport choice depends on the deployment context.  Unix stream
input delivers higher throughput for applications that maintain a persistent
connection to logfenced.  Unix datagram input is the correct choice when
logfenced is acting as a drop-in man-in-the-middle for existing syslog clients
that already send to `/run/syslog` or a similar datagram socket — the lower
throughput ceiling is generally not a concern for that workload.
