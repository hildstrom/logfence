# Benchmark Results

Benchmarks measure end-to-end message throughput: client encode → Unix stream
socket → daemon decode → validate → forward to mock rsyslog Unix datagram
socket.  Each iteration sends 1 000 messages.  Results are reported by
Criterion as elements/second (one element = one syslog message).

Run environment: Linux, release build (`cargo bench -p logfence-daemon`).

Test System: M4 Max MacBook Pro (16 cores, 128 GB RAM), Apple Container implementation for Mac (lightweight Linux VM, 9 cores, 8 GB RAM)

## no_schema

`[validation] mode = "off"` — daemon checks that the payload is a JSON object
but performs no schema validation.  Message body: `{"event":"bench"}` or
`{"event":"load"}` (single field).

| Benchmark | Connections | Msgs/conn | Median thrpt | 95% CI |
|---|---|---|---|---|
| `single_connection_1k` | 1 | 1 000 | 919.57 Kelem/s | 917.5 – 921.6 |
| `sustained_load_4x250` | 4 | 250 | 1 230.9 Kelem/s | 1 227 – 1 235 |
| `sustained_load_100x10` | 100 | 10 | 1 083.7 Kelem/s | 1 074 – 1 093 |

## with_schema

`[validation] mode = "strict"` with a ten-field JSON Schema
(`additionalProperties: false`).  Message body: ten-field JSON object
(`auth_method`, `duration_ms`, `event`, `region`, `request_id`, `service`,
`session_id`, `source_ip`, `success`, `user`).

| Benchmark | Connections | Msgs/conn | Median thrpt | 95% CI |
|---|---|---|---|---|
| `single_connection_1k` | 1 | 1 000 | 446.88 Kelem/s | 444.3 – 449.4 |
| `sustained_load_4x250` | 4 | 250 | 708.36 Kelem/s | 706.9 – 709.8 |
| `sustained_load_100x10` | 100 | 10 | 707.04 Kelem/s | 704.4 – 709.5 |

## Schema validation overhead

| Benchmark | no_schema | with_schema | Overhead |
|---|---|---|---|
| `single_connection_1k` | 919.57 Kelem/s | 446.88 Kelem/s | 2.1× |
| `sustained_load_4x250` | 1 230.9 Kelem/s | 708.36 Kelem/s | 1.7× |
| `sustained_load_100x10` | 1 083.7 Kelem/s | 707.04 Kelem/s | 1.5× |

Schema validation (JSON parse + `jsonschema` evaluation) costs roughly 2× on a
single connection.  Concurrency recovers a significant portion of that penalty:
the overhead drops to 1.7× at 4 connections and 1.5× at 100 connections, as
the Tokio scheduler overlaps validation work across concurrent sessions.

The 4-connection and 100-connection `with_schema` benchmarks converge to nearly
the same throughput (~708 Kelem/s), suggesting schema validation is the
bottleneck at that point rather than connection fan-in.
