# logfence and JALoP — Comparison and Analysis

JALoP (Journal of Audit Log Protocol) and logfence are related projects in the
secure logging space, but they address different problems at different levels of
complexity. They are not direct competitors and can be deployed together.

---

## Purpose and Scope

**JALoP** is a comprehensive tamper-evident audit logging system. It provides
local storage, integrity guarantees via cryptographic digests and digital
signatures, and a network distribution protocol for moving audit records between
systems. It was developed by Tresys Technology under DARPA funding and targets
high-assurance environments — government, defense, and intelligence community
workloads.

**logfence** is a validating filter. It enforces that log messages are
well-formed, schema-compliant structured data before they reach rsyslog. It does
not store logs, sign them, or distribute them. Its scope is deliberately narrow:
clean the data at the point it enters the syslog pipeline.

They can complement each other — logfence upstream of a JALoP producer would
ensure only schema-valid messages enter JALoP's tamper-evident chain.

---

## Complexity

JALoP is substantially more complex:

- **Protocol** — JALoP 1.x uses BEEP (RFC 3080) for network transport, a
  multi-channel, session-oriented protocol with its own framing, error handling,
  and channel management. JALoP 2.x replaced BEEP with HTTPS. logfence uses
  plain Unix stream sockets with RFC 6587 octet-count framing.
- **Record format** — JALoP wraps log records in XML envelopes with metadata
  headers, digest values, and signature blocks. logfence uses RFC 5424 syslog
  with a JSON payload — both are existing standards, nothing proprietary.
- **Infrastructure** — JALoP requires a PKI to be operational — certificates,
  keys, signing infrastructure — before it provides its integrity guarantees.
  logfence requires only JSON Schema files.
- **Components** — JALoP has separate local store daemons, subscriber daemons,
  publisher daemons, and network relay components. logfence has one daemon and
  one client library.
- **Codebase** — JALoP's reference implementation is C/C++ with all the memory
  management complexity that entails. logfence is approximately 3 000 lines of
  safe Rust.

For teams without a government or defense mandate, JALoP's complexity is very
difficult to justify.

---

## Stability and Safety

JALoP's C/C++ implementation carries inherent memory safety risk — buffer
overflows, use-after-free, and similar vulnerabilities are realistic concerns in
a component that parses untrusted log data from applications. The irony of an
audit logging system being exploited via its own parsing path is not
hypothetical; this class of vulnerability has affected similar infrastructure
software.

logfence uses Rust with `unsafe_code = "deny"` across the workspace. The memory
safety properties are enforced at compile time, not by convention or review
discipline. For a security boundary component that parses untrusted input from
potentially compromised applications, this is a meaningful structural advantage.

---

## Performance

JALoP is not designed for high throughput. Each record involves:

- XML serialization
- SHA-256 (or stronger) digest computation over the record and its metadata
- Optional digital signing
- BEEP channel framing (1.x) or HTTPS framing (2.x)
- Local disk write before acknowledgment (to guarantee durability)

The disk write in particular means JALoP throughput is bounded by storage I/O,
not CPU or network. This is intentional — the durability guarantee requires it.

logfence sustains 200–700 K messages/second without schema validation and
66–400 K messages/second with strict JSON Schema enforcement, depending on
connection count. This is roughly two to three orders of magnitude faster than
JALoP can sustain on the same hardware. For high-volume application logging this
gap is decisive. For low-volume audit trails where every record must survive a
system compromise, JALoP's model is the right one.

---

## Application Logging APIs

JALoP provides producer libraries in C, C++, and Java. Applications call the
producer API to submit journal, syslog, or audit log entries. The library
handles local buffering and submission to the local store daemon.

logfence provides two client libraries. logfence-client (Rust) offers a fluent
`MessageBuilder` API. logfence-client-c wraps it as a C shared library
(`.so`/`.dylib`) and static archive (`.a`), covering C, C++, and any language
with C FFI — Python, Ruby, Go, and others. JALoP's Java support has no
equivalent in logfence, but the C API covers the majority of systems languages.
The underlying protocol is simple enough that a native client could be written in
any language with Unix socket support.

Both take the same architectural approach: an in-process library submits to a
local daemon over a host socket, isolating the application from the downstream
infrastructure.

---

## Industry Standards

| Aspect | JALoP | logfence |
|---|---|---|
| Transport | BEEP/RFC 3080 (v1.x), HTTPS (v2.x) | Unix domain sockets |
| Message format | XML with custom envelope | RFC 5424 syslog |
| Schema/validation | Custom digest and signing | JSON Schema (draft 7, 2019-09) |
| Integrity | Cryptographic digest chains, digital signatures | None (validation only, no signing) |
| Target standard | NIST SP 800-92, DoD audit requirements | RFC 5424, RFC 6587 |
| Ecosystem fit | Government/defense audit pipelines | rsyslog / syslog infrastructure |

logfence deliberately stays within the existing syslog ecosystem — RFC 5424
messages pass through logfence unchanged in format. Any rsyslog configuration,
SIEM, or log aggregator that already consumes syslog continues to work without
modification. JALoP is a separate pipeline that needs purpose-built subscribers
to consume its records.

---

## logfence + rsyslog + RELP

When rsyslog is configured to use RELP (Reliable Event Logging Protocol) for
network transport, the combined stack becomes considerably more competitive with
JALoP for a broader range of use cases.

### What RELP adds

RELP is a transport protocol designed specifically for syslog that provides:

- **Acknowledged delivery** — the receiver explicitly acknowledges each message;
  the sender retransmits on failure. Unlike UDP syslog or even TCP syslog,
  messages are not silently dropped on network or receiver failure.
- **Connection-oriented with session recovery** — RELP maintains a persistent
  TCP session and can recover mid-stream without losing unacknowledged messages.
- **TLS support** — rsyslog's RELP implementation supports TLS with mutual
  certificate authentication, providing both encryption and peer identity
  verification.
- **No message loss on restart** — rsyslog can queue messages to disk and replay
  them over RELP after a receiver restart.

rsyslog supports RELP both as a sender (omrelp) and receiver (imrelp), and RELP
is well-established in enterprise Linux environments.

### Delivery guarantee

The primary structural advantage JALoP holds over a plain rsyslog pipeline is
guaranteed delivery with durability. JALoP writes to local disk before
acknowledging to the producer, and uses its network protocol to confirm receipt
at the subscriber before advancing the digest chain. Without RELP, rsyslog over
TCP provides no such guarantee — messages in flight when a connection drops are
gone.

With RELP, rsyslog provides acknowledged delivery end-to-end. It is not
identical to JALoP's model — JALoP's local store means records survive even if
the network is down indefinitely, whereas RELP requires eventual network
connectivity — but for most threat models the practical difference is small.

### Transport integrity

RELP over TLS with mutual authentication provides:

- Encryption in transit
- Receiver authentication (you know you are sending to the real log server)
- Sender authentication (the log server knows messages come from authorized
  hosts)

JALoP's network protocol also uses TLS with mutual authentication, so this gap
closes entirely.

### Revised capability comparison

| Aspect | logfence + rsyslog + RELP | JALoP |
|---|---|---|
| Delivery guarantee | Acknowledged, retransmit on failure | Acknowledged, local store first |
| Offline durability | rsyslog disk queue (configurable) | Full local store, indefinite retention |
| Transport security | TLS with mutual authentication | TLS with mutual authentication |
| Cryptographic integrity | None — TLS protects transit only | Digest chain + signatures cover record content |
| Tamper evidence | No | Yes — digest chain detects post-receipt modification |
| Record integrity after receipt | None | Digest chain verifiable by third party |
| Compliance artifact | Syslog records in rsyslog storage | Signed, chained audit records |
| Throughput | 66–700 K msg/s | Storage I/O bound |
| Operational complexity | Low | High (PKI, multiple daemons) |
| Memory safety | Rust, compile-time enforced | C/C++, manual |
| Ecosystem fit | Existing rsyslog infrastructure | Purpose-built subscribers required |

### The remaining gap: tamper evidence

TLS protects messages in transit — it guarantees that a message was not modified
between sender and receiver and was sent to the right destination. It does not
guarantee anything about what happens to a record after it arrives. A privileged
attacker with access to the log server can modify or delete records without any
cryptographic evidence of tampering.

JALoP's digest chain covers the content of records after they are stored. Each
record's digest incorporates the previous record's digest, so deleting or
modifying a record breaks the chain in a detectable way. This is the property
that compliance frameworks like NIST SP 800-92 specifically require for
high-assurance audit trails, and it is something RELP+TLS cannot provide
regardless of configuration.

---

## When to Use Each

**Choose JALoP when:**
- You need tamper-evident audit trails that survive a system compromise
- Your compliance framework specifically requires cryptographic integrity of
  stored audit records (NIST SP 800-92, DoD, IC requirements)
- You need to distribute audit records reliably across a network with delivery
  guarantees and indefinite offline durability
- You have the PKI and operational infrastructure to support it

**Choose logfence + rsyslog + RELP when:**
- You want to enforce structured logging discipline across applications
- You need to ensure malformed or schema-violating messages never reach
  downstream consumers
- You are already invested in rsyslog and want to add a validation layer without
  replacing your logging infrastructure
- Throughput, operational simplicity, and ecosystem compatibility are priorities
- Your compliance framework does not specifically require post-receipt
  cryptographic tamper evidence

**Use both when:**
- You have high-assurance applications that must produce tamper-evident audit
  records and you want to validate their structure before the records enter
  JALoP's integrity chain — logfence upstream, JALoP downstream

---

## Summary

For most production environments — even security-sensitive ones — the logfence +
rsyslog + RELP stack is fully adequate. logfence enforces schema-valid structured
data at the source, rsyslog provides buffering, filtering, routing, and format
transformation, and RELP provides acknowledged delivery with TLS encryption and
mutual authentication. The combination integrates with existing rsyslog
infrastructure and tooling, is operationally simpler, and sustains significantly
higher throughput.

JALoP's remaining and definitive advantage is post-receipt tamper evidence — the
ability for an auditor to verify that records have not been modified or deleted
after they were stored, using a cryptographic proof that does not require
trusting the storage system. If your compliance framework requires that property,
JALoP is still the right answer. If it does not — and most frameworks outside
government and defense do not explicitly require it — logfence + rsyslog + RELP
is a strong, practical alternative with far less operational overhead.
