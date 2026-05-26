# logfence + rsyslog + mmhashchainsigs + RELP vs. JALoP (Revision 3)

This analysis is of the latest JALoP Reference Implementation 2.x.x.x,
latest logfence, and latest mmhashchainsigs in May 2026.

This is the third comparison of these two approaches to tamper-evident
audit logging. The first analysis found
that JALoP's remaining advantage over the rsyslog stack was post-receipt
tamper evidence. The second found
that mmhashchainsigs closed the tamper-evidence gap and that JALoP's
remaining advantage was X.509 / PKI-anchored signer identity.

Since the second analysis, mmhashchainsigs has added:

- **X.509 certificate support** — three trust modes: raw key, pinned
  leaf cert, and CA-validated cert chain with optional CRL checking.
- **ECDSA P-256, P-384, and P-521 signing** — in addition to the
  original Ed25519.
- **SHA-384 and SHA-512 chain hashes** — in addition to the original
  SHA-256.

This revision re-evaluates every topic from the first two analyses in
light of these additions.

---

## Architecture at a glance

| Layer | rsyslog stack | JALoP |
|---|---|---|
| Schema enforcement | logfence validates RFC 5424 fields and JSON Schema (draft 7 / 2019-09) per message before rsyslog sees it | Opt-in JAF XSD validation for audit records only, in the JPL client library; log and journal records are not validated |
| Local relay | rsyslogd with imuxsock / imptcp / imrelp inputs | jal-local-store (LMDB-backed) |
| Integrity at rest | mmhashchainsigs: configurable hash chain (SHA-256/384/512) + periodic signature (Ed25519 or ECDSA P-256/P-384/P-521), optional X.509 cert embedding | XML record + detached XML-DSig signature in LMDB |
| Wire transport | omrelp over RELP/TLS with mutual authentication | BEEP (v1) or HTTP/1.1 + TLS (v2) |
| Storage | Plain files via omfile with sd-preserve template | LMDB database files (default 200 MB cap) |
| Verification | Standalone mmhashchainsigs-verify CLI; supports raw pubkey, pinned cert, or CA-bundle trust modes | LMDB inspection plus XML-DSig validation against a stored cert |
| Languages on the wire | RFC 5424 text + RFC 5424 structured data | XML records, XML-DSig, XML manifests |

The rsyslog stack keeps the message in RFC 5424 form end to end. JALoP
wraps each record in XML metadata and stores the wrapper plus its
signature in LMDB.

---

## Signer identity and PKI

The second analysis identified X.509 / PKI-anchored signer identity as
JALoP's remaining structural advantage. mmhashchainsigs now supports
the full X.509 trust model:

| Capability | rsyslog stack | JALoP |
|---|---|---|
| Raw asymmetric key | Ed25519 or ECDSA (P-256/P-384/P-521) | RSA or ECDSA via XML-DSig |
| X.509 leaf pinning | `--cert` mode; verifier pins the leaf PEM | Operator pins the signer cert |
| CA-validated chain | `--ca-bundle` with embedded cert on INIT lines; full OpenSSL chain validation | XML-DSig cert chain validation |
| Certificate revocation | Static CRL via `--crl-file`; no network fetch (offline audit) | Depends on libxmlsec1 configuration |
| Cert rotation | Graceful rsyslog restart; new chain INIT carries new cert | Replace cert on producer, restart local store |
| Self-signed bootstrap | `mmhashchainsigs-keygen.sh selfsign`; upgrade to CA-issued cert later with no format change | Manual cert generation |

Both stacks now support the same trust hierarchy: raw keys for simple
deployments, pinned certs for auditable identity without a CA, and
CA-validated chains for enterprise PKI. The mmhashchainsigs verifier
intentionally avoids network-based revocation (OCSP) because audit
verification must work offline on stored data; static CRL files cover
the revocation requirement without introducing a runtime dependency on
external infrastructure.

JALoP uses XML-DSig, which supports RSA in addition to ECDSA.
mmhashchainsigs deliberately excludes RSA — Ed25519 and ECDSA cover
every compliance requirement RSA satisfies, with smaller signatures
and faster verification.

**This gap is closed.** The X.509 advantage identified in the second
analysis no longer applies.

---

## Client APIs

JALoP and the rsyslog stack take fundamentally different approaches to
how applications submit audit and log data.

### JALoP Producer Library (JPL)

The JPL is a C library with three record-type entry points, each
taking C structs plus an opaque byte buffer:

- **`jalp_audit(ctx, app_meta, audit_buffer, size)`** — for audit
  records. The `audit_buffer` is a byte buffer that must contain XML
  conforming to the JALoP Audit Format (JAF) Event List Document
  schema. Schema validation is opt-in: the application must set
  the `JAF_VALIDATE_XML` flag on the context via
  `jalp_context_set_flag`. When the flag is set, the JPL parses the
  buffer as XML and validates it against the JAF XSD before sending
  to the local store. When the flag is not set, no validation occurs
  and the buffer is sent as-is.

- **`jalp_log(ctx, app_meta, log_buffer, size)`** — for syslog-style
  log messages. The `log_buffer` is a free-form byte buffer with no
  schema requirement. No validation is performed on the buffer
  contents.

- **`jalp_journal(ctx, app_meta, journal_buffer, size)`** — for large
  binary payloads (PDFs, archives, disk images). The buffer is opaque
  bytes. Alternatively, `jalp_journal_fd` and `jalp_journal_path`
  send a file descriptor or path to avoid copying large files into
  memory.

All three entry points accept an optional `jalp_app_metadata` struct,
which is a union of four modes:

| Mode | Content |
|------|---------|
| `JALP_METADATA_SYSLOG` | `jalp_syslog_metadata`: timestamp, message_id, entry, facility, severity, plus a linked list of RFC 5424-style structured data (SD-ID + key/value params) |
| `JALP_METADATA_LOGGER` | `jalp_logger_metadata`: logger name, severity (int + string), timestamp, threadId, message, NDC, MDC, stack frames, structured data — modeled after log4j |
| `JALP_METADATA_CUSTOM` | Arbitrary XML string (any schema or none) |
| `JALP_METADATA_NONE` | No metadata |

The JPL converts whichever struct is provided into an XML
`applicationMetadata` document, optionally signs it with an RSA key
loaded on the context, and sends it alongside the payload to the
local store over a Unix domain socket.

The context is not thread-safe — the application must guard access or
create separate contexts per thread.

### logfence client

logfence provides two client libraries. Both produce a single record
type: an RFC 5424 syslog message with a JSON object body.

**Rust (`logfence-client`)** — a fluent `MessageBuilder`:

```rust
MessageBuilder::new(Facility::Local0, Severity::Info)
    .timestamp(now_rfc3339())
    .hostname("myhost")
    .app_name("myapp")
    .msgid("REQUEST")
    .kv("user_id", 42_u32)?
    .kv("action", "login")?
    .send(&transport)
    .await?;
```

RFC 5424 header fields (facility, severity, timestamp, hostname,
app-name, proc-id, msg-id) are set via chained methods. The message
body is built key-by-key via `.kv(key, value)`, where the value can
be any `serde::Serialize` type — strings, integers, booleans, nested
objects, arrays. Keys are sorted alphabetically; duplicates use
last-wins. An optional `@cee:` prefix enables CEE-compatible syslog
output.

**C (`logfence-client-c`)** — a single function call:

```c
LfMsgAttr attr = {0};
attr.app_name = "myapp";
attr.msg_id   = "LOGIN";

lf_send(client, LF_FACILITY_LOCAL0, LF_SEVERITY_INFO,
        &attr, "{\"user\":\"alice\",\"result\":\"ok\"}");
```

The caller passes facility, severity, an optional `LfMsgAttr` struct
(hostname, app-name, msg-id, proc-id, timestamp, cee-cookie flag —
all optional with sensible defaults), and a pre-serialized JSON object
string. The C client handle is thread-safe for concurrent `lf_send`
calls.

### API comparison

| Aspect | JALoP (JPL) | logfence-client |
|---|---|---|
| Language bindings | C, C++, Java | Rust, C (FFI covers C++, Python, Go, etc.) |
| Record types | 3 (audit, log, journal) | 1 (RFC 5424 syslog with JSON body) |
| Message format | Opaque byte buffers + C struct metadata → XML | RFC 5424 header + JSON key-value pairs |
| Audit schema validation | Opt-in JAF XSD validation in the JPL client | JSON Schema validation in the logfenced daemon |
| Log/journal validation | None | JSON Schema validation in the logfenced daemon |
| Thread safety | Not thread-safe; one context per thread or external locking | Thread-safe (C client); async (Rust client) |
| Large binary payloads | Direct support via `jalp_journal_fd` / `jalp_journal_path` | Not in scope — syslog is a text protocol |
| Structured metadata | Linked lists of `jalp_param`, `jalp_structured_data`, `jalp_stack_frame` structs | Flat JSON key-value pairs (nested objects supported) |
| Integration effort | Link against JPL; allocate and populate C struct trees | Rust: chain method calls. C: one function call with a JSON string |
| Wire format | Proprietary socket protocol to local store | RFC 5424 over Unix domain socket (stream or datagram) |

The logfence API is substantially simpler to integrate. An application
that already produces JSON (which is most modern applications) needs
one function call in C or a few chained method calls in Rust. The
JALoP API requires the application to allocate and populate trees of
C structs — linked lists of params, structured data groups, stack
frames — which the JPL then serializes into XML. For audit records
specifically, the application must provide pre-formed XML conforming
to the JAF schema if it wants structured audit data beyond the
application metadata.

---

## Signing algorithms

| Algorithm | mmhashchainsigs | JALoP (XML-DSig) |
|---|---|---|
| Ed25519 | Yes (default) | No |
| ECDSA P-256 | Yes | Yes |
| ECDSA P-384 | Yes | Yes |
| ECDSA P-521 | Yes | Yes |
| RSA | Rejected at startup | Yes |

mmhashchainsigs supports Ed25519 in addition to ECDSA, which JALoP's
XML-DSig stack does not. Ed25519 produces the smallest signatures
(64 bytes fixed) and the fastest sign/verify operations. For
deployments that do not require NIST curves, Ed25519 is the best
choice.

For compliance regimes that mandate NIST Suite B cryptography (e.g.,
CNSA 1.0 requiring P-384), mmhashchainsigs now satisfies the
requirement directly. Each curve is paired with its standard digest
per FIPS 186-4 / RFC 5480 §4.

---

## Chain hash algorithms

| Algorithm | mmhashchainsigs | JALoP |
|---|---|---|
| SHA-256 | Yes (default) | Yes (configurable since v2.1) |
| SHA-384 | Yes | Yes |
| SHA-512 | Yes | Yes |

Both stacks now offer the same digest menu. The mmhashchainsigs
verifier auto-detects the algorithm from the hex width of the `h=`
field (64/96/128 chars), so the verifier does not need to be told
which hash the signer used.

---

## Tamper resistance

This was the decisive gap identified in the first analysis and closed
in the second. The position has not changed, but mmhashchainsigs has
strengthened its implementation:

**rsyslog stack (mmhashchainsigs).**

- Per-message hash chain:
  `H(n) = HASH(H(n-1) || seq_be64 || payload(n))`,
  where HASH is SHA-256, SHA-384, or SHA-512.
- payload covers: captured syslog header fields (in
  `mmhashchainsigs-hdr@32473`), any non-self client structured data,
  and the message body.
- Periodic asymmetric signature (Ed25519 or ECDSA) over the current
  chain hash, with a final signature on graceful shutdown.
- Asymmetric: only the signing host holds the private key. The
  verifier needs only the public key, pinned cert, or CA bundle.
- mmhashchainsigs-verify detects: modification, deletion, insertion,
  reorder, splice from a different chain (fingerprint mismatch), and
  unsigned tail (`--strict` mode).
- X.509 cert can be embedded in chain INIT lines, enabling CA-bundle
  verifiers to validate signer identity without out-of-band cert
  distribution.

**JALoP.**

- Per-record XML-DSig signature. Modification is detectable
  record-by-record.
- No inter-record hash chain in the on-disk store. Deletion or
  reordering is detectable only if the verifier independently tracks
  record identifiers and sequencing.
- Asymmetric: the signer's private key is held only by the producer
  or local store; verifiers use the certificate.

**The chain-vs-per-record distinction remains the load-bearing
difference.** With per-message hash chaining, an attacker who deletes
a message must rewrite every subsequent hash and re-sign every
subsequent signature block. With per-record signatures only, deleting
a signed record is detectable only if the verifier independently knows
the record was supposed to exist. mmhashchainsigs provides stronger
tamper-evidence semantics than JALoP in this dimension.

---

## Performance

**Measured rsyslog stack.** On a 9-core / 8 GB aarch64 Linux VM with
rsyslog 8.2312, OpenSSL 3.0.13, Ed25519, SHA-256, signinterval=1024:

| Pipeline | Throughput |
|---|---|
| baseline omfile (no signing) | ~376,000 msg/s |
| mmhashchainsigs + omfile | ~343,000 msg/s |
| mmhashchainsigs-verify | ~578,000 lines/s |

Signing overhead is ~9%. SHA-384 and SHA-512 will increase per-message
hash cost slightly but not change the order of magnitude. ECDSA
signatures are more expensive per-operation than Ed25519 but fire only
once per signinterval (default 1024 messages), so the amortized impact
is small.

**JALoP.** The reference implementation does not publish throughput
numbers. The per-record work is structurally heavier: XML serialization,
XML canonicalization, and XML-DSig signing per record (or batch). The
rsyslog stack does one hash update per message and one signature per
1024 messages.

**On-disk size.** mmhashchainsigs files are ~2.3x the
RSYSLOG_TraditionalFileFormat baseline. JALoP stores each record as an
XML document plus a detached XML-DSig blob in LMDB, with page-aligned
entries. The rsyslog stack produces smaller per-record output in all
realistic configurations.

---

## Stability and safety

**rsyslog stack.**

- rsyslogd: large deployed base, long production track record.
- mmhashchainsigs: C with one direct dependency (OpenSSL >= 3.0).
  Cryptographic failures suspend the action (rsyslog retries) rather
  than dropping messages. The module never crashes on error. Private
  key file mode is enforced at startup. Key material is cleansed from
  memory on shutdown.
- logfence: Rust on Tokio with `unsafe_code = "deny"`. Memory safety
  enforced at compile time. Hot reload via SIGHUP.
- RELP: mature reliable-delivery protocol with TLS and acknowledged
  framing.
- Graceful shutdown writes an atomic state file so the first message
  after restart signs the unsigned tail before starting a new chain.
  Crash loss is bounded by signinterval.

**JALoP reference implementation.**

- C/C++17 with a large dependency surface: libcurl, libxml2,
  libxmlsec1, OpenSSL, LMDB, libmicrohttpd. The README notes that
  the libmicrohttpd shipped in some enterprise distributions is
  insufficient.
- Known limitations documented in the README: "potential record loss
  with duplicate identifiers, temporary transmission of outdated
  records under certain conditions, and challenges with subscriber
  interruption under high volume scenarios."
- Recent work (v2.3.1.0, Jan 2026) added a Rust inline filter
  (jaldb_inline_filter) with SECCOMP sandboxing to protect the LMDB
  database from a compromised publisher. This acknowledges the
  attack surface of the publisher-to-store boundary.
- Local store has a default 200 MB cap; operators manage rotation and
  offload.

---

## Security

**Schema validation and ingress control.** The two stacks validate at
different points in the pipeline and with different scope:

- **logfence** validates every message — all RFC 5424 header fields
  and the JSON body against optional JSON Schemas — in the daemon,
  before rsyslog (and therefore mmhashchainsigs) ever sees the
  message. Validation is mandatory and covers all record types.
  Invalid messages are dropped (strict mode) or flagged (warn mode).
  The application does not need to opt in; validation is a property
  of the pipeline.

- **JALoP** validates audit records against the JAF XSD, but only
  when the application sets the `JAF_VALIDATE_XML` flag on the JPL
  context. When the flag is set, validation happens in the JPL
  client library, inside the calling application's process. The
  local store itself performs no schema validation on ingest — the
  `jalls_handle_audit` handler contains `// TODO: Parse the audit
  data if needed` and stores the buffer as-is. Log records
  (`jalp_log`) and journal records (`jalp_journal`) are never
  schema-validated at any point. JALoP v2.3.1.0 added a Rust inline
  filter between the publisher and the LMDB database that performs
  syntactic and semantic validation, but this filter sits downstream
  of the local store, not at the ingress boundary.

The distinction matters for trust boundaries. logfence validates at
the chokepoint between applications and the signing pipeline — a
compromised or buggy application cannot inject malformed data into the
integrity chain. JALoP's validation is opt-in, in-process (so a
compromised application can simply not set the flag), and absent for
two of the three record types.

**Key handling.**

- mmhashchainsigs: refuses to start if the private key is
  world-readable; cleanses key material with OPENSSL_cleanse on
  shutdown; holds key material in memory only as needed.
- JALoP: key handling depends on libxmlsec1 and operator
  provisioning. The reference implementation does not enforce
  file-mode checks on the private key.

**Attack surface.**

- rsyslog stack: rsyslog, OpenSSL in mmhashchainsigs, Rust/Tokio in
  logfence. RELP/TLS is rsyslog's existing transport. One crypto
  library (OpenSSL).
- JALoP: libxml2, libxmlsec1, libcurl, libmicrohttpd, OpenSSL,
  LMDB, plus the Rust inline filter with its crate dependencies.
  XML-DSig is historically a source of canonicalization and
  signature-wrapping vulnerabilities (XSW); libxmlsec1 exposes the
  full XML-DSig surface.

**Transport security.** RELP over TLS with mutual authentication is
equivalent to JALoP v2's HTTPS with TLS. Both meet in-transit
requirements.

---

## Compliance coverage

| Requirement | rsyslog stack | JALoP |
|---|---|---|
| Integrity of stored records (NIST SP 800-92) | Hash chain + periodic signature; modification, deletion, insertion, reorder all detected | Per-record XML-DSig; modification detected, deletion/reorder requires external bookkeeping |
| Asymmetric signer identity | Ed25519 or ECDSA; raw key, pinned cert, or CA-validated | RSA or ECDSA via XML-DSig cert chain |
| X.509 PKI trust model | Full: CA bundle, chain validation, static CRL | Full: XML-DSig cert chain, depends on libxmlsec1 for revocation |
| NIST Suite B / CNSA 1.0 curves | ECDSA P-256, P-384, P-521 | ECDSA P-256, P-384, P-521 |
| FIPS 186-4 hash/sign pairing | Each curve paired with standard digest | Via XML-DSig algorithm URIs |
| SHA-384 / SHA-512 digests | Configurable chain hash | Configurable record digest |
| Tamper evidence after receipt | Yes: chain hash detects all tampering without external state | Partial: modification detected per-record, deletion requires external tracking |
| Audit trail verifiable offline | mmhashchainsigs-verify, no network dependency | Requires JALoP tools and LMDB reader |
| Acknowledged delivery | RELP | JALoP protocol acknowledgments |
| Transport encryption | TLS with mutual auth | TLS with mutual auth |

The rsyslog stack now matches or exceeds JALoP on every compliance
dimension examined. The chain-based tamper evidence is structurally
stronger than per-record signatures for detecting deletion and
reordering.

---

## Ease of integration

**rsyslog stack.**

- No application changes. Anything that already speaks syslog —
  journald, auditd, libc syslog(3), any logging framework with a
  syslog backend — flows through unmodified.
- auditd integration is a configuration line (audisp-syslog or
  equivalent), not a code change.
- On-wire and on-disk format is RFC 5424. Existing tooling that reads
  syslog files keeps working. Verification is a separate offline step.
- Configuration is rsyslog .conf plus one action stanza for
  mmhashchainsigs. Key/cert generation is a single script invocation.
- logfence integration for pre-validation is a Unix-socket client
  library (logfence-client, with a C wrapper for FFI).
- RHEL 10 and Ubuntu 24.04 LTS ship rsyslog; mmhashchainsigs builds
  against rsyslog-dev headers on both.

**JALoP.**

- Applications integrate by linking against the JALoP Producer Library
  (JPL) and calling its API. Existing syslog producers need a
  translation layer.
- A dedicated JALoP-Auditd-Plugin forwards auditd records into the
  JALoP local store.
- Local store and network stores are separate daemons with their own
  configuration and operational footprint.
- The data format is XML; downstream consumers need to parse JALoP XML
  rather than syslog.
- The reference implementation is not packaged in RHEL or Ubuntu and
  must be built from source against multiple libraries. The build
  system uses SCons and requires Git LFS for Rust dependency RPMs.

---

## Journal records and large binary payloads

JALoP has a dedicated journal record type for large binary payloads —
disk images, PDFs, packet captures, database dumps, and similar
artifacts. The JPL API supports submitting these as in-memory buffers,
file descriptors (`jalp_journal_fd`), or file paths
(`jalp_journal_path`). The local store receives the payload over the
Unix domain socket (or via `SCM_RIGHTS` fd passing to avoid copies),
stores it in LMDB alongside its XML-DSig signature and application
metadata, and distributes it to network subscribers using the JALoP
protocol. The entire lifecycle — ingest, signing, storage, and
distribution — is handled within the JALoP pipeline.

The rsyslog stack has no equivalent. Syslog is a text protocol with
practical message size limits (typically 8 KB for UDP, larger for TCP
and RELP but still not designed for multi-megabyte payloads). The
rsyslog stack handles the metadata naturally — an application can
emit a syslog message with JSON fields describing the artifact
(filename, size, hash, location, threat level) and that message flows
through logfence, mmhashchainsigs, and RELP like any other log line.
The binary payload itself must be stored and transferred out of band.

In practice, this means pairing the rsyslog stack with a separate
mechanism for large artifacts:

- **Shared filesystem or object store.** The application writes the
  artifact to a known location and logs a syslog message referencing
  it by path or object key. The artifact's integrity can be covered
  by including its cryptographic hash in the syslog message, which
  mmhashchainsigs then protects in the hash chain.
- **Dedicated transfer tool.** rsync, scp, or an artifact manager
  moves the file to the receiver. The syslog message provides the
  binding between the audit trail and the artifact.

This is a genuine remaining gap. JALoP handles journal records as
first-class citizens in a single pipeline. The rsyslog stack requires
the operator to build the out-of-band transfer and storage
separately, with the syslog message serving as the integrity-protected
reference linking the audit trail to the artifact.

For environments where the primary workload is text-based audit and
log messages (the majority of syslog use cases, including auditd,
application logs, and security events), this gap does not apply. It
matters when the audit requirement includes large binary evidence —
forensic images, malware samples, or similar artifacts — that must be
stored and distributed alongside their audit metadata.

---

## Operational considerations

**Tooling.** rsyslog has years of operator-facing tooling: templates,
queues, action filters, ruleset isolation, log rotation with standard
tools. JALoP tooling is narrower and tied to the reference
implementation. LMDB files are not directly readable without JALoP-aware
tools.

**Verification.** mmhashchainsigs-verify is a single statically-linkable
binary that reads a text log file and a public key (or cert, or CA
bundle). It produces deterministic pass/fail output with line-level
error reporting. JALoP verification requires the JALoP tools, LMDB
access, and XML-DSig validation.

**Distribution and packaging.** rsyslog is in every major Linux
distribution. mmhashchainsigs builds with make against rsyslog-dev and
OpenSSL. JALoP's build requires SCons, libxml2, libxmlsec1, libcurl,
libmicrohttpd, LMDB, and a Rust toolchain (for the inline filter as of
v2.3.1.0). The JALoP README includes multi-page build instructions with
platform-specific workarounds.

**Format longevity.** RFC 5424 plus a vendor SD-ID
(`mmhashchainsigs@32473`) is a stable text format that survives log
rotation, grep, journalctl, and SIEM ingestion unchanged. LMDB files
require JALoP-specific readers.

**Cert rotation.** mmhashchainsigs rotates certs with a graceful rsyslog
restart: the state file ensures the old chain is signed before the new
chain begins. CA-bundle verifiers automatically pick up the new cert
from the new INIT line. JALoP cert rotation requires updating the
producer configuration and restarting the local store.

---

## When the rsyslog stack is the better fit

- Producers already speak syslog (most Linux audit and application
  logging).
- Operators want existing rsyslog operational knowledge to carry over.
- The compliance requirement includes tamper-evident audit at rest, and
  per-message chain + periodic signature is sufficient (most NIST/DoD/IC
  controls require detection of modification, deletion, insertion, and
  reorder).
- X.509 PKI-anchored signer identity is required — mmhashchainsigs
  now supports this directly.
- NIST Suite B or CNSA 1.0 curves are required — ECDSA P-256/P-384/P-521
  are available.
- Throughput matters — measured ~9% overhead at ~343k msg/s.
- Operational simplicity and minimal dependency footprint are priorities.

## When JALoP may still be the better fit

- A procurement explicitly mandates "JALoP-conformant" audit exchange
  (some government contracts specify the protocol by name).
- The consumer side is already JALoP-native and expects XML records with
  detached XML-DSig.
- RSA signing is required by policy (mmhashchainsigs does not support
  RSA).
- The audit requirement includes large binary payloads (forensic images,
  malware samples, packet captures) that must be ingested, signed,
  stored, and distributed in a single pipeline. JALoP's journal record
  type handles this natively; the rsyslog stack requires out-of-band
  artifact storage and transfer.

---

## Summary

The first analysis found that JALoP's advantage over the rsyslog stack
was post-receipt tamper evidence. The second found that mmhashchainsigs
closed that gap and that JALoP's remaining advantage was X.509 /
PKI-anchored signer identity with NIST curve support.

With the addition of X.509 certificate support (raw key, pinned cert,
and CA-validated chain with CRL), ECDSA P-256/P-384/P-521 signing, and
SHA-384/SHA-512 chain hashes, the rsyslog stack now matches JALoP on
every compliance and security dimension that previously favored JALoP,
while retaining structural advantages in:

- **Tamper evidence** — per-message hash chaining detects deletion and
  reordering without external bookkeeping; JALoP's per-record XML-DSig
  does not.
- **Performance** — ~343k msg/s with ~9% signing overhead vs. JALoP's
  structurally heavier XML serialization and per-record signing path.
- **Integration** — zero application changes for syslog producers;
  standard RFC 5424 files on disk; single rsyslog action stanza.
- **Operational footprint** — one crypto dependency (OpenSSL), standard
  rsyslog infrastructure, text-format logs readable with standard tools.
- **Security surface** — smaller dependency chain; no XML-DSig
  canonicalization attack surface; compile-time memory safety in
  logfence.
- **Schema enforcement** — logfence validates every message at the
  pipeline chokepoint before signing. JALoP offers opt-in JAF XSD
  validation for audit records only, inside the client library; log
  and journal records are never validated.
- **Client API simplicity** — one function call (C) or a few chained
  methods (Rust) vs. allocating trees of C structs and providing
  pre-formed XML.

JALoP retains two advantages the rsyslog stack does not cover:

1. **Journal records** — native ingest, signing, storage, and
   distribution of large binary payloads in a single pipeline. The
   rsyslog stack requires out-of-band artifact handling.
2. **Niche procurement** — contracts that mandate the JALoP protocol
   by name, environments with existing JALoP-native consumers, or
   the uncommon requirement for RSA signing.

For the vast majority of audit and logging workloads — text-based
syslog messages, auditd events, application logs, security events —
the logfence + rsyslog + mmhashchainsigs + RELP stack is the stronger
choice across every dimension: tamper resistance, performance,
compliance coverage, signer identity, schema enforcement, client API
ergonomics, ease of integration, and operational simplicity.

---

## References

- [mmhashchainsigs README](mmhashchainsigs/README.md)
- [mmhashchainsigs X.509 design](mmhashchainsigs/docs/X509.md)
- [mmhashchainsigs benchmark](mmhashchainsigs/docs/BENCHMARK.md)
- [logfence](https://github.com/hildstrom/logfence)
- [logfence JALoP comparison (JALOP.md)](logfence/docs/JALOP.md)
- [mmhashchainsigs JALoP comparison (JALOP.md)](mmhashchainsigs/docs/JALOP.md)
- [JALoP Reference Implementation](https://github.com/JALoP/JALoP)
- [JALoP Auditd Plugin](https://github.com/JALoP/JALoP-Auditd-Plugin)
- NIST SP 800-92, *Guide to Computer Security Log Management*
