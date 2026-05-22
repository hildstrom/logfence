# Development Environment

## Rust toolchain

| Item | Value |
|---|---|
| Toolchain | Stable (currently 1.95.0 in this environment) |
| MSRV | 1.86 (set in `[workspace.package] rust-version`) |
| Edition | 2021 |

MSRV was 1.85 because that is the oldest stable release that provides all features used:
`let...else`, `impl Trait` in argument position, `std::str::from_utf8` accepting `&[u8]` slices from
`BytesMut`, and `#[allow(..., reason = "...")]` attribute syntax (stabilised in 1.81).
It was incremented to 1.86 to satisfy some build dependencies when building with the older toolchain.

Install the required toolchain via rustup:

```
rustup toolchain install stable
rustup component add clippy rustfmt
```

---

## Workspace layout

```
Cargo.toml                  workspace manifest + shared dependency table
crates/
  logfence-proto/           shared syslog types and framing codecs (lib)
  logfence-client/          application-facing client library (lib)
  logfence-client-c/        C API wrapper for logfence-client (cdylib + staticlib)
  logfence-daemon/          filter daemon binary (bin: logfenced)
```

All crates inherit `version`, `edition`, `rust-version`, `license`, and `repository`
from `[workspace.package]`.  All dependency versions are declared once in
`[workspace.dependencies]` and referenced with `{ workspace = true }` in each crate.

---

## Pinned dependency versions

Versions were looked up from crates.io at project creation time (2026-05-14) and are
pinned exactly.  Update them deliberately — do not change a version without reading the
changelog.

| Crate | Version | Purpose |
|---|---|---|
| `tokio` | 1.52.3 | Async runtime |
| `tokio-util` | 0.7.18 | `Decoder` / `Encoder` codec traits |
| `serde` | 1.0.228 | Serialization derive macros |
| `serde_json` | 1.0.149 | JSON parsing |
| `toml` | 1.1.2 | Config file parsing |
| `jsonschema` | 0.46.5 | JSON Schema validation (pure Rust, no C deps) |
| `thiserror` | 2.0.18 | Error derivation |
| `tracing` | 0.1.44 | Daemon-internal structured logging |
| `tracing-subscriber` | 0.3.23 | Tracing subscriber (stderr / env-filter) |
| `clap` | 4.6.1 | CLI argument parsing |
| `bytes` | 1.11.1 | Zero-copy byte buffers (`BytesMut`) |

The following dev-only dependencies are pinned in individual crate `Cargo.toml`
files (not the workspace manifest) and follow the same deliberate-update policy:

| Crate | Version | Used in |
|---|---|---|
| `criterion` | 0.8.2 | `logfence-daemon` benchmarks |
| `socket2` | 0.6.3 | `logfence-daemon` tests and benchmarks (SO_RCVBUF) |
| `tempfile` | 3.27.0 | `logfence-client`, `logfence-client-c`, `logfence-daemon` tests |

---

## Workspace lint configuration

Lints are declared in `[workspace.lints]` in the root `Cargo.toml` so they apply
uniformly to every crate.  Each crate opts in with `[lints] workspace = true`.

### Active denies (production code must not trigger these)

| Lint | Level | Reason |
|---|---|---|
| `unsafe_code` | deny | No unsafe in this codebase |
| `clippy::unwrap_used` | deny | Panics must not reach production code |
| `clippy::panic` | deny | Same |
| `clippy::panic_in_result_fn` | deny | Same |
| `clippy::unimplemented` | deny | Same |
| `clippy::exit` | deny | Daemons must shut down cleanly via signal handling |
| `clippy::mem_forget` | deny | Prevents resource leaks |
| `clippy::await_holding_lock` | deny | Deadlock prevention |
| `clippy::large_futures` | deny | Avoids stack overflows in async code |
| `clippy::dbg_macro` | deny | Debug output must not reach production |
| `clippy::todo` | deny | Incomplete implementations must not ship |
| `clippy::print_stdout` | deny | Daemon output goes through tracing, not stdout |
| `clippy::print_stderr` | deny | Same |

### Pedantic group

`clippy::pedantic` is enabled at `warn` (promoted to error in CI via `-- -D warnings`).
Two pedantic lints are relaxed at workspace level because they produce excessive noise:

| Lint | Level | Reason |
|---|---|---|
| `clippy::module_name_repetitions` | allow | Common and readable in Rust |
| `clippy::similar_names` | allow | Short variable names are idiomatic in parsers |

### Suppress-lint guard

`clippy::allow_attributes_without_reason` is set to `warn` (promoted to error in CI).
Any `#[allow(...)]` attribute **must** include a `reason = "..."` argument:

```rust
#[allow(clippy::unwrap_used, reason = "unwrap is appropriate in test assertions")]
```

`allow_attributes = "deny"` was considered but rejected because it prevents test modules
from suppressing `unwrap_used` and `panic_in_result_fn`, which are both appropriate in
test assertions.  The `reason` requirement provides the same audit trail.

### Test module pattern

Test modules allow `clippy::unwrap_used` with a reason annotation.
Use standard `()` return type and `assert!` / `assert_eq!` macros:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unwrap is appropriate in test assertions")]
mod tests {
    use super::*;

    #[test]
    fn some_test() {
        let msg = SyslogMessage::parse("<13>1 - - - - - - body").unwrap();
        assert_eq!(msg.msg, "body");
    }
}
```

Do **not** return `Result` from test functions — `clippy::panic_in_result_fn` (part of
`pedantic`) treats `assert!` macros as panics in Result-returning functions.

---

## CI pipeline

Seven jobs run on every push and pull request to `main`:

| Job | Runner | What it checks |
|---|---|---|
| `fmt` | ubuntu-latest | `cargo fmt --check --all` |
| `clippy` | ubuntu-latest | `cargo clippy --workspace --all-targets -- -D warnings` |
| `test-ubuntu` | ubuntu-24.04 | `cargo test --workspace` |
| `test-rhel` | UBI10 container | `cargo test --workspace` |
| `test-macos` | macos-26 | `cargo test --workspace` |
| `msrv` | ubuntu-latest | `cargo check --workspace` at Rust 1.86 |
| `security` | ubuntu-latest | `cargo deny check` |

All `actions/checkout` and `dtolnay/rust-toolchain` steps are pinned to full SHA hashes
with version comments.  `persist-credentials: false` is set on every checkout step.

---

## Supply chain audit (cargo-deny)

`deny.toml` enforces three policies on every CI run:

- **Advisories** — yanked crates are denied; security advisories are fetched and checked.
- **Licenses** — only the following SPDX identifiers are allowed:
  `MIT`, `MIT-0`, `Apache-2.0`, `Apache-2.0 WITH LLVM-exception`,
  `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Unicode-3.0`, `Zlib`.
- **Sources** — only `crates.io` is allowed; unknown registries and git sources are denied.

Run the audit locally:

```
cargo install cargo-deny --locked
cargo deny check
```

---

## Local development commands

```bash
# Build everything
cargo build --workspace

# Run all tests (unit + integration)
cargo test --workspace

# Run only integration tests
cargo test -p logfence-daemon --test integration_test

# Run a single integration test by name
cargo test -p logfence-daemon --test integration_test -- max_connections_backpressure

# Run throughput benchmarks (all groups)
cargo bench -p logfence-daemon

# Run one benchmark group (groups are named <prefix>_<input>_<output>)
cargo bench -p logfence-daemon -- no_schema_stream_dgram/
cargo bench -p logfence-daemon -- no_schema_stream_stream/
cargo bench -p logfence-daemon -- no_schema_dgram_dgram/
cargo bench -p logfence-daemon -- no_schema_dgram_stream/
cargo bench -p logfence-daemon -- with_schema_stream_dgram/

# Run a single benchmark within a group
cargo bench -p logfence-daemon -- no_schema_stream_dgram/load_1x1000
cargo bench -p logfence-daemon -- no_schema_stream_dgram/load_4x250
cargo bench -p logfence-daemon -- no_schema_stream_dgram/load_100x10

# Lint (mirrors CI)
cargo clippy --workspace --all-targets -- -D warnings

# Format
cargo fmt --all

# Format check only (mirrors CI)
cargo fmt --check --all

# Supply chain audit
cargo deny check

# Run the daemon
cargo run --bin logfenced -- --config config/logfenced.example.toml
```
