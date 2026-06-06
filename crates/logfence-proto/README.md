# logfence-proto

Shared syslog protocol types and framing codecs for the
[logfence](https://github.com/hildstrom/logfence) project.

This crate has no knowledge of schemas, config, or application logic. It is
used by both `logfence-client` and `logfence-daemon`.

## Types

**RFC 5424 syslog types** (`syslog` module):

- `Facility` -- syslog facility codes (Kern, User, Local0..Local7, etc.)
- `Severity` -- syslog severity levels (Emergency through Debug)
- `Priority` -- computed from Facility and Severity per RFC 5424 section 6.2.1
- `SyslogMessage` -- full RFC 5424 message with parser and `Display` (wire
  format) implementation

**RFC 6587 framing codecs** (`frame` module):

- `OctetCountCodec` -- octet-counting framing (RFC 6587 section 3.4.1)
- `DelimiterCodec` -- newline or NUL delimiter framing (RFC 6587 section 3.4.2)

Both codecs implement `tokio_util::codec::{Decoder, Encoder}`.

## Usage

```toml
[dependencies]
logfence-proto = "0.1"
```

```rust
use logfence_proto::syslog::{Facility, Severity, Priority, SyslogMessage};
use logfence_proto::frame::OctetCountCodec;
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or
[MIT license](../../LICENSE-MIT) at your option.
