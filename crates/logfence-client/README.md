# logfence-client

Client library for sending structured syslog messages to a
[logfenced](https://github.com/hildstrom/logfence) daemon or directly to
rsyslog via Unix domain sockets.

Part of the [logfence](https://github.com/hildstrom/logfence) project.

## Features

- **`MessageBuilder`** -- fluent API for constructing RFC 5424 syslog messages
  with JSON key-value payloads
- **`UnixTransport`** -- stream transport with RFC 6587 octet-count framing,
  for logfenced or rsyslog `imuxsock` stream input
- **`UnixDatagramTransport`** -- datagram transport (one message per datagram),
  for rsyslog `imuxsock` datagram input or logfenced `unix_dgram` mode
- Automatic retry with exponential backoff on datagram buffer-full errors
- Lazy connection establishment with automatic reconnect after I/O errors
- MITRE CEE cookie (`@cee:`) support via `cee_cookie()` on `MessageBuilder`

## Usage

```toml
[dependencies]
logfence-client = "0.1"
logfence-proto = "0.1"
```

### Stream transport (logfenced or rsyslog)

```rust,no_run
use logfence_client::{MessageBuilder, UnixTransport, now_rfc3339};
use logfence_proto::syslog::{Facility, Severity};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let transport = UnixTransport::new("/run/logfenced/logfenced.sock", 65_536);

    MessageBuilder::new(Facility::Local0, Severity::Info)
        .timestamp(now_rfc3339())
        .hostname("myhost")
        .app_name("myapp")
        .msgid("REQUEST")
        .kv("user_id", 42_u32)?
        .kv("action", "login")?
        .send(&transport)
        .await?;

    Ok(())
}
```

### Datagram transport (rsyslog or logfenced)

```rust,no_run
use logfence_client::{MessageBuilder, UnixDatagramTransport, now_rfc3339};
use logfence_proto::syslog::{Facility, Severity};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let transport = UnixDatagramTransport::new("/run/syslog", 65_536);

    MessageBuilder::new(Facility::Local0, Severity::Info)
        .timestamp(now_rfc3339())
        .app_name("myapp")
        .kv("event", "startup")?
        .send(&transport)
        .await?;

    Ok(())
}
```

### Datagram retry configuration

By default the datagram transport retries up to 4 times with exponential
backoff (100 us, 200 us, 400 us, ...) when the receiver's socket buffer is
full. Override with `max_attempts`:

```rust,no_run
# use logfence_client::UnixDatagramTransport;
let transport = UnixDatagramTransport::new("/run/syslog", 65_536)
    .max_attempts(0);  // retry indefinitely
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or
[MIT license](../../LICENSE-MIT) at your option.
