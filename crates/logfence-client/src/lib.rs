//! logfence client library.
//!
//! Provides a fluent [`MessageBuilder`] for constructing RFC 5424 syslog
//! messages with JSON key-value payloads, and transport implementations for
//! delivering them to a running [`logfenced`] daemon or directly to rsyslog.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use logfence_client::{MessageBuilder, UnixTransport, UnixDatagramTransport, now_rfc3339};
//! use logfence_proto::syslog::{Facility, Severity};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Stream transport (octet-count framing) — for logfenced or rsyslog imuxsock stream.
//! let transport = UnixTransport::new("/run/logfenced/logfenced.sock", 65536);
//! // Datagram transport — for rsyslog imuxsock datagram or logfenced unix_dgram mode.
//! // let transport = UnixDatagramTransport::new("/run/syslog", 65536);
//!
//! MessageBuilder::new(Facility::Local0, Severity::Info)
//!     .timestamp(now_rfc3339())
//!     .hostname("myhost")
//!     .app_name("myapp")
//!     .msgid("REQUEST")
//!     .kv("user_id", 42_u32)?
//!     .kv("action", "login")?
//!     .send(&transport)
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! [`logfenced`]: https://github.com/example/logfence

pub mod builder;
pub mod error;
pub mod transport;

pub use builder::{now_rfc3339, MessageBuilder};
pub use error::{BuildError, ClientError};
pub use transport::{Transport, UnixDatagramTransport, UnixTransport};
