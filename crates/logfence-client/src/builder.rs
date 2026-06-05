//! Fluent [`MessageBuilder`] for constructing RFC 5424 syslog messages.
//!
//! # Example
//!
//! ```rust,no_run
//! use logfence_client::{MessageBuilder, UnixTransport};
//! use logfence_proto::syslog::{Facility, Severity};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let transport = UnixTransport::new("/run/logfenced/logfenced.sock", 65536);
//!
//! MessageBuilder::new(Facility::Local0, Severity::Info)
//!     .app_name("myapp")
//!     .msgid("REQUEST")
//!     .kv("user_id", 42_u32)?
//!     .kv("action", "login")?
//!     .send(&transport)
//!     .await?;
//! # Ok(())
//! # }
//! ```

use std::collections::BTreeMap;

use serde_json::Value;

use logfence_proto::syslog::{Facility, Priority, Severity, SyslogMessage};

use crate::{
    error::{BuildError, ClientError},
    transport::Transport,
};

// ── MessageBuilder ────────────────────────────────────────────────────────────

/// The MITRE CEE cookie prepended to the MSG field in CEE-formatted messages.
pub const CEE_COOKIE: &str = "@cee:";

/// Fluent builder for a single syslog message with a JSON key-value payload.
///
/// Fields default to the RFC 5424 nil value (`-`) unless set explicitly,
/// except `proc_id` which defaults to the current process ID.
///
/// Keys provided to [`kv`](Self::kv) are sorted alphabetically in the
/// serialized JSON object. Duplicate keys are deduplicated — the last value
/// provided for a given key is used.
///
/// Call [`cee_cookie`](Self::cee_cookie) to prefix the JSON payload with
/// `@cee:`, producing a MITRE CEE-compatible syslog message.
#[derive(Debug)]
pub struct MessageBuilder {
    facility: Facility,
    severity: Severity,
    timestamp: Option<String>,
    hostname: Option<String>,
    app_name: Option<String>,
    proc_id: Option<String>,
    msg_id: Option<String>,
    fields: BTreeMap<String, Value>,
    cee_cookie: bool,
}

impl MessageBuilder {
    /// Create a new builder with the given facility and severity.
    ///
    /// The process ID is populated automatically from [`std::process::id`].
    /// All other optional header fields default to nil (`-`).
    #[must_use]
    pub fn new(facility: Facility, severity: Severity) -> Self {
        Self {
            facility,
            severity,
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: Some(std::process::id().to_string()),
            msg_id: None,
            fields: BTreeMap::new(),
            cee_cookie: false,
        }
    }

    /// Prefix the JSON payload with the MITRE CEE cookie (`@cee:`).
    ///
    /// When enabled, the built message body will be `@cee:{...}` instead of
    /// `{...}`, making it compatible with CEE-aware log processors (e.g.
    /// rsyslog's `mmjsonparse` module).
    ///
    /// The default is `false` (no CEE cookie).
    #[must_use]
    pub fn cee_cookie(mut self, enabled: bool) -> Self {
        self.cee_cookie = enabled;
        self
    }

    /// Set the RFC 5424 TIMESTAMP field (RFC 3339 formatted string).
    ///
    /// Use [`now_rfc3339`] to obtain the current UTC time without pulling
    /// in an external time library.
    #[must_use]
    pub fn timestamp(mut self, ts: impl Into<String>) -> Self {
        self.timestamp = Some(ts.into());
        self
    }

    /// Set the RFC 5424 HOSTNAME field.
    #[must_use]
    pub fn hostname(mut self, h: impl Into<String>) -> Self {
        self.hostname = Some(h.into());
        self
    }

    /// Set the RFC 5424 APP-NAME field.
    #[must_use]
    pub fn app_name(mut self, name: impl Into<String>) -> Self {
        self.app_name = Some(name.into());
        self
    }

    /// Override the RFC 5424 PROCID field (defaults to the current PID).
    #[must_use]
    pub fn proc_id(mut self, pid: impl Into<String>) -> Self {
        self.proc_id = Some(pid.into());
        self
    }

    /// Set the RFC 5424 MSGID field.
    #[must_use]
    pub fn msgid(mut self, id: impl Into<String>) -> Self {
        self.msg_id = Some(id.into());
        self
    }

    /// Add a JSON key-value field to the message payload.
    ///
    /// `val` can be any type that implements [`serde::Serialize`]: strings,
    /// integers, booleans, floats, nested objects, and arrays are all accepted.
    ///
    /// If the same `key` is added more than once, the last value is used.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::EmptyKey`] if `key` is the empty string.
    /// Returns [`BuildError::Serialize`] if `val` cannot be serialized to JSON
    /// (rare — only custom `Serialize` implementations can fail).
    pub fn kv(
        mut self,
        key: impl Into<String>,
        val: impl serde::Serialize,
    ) -> Result<Self, BuildError> {
        let key = key.into();
        if key.is_empty() {
            return Err(BuildError::EmptyKey);
        }
        let value = serde_json::to_value(val)?;
        self.fields.insert(key, value);
        Ok(self)
    }

    /// Assemble the accumulated fields into a [`SyslogMessage`].
    ///
    /// The JSON payload is serialized with keys in alphabetical order.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::Serialize`] if the field map cannot be serialized
    /// to a JSON string (should not happen in practice for well-formed values).
    pub fn build(self) -> Result<SyslogMessage, BuildError> {
        let json = serde_json::to_string(&self.fields)?;
        let msg = if self.cee_cookie {
            format!("{CEE_COOKIE}{json}")
        } else {
            json
        };
        Ok(SyslogMessage {
            priority: Priority {
                facility: self.facility,
                severity: self.severity,
            },
            timestamp: self.timestamp,
            hostname: self.hostname,
            app_name: self.app_name,
            proc_id: self.proc_id,
            msg_id: self.msg_id,
            structured_data: "-".to_owned(),
            msg,
        })
    }

    /// Build the message and send it via `transport` in one step.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Build`] if [`build`](Self::build) fails, or a
    /// transport-specific error if delivery fails.
    pub async fn send<T: Transport>(self, transport: &T) -> Result<(), ClientError> {
        let msg = self.build()?;
        transport.send(&msg).await
    }
}

// ── Timestamp utility ─────────────────────────────────────────────────────────

/// Return the current UTC time as an RFC 3339 string with seconds precision,
/// e.g. `"2026-05-14T12:00:00Z"`.
///
/// Uses only `std::time::SystemTime` — no external time library required.
/// Suitable for use with [`MessageBuilder::timestamp`].
#[must_use]
pub fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    epoch_secs_to_rfc3339(secs)
}

fn epoch_secs_to_rfc3339(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let h = rem / 3_600;
    let m = (rem % 3_600) / 60;
    let s = rem % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Howard Hinnant's algorithm: days since the Unix epoch → (year, month, day).
///
/// Reference: <https://howardhinnant.github.io/date_algorithms.html#civil_from_days>
///
/// All intermediate values are provably bounded for any Unix timestamp
/// representable as a `u64`, so the `as` casts are safe.
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "intermediate values are mathematically bounded by the Unix epoch range; \
              results fit in i32/u32 for any date within ±millions of years"
)]
fn civil_from_days(days: u64) -> (i32, u32, u32) {
    let z: i64 = days as i64 + 719_468;
    let era: i64 = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe: u64 = (z - era * 146_097) as u64;
    let yoe: u64 = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y: i64 = yoe as i64 + era * 400;
    let doy: u64 = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp: u64 = (5 * doy + 2) / 153;
    let d: u64 = doy - (153 * mp + 2) / 5 + 1;
    let m: u64 = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "unwrap is appropriate in test assertions"
)]
mod tests {
    use logfence_proto::syslog::{Facility, Severity};

    use super::*;

    // ── MessageBuilder ────────────────────────────────────────────────────────

    #[test]
    fn build_defaults() {
        let msg = MessageBuilder::new(Facility::Local0, Severity::Info)
            .build()
            .unwrap();

        assert_eq!(msg.priority.as_integer(), 134); // Local0=16, Info=6 → 16*8+6=134
        assert!(msg.timestamp.is_none());
        assert!(msg.hostname.is_none());
        assert!(msg.app_name.is_none());
        // proc_id is auto-set to current PID
        assert!(msg.proc_id.is_some());
        assert!(msg.msg_id.is_none());
        assert_eq!(msg.structured_data, "-");
        assert_eq!(msg.msg, "{}"); // empty JSON object
    }

    #[test]
    fn build_with_all_header_fields() {
        let msg = MessageBuilder::new(Facility::Daemon, Severity::Warning)
            .timestamp("2026-05-14T12:00:00Z")
            .hostname("myhost")
            .app_name("myapp")
            .proc_id("9999")
            .msgid("AUDIT")
            .build()
            .unwrap();

        assert_eq!(msg.timestamp.as_deref(), Some("2026-05-14T12:00:00Z"));
        assert_eq!(msg.hostname.as_deref(), Some("myhost"));
        assert_eq!(msg.app_name.as_deref(), Some("myapp"));
        assert_eq!(msg.proc_id.as_deref(), Some("9999"));
        assert_eq!(msg.msg_id.as_deref(), Some("AUDIT"));
    }

    #[test]
    fn build_kv_string() {
        let msg = MessageBuilder::new(Facility::Local0, Severity::Info)
            .kv("action", "login")
            .unwrap()
            .build()
            .unwrap();

        let v: serde_json::Value = serde_json::from_str(&msg.msg).unwrap();
        assert_eq!(v["action"], "login");
    }

    #[test]
    fn build_kv_integer() {
        let msg = MessageBuilder::new(Facility::Local0, Severity::Info)
            .kv("user_id", 42_u32)
            .unwrap()
            .build()
            .unwrap();

        let v: serde_json::Value = serde_json::from_str(&msg.msg).unwrap();
        assert_eq!(v["user_id"], 42);
    }

    #[test]
    fn build_kv_bool() {
        let msg = MessageBuilder::new(Facility::Local0, Severity::Info)
            .kv("success", true)
            .unwrap()
            .build()
            .unwrap();

        let v: serde_json::Value = serde_json::from_str(&msg.msg).unwrap();
        assert_eq!(v["success"], true);
    }

    #[test]
    fn build_kv_nested_object() {
        let nested = serde_json::json!({"code": 200, "reason": "OK"});
        let msg = MessageBuilder::new(Facility::Local0, Severity::Info)
            .kv("response", nested)
            .unwrap()
            .build()
            .unwrap();

        let v: serde_json::Value = serde_json::from_str(&msg.msg).unwrap();
        assert_eq!(v["response"]["code"], 200);
    }

    #[test]
    fn build_kv_multiple_fields_sorted() {
        let msg = MessageBuilder::new(Facility::Local0, Severity::Info)
            .kv("z_last", 3_u32)
            .unwrap()
            .kv("a_first", 1_u32)
            .unwrap()
            .kv("m_middle", 2_u32)
            .unwrap()
            .build()
            .unwrap();

        // BTreeMap serializes keys in alphabetical order.
        assert_eq!(msg.msg, r#"{"a_first":1,"m_middle":2,"z_last":3}"#);
    }

    #[test]
    fn build_kv_duplicate_key_last_wins() {
        let msg = MessageBuilder::new(Facility::Local0, Severity::Info)
            .kv("key", "first")
            .unwrap()
            .kv("key", "second")
            .unwrap()
            .build()
            .unwrap();

        let v: serde_json::Value = serde_json::from_str(&msg.msg).unwrap();
        assert_eq!(v["key"], "second");
    }

    #[test]
    fn build_kv_empty_key_rejected() {
        let err = MessageBuilder::new(Facility::Local0, Severity::Info)
            .kv("", "value")
            .unwrap_err();
        assert!(matches!(err, BuildError::EmptyKey));
    }

    #[test]
    fn build_produces_valid_syslog_message() {
        // The built message must round-trip through the RFC 5424 parser.
        let msg = MessageBuilder::new(Facility::Local7, Severity::Debug)
            .app_name("roundtrip")
            .msgid("TEST")
            .kv("hello", "world")
            .unwrap()
            .build()
            .unwrap();

        let wire = msg.to_string();
        let parsed = SyslogMessage::parse(&wire).unwrap();
        assert_eq!(parsed, msg);
    }

    // ── now_rfc3339 ───────────────────────────────────────────────────────────

    #[test]
    fn now_rfc3339_format() {
        let ts = now_rfc3339();
        // Basic structural check: YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(ts.len(), 20);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[13..14], ":");
        assert_eq!(&ts[16..17], ":");
        assert_eq!(&ts[19..20], "Z");
    }

    // ── CEE cookie ────────────────────────────────────────────────────────────

    #[test]
    fn build_cee_cookie_prefixes_json() {
        let msg = MessageBuilder::new(Facility::Local0, Severity::Info)
            .cee_cookie(true)
            .kv("event", "login")
            .unwrap()
            .build()
            .unwrap();

        assert!(
            msg.msg.starts_with("@cee:"),
            "expected @cee: prefix, got: {}",
            msg.msg
        );
        let json_part = &msg.msg["@cee:".len()..];
        let v: serde_json::Value = serde_json::from_str(json_part).unwrap();
        assert_eq!(v["event"], "login");
    }

    #[test]
    fn build_without_cee_cookie_has_no_prefix() {
        let msg = MessageBuilder::new(Facility::Local0, Severity::Info)
            .kv("event", "login")
            .unwrap()
            .build()
            .unwrap();

        assert!(
            !msg.msg.starts_with("@cee:"),
            "expected no @cee: prefix, got: {}",
            msg.msg
        );
    }

    #[test]
    fn build_cee_cookie_empty_fields() {
        let msg = MessageBuilder::new(Facility::Local0, Severity::Info)
            .cee_cookie(true)
            .build()
            .unwrap();

        assert_eq!(msg.msg, "@cee:{}");
    }

    #[test]
    fn build_cee_cookie_multiple_fields_sorted() {
        let msg = MessageBuilder::new(Facility::Local0, Severity::Info)
            .cee_cookie(true)
            .kv("z", 3_u32)
            .unwrap()
            .kv("a", 1_u32)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(msg.msg, r#"@cee:{"a":1,"z":3}"#);
    }

    #[test]
    fn epoch_secs_known_dates() {
        // Unix epoch itself
        assert_eq!(epoch_secs_to_rfc3339(0), "1970-01-01T00:00:00Z");
        // 2000-01-01T00:00:00Z = 946_684_800
        assert_eq!(epoch_secs_to_rfc3339(946_684_800), "2000-01-01T00:00:00Z");
        // Leap day: 2000-02-29T00:00:00Z = 951_782_400
        assert_eq!(epoch_secs_to_rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        // 2026-05-14T00:00:00Z = 1_778_716_800 (= 1_747_180_800 + 365*86400, 2025→2026)
        assert_eq!(epoch_secs_to_rfc3339(1_778_716_800), "2026-05-14T00:00:00Z");
        // Time component: 2026-05-14T13:45:30Z
        assert_eq!(
            epoch_secs_to_rfc3339(1_778_716_800 + 13 * 3_600 + 45 * 60 + 30),
            "2026-05-14T13:45:30Z"
        );
    }
}
