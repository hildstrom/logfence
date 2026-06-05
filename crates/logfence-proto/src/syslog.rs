//! RFC 5424 syslog message types.
//!
//! Reference: <https://datatracker.ietf.org/doc/html/rfc5424>

use std::fmt;

use thiserror::Error;

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors produced while parsing a raw syslog string into a [`SyslogMessage`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    /// The `<PRI>` value is outside the valid range 0–191.
    #[error("invalid priority value '{0}' (valid range: 0–191)")]
    InvalidPriority(String),

    /// A required header field is missing or structurally malformed.
    #[error("malformed syslog header: {0}")]
    MalformedHeader(String),

    /// The message is not valid UTF-8.
    #[error("message is not valid UTF-8")]
    InvalidUtf8,

    /// A header field value violates RFC 5424 content or length constraints.
    #[error("invalid {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
}

// ── Facility ─────────────────────────────────────────────────────────────────

/// RFC 5424 §6.2.1 facility codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Facility {
    Kern = 0,
    User = 1,
    Mail = 2,
    Daemon = 3,
    Auth = 4,
    Syslog = 5,
    Lpr = 6,
    News = 7,
    Uucp = 8,
    Cron = 9,
    AuthPriv = 10,
    Ftp = 11,
    Ntp = 12,
    LogAudit = 13,
    LogAlert = 14,
    Clock = 15,
    Local0 = 16,
    Local1 = 17,
    Local2 = 18,
    Local3 = 19,
    Local4 = 20,
    Local5 = 21,
    Local6 = 22,
    Local7 = 23,
}

impl Facility {
    /// Parse a facility from its numeric code (0–23).
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidPriority`] if `n` is greater than 23.
    pub fn from_integer(n: u8) -> Result<Self, ParseError> {
        match n {
            0 => Ok(Self::Kern),
            1 => Ok(Self::User),
            2 => Ok(Self::Mail),
            3 => Ok(Self::Daemon),
            4 => Ok(Self::Auth),
            5 => Ok(Self::Syslog),
            6 => Ok(Self::Lpr),
            7 => Ok(Self::News),
            8 => Ok(Self::Uucp),
            9 => Ok(Self::Cron),
            10 => Ok(Self::AuthPriv),
            11 => Ok(Self::Ftp),
            12 => Ok(Self::Ntp),
            13 => Ok(Self::LogAudit),
            14 => Ok(Self::LogAlert),
            15 => Ok(Self::Clock),
            16 => Ok(Self::Local0),
            17 => Ok(Self::Local1),
            18 => Ok(Self::Local2),
            19 => Ok(Self::Local3),
            20 => Ok(Self::Local4),
            21 => Ok(Self::Local5),
            22 => Ok(Self::Local6),
            23 => Ok(Self::Local7),
            _ => Err(ParseError::InvalidPriority(n.to_string())),
        }
    }
}

// ── Severity ─────────────────────────────────────────────────────────────────

/// RFC 5424 §6.2.1 severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Severity {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl Severity {
    /// Parse a severity from its numeric code (0–7).
    ///
    /// Values 8–255 are mapped to [`Severity::Debug`] per RFC 5424 §6.2.1.
    #[must_use]
    pub fn from_integer(n: u8) -> Self {
        match n {
            0 => Self::Emergency,
            1 => Self::Alert,
            2 => Self::Critical,
            3 => Self::Error,
            4 => Self::Warning,
            5 => Self::Notice,
            6 => Self::Info,
            _ => Self::Debug,
        }
    }
}

// ── Priority ─────────────────────────────────────────────────────────────────

/// Combined facility + severity, encoded as the RFC 5424 `PRI` integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Priority {
    pub facility: Facility,
    pub severity: Severity,
}

impl Priority {
    /// Parse a priority from a raw `PRI` integer (0–191).
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidPriority`] if `pri` is greater than 191
    /// or encodes an invalid facility code.
    pub fn from_integer(pri: u8) -> Result<Self, ParseError> {
        if pri > 191 {
            return Err(ParseError::InvalidPriority(pri.to_string()));
        }
        let facility = Facility::from_integer(pri / 8)?;
        let severity = Severity::from_integer(pri % 8);
        Ok(Self { facility, severity })
    }

    /// Encode as the RFC 5424 `PRIVAL` integer.
    #[must_use]
    pub fn as_integer(self) -> u8 {
        (self.facility as u8) * 8 + (self.severity as u8)
    }
}

// ── SyslogMessage ─────────────────────────────────────────────────────────────

/// A parsed RFC 5424 syslog message.
///
/// All optional header fields use `None` to represent the RFC 5424 nil value (`-`).
/// The `structured_data` field stores the raw text of the STRUCTURED-DATA element
/// (either `"-"` or one or more `[SD-ID ...]` blocks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogMessage {
    pub priority: Priority,
    /// RFC 3339 timestamp string, or `None` for the nil value `-`.
    pub timestamp: Option<String>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub proc_id: Option<String>,
    pub msg_id: Option<String>,
    /// Raw STRUCTURED-DATA text (`"-"` or `"[SD-ID ...]"`).
    pub structured_data: String,
    /// The MSG field — expected to be a JSON object for logfence.
    pub msg: String,
}

impl SyslogMessage {
    /// Parse a raw RFC 5424 syslog string.
    ///
    /// Leading/trailing whitespace and trailing NUL/newline bytes are stripped
    /// before parsing.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] if the input is structurally invalid: bad PRI,
    /// wrong version, missing header fields, or a malformed STRUCTURED-DATA block.
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        let s = raw.trim_end_matches(['\n', '\r', '\0']);

        // <PRI>
        let s = s
            .strip_prefix('<')
            .ok_or_else(|| ParseError::MalformedHeader("expected '<' to start PRI".into()))?;
        let (pri_str, s) = s
            .split_once('>')
            .ok_or_else(|| ParseError::MalformedHeader("expected '>' to close PRI".into()))?;
        let pri_val: u8 = pri_str
            .parse()
            .map_err(|_| ParseError::InvalidPriority(pri_str.into()))?;
        let priority = Priority::from_integer(pri_val)?;

        // VERSION — must be exactly "1"
        let s = s
            .strip_prefix("1 ")
            .ok_or_else(|| ParseError::MalformedHeader("expected VERSION '1'".into()))?;

        // TIMESTAMP
        let (timestamp, s) = split_header_field(s, "TIMESTAMP")?;

        // HOSTNAME
        let (hostname, s) = split_header_field(s, "HOSTNAME")?;

        // APP-NAME
        let (app_name, s) = split_header_field(s, "APP-NAME")?;

        // PROCID
        let (proc_id, s) = split_header_field(s, "PROCID")?;

        // MSGID
        let (msg_id, s) = split_header_field(s, "MSGID")?;

        // STRUCTURED-DATA and optional MSG
        let (structured_data, msg) = parse_structured_data_and_msg(s)?;

        // Content and range validation per RFC 5424 §6.
        if let Some(ts) = &timestamp {
            validate_timestamp(ts)?;
        }
        if let Some(h) = &hostname {
            validate_printusascii_field(h, "HOSTNAME", 255)?;
        }
        if let Some(a) = &app_name {
            validate_printusascii_field(a, "APP-NAME", 48)?;
        }
        if let Some(p) = &proc_id {
            validate_printusascii_field(p, "PROCID", 128)?;
        }
        if let Some(m) = &msg_id {
            validate_printusascii_field(m, "MSGID", 32)?;
        }
        validate_structured_data_content(&structured_data)?;

        Ok(Self {
            priority,
            timestamp,
            hostname,
            app_name,
            proc_id,
            msg_id,
            structured_data,
            msg,
        })
    }
}

/// Render the message in RFC 5424 wire format.
impl fmt::Display for SyslogMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "<{}>1 {} {} {} {} {} {}",
            self.priority.as_integer(),
            self.timestamp.as_deref().unwrap_or("-"),
            self.hostname.as_deref().unwrap_or("-"),
            self.app_name.as_deref().unwrap_or("-"),
            self.proc_id.as_deref().unwrap_or("-"),
            self.msg_id.as_deref().unwrap_or("-"),
            self.structured_data,
        )?;
        if !self.msg.is_empty() {
            write!(f, " {}", self.msg)?;
        }
        Ok(())
    }
}

// ── Parsing helpers ───────────────────────────────────────────────────────────

/// Split a SP-delimited header field from `s`, returning `(field_value, remainder)`.
/// A bare `-` is mapped to `None` (the RFC 5424 nil value).
fn split_header_field<'a>(
    s: &'a str,
    field_name: &'static str,
) -> Result<(Option<String>, &'a str), ParseError> {
    let (raw, rest) = s
        .split_once(' ')
        .ok_or_else(|| ParseError::MalformedHeader(format!("expected {field_name}")))?;
    Ok((nil_to_option(raw), rest))
}

/// Map the RFC 5424 nil value (`-`) to `None`; everything else becomes `Some`.
fn nil_to_option(s: &str) -> Option<String> {
    if s == "-" {
        None
    } else {
        Some(s.to_owned())
    }
}

/// Parse the STRUCTURED-DATA field and the optional MSG that follows it.
///
/// STRUCTURED-DATA is either:
/// - `"-"` — the nil value, followed optionally by ` MSG`
/// - One or more `[SD-ID ...]` blocks, followed optionally by ` MSG`
///
/// Escape sequences inside SD param values (`\"`, `\\`, `\]`) are respected
/// when scanning for the closing `]` of each element.
fn parse_structured_data_and_msg(s: &str) -> Result<(String, String), ParseError> {
    if let Some(rest) = s.strip_prefix('-') {
        let msg = rest.strip_prefix(' ').unwrap_or("").to_owned();
        return Ok(("-".to_owned(), msg));
    }

    if !s.starts_with('[') {
        return Err(ParseError::MalformedHeader(
            "STRUCTURED-DATA must start with '-' or '['".into(),
        ));
    }

    let sd_end = find_structured_data_end(s)?;
    let structured_data = s[..sd_end].to_owned();
    let msg = s[sd_end..].strip_prefix(' ').unwrap_or("").to_owned();
    Ok((structured_data, msg))
}

/// Return the byte offset just past the last SD-ELEMENT in `s`.
///
/// Scans through balanced `[...]` blocks, honouring escape sequences inside
/// double-quoted param values so that `\]` is not treated as a closing bracket.
fn find_structured_data_end(s: &str) -> Result<usize, ParseError> {
    let bytes = s.as_bytes();
    let mut i = 0;

    while i < bytes.len() && bytes[i] == b'[' {
        i += 1; // consume '['
        let mut in_param_value = false;
        let mut escaped = false;

        loop {
            if i >= bytes.len() {
                return Err(ParseError::MalformedHeader(
                    "unterminated SD-ELEMENT (missing ']')".into(),
                ));
            }
            if escaped {
                escaped = false;
                i += 1;
                continue;
            }
            match bytes[i] {
                b'\\' => escaped = true,
                b'"' => in_param_value = !in_param_value,
                b']' if !in_param_value => {
                    i += 1; // consume ']'
                    break;
                }
                _ => {}
            }
            i += 1;
        }
        // After ']', either another '[' starts the next element, a ' ' precedes
        // MSG, or we are at end-of-string. Both are handled by the while condition.
    }

    Ok(i)
}

// ── RFC 5424 content validators ───────────────────────────────────────────────

/// Validate a header field that must consist of 1–`max_len` PRINTUSASCII chars.
///
/// PRINTUSASCII is the set of visible US-ASCII characters: decimal 33–126.
/// RFC 5424 §6.2.2 applies this constraint to HOSTNAME, APP-NAME, PROCID, and
/// MSGID.
fn validate_printusascii_field(
    s: &str,
    field: &'static str,
    max_len: usize,
) -> Result<(), ParseError> {
    if s.is_empty() {
        return Err(ParseError::InvalidField {
            field,
            reason: "must not be empty".into(),
        });
    }
    if s.len() > max_len {
        return Err(ParseError::InvalidField {
            field,
            reason: format!("exceeds {max_len}-character limit (got {})", s.len()),
        });
    }
    for c in s.chars() {
        if !matches!(c as u32, 33..=126) {
            return Err(ParseError::InvalidField {
                field,
                reason: format!("contains non-printable ASCII character {c:?}"),
            });
        }
    }
    Ok(())
}

/// Validate a TIMESTAMP value per RFC 5424 §6.2.3.
///
/// Accepts `YYYY-MM-DDThh:mm:ss[.{1,6}frac](Z|+/-hh:mm)`.
/// All components are range-checked; leap seconds (second = 60) are allowed.
fn validate_timestamp(s: &str) -> Result<(), ParseError> {
    let b = s.as_bytes();

    // Minimum: YYYY-MM-DDThh:mm:ssZ = 20 bytes.
    if b.len() < 20 {
        return Err(ts_err("too short for RFC 5424 timestamp"));
    }

    // Structural format: YYYY-MM-DDThh:mm:ss
    if !all_digits(&b[0..4])
        || b[4] != b'-'
        || !all_digits(&b[5..7])
        || b[7] != b'-'
        || !all_digits(&b[8..10])
        || b[10] != b'T'
        || !all_digits(&b[11..13])
        || b[13] != b':'
        || !all_digits(&b[14..16])
        || b[16] != b':'
        || !all_digits(&b[17..19])
    {
        return Err(ts_err("does not match YYYY-MM-DDThh:mm:ss format"));
    }

    // Range checks.
    let month = parse2digit(&b[5..7]);
    let day = parse2digit(&b[8..10]);
    let hour = parse2digit(&b[11..13]);
    let minute = parse2digit(&b[14..16]);
    let second = parse2digit(&b[17..19]);

    if !(1..=12).contains(&month) {
        return Err(ts_err("month out of range (01–12)"));
    }
    if !(1..=31).contains(&day) {
        return Err(ts_err("day out of range (01–31)"));
    }
    if hour > 23 {
        return Err(ts_err("hour out of range (00–23)"));
    }
    if minute > 59 {
        return Err(ts_err("minute out of range (00–59)"));
    }
    if second > 60 {
        return Err(ts_err("second out of range (00–60)"));
    }

    let mut pos = 19;

    // Optional fractional seconds: '.' followed by 1–6 digits.
    if pos < b.len() && b[pos] == b'.' {
        pos += 1;
        let frac_start = pos;
        while pos < b.len() && b[pos].is_ascii_digit() {
            pos += 1;
        }
        let frac_len = pos - frac_start;
        if !(1..=6).contains(&frac_len) {
            return Err(ts_err("fractional seconds must be 1–6 digits"));
        }
    }

    // Timezone: 'Z' or '+'/'-' hh ':' mm.
    if pos >= b.len() {
        return Err(ts_err("missing timezone"));
    }
    if b[pos] == b'Z' {
        pos += 1;
    } else if b[pos] == b'+' || b[pos] == b'-' {
        pos += 1;
        if pos + 5 > b.len() {
            return Err(ts_err("timezone offset too short"));
        }
        if !all_digits(&b[pos..pos + 2]) || b[pos + 2] != b':' || !all_digits(&b[pos + 3..pos + 5])
        {
            return Err(ts_err("timezone offset does not match hh:mm format"));
        }
        let tz_hour = parse2digit(&b[pos..pos + 2]);
        let tz_min = parse2digit(&b[pos + 3..pos + 5]);
        if tz_hour > 23 || tz_min > 59 {
            return Err(ts_err("timezone offset out of range"));
        }
        pos += 5;
    } else {
        return Err(ts_err(
            "invalid timezone indicator (expected 'Z' or '+'/'-')",
        ));
    }

    if pos != b.len() {
        return Err(ts_err("trailing characters after timezone"));
    }

    Ok(())
}

fn ts_err(reason: &str) -> ParseError {
    ParseError::InvalidField {
        field: "TIMESTAMP",
        reason: reason.into(),
    }
}

fn all_digits(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(u8::is_ascii_digit)
}

fn parse2digit(b: &[u8]) -> u8 {
    (b[0] - b'0') * 10 + (b[1] - b'0')
}

/// Validate the content of a STRUCTURED-DATA string per RFC 5424 §6.3.
///
/// Checks that every SD-ID and PARAM-NAME is 1–32 PRINTUSASCII characters
/// (excluding `=`, `]`, and `"`), and that every PARAM-NAME is followed by a
/// quoted PARAM-VALUE.  The bracket structure has already been validated by
/// [`parse_structured_data_and_msg`].
fn validate_structured_data_content(sd: &str) -> Result<(), ParseError> {
    if sd == "-" {
        return Ok(());
    }

    let b = sd.as_bytes();
    let mut pos = 0;

    while pos < b.len() {
        // Each SD-ELEMENT starts with '[' (guaranteed by prior structural parse).
        pos += 1; // consume '['

        // SD-ID: bytes up to the first SP or ']'.
        let id_start = pos;
        while pos < b.len() && b[pos] != b' ' && b[pos] != b']' {
            pos += 1;
        }
        validate_sd_name(&sd[id_start..pos], "SD-ID")?;

        // Zero or more " PARAM-NAME="PARAM-VALUE"" entries.
        while pos < b.len() && b[pos] == b' ' {
            pos += 1; // consume leading SP

            // ']' directly after SP is non-standard but handled gracefully.
            if pos < b.len() && b[pos] == b']' {
                break;
            }

            // PARAM-NAME: bytes up to '=' (or ']' on malformed input).
            let name_start = pos;
            while pos < b.len() && b[pos] != b'=' && b[pos] != b']' {
                pos += 1;
            }
            if pos >= b.len() || b[pos] != b'=' {
                return Err(ParseError::InvalidField {
                    field: "STRUCTURED-DATA",
                    reason: "PARAM-NAME not followed by '='".into(),
                });
            }
            validate_sd_name(&sd[name_start..pos], "PARAM-NAME")?;
            pos += 1; // consume '='

            if pos >= b.len() || b[pos] != b'"' {
                return Err(ParseError::InvalidField {
                    field: "STRUCTURED-DATA",
                    reason: "PARAM-VALUE must be quoted".into(),
                });
            }
            pos += 1; // consume opening '"'

            // Skip PARAM-VALUE, respecting backslash escape sequences.
            let mut escaped = false;
            loop {
                if pos >= b.len() {
                    return Err(ParseError::InvalidField {
                        field: "STRUCTURED-DATA",
                        reason: "unterminated PARAM-VALUE".into(),
                    });
                }
                let byte = b[pos];
                pos += 1;
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    break; // closing '"'
                }
            }
        }

        // Consume the closing ']'.
        if pos < b.len() && b[pos] == b']' {
            pos += 1;
        }
    }

    Ok(())
}

/// Validate an SD-ID or PARAM-NAME token per RFC 5424 §6.3.
///
/// Must be 1–32 PRINTUSASCII characters excluding `=`, `]`, and `"`.
fn validate_sd_name(s: &str, field: &'static str) -> Result<(), ParseError> {
    if s.is_empty() {
        return Err(ParseError::InvalidField {
            field,
            reason: "must not be empty".into(),
        });
    }
    if s.len() > 32 {
        return Err(ParseError::InvalidField {
            field,
            reason: format!("exceeds 32-character limit (got {})", s.len()),
        });
    }
    for c in s.chars() {
        if !matches!(c as u32, 33..=126) || matches!(c, '=' | ']' | '"') {
            return Err(ParseError::InvalidField {
                field,
                reason: format!("contains invalid character {c:?}"),
            });
        }
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "unwrap is appropriate in test assertions"
)]
mod tests {
    use super::*;

    // ── Priority ─────────────────────────────────────────────────────────────

    #[test]
    fn priority_round_trip() {
        for pri in 0u8..=191 {
            let p = Priority::from_integer(pri).unwrap();
            assert_eq!(p.as_integer(), pri);
        }
    }

    #[test]
    fn priority_rejects_out_of_range() {
        assert!(Priority::from_integer(192).is_err());
        assert!(Priority::from_integer(255).is_err());
    }

    #[test]
    fn priority_local7_info() {
        // Local7 = 23, Info = 6 → PRI = 23*8+6 = 190
        let p = Priority::from_integer(190).unwrap();
        assert_eq!(p.facility, Facility::Local7);
        assert_eq!(p.severity, Severity::Info);
        assert_eq!(p.as_integer(), 190);
    }

    // ── SyslogMessage — valid input ──────────────────────────────────────────

    #[test]
    fn parse_full_message() {
        let raw = r#"<190>1 2026-05-14T12:00:00Z myhost myapp 7823 REQUEST - {"user_id":42}"#;
        let msg = SyslogMessage::parse(raw).unwrap();
        assert_eq!(msg.priority.as_integer(), 190);
        assert_eq!(msg.timestamp.as_deref(), Some("2026-05-14T12:00:00Z"));
        assert_eq!(msg.hostname.as_deref(), Some("myhost"));
        assert_eq!(msg.app_name.as_deref(), Some("myapp"));
        assert_eq!(msg.proc_id.as_deref(), Some("7823"));
        assert_eq!(msg.msg_id.as_deref(), Some("REQUEST"));
        assert_eq!(msg.structured_data, "-");
        assert_eq!(msg.msg, r#"{"user_id":42}"#);
    }

    #[test]
    fn parse_nil_fields() {
        let raw = "<13>1 - - - - - - hello";
        let msg = SyslogMessage::parse(raw).unwrap();
        assert!(msg.timestamp.is_none());
        assert!(msg.hostname.is_none());
        assert!(msg.app_name.is_none());
        assert!(msg.proc_id.is_none());
        assert!(msg.msg_id.is_none());
        assert_eq!(msg.structured_data, "-");
        assert_eq!(msg.msg, "hello");
    }

    #[test]
    fn parse_empty_msg() {
        // No MSG field at all (SD is nil and nothing follows)
        let raw = "<13>1 - - - - - -";
        let msg = SyslogMessage::parse(raw).unwrap();
        assert_eq!(msg.msg, "");
    }

    #[test]
    fn parse_msg_with_spaces_and_embedded_newline() {
        // Octet-count framing delivers the full message with the embedded newline
        let raw = "<190>1 2026-05-14T12:00:00Z host app 1 ID - {\"line\":\"a\\nb\"}";
        let msg = SyslogMessage::parse(raw).unwrap();
        assert_eq!(msg.msg, r#"{"line":"a\nb"}"#);
    }

    #[test]
    fn parse_structured_data_single_element() {
        let raw = r#"<14>1 - host app 1 ID [exampleSDID@32473 iut="3" eventSource="App"] msg"#;
        let msg = SyslogMessage::parse(raw).unwrap();
        assert_eq!(
            msg.structured_data,
            r#"[exampleSDID@32473 iut="3" eventSource="App"]"#
        );
        assert_eq!(msg.msg, "msg");
    }

    #[test]
    fn parse_structured_data_multiple_elements() {
        let raw = r#"<14>1 - - - - - [a x="1"][b y="2"] body"#;
        let msg = SyslogMessage::parse(raw).unwrap();
        assert_eq!(msg.structured_data, r#"[a x="1"][b y="2"]"#);
        assert_eq!(msg.msg, "body");
    }

    #[test]
    fn parse_structured_data_escaped_bracket_in_value() {
        // '\]' inside a param value must NOT end the SD element
        let raw = r#"<14>1 - - - - - [id val="\]"] payload"#;
        let msg = SyslogMessage::parse(raw).unwrap();
        assert_eq!(msg.structured_data, r#"[id val="\]"]"#);
        assert_eq!(msg.msg, "payload");
    }

    #[test]
    fn parse_strips_trailing_newline() {
        let raw = "<13>1 - - - - - - body\n";
        let msg = SyslogMessage::parse(raw).unwrap();
        assert_eq!(msg.msg, "body");
    }

    #[test]
    fn parse_strips_trailing_nul() {
        let raw = "<13>1 - - - - - - body\0";
        let msg = SyslogMessage::parse(raw).unwrap();
        assert_eq!(msg.msg, "body");
    }

    // ── SyslogMessage — error cases ──────────────────────────────────────────

    #[test]
    fn parse_rejects_missing_pri_open() {
        assert!(SyslogMessage::parse("13>1 - - - - - - x").is_err());
    }

    #[test]
    fn parse_rejects_missing_pri_close() {
        assert!(SyslogMessage::parse("<131 - - - - - - x").is_err());
    }

    #[test]
    fn parse_rejects_pri_out_of_range() {
        let result = SyslogMessage::parse("<192>1 - - - - - - x");
        assert!(matches!(result, Err(ParseError::InvalidPriority(_))));
    }

    #[test]
    fn parse_rejects_non_numeric_pri() {
        assert!(SyslogMessage::parse("<abc>1 - - - - - - x").is_err());
    }

    #[test]
    fn parse_rejects_wrong_version() {
        assert!(SyslogMessage::parse("<13>2 - - - - - - x").is_err());
    }

    #[test]
    fn parse_rejects_truncated_header() {
        // Missing MSGID and STRUCTURED-DATA
        assert!(SyslogMessage::parse("<13>1 - - - -").is_err());
    }

    #[test]
    fn parse_rejects_unterminated_sd_element() {
        assert!(SyslogMessage::parse("<13>1 - - - - - [unterminated").is_err());
    }

    // ── Display round-trip ───────────────────────────────────────────────────

    #[test]
    fn display_round_trip_full() {
        let raw = r#"<190>1 2026-05-14T12:00:00Z myhost myapp 7823 REQUEST - {"k":"v"}"#;
        let msg = SyslogMessage::parse(raw).unwrap();
        let rendered = msg.to_string();
        assert_eq!(rendered, raw);
        // Parse again to confirm idempotency
        let msg2 = SyslogMessage::parse(&rendered).unwrap();
        assert_eq!(msg, msg2);
    }

    #[test]
    fn display_round_trip_nil_fields() {
        let raw = "<13>1 - - - - - - body";
        let msg = SyslogMessage::parse(raw).unwrap();
        assert_eq!(msg.to_string(), raw);
    }

    #[test]
    fn display_round_trip_no_msg() {
        let raw = "<13>1 - - - - - -";
        let msg = SyslogMessage::parse(raw).unwrap();
        assert_eq!(msg.to_string(), raw);
    }

    // ── TIMESTAMP validation ──────────────────────────────────────────────────

    #[test]
    fn parse_accepts_timestamp_utc_z() {
        let raw = "<13>1 2026-05-18T09:27:03Z - - - - - body";
        assert!(SyslogMessage::parse(raw).is_ok());
    }

    #[test]
    fn parse_accepts_timestamp_positive_offset() {
        let raw = "<13>1 2026-05-18T14:57:03+05:30 - - - - - body";
        assert!(SyslogMessage::parse(raw).is_ok());
    }

    #[test]
    fn parse_accepts_timestamp_negative_offset() {
        let raw = "<13>1 2026-05-18T04:27:03-05:00 - - - - - body";
        assert!(SyslogMessage::parse(raw).is_ok());
    }

    #[test]
    fn parse_accepts_timestamp_fractional_seconds() {
        let raw = "<13>1 2026-05-18T09:27:03.874960+00:00 - - - - - body";
        assert!(SyslogMessage::parse(raw).is_ok());
    }

    #[test]
    fn parse_accepts_timestamp_single_fraction_digit() {
        let raw = "<13>1 2026-05-18T09:27:03.1Z - - - - - body";
        assert!(SyslogMessage::parse(raw).is_ok());
    }

    #[test]
    fn parse_accepts_timestamp_leap_second() {
        // second = 60 is valid for leap seconds per RFC 5424.
        let raw = "<13>1 2026-06-30T23:59:60Z - - - - - body";
        assert!(SyslogMessage::parse(raw).is_ok());
    }

    #[test]
    fn parse_rejects_timestamp_too_short() {
        let raw = "<13>1 2026-05-18 - - - - - body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField {
                field: "TIMESTAMP",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_timestamp_invalid_format() {
        let raw = "<13>1 not-a-timestamp - - - - - body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField {
                field: "TIMESTAMP",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_timestamp_month_out_of_range() {
        let raw = "<13>1 2026-13-01T00:00:00Z - - - - - body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField {
                field: "TIMESTAMP",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_timestamp_day_zero() {
        let raw = "<13>1 2026-05-00T00:00:00Z - - - - - body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField {
                field: "TIMESTAMP",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_timestamp_day_out_of_range() {
        let raw = "<13>1 2026-05-32T00:00:00Z - - - - - body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField {
                field: "TIMESTAMP",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_timestamp_hour_out_of_range() {
        let raw = "<13>1 2026-05-18T24:00:00Z - - - - - body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField {
                field: "TIMESTAMP",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_timestamp_minute_out_of_range() {
        let raw = "<13>1 2026-05-18T00:60:00Z - - - - - body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField {
                field: "TIMESTAMP",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_timestamp_second_out_of_range() {
        // 61 is not allowed; only 60 (leap second) is.
        let raw = "<13>1 2026-05-18T00:00:61Z - - - - - body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField {
                field: "TIMESTAMP",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_timestamp_missing_timezone() {
        // No 'Z' or offset after seconds — treated as missing timezone.
        let raw = "<13>1 2026-05-18T09:27:03 - - - - - body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField {
                field: "TIMESTAMP",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_timestamp_fraction_too_long() {
        // 7 fractional digits exceed the RFC 5424 limit of 6.
        let raw = "<13>1 2026-05-18T09:27:03.1234567Z - - - - - body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField {
                field: "TIMESTAMP",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_timestamp_trailing_chars() {
        let raw = "<13>1 2026-05-18T09:27:03ZEXTRA - - - - - body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField {
                field: "TIMESTAMP",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_timestamp_tz_offset_out_of_range() {
        let raw = "<13>1 2026-05-18T09:27:03+24:00 - - - - - body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField {
                field: "TIMESTAMP",
                ..
            }
        ));
    }

    // ── HOSTNAME / APP-NAME / PROCID / MSGID validation ───────────────────────

    #[test]
    fn parse_accepts_hostname_max_length() {
        let hostname = "a".repeat(255);
        let raw = format!("<13>1 - {hostname} - - - - body");
        assert!(SyslogMessage::parse(&raw).is_ok());
    }

    #[test]
    fn parse_rejects_hostname_too_long() {
        let hostname = "a".repeat(256);
        let raw = format!("<13>1 - {hostname} - - - - body");
        assert!(matches!(
            SyslogMessage::parse(&raw).unwrap_err(),
            ParseError::InvalidField {
                field: "HOSTNAME",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_hostname_non_printable_ascii() {
        // SOH (0x01) is below the PRINTUSASCII range (33–126).
        let raw = "<13>1 - host\x01name - - - - body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField {
                field: "HOSTNAME",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_hostname_del_char() {
        // DEL (0x7F = 127) is above PRINTUSASCII range (33–126).
        let raw = "<13>1 - host\x7fname - - - - body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField {
                field: "HOSTNAME",
                ..
            }
        ));
    }

    #[test]
    fn parse_accepts_app_name_max_length() {
        let name = "a".repeat(48);
        let raw = format!("<13>1 - - {name} - - - body");
        assert!(SyslogMessage::parse(&raw).is_ok());
    }

    #[test]
    fn parse_rejects_app_name_too_long() {
        let name = "a".repeat(49);
        let raw = format!("<13>1 - - {name} - - - body");
        assert!(matches!(
            SyslogMessage::parse(&raw).unwrap_err(),
            ParseError::InvalidField {
                field: "APP-NAME",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_app_name_non_printable_ascii() {
        let raw = "<13>1 - - app\tname - - - body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField {
                field: "APP-NAME",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_procid_too_long() {
        let procid = "1".repeat(129);
        let raw = format!("<13>1 - - - {procid} - - body");
        assert!(matches!(
            SyslogMessage::parse(&raw).unwrap_err(),
            ParseError::InvalidField {
                field: "PROCID",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_msgid_too_long() {
        let msgid = "A".repeat(33);
        let raw = format!("<13>1 - - - - {msgid} - body");
        assert!(matches!(
            SyslogMessage::parse(&raw).unwrap_err(),
            ParseError::InvalidField { field: "MSGID", .. }
        ));
    }

    // ── STRUCTURED-DATA content validation ────────────────────────────────────

    #[test]
    fn parse_rejects_sd_id_too_long() {
        let long_id = "a".repeat(33);
        let raw = format!("<13>1 - - - - - [{long_id}] body");
        assert!(matches!(
            SyslogMessage::parse(&raw).unwrap_err(),
            ParseError::InvalidField { field: "SD-ID", .. }
        ));
    }

    #[test]
    fn parse_rejects_sd_id_with_equals_sign() {
        let raw = r"<13>1 - - - - - [bad=id] body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField { field: "SD-ID", .. }
        ));
    }

    #[test]
    fn parse_rejects_sd_id_with_double_quote() {
        // '"' in SD-ID position causes the structural parser to treat the rest as
        // a param value, so the closing ']' is consumed as value content and the
        // element is never terminated — MalformedHeader is the correct outcome.
        let raw = "<13>1 - - - - - [bad\"id] body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::MalformedHeader(..)
        ));
    }

    #[test]
    fn parse_rejects_sd_id_empty() {
        // An SD-ELEMENT with only spaces before the closing ']' has an empty SD-ID.
        // The structural parse succeeds; the content validator must catch it.
        let raw = "<13>1 - - - - - [ ] body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField { field: "SD-ID", .. }
        ));
    }

    #[test]
    fn parse_rejects_param_name_too_long() {
        let long_name = "a".repeat(33);
        let raw = format!(r#"<13>1 - - - - - [id {long_name}="v"] body"#);
        assert!(matches!(
            SyslogMessage::parse(&raw).unwrap_err(),
            ParseError::InvalidField {
                field: "PARAM-NAME",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_param_name_with_equals_sign() {
        // The PARAM-NAME scanner stops at the first '=', so name='a' passes.
        // After consuming '=', the value starts with 'b' (not '"'), so the content
        // validator rejects the element with an unquoted-value error under STRUCTURED-DATA.
        let raw = r#"<13>1 - - - - - [id a=b="v"] body"#;
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField {
                field: "STRUCTURED-DATA",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_param_missing_equals() {
        // SD-ELEMENT where a param word has no '=' — catches structurally accepted
        // but content-invalid inputs like "[id name]".
        let raw = "<13>1 - - - - - [id name] body";
        assert!(matches!(
            SyslogMessage::parse(raw).unwrap_err(),
            ParseError::InvalidField {
                field: "STRUCTURED-DATA",
                ..
            }
        ));
    }
}
