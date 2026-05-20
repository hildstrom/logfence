//! Framing codecs for syslog over stream sockets.
//!
//! Two modes defined by RFC 6587 are supported:
//!
//! - [`OctetCountCodec`] — octet-count framing (§3.4.1, preferred).
//!   Each message is prefixed with its decimal byte count and a space:
//!   `"<count> <message>"`.
//!
//! - [`DelimiterCodec`] — non-transparent framing (§3.4.2).
//!   Each message is terminated by a delimiter byte (typically `\n` or `\0`).
//!
//! Both codecs implement `tokio_util::codec::{Decoder, Encoder}`, producing
//! and consuming [`SyslogMessage`] values.

use bytes::{Buf, BufMut, BytesMut};
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

use crate::syslog::{ParseError, SyslogMessage};

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors produced by the framing codecs.
#[derive(Debug, Error)]
pub enum FrameError {
    /// The encoded or decoded message exceeds the configured size limit.
    #[error("message size {got} bytes exceeds maximum of {max} bytes")]
    MessageTooLarge { max: usize, got: usize },

    /// The octet-count prefix is not a valid ASCII decimal integer.
    #[error("invalid octet-count prefix")]
    InvalidOctetCount,

    /// The frame bytes are not valid UTF-8.
    #[error("frame is not valid UTF-8")]
    InvalidUtf8,

    /// The octet-count prefix is so long it cannot be a valid decimal number.
    #[error("octet-count prefix exceeds {MAX_DIGITS} digits")]
    OctetCountPrefixTooLong,

    /// The syslog message failed to parse.
    #[error("syslog parse error: {0}")]
    Parse(#[from] ParseError),

    /// An underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Maximum number of ASCII decimal digits allowed in an octet-count prefix.
/// `usize::MAX` on a 64-bit host is 20 digits; we allow one extra for safety.
const MAX_DIGITS: usize = 20;

// ── OctetCountCodec ───────────────────────────────────────────────────────────

/// RFC 6587 §3.4.1 octet-count framing codec.
///
/// Each message on the wire is:
/// ```text
/// <decimal-length> SP <syslog-message>
/// ```
///
/// This framing is transparent to message content — messages may contain any
/// byte sequence including newlines and NULs.
#[derive(Debug, Clone)]
pub struct OctetCountCodec {
    /// Maximum accepted message size in bytes (protects against malformed input).
    max_size: usize,
}

impl OctetCountCodec {
    /// Create a codec with the given maximum message size.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self { max_size }
    }
}

impl Decoder for OctetCountCodec {
    type Item = SyslogMessage;
    type Error = FrameError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Locate the SP that separates the length prefix from the message body.
        let Some(sp_pos) = buf.iter().position(|&b| b == b' ') else {
            // No SP yet — check that the length prefix is not absurdly long.
            if buf.len() > MAX_DIGITS {
                return Err(FrameError::OctetCountPrefixTooLong);
            }
            return Ok(None);
        };

        // Parse the decimal length prefix.
        let len_str =
            std::str::from_utf8(&buf[..sp_pos]).map_err(|_| FrameError::InvalidOctetCount)?;
        let msg_len: usize = len_str.parse().map_err(|_| FrameError::InvalidOctetCount)?;

        if msg_len > self.max_size {
            return Err(FrameError::MessageTooLarge {
                max: self.max_size,
                got: msg_len,
            });
        }

        // Wait until the full message body is available.
        let total = sp_pos + 1 + msg_len; // length-prefix + SP + body
        if buf.len() < total {
            buf.reserve(total - buf.len());
            return Ok(None);
        }

        // Consume the length prefix and SP.
        buf.advance(sp_pos + 1);
        // Extract exactly `msg_len` bytes.
        let msg_bytes = buf.split_to(msg_len);

        let msg_str = std::str::from_utf8(&msg_bytes).map_err(|_| FrameError::InvalidUtf8)?;
        let message = SyslogMessage::parse(msg_str)?;
        Ok(Some(message))
    }
}

impl Encoder<SyslogMessage> for OctetCountCodec {
    type Error = FrameError;

    fn encode(&mut self, item: SyslogMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let msg = item.to_string();
        let len = msg.len();
        if len > self.max_size {
            return Err(FrameError::MessageTooLarge {
                max: self.max_size,
                got: len,
            });
        }
        // Reserve space for "<len> <msg>" in a single allocation.
        let prefix = format!("{len} ");
        dst.reserve(prefix.len() + len);
        dst.put_slice(prefix.as_bytes());
        dst.put_slice(msg.as_bytes());
        Ok(())
    }
}

// ── DelimiterCodec ────────────────────────────────────────────────────────────

/// RFC 6587 §3.4.2 non-transparent (delimiter) framing codec.
///
/// Each message on the wire is terminated by a single delimiter byte.
/// The most common delimiters are `b'\n'` (newline) and `b'\0'` (NUL).
///
/// **Note:** this framing is not transparent — messages must not contain the
/// delimiter byte. JSON payloads with embedded newlines require
/// [`OctetCountCodec`] instead.
#[derive(Debug, Clone)]
pub struct DelimiterCodec {
    delimiter: u8,
    max_size: usize,
}

impl DelimiterCodec {
    /// Create a codec using the given `delimiter` byte and maximum message size.
    #[must_use]
    pub fn new(delimiter: u8, max_size: usize) -> Self {
        Self {
            delimiter,
            max_size,
        }
    }

    /// Convenience constructor for newline (`\n`) delimited framing.
    #[must_use]
    pub fn newline(max_size: usize) -> Self {
        Self::new(b'\n', max_size)
    }
}

impl Decoder for DelimiterCodec {
    type Item = SyslogMessage;
    type Error = FrameError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(pos) = buf.iter().position(|&b| b == self.delimiter) else {
            if buf.len() > self.max_size {
                return Err(FrameError::MessageTooLarge {
                    max: self.max_size,
                    got: buf.len(),
                });
            }
            return Ok(None);
        };

        if pos > self.max_size {
            return Err(FrameError::MessageTooLarge {
                max: self.max_size,
                got: pos,
            });
        }

        let msg_bytes = buf.split_to(pos);
        buf.advance(1); // consume the delimiter

        let msg_str = std::str::from_utf8(&msg_bytes).map_err(|_| FrameError::InvalidUtf8)?;
        let message = SyslogMessage::parse(msg_str)?;
        Ok(Some(message))
    }
}

impl Encoder<SyslogMessage> for DelimiterCodec {
    type Error = FrameError;

    fn encode(&mut self, item: SyslogMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let msg = item.to_string();
        let len = msg.len();
        if len > self.max_size {
            return Err(FrameError::MessageTooLarge {
                max: self.max_size,
                got: len,
            });
        }
        dst.reserve(len + 1);
        dst.put_slice(msg.as_bytes());
        dst.put_u8(self.delimiter);
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "unwrap is appropriate in test assertions"
)]
mod tests {
    use super::*;

    fn sample_msg() -> SyslogMessage {
        SyslogMessage::parse(r#"<190>1 2026-05-14T12:00:00Z host app 42 ID - {"k":"v"}"#).unwrap()
    }

    fn all_nil_msg() -> SyslogMessage {
        SyslogMessage::parse("<13>1 - - - - - - body").unwrap()
    }

    // ── OctetCountCodec — encode ──────────────────────────────────────────────

    #[test]
    fn octet_encode_format() {
        let mut codec = OctetCountCodec::new(65536);
        let mut buf = BytesMut::new();
        let msg = sample_msg();
        let expected_body = msg.to_string();
        codec.encode(msg, &mut buf).unwrap();

        let frame = std::str::from_utf8(&buf).unwrap();
        let (count_str, body) = frame.split_once(' ').unwrap();
        assert_eq!(count_str.parse::<usize>().unwrap(), expected_body.len());
        assert_eq!(body, expected_body);
    }

    #[test]
    fn octet_encode_rejects_oversized() {
        let mut codec = OctetCountCodec::new(10); // tiny limit
        let err = codec
            .encode(sample_msg(), &mut BytesMut::new())
            .unwrap_err();
        assert!(matches!(err, FrameError::MessageTooLarge { .. }));
    }

    // ── OctetCountCodec — decode ──────────────────────────────────────────────

    #[test]
    fn octet_decode_single_frame() {
        let mut codec = OctetCountCodec::new(65536);
        let msg = sample_msg();
        let wire = format!("{} {}", msg.to_string().len(), msg);
        let mut buf = BytesMut::from(wire.as_str());

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, msg);
        assert!(buf.is_empty(), "buffer should be fully consumed");
    }

    #[test]
    fn octet_decode_two_frames_in_one_buffer() {
        let mut codec = OctetCountCodec::new(65536);
        let m1 = sample_msg();
        let m2 = all_nil_msg();
        let wire = format!(
            "{} {}{} {}",
            m1.to_string().len(),
            m1,
            m2.to_string().len(),
            m2
        );
        let mut buf = BytesMut::from(wire.as_str());

        let d1 = codec.decode(&mut buf).unwrap().unwrap();
        let d2 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(d1, m1);
        assert_eq!(d2, m2);
        assert!(buf.is_empty());
    }

    #[test]
    fn octet_decode_partial_frame_returns_none() {
        let mut codec = OctetCountCodec::new(65536);
        let msg = sample_msg();
        let full_wire = format!("{} {}", msg.to_string().len(), msg);
        // Deliver only the first half of the frame.
        let partial = &full_wire[..full_wire.len() / 2];
        let mut buf = BytesMut::from(partial);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn octet_decode_partial_length_prefix_returns_none() {
        let mut codec = OctetCountCodec::new(65536);
        // Only the length digits, no SP yet.
        let mut buf = BytesMut::from("123");
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn octet_decode_rejects_oversized() {
        let mut codec = OctetCountCodec::new(10);
        let msg = sample_msg();
        let wire = format!("{} {}", msg.to_string().len(), msg);
        let mut buf = BytesMut::from(wire.as_str());
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, FrameError::MessageTooLarge { .. }));
    }

    #[test]
    fn octet_decode_rejects_invalid_count() {
        let mut codec = OctetCountCodec::new(65536);
        let mut buf = BytesMut::from("abc <190>1 - - - - - - x");
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, FrameError::InvalidOctetCount));
    }

    #[test]
    fn octet_decode_rejects_prefix_too_long() {
        let mut codec = OctetCountCodec::new(65536);
        // 21 digits with no SP — exceeds MAX_DIGITS
        let digits = "1".repeat(MAX_DIGITS + 1);
        let mut buf = BytesMut::from(digits.as_str());
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, FrameError::OctetCountPrefixTooLong));
    }

    #[test]
    fn octet_encode_decode_round_trip() {
        let mut codec = OctetCountCodec::new(65536);
        let msg = sample_msg();
        let mut buf = BytesMut::new();
        codec.encode(msg.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, msg);
        assert!(buf.is_empty());
    }

    // MSG containing an embedded newline is transparent with octet-count framing.
    #[test]
    fn octet_encode_decode_embedded_newline() {
        let raw = "<190>1 2026-05-14T00:00:00Z h a 1 ID - {\"line\":\"a\\nb\"}";
        let msg = SyslogMessage::parse(raw).unwrap();
        let mut codec = OctetCountCodec::new(65536);
        let mut buf = BytesMut::new();
        codec.encode(msg.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, msg);
    }

    // ── DelimiterCodec — encode ───────────────────────────────────────────────

    #[test]
    fn delimiter_encode_appends_newline() {
        let mut codec = DelimiterCodec::newline(65536);
        let msg = sample_msg();
        let expected_body = msg.to_string();
        let mut buf = BytesMut::new();
        codec.encode(msg, &mut buf).unwrap();
        let frame = std::str::from_utf8(&buf).unwrap();
        assert_eq!(frame, format!("{expected_body}\n"));
    }

    #[test]
    fn delimiter_encode_rejects_oversized() {
        let mut codec = DelimiterCodec::newline(10);
        let err = codec
            .encode(sample_msg(), &mut BytesMut::new())
            .unwrap_err();
        assert!(matches!(err, FrameError::MessageTooLarge { .. }));
    }

    // ── DelimiterCodec — decode ───────────────────────────────────────────────

    #[test]
    fn delimiter_decode_single_frame() {
        let mut codec = DelimiterCodec::newline(65536);
        let msg = all_nil_msg();
        let wire = format!("{msg}\n");
        let mut buf = BytesMut::from(wire.as_str());
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, msg);
        assert!(buf.is_empty());
    }

    #[test]
    fn delimiter_decode_two_frames() {
        let mut codec = DelimiterCodec::newline(65536);
        let m1 = sample_msg();
        let m2 = all_nil_msg();
        let wire = format!("{m1}\n{m2}\n");
        let mut buf = BytesMut::from(wire.as_str());
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap(), m1);
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap(), m2);
        assert!(buf.is_empty());
    }

    #[test]
    fn delimiter_decode_partial_returns_none() {
        let mut codec = DelimiterCodec::newline(65536);
        let msg = sample_msg();
        let partial = msg.to_string(); // no trailing newline
        let mut buf = BytesMut::from(partial.as_str());
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn delimiter_decode_rejects_oversized() {
        let mut codec = DelimiterCodec::newline(10);
        let msg = sample_msg();
        let wire = format!("{msg}\n");
        let mut buf = BytesMut::from(wire.as_str());
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, FrameError::MessageTooLarge { .. }));
    }

    #[test]
    fn delimiter_encode_decode_round_trip() {
        let mut codec = DelimiterCodec::newline(65536);
        let msg = sample_msg();
        let mut buf = BytesMut::new();
        codec.encode(msg.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, msg);
        assert!(buf.is_empty());
    }
}
