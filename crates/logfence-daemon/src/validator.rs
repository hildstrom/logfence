//! JSON payload validation for incoming syslog messages.
//!
//! [`Validator`] checks that the `msg` field of a [`SyslogMessage`] is a valid
//! JSON object and, when schemas are configured, that it matches at least one
//! of the loaded JSON Schema documents.

use std::collections::HashMap;

use jsonschema::Validator as JsonSchemaValidator;
use logfence_proto::syslog::SyslogMessage;
use serde_json::Value;
use thiserror::Error;
use tracing::warn;

use crate::config::{CeeCookieMode, ValidationMode};

// ── Error ─────────────────────────────────────────────────────────────────────

/// The MITRE CEE cookie prefix prepended to the MSG field in CEE-formatted messages.
const CEE_COOKIE: &str = "@cee:";

/// Reason a message failed validation.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// The message body is not valid JSON.
    #[error("message is not valid JSON: {0}")]
    NotJson(#[source] serde_json::Error),

    /// The message body is valid JSON but not a JSON object.
    #[error("message must be a JSON object, got {kind}")]
    NotObject { kind: &'static str },

    /// The message did not match any of the loaded schemas.
    #[error("message does not match any configured schema")]
    SchemaRejected,

    /// The message body has a CEE cookie (`@cee:`) but `input_cee` is `Never`.
    #[error("message has CEE cookie but input_cee = \"never\"")]
    UnexpectedCeeCookie,

    /// The message body is missing a CEE cookie but `input_cee` is `Always`.
    #[error("message is missing required CEE cookie (@cee:)")]
    MissingCeeCookie,
}

// ── Validator ─────────────────────────────────────────────────────────────────

/// Routes messages to a specific schema based on a named JSON field value.
struct DiscriminatorMap {
    field: String,
    map: HashMap<String, JsonSchemaValidator>,
}

/// Validates syslog message payloads against JSON Schema documents.
///
/// Constructed via [`Validator::new`]; then call [`Validator::validate`] on
/// each incoming message.
pub struct Validator {
    mode: ValidationMode,
    schemas: Vec<JsonSchemaValidator>,
    discriminator: Option<DiscriminatorMap>,
    input_cee: CeeCookieMode,
    output_cee: CeeCookieMode,
    canonical_json: bool,
}

impl Validator {
    /// Build a validator from the given mode and a list of compiled schemas.
    ///
    /// Prefer [`Validator::from_values`] to compile raw JSON documents.
    /// CEE cookie modes default to [`CeeCookieMode::Never`]; use
    /// [`with_input_cee`](Self::with_input_cee) and
    /// [`with_output_cee`](Self::with_output_cee) to configure them.
    #[must_use]
    pub fn new(mode: ValidationMode, schemas: Vec<JsonSchemaValidator>) -> Self {
        Self {
            mode,
            schemas,
            discriminator: None,
            input_cee: CeeCookieMode::Never,
            output_cee: CeeCookieMode::Never,
            canonical_json: false,
        }
    }

    /// Enable or disable canonical JSON output.
    ///
    /// When enabled, [`prepare_for_forwarding`](Self::prepare_for_forwarding)
    /// re-serializes the JSON payload with object keys sorted lexicographically
    /// at every nesting level.  Disabled by default.
    #[must_use]
    pub fn with_canonical_json(mut self, enabled: bool) -> Self {
        self.canonical_json = enabled;
        self
    }

    /// Set the CEE cookie mode for incoming messages.
    #[must_use]
    pub fn with_input_cee(mut self, mode: CeeCookieMode) -> Self {
        self.input_cee = mode;
        self
    }

    /// Set the CEE cookie mode for outgoing (forwarded) messages.
    #[must_use]
    pub fn with_output_cee(mut self, mode: CeeCookieMode) -> Self {
        self.output_cee = mode;
        self
    }

    /// Attach a discriminator routing map to this validator.
    ///
    /// When a message is validated, the string value of `field` is looked up in
    /// `docs` for an O(1) schema selection.  Messages whose discriminator field
    /// is absent or whose value is not in `docs` fall back to the `schemas`
    /// linear scan.
    ///
    /// # Errors
    ///
    /// Returns a string describing the first schema document that fails to compile.
    pub fn with_discriminator_docs(
        self,
        field: String,
        docs: HashMap<String, Value>,
    ) -> Result<Self, String> {
        let map = docs
            .into_iter()
            .map(|(key, doc)| {
                jsonschema::validator_for(&doc)
                    .map_err(|e| format!("invalid discriminator schema for '{key}': {e}"))
                    .map(|v| (key, v))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;
        Ok(Self {
            discriminator: Some(DiscriminatorMap { field, map }),
            ..self
        })
    }

    /// Compile JSON Schema documents from [`serde_json::Value`]s and build a
    /// validator.
    ///
    /// Compile JSON Schema documents from [`serde_json::Value`]s and build a
    /// validator.
    ///
    /// # Errors
    ///
    /// Returns a string describing the first invalid schema document.
    pub fn from_values(mode: ValidationMode, docs: &[Value]) -> Result<Self, String> {
        let schemas = docs
            .iter()
            .map(|doc| jsonschema::validator_for(doc).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::new(mode, schemas))
    }

    /// Validate the payload of `msg`.
    ///
    /// Returns `Ok(())` if the message should be forwarded, or a
    /// [`ValidationError`] if it should be dropped.
    ///
    /// In [`ValidationMode::Warn`] mode, schema mismatches are logged but the
    /// message is still forwarded (`Ok(())` is returned). In
    /// [`ValidationMode::Off`] mode only the JSON-object check is performed.
    ///
    /// When a discriminator is configured, the named field's string value is
    /// used for O(1) schema lookup before falling back to the linear scan.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::NotJson`] if the payload is not valid JSON.
    /// Returns [`ValidationError::NotObject`] if the payload is not a JSON object.
    /// Returns [`ValidationError::SchemaRejected`] (only in `Strict` mode) if
    /// the payload does not match any loaded schema.
    pub fn validate(&self, msg: &SyslogMessage) -> Result<(), ValidationError> {
        let has_cookie = msg.msg.starts_with(CEE_COOKIE);
        let json_str: &str = match self.input_cee {
            CeeCookieMode::Never => {
                if has_cookie {
                    return Err(ValidationError::UnexpectedCeeCookie);
                }
                &msg.msg
            }
            CeeCookieMode::Optional => {
                if has_cookie {
                    &msg.msg[CEE_COOKIE.len()..]
                } else {
                    &msg.msg
                }
            }
            CeeCookieMode::Always => {
                if !has_cookie {
                    return Err(ValidationError::MissingCeeCookie);
                }
                &msg.msg[CEE_COOKIE.len()..]
            }
        };

        let value: Value = serde_json::from_str(json_str).map_err(ValidationError::NotJson)?;
        if !value.is_object() {
            return Err(ValidationError::NotObject {
                kind: json_kind(&value),
            });
        }

        if self.mode == ValidationMode::Off {
            return Ok(());
        }

        if self.schema_matches(&value) {
            return Ok(());
        }

        match self.mode {
            ValidationMode::Strict => Err(ValidationError::SchemaRejected),
            ValidationMode::Warn => {
                warn!("message does not match any configured schema; forwarding anyway");
                Ok(())
            }
            ValidationMode::Off => Ok(()),
        }
    }

    /// Return the message prepared for forwarding, applying `output_cee` and
    /// (optionally) canonical JSON normalization.
    ///
    /// **`output_cee` policy:**
    /// - [`CeeCookieMode::Never`]: strip `@cee:` prefix if present.
    /// - [`CeeCookieMode::Optional`]: forward MSG as-is (preserving any cookie).
    /// - [`CeeCookieMode::Always`]: add `@cee:` prefix if absent.
    ///
    /// **`canonical_json` policy (when enabled):**
    /// The bare JSON (with any `@cee:` prefix stripped) is parsed and
    /// re-serialized with object keys sorted lexicographically at every nesting
    /// level.  The `@cee:` prefix is then re-applied according to `output_cee`.
    ///
    /// Returns [`Cow::Borrowed`] when no transformation is needed, avoiding an
    /// allocation.
    #[must_use]
    pub fn prepare_for_forwarding<'a>(
        &self,
        msg: &'a SyslogMessage,
    ) -> std::borrow::Cow<'a, SyslogMessage> {
        let has_cookie = msg.msg.starts_with(CEE_COOKIE);
        let bare_json: &str = if has_cookie {
            &msg.msg[CEE_COOKIE.len()..]
        } else {
            &msg.msg
        };

        // Optionally re-serialize with sorted keys; only produces Some when the
        // output actually differs from the input (avoids an allocation otherwise).
        let canonical: Option<String> = if self.canonical_json {
            canonicalize_json(bare_json).filter(|s| s.as_str() != bare_json)
        } else {
            None
        };
        let effective_json: &str = canonical.as_deref().unwrap_or(bare_json);

        let new_msg: Option<String> = match self.output_cee {
            CeeCookieMode::Never => {
                // Output must not carry @cee:; use effective_json directly.
                if !has_cookie && canonical.is_none() {
                    None
                } else {
                    Some(effective_json.to_owned())
                }
            }
            CeeCookieMode::Optional => {
                // Preserve the original cookie status; only change when JSON changed.
                canonical.as_ref().map(|cj| {
                    if has_cookie {
                        format!("{CEE_COOKIE}{cj}")
                    } else {
                        cj.clone()
                    }
                })
            }
            CeeCookieMode::Always => {
                // Output must carry @cee:.
                if has_cookie && canonical.is_none() {
                    None
                } else {
                    Some(format!("{CEE_COOKIE}{effective_json}"))
                }
            }
        };

        if let Some(msg_field) = new_msg {
            let mut owned = msg.clone();
            owned.msg = msg_field;
            std::borrow::Cow::Owned(owned)
        } else {
            std::borrow::Cow::Borrowed(msg)
        }
    }

    /// Returns `true` if `value` matches an applicable schema.
    ///
    /// Checks the discriminator map first (O(1)), then falls back to a linear
    /// scan of `self.schemas`.  Returns `true` when no schemas are configured.
    fn schema_matches(&self, value: &Value) -> bool {
        if let Some(disc) = &self.discriminator {
            if let Some(disc_val) = value.get(&disc.field).and_then(|v| v.as_str()) {
                if let Some(schema) = disc.map.get(disc_val) {
                    return schema.is_valid(value);
                }
            }
            // Discriminator field absent or value not in map — fall through.
        }

        if self.schemas.is_empty() {
            return true;
        }

        self.schemas.iter().any(|s| s.is_valid(value))
    }
}

/// Re-serialize `json_str` with object keys sorted at every nesting level.
///
/// Returns `None` if the input is not valid JSON (should not happen when called
/// after a successful `validate()`).
fn canonicalize_json(json_str: &str) -> Option<String> {
    let value: Value = serde_json::from_str(json_str).ok()?;
    serde_json::to_string(&sorted_value(value)).ok()
}

/// Recursively rebuild a JSON value with object keys sorted lexicographically.
///
/// This is explicit rather than relying on `serde_json`'s default `BTreeMap`
/// backend so that the behaviour is correct regardless of whether the
/// `preserve_order` feature is later enabled.
fn sorted_value(v: Value) -> Value {
    match v {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, sorted_value(v)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(arr) => Value::Array(arr.into_iter().map(sorted_value).collect()),
        other => other,
    }
}

fn json_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "unwrap is appropriate in test assertions"
)]
mod tests {
    use logfence_proto::syslog::{Facility, Priority, Severity};
    use serde_json::json;

    use super::*;

    fn msg(body: &str) -> SyslogMessage {
        SyslogMessage {
            priority: Priority(Facility::Local0, Severity::Info),
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            msg_id: None,
            structured_data: "-".into(),
            msg: body.into(),
        }
    }

    fn schema_requires_field(field: &str) -> Value {
        json!({
            "type": "object",
            "required": [field],
            "properties": {
                field: { "type": "string" }
            }
        })
    }

    // ── mode = off ────────────────────────────────────────────────────────────

    #[test]
    fn off_accepts_any_json_object() {
        let v = Validator::new(ValidationMode::Off, vec![]);
        assert!(v.validate(&msg(r#"{"x":1}"#)).is_ok());
    }

    #[test]
    fn off_rejects_non_json() {
        let v = Validator::new(ValidationMode::Off, vec![]);
        assert!(matches!(
            v.validate(&msg("not json")).unwrap_err(),
            ValidationError::NotJson(_)
        ));
    }

    #[test]
    fn off_rejects_json_array() {
        let v = Validator::new(ValidationMode::Off, vec![]);
        assert!(matches!(
            v.validate(&msg("[1,2,3]")).unwrap_err(),
            ValidationError::NotObject { .. }
        ));
    }

    // ── mode = strict, no schemas ─────────────────────────────────────────────

    #[test]
    fn strict_no_schemas_accepts_any_object() {
        let v = Validator::new(ValidationMode::Strict, vec![]);
        assert!(v.validate(&msg(r#"{"k":"v"}"#)).is_ok());
    }

    // ── mode = strict, with schemas ───────────────────────────────────────────

    #[test]
    fn strict_accepts_matching_message() {
        let schema = schema_requires_field("action");
        let v = Validator::from_values(ValidationMode::Strict, &[schema]).unwrap();
        assert!(v.validate(&msg(r#"{"action":"login"}"#)).is_ok());
    }

    #[test]
    fn strict_rejects_non_matching_message() {
        let schema = schema_requires_field("action");
        let v = Validator::from_values(ValidationMode::Strict, &[schema]).unwrap();
        assert!(matches!(
            v.validate(&msg(r#"{"other":"field"}"#)).unwrap_err(),
            ValidationError::SchemaRejected
        ));
    }

    #[test]
    fn strict_accepts_when_any_schema_matches() {
        let s1 = schema_requires_field("action");
        let s2 = schema_requires_field("event");
        let v = Validator::from_values(ValidationMode::Strict, &[s1, s2]).unwrap();
        assert!(v.validate(&msg(r#"{"event":"boot"}"#)).is_ok());
    }

    // ── mode = warn ───────────────────────────────────────────────────────────

    #[test]
    fn warn_forwards_non_matching_message() {
        let schema = schema_requires_field("action");
        let v = Validator::from_values(ValidationMode::Warn, &[schema]).unwrap();
        // Should return Ok even though the message doesn't match.
        assert!(v.validate(&msg(r#"{"other":"field"}"#)).is_ok());
    }

    #[test]
    fn warn_still_rejects_non_json() {
        let v = Validator::new(ValidationMode::Warn, vec![]);
        assert!(v.validate(&msg("bad")).is_err());
    }

    // ── discriminator routing ─────────────────────────────────────────────────

    fn make_discriminator_validator() -> Validator {
        let schema_a = json!({
            "type": "object",
            "required": ["service", "action"],
            "properties": {
                "service": { "type": "string" },
                "action": { "type": "string" }
            }
        });
        let schema_b = json!({
            "type": "object",
            "required": ["service", "event"],
            "properties": {
                "service": { "type": "string" },
                "event": { "type": "string" }
            }
        });
        let mut docs = std::collections::HashMap::new();
        docs.insert("api-gateway".to_owned(), schema_a);
        docs.insert("auth-service".to_owned(), schema_b);
        Validator::new(ValidationMode::Strict, vec![])
            .with_discriminator_docs("service".to_owned(), docs)
            .unwrap()
    }

    #[test]
    fn discriminator_routes_to_correct_schema() {
        let v = make_discriminator_validator();
        assert!(v
            .validate(&msg(r#"{"service":"api-gateway","action":"create"}"#))
            .is_ok());
        assert!(v
            .validate(&msg(r#"{"service":"auth-service","event":"login"}"#))
            .is_ok());
    }

    #[test]
    fn discriminator_rejects_wrong_schema_for_service() {
        let v = make_discriminator_validator();
        // api-gateway schema requires "action", not "event"
        assert!(matches!(
            v.validate(&msg(r#"{"service":"api-gateway","event":"login"}"#))
                .unwrap_err(),
            ValidationError::SchemaRejected
        ));
    }

    #[test]
    fn discriminator_falls_back_to_linear_scan_for_unknown_service() {
        let fallback_schema = schema_requires_field("fallback_field");
        let v = Validator::from_values(ValidationMode::Strict, &[fallback_schema])
            .unwrap()
            .with_discriminator_docs("service".to_owned(), std::collections::HashMap::new())
            .unwrap();
        // Unknown service → linear scan → needs fallback_field
        assert!(v
            .validate(&msg(r#"{"service":"unknown","fallback_field":"x"}"#))
            .is_ok());
        assert!(matches!(
            v.validate(&msg(r#"{"service":"unknown","other":"x"}"#))
                .unwrap_err(),
            ValidationError::SchemaRejected
        ));
    }

    #[test]
    fn discriminator_falls_back_when_field_absent() {
        let fallback_schema = schema_requires_field("action");
        let mut disc_docs = std::collections::HashMap::new();
        disc_docs.insert("api-gateway".to_owned(), schema_requires_field("action"));
        let v = Validator::from_values(ValidationMode::Strict, &[fallback_schema])
            .unwrap()
            .with_discriminator_docs("service".to_owned(), disc_docs)
            .unwrap();
        // No "service" field → falls back to linear scan
        assert!(v.validate(&msg(r#"{"action":"login"}"#)).is_ok());
    }

    // ── CEE cookie — input_cee ────────────────────────────────────────────────

    #[test]
    fn input_cee_never_rejects_cookie() {
        let v = Validator::new(ValidationMode::Off, vec![]);
        // input_cee defaults to Never
        assert!(matches!(
            v.validate(&msg(r#"@cee:{"event":"x"}"#)).unwrap_err(),
            ValidationError::UnexpectedCeeCookie
        ));
    }

    #[test]
    fn input_cee_never_accepts_plain_json() {
        let v = Validator::new(ValidationMode::Off, vec![]);
        assert!(v.validate(&msg(r#"{"event":"x"}"#)).is_ok());
    }

    #[test]
    fn input_cee_optional_accepts_cee_message() {
        let v = Validator::new(ValidationMode::Off, vec![]).with_input_cee(CeeCookieMode::Optional);
        assert!(v.validate(&msg(r#"@cee:{"event":"x"}"#)).is_ok());
    }

    #[test]
    fn input_cee_optional_accepts_plain_json() {
        let v = Validator::new(ValidationMode::Off, vec![]).with_input_cee(CeeCookieMode::Optional);
        assert!(v.validate(&msg(r#"{"event":"x"}"#)).is_ok());
    }

    #[test]
    fn input_cee_always_rejects_plain_json() {
        let v = Validator::new(ValidationMode::Off, vec![]).with_input_cee(CeeCookieMode::Always);
        assert!(matches!(
            v.validate(&msg(r#"{"event":"x"}"#)).unwrap_err(),
            ValidationError::MissingCeeCookie
        ));
    }

    #[test]
    fn input_cee_always_accepts_cee_message() {
        let v = Validator::new(ValidationMode::Off, vec![]).with_input_cee(CeeCookieMode::Always);
        assert!(v.validate(&msg(r#"@cee:{"event":"x"}"#)).is_ok());
    }

    #[test]
    fn input_cee_optional_validates_json_after_stripping() {
        // Schema requires "action"; @cee: prefix is stripped before validation.
        let schema = schema_requires_field("action");
        let v = Validator::from_values(ValidationMode::Strict, &[schema])
            .unwrap()
            .with_input_cee(CeeCookieMode::Optional);
        assert!(v.validate(&msg(r#"@cee:{"action":"login"}"#)).is_ok());
        assert!(matches!(
            v.validate(&msg(r#"@cee:{"other":"x"}"#)).unwrap_err(),
            ValidationError::SchemaRejected
        ));
    }

    #[test]
    fn input_cee_always_validates_json_after_stripping() {
        // Schema requires "event"; @cee: prefix is stripped before validation.
        let schema = schema_requires_field("event");
        let v = Validator::from_values(ValidationMode::Strict, &[schema])
            .unwrap()
            .with_input_cee(CeeCookieMode::Always);
        assert!(v.validate(&msg(r#"@cee:{"event":"boot"}"#)).is_ok());
        assert!(matches!(
            v.validate(&msg(r#"@cee:{"other":"boot"}"#)).unwrap_err(),
            ValidationError::SchemaRejected
        ));
    }

    // ── CEE cookie — output_cee / prepare_for_forwarding ─────────────────────

    #[test]
    fn output_cee_never_strips_existing_cookie() {
        let v = Validator::new(ValidationMode::Off, vec![]).with_output_cee(CeeCookieMode::Never);
        let m = msg(r#"@cee:{"event":"x"}"#);
        let prepared = v.prepare_for_forwarding(&m);
        assert_eq!(prepared.msg, r#"{"event":"x"}"#);
    }

    #[test]
    fn output_cee_never_preserves_plain_json() {
        let v = Validator::new(ValidationMode::Off, vec![]).with_output_cee(CeeCookieMode::Never);
        let m = msg(r#"{"event":"x"}"#);
        let prepared = v.prepare_for_forwarding(&m);
        assert_eq!(prepared.msg, r#"{"event":"x"}"#);
    }

    #[test]
    fn output_cee_optional_preserves_cee_message() {
        let v =
            Validator::new(ValidationMode::Off, vec![]).with_output_cee(CeeCookieMode::Optional);
        let m = msg(r#"@cee:{"event":"x"}"#);
        let prepared = v.prepare_for_forwarding(&m);
        assert_eq!(prepared.msg, r#"@cee:{"event":"x"}"#);
    }

    #[test]
    fn output_cee_optional_preserves_plain_json() {
        let v =
            Validator::new(ValidationMode::Off, vec![]).with_output_cee(CeeCookieMode::Optional);
        let m = msg(r#"{"event":"x"}"#);
        let prepared = v.prepare_for_forwarding(&m);
        assert_eq!(prepared.msg, r#"{"event":"x"}"#);
    }

    #[test]
    fn output_cee_always_adds_cookie_when_absent() {
        let v = Validator::new(ValidationMode::Off, vec![]).with_output_cee(CeeCookieMode::Always);
        let m = msg(r#"{"event":"x"}"#);
        let prepared = v.prepare_for_forwarding(&m);
        assert_eq!(prepared.msg, r#"@cee:{"event":"x"}"#);
    }

    #[test]
    fn output_cee_always_preserves_existing_cookie() {
        let v = Validator::new(ValidationMode::Off, vec![]).with_output_cee(CeeCookieMode::Always);
        let m = msg(r#"@cee:{"event":"x"}"#);
        let prepared = v.prepare_for_forwarding(&m);
        assert_eq!(prepared.msg, r#"@cee:{"event":"x"}"#);
    }

    #[test]
    fn prepare_for_forwarding_borrows_when_no_change_needed() {
        use std::borrow::Cow;
        let v = Validator::new(ValidationMode::Off, vec![]);
        // output_cee = Never, no cookie → Cow::Borrowed
        let m = msg(r#"{"event":"x"}"#);
        let prepared = v.prepare_for_forwarding(&m);
        assert!(matches!(prepared, Cow::Borrowed(_)));
    }

    #[test]
    fn prepare_for_forwarding_owns_when_transformation_needed() {
        use std::borrow::Cow;
        let v = Validator::new(ValidationMode::Off, vec![]).with_output_cee(CeeCookieMode::Always);
        let m = msg(r#"{"event":"x"}"#);
        let prepared = v.prepare_for_forwarding(&m);
        assert!(matches!(prepared, Cow::Owned(_)));
    }

    // ── canonical JSON ────────────────────────────────────────────────────────

    #[test]
    fn canonical_json_sorts_top_level_keys() {
        let v = Validator::new(ValidationMode::Off, vec![]).with_canonical_json(true);
        let m = msg(r#"{"z":3,"a":1,"m":2}"#);
        let prepared = v.prepare_for_forwarding(&m);
        assert_eq!(prepared.msg, r#"{"a":1,"m":2,"z":3}"#);
    }

    #[test]
    fn canonical_json_sorts_nested_object_keys() {
        let v = Validator::new(ValidationMode::Off, vec![]).with_canonical_json(true);
        let m = msg(r#"{"b":{"y":2,"x":1},"a":0}"#);
        let prepared = v.prepare_for_forwarding(&m);
        assert_eq!(prepared.msg, r#"{"a":0,"b":{"x":1,"y":2}}"#);
    }

    #[test]
    fn canonical_json_preserves_array_element_order() {
        let v = Validator::new(ValidationMode::Off, vec![]).with_canonical_json(true);
        let m = msg(r#"{"items":[3,1,2]}"#);
        let prepared = v.prepare_for_forwarding(&m);
        assert_eq!(prepared.msg, r#"{"items":[3,1,2]}"#);
    }

    #[test]
    fn canonical_json_removes_extra_whitespace() {
        let v = Validator::new(ValidationMode::Off, vec![]).with_canonical_json(true);
        let m = msg(r#"{ "b" : 2 , "a" : 1 }"#);
        let prepared = v.prepare_for_forwarding(&m);
        assert_eq!(prepared.msg, r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn canonical_json_borrows_when_already_canonical() {
        use std::borrow::Cow;
        let v = Validator::new(ValidationMode::Off, vec![]).with_canonical_json(true);
        let m = msg(r#"{"a":1,"b":2}"#);
        let prepared = v.prepare_for_forwarding(&m);
        assert!(matches!(prepared, Cow::Borrowed(_)));
    }

    #[test]
    fn canonical_json_disabled_preserves_original_order() {
        use std::borrow::Cow;
        let v = Validator::new(ValidationMode::Off, vec![]); // canonical_json = false
        let m = msg(r#"{"z":3,"a":1}"#);
        let prepared = v.prepare_for_forwarding(&m);
        // No transformation: must borrow and preserve original string.
        assert!(matches!(prepared, Cow::Borrowed(_)));
        assert_eq!(prepared.msg, r#"{"z":3,"a":1}"#);
    }

    #[test]
    fn canonical_json_combined_with_output_cee_always() {
        let v = Validator::new(ValidationMode::Off, vec![])
            .with_canonical_json(true)
            .with_output_cee(CeeCookieMode::Always);
        let m = msg(r#"{"z":1,"a":2}"#);
        let prepared = v.prepare_for_forwarding(&m);
        assert_eq!(prepared.msg, r#"@cee:{"a":2,"z":1}"#);
    }

    #[test]
    fn canonical_json_combined_with_cee_optional_preserves_cookie() {
        let v = Validator::new(ValidationMode::Off, vec![])
            .with_canonical_json(true)
            .with_output_cee(CeeCookieMode::Optional);
        let m = msg(r#"@cee:{"z":1,"a":2}"#);
        let prepared = v.prepare_for_forwarding(&m);
        assert_eq!(prepared.msg, r#"@cee:{"a":2,"z":1}"#);
    }

    #[test]
    fn canonical_json_combined_with_output_cee_never_strips_cookie() {
        let v = Validator::new(ValidationMode::Off, vec![])
            .with_canonical_json(true)
            .with_output_cee(CeeCookieMode::Never);
        let m = msg(r#"@cee:{"z":1,"a":2}"#);
        let prepared = v.prepare_for_forwarding(&m);
        assert_eq!(prepared.msg, r#"{"a":2,"z":1}"#);
    }
}
