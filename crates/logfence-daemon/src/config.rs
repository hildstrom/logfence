//! Configuration loading for logfenced.
//!
//! Reads a TOML file from the path specified on the command line (or
//! `/etc/logfenced/logfenced.toml` by default) and deserializes it into
//! [`Config`].

use std::{collections::HashMap, fs, path::Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors that can occur while loading or validating the configuration file.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The config file could not be read from disk.
    #[error("cannot read config file '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// The config file content is not valid TOML or does not match the schema.
    #[error("cannot parse config file '{path}': {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },

    /// A config value is out of range or otherwise invalid.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

// ── Config structs ────────────────────────────────────────────────────────────

/// Top-level daemon configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Daemon socket and connection settings.
    pub daemon: DaemonConfig,

    /// Rsyslog forwarding settings.
    pub rsyslog: RsyslogConfig,

    /// Message validation settings.
    #[serde(default)]
    pub validation: ValidationConfig,

    /// Daemon operational logging settings.
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Metrics stats socket settings.
    #[serde(default)]
    pub metrics: MetricsConfig,
}

/// Settings for the daemon's listening socket.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonConfig {
    /// Path to the Unix domain socket to listen on.
    #[serde(default = "DaemonConfig::default_listen_socket")]
    pub listen_socket: String,

    /// Octal permission bits for the socket file (e.g. `"0660"`).
    #[serde(default = "DaemonConfig::default_socket_mode")]
    pub socket_mode: String,

    /// Optional group name to own the socket file.
    #[serde(default)]
    pub socket_group: Option<String>,

    /// Maximum number of concurrent client connections.
    #[serde(default = "DaemonConfig::default_max_connections")]
    pub max_connections: usize,

    /// Maximum accepted message size in bytes.
    #[serde(default = "DaemonConfig::default_max_message_size")]
    pub max_message_size: usize,

    /// Transport protocol for the listening socket.
    #[serde(default)]
    pub listen_transport: ListenTransport,

    /// Framing mode for incoming messages on a stream socket.
    ///
    /// Ignored when `listen_transport = "unix_dgram"`.
    #[serde(default)]
    pub framing: FramingMode,

    /// Sender identity mode for forwarded messages.
    #[serde(default)]
    pub sender: SenderMode,
}

impl DaemonConfig {
    fn default_listen_socket() -> String {
        "/run/logfenced/logfenced.sock".to_owned()
    }

    fn default_socket_mode() -> String {
        "0660".to_owned()
    }

    fn default_max_connections() -> usize {
        256
    }

    fn default_max_message_size() -> usize {
        65_536
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            listen_socket: Self::default_listen_socket(),
            socket_mode: Self::default_socket_mode(),
            socket_group: None,
            max_connections: Self::default_max_connections(),
            max_message_size: Self::default_max_message_size(),
            listen_transport: ListenTransport::default(),
            framing: FramingMode::default(),
            sender: SenderMode::default(),
        }
    }
}

/// Transport protocol for the daemon's listening socket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenTransport {
    /// Unix stream socket (default). Clients maintain a persistent connection
    /// and messages use RFC 6587 octet-count or newline framing.
    #[default]
    UnixStream,
    /// Unix datagram socket. Each datagram is one complete, unframed RFC 5424
    /// message. This matches rsyslog's standard `imuxsock` input mode and
    /// makes logfenced a drop-in man-in-the-middle for syslog clients.
    UnixDgram,
}

/// Framing protocol for the incoming Unix stream socket.
///
/// Only relevant when `listen_transport = "unix_stream"`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FramingMode {
    /// RFC 6587 §3.4.1 octet-count framing (preferred).
    #[default]
    OctetCount,
    /// One message per newline-terminated line.
    Newline,
}

/// How logfenced identifies the sender in forwarded messages.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SenderMode {
    /// Forward the original sender fields (hostname, `app_name`, `proc_id`) unchanged.
    #[default]
    Original,
    /// Rewrite sender fields to identify logfenced as the message source.
    ///
    /// The original hostname, `app_name`, and `proc_id` are preserved in RFC 5424
    /// STRUCTURED-DATA as `[logfence.src hostname="..." app="..." pid="..."]`.
    Logfenced,
}

/// Settings for forwarding messages to rsyslog.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RsyslogConfig {
    /// Transport to use for forwarding.
    #[serde(default)]
    pub transport: ForwardTransport,

    /// Socket path for Unix transports.
    #[serde(default = "RsyslogConfig::default_socket")]
    pub socket: String,

    /// Maximum number of datagram send attempts when the receiver's buffer is
    /// full (`ENOBUFS`).  `0` means unlimited — retry until the send succeeds
    /// or a non-retryable error occurs.  Default: `4`.
    ///
    /// Attempts 1–4 use a short exponential back-off (immediate → 100 µs →
    /// 500 µs → 2 ms).  Attempt 5 and above wait 1 s between each try,
    /// providing stronger backpressure when the receiver is persistently slow.
    ///
    /// Only relevant when `transport = "unix_dgram"`.
    #[serde(default = "RsyslogConfig::default_dgram_max_attempts")]
    pub dgram_max_attempts: u32,

    /// What to do when all datagram send attempts are exhausted.
    ///
    /// `"drop"` (default) — drop the message and report an error.
    /// `"terminate"` — initiate a graceful daemon shutdown.
    ///
    /// Ignored when `dgram_max_attempts = 0` (unlimited retries never exhaust).
    /// Only relevant when `transport = "unix_dgram"`.
    #[serde(default)]
    pub dgram_exhausted: DgramExhausted,
}

impl RsyslogConfig {
    fn default_socket() -> String {
        "/run/syslog".to_owned()
    }

    const fn default_dgram_max_attempts() -> u32 {
        4
    }
}

impl Default for RsyslogConfig {
    fn default() -> Self {
        Self {
            transport: ForwardTransport::default(),
            socket: Self::default_socket(),
            dgram_max_attempts: Self::default_dgram_max_attempts(),
            dgram_exhausted: DgramExhausted::default(),
        }
    }
}

/// Transport used to forward validated messages to rsyslog.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardTransport {
    /// Unix datagram socket (`/run/syslog`).
    #[default]
    UnixDgram,
    /// Unix stream socket with octet-count framing.
    UnixStream,
}

/// What to do when datagram send attempts are exhausted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DgramExhausted {
    /// Drop the message and return an error to the caller (default).
    #[default]
    Drop,
    /// Cancel the daemon shutdown token to initiate graceful termination.
    Terminate,
}

/// Message validation settings.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ValidationConfig {
    /// Schema enforcement mode.
    #[serde(default)]
    pub mode: ValidationMode,

    /// Paths to JSON Schema files used for linear-scan validation.
    /// Empty means accept any valid JSON object (when no discriminator is set).
    #[serde(default)]
    pub schemas: Vec<String>,

    /// Name of the JSON field used to route messages to a specific schema.
    /// When set, the field's string value is looked up in `schema_map` for an
    /// O(1) schema selection.  Messages whose discriminator field is absent or
    /// whose value is not in `schema_map` fall back to the `schemas` linear scan.
    #[serde(default)]
    pub discriminator: Option<String>,

    /// Maps discriminator field values to JSON Schema file paths.
    /// Requires `discriminator` to be set.
    #[serde(default)]
    pub schema_map: HashMap<String, String>,

    /// MITRE CEE cookie handling for incoming messages.
    ///
    /// Controls whether `@cee:` in the MSG field is required, optional, or
    /// forbidden.  The cookie is stripped before JSON parsing when present.
    #[serde(default)]
    pub input_cee: CeeCookieMode,

    /// MITRE CEE cookie handling for outgoing (forwarded) messages.
    ///
    /// Controls whether `@cee:` is added to, preserved in, or stripped from the
    /// MSG field before forwarding to rsyslog.
    #[serde(default)]
    pub output_cee: CeeCookieMode,

    /// Re-serialize the JSON payload with object keys sorted in ascending
    /// lexicographic order before forwarding.
    ///
    /// When `false` (the default) the original JSON string is forwarded as-is,
    /// which avoids a parse + re-serialize cycle and keeps forwarding throughput
    /// at its maximum.  When `true` the payload is parsed into a JSON value,
    /// all object keys at every nesting level are sorted, and the value is
    /// re-serialized to compact JSON with no extra whitespace.
    #[serde(default)]
    pub canonical_json: bool,
}

/// How the MITRE CEE cookie (`@cee:`) in the syslog MSG field is treated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CeeCookieMode {
    /// The CEE cookie must not be present.
    #[default]
    Never,
    /// The CEE cookie is accepted but not required.
    Optional,
    /// The CEE cookie must be present.
    Always,
}

/// How strictly incoming messages are validated against schemas.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationMode {
    /// Message must match at least one schema; drop non-matching messages.
    #[default]
    Strict,
    /// Log schema mismatch but forward the message anyway.
    Warn,
    /// Only require a valid JSON object; skip schema comparison.
    Off,
}

/// Settings for the metrics stats socket.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// Enable the metrics stats socket.
    ///
    /// When `true`, logfenced binds `socket` and serves a JSON
    /// [`metrics::Snapshot`](crate::metrics::Snapshot) to each connecting
    /// client before closing the connection.
    #[serde(default)]
    pub enabled: bool,

    /// Path for the Unix stream socket that serves JSON metrics snapshots.
    #[serde(default = "MetricsConfig::default_socket")]
    pub socket: String,
}

impl MetricsConfig {
    fn default_socket() -> String {
        "/run/logfenced/logfenced.stats.sock".to_owned()
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socket: Self::default_socket(),
        }
    }
}

/// Daemon operational logging settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    /// Log level for daemon's own operational output.
    #[serde(default = "LoggingConfig::default_level")]
    pub level: String,

    /// Log destination: `"stderr"` or an absolute file path.
    #[serde(default = "LoggingConfig::default_output")]
    pub output: String,
}

impl LoggingConfig {
    fn default_level() -> String {
        "info".to_owned()
    }

    fn default_output() -> String {
        "stderr".to_owned()
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: Self::default_level(),
            output: Self::default_output(),
        }
    }
}

// ── Loader ────────────────────────────────────────────────────────────────────

/// Load and validate a [`Config`] from a TOML file at `path`.
///
/// # Errors
///
/// Returns [`ConfigError::Io`] if the file cannot be read, or
/// [`ConfigError::Parse`] if the TOML is malformed or missing required fields,
/// or [`ConfigError::Invalid`] if a value is out of range.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let path_str = path.display().to_string();
    let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path_str.clone(),
        source,
    })?;
    let cfg: Config = toml::from_str(&text).map_err(|source| ConfigError::Parse {
        path: path_str,
        source,
    })?;
    validate(&cfg)?;
    Ok(cfg)
}

fn validate(cfg: &Config) -> Result<(), ConfigError> {
    // Parse the socket_mode as octal and check the range.
    let mode_str = cfg.daemon.socket_mode.trim_start_matches('0');
    let mode_str = if mode_str.is_empty() { "0" } else { mode_str };
    u32::from_str_radix(mode_str, 8).map_err(|_| {
        ConfigError::Invalid(format!(
            "daemon.socket_mode '{}' is not a valid octal permission string",
            cfg.daemon.socket_mode
        ))
    })?;

    if cfg.daemon.max_connections == 0 {
        return Err(ConfigError::Invalid(
            "daemon.max_connections must be at least 1".to_owned(),
        ));
    }

    if cfg.daemon.max_message_size == 0 {
        return Err(ConfigError::Invalid(
            "daemon.max_message_size must be at least 1".to_owned(),
        ));
    }

    if !cfg.validation.schema_map.is_empty() && cfg.validation.discriminator.is_none() {
        return Err(ConfigError::Invalid(
            "validation.schema_map requires validation.discriminator to be set".to_owned(),
        ));
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
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    fn write_toml(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn load_minimal_config() {
        let f = write_toml(
            r#"
[daemon]
listen_socket = "/tmp/test.sock"

[rsyslog]
"#,
        );
        let cfg = load(f.path()).unwrap();
        assert_eq!(cfg.daemon.listen_socket, "/tmp/test.sock");
        assert_eq!(cfg.rsyslog.transport, ForwardTransport::UnixDgram);
        assert_eq!(cfg.validation.mode, ValidationMode::Strict);
        assert!(cfg.validation.schemas.is_empty());
    }

    #[test]
    fn load_full_config() {
        let f = write_toml(
            r#"
[daemon]
listen_socket = "/run/logfenced/logfenced.sock"
socket_mode = "0660"
max_connections = 128
max_message_size = 32768
framing = "newline"

[rsyslog]
transport = "unix_stream"
socket = "/run/syslog"

[validation]
mode = "warn"
schemas = ["/etc/logfenced/schemas/audit.json"]

[logging]
level = "debug"
output = "stderr"
"#,
        );
        let cfg = load(f.path()).unwrap();
        assert_eq!(cfg.daemon.max_connections, 128);
        assert_eq!(cfg.daemon.framing, FramingMode::Newline);
        assert_eq!(cfg.rsyslog.transport, ForwardTransport::UnixStream);
        assert_eq!(cfg.rsyslog.socket, "/run/syslog");
        assert_eq!(cfg.validation.mode, ValidationMode::Warn);
        assert_eq!(cfg.validation.schemas.len(), 1);
        assert_eq!(cfg.logging.level, "debug");
    }

    #[test]
    fn load_rejects_missing_file() {
        let err = load(Path::new("/nonexistent/path.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }));
    }

    #[test]
    fn load_rejects_invalid_toml() {
        let f = write_toml("not valid toml ][");
        let err = load(f.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn validate_rejects_zero_connections() {
        let f = write_toml(
            r"
[daemon]
max_connections = 0

[rsyslog]
",
        );
        let err = load(f.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn validate_rejects_bad_socket_mode() {
        let f = write_toml("[daemon]\nsocket_mode = \"0999\"\n\n[rsyslog]\n");
        let err = load(f.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn load_discriminator_config() {
        let f = write_toml(
            r#"
[daemon]
listen_socket = "/tmp/test.sock"

[rsyslog]

[validation]
mode = "strict"
discriminator = "service"

[validation.schema_map]
api-gateway = "/etc/logfenced/schemas/api.json"
auth-service = "/etc/logfenced/schemas/auth.json"
"#,
        );
        let cfg = load(f.path()).unwrap();
        assert_eq!(cfg.validation.discriminator.as_deref(), Some("service"));
        assert_eq!(cfg.validation.schema_map.len(), 2);
        assert_eq!(
            cfg.validation
                .schema_map
                .get("api-gateway")
                .map(String::as_str),
            Some("/etc/logfenced/schemas/api.json")
        );
    }

    #[test]
    fn validate_rejects_schema_map_without_discriminator() {
        let f = write_toml(
            r#"
[daemon]
listen_socket = "/tmp/test.sock"

[rsyslog]

[validation.schema_map]
svc = "/etc/logfenced/schemas/svc.json"
"#,
        );
        let err = load(f.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn default_config_is_valid() {
        let cfg = Config {
            daemon: DaemonConfig::default(),
            rsyslog: RsyslogConfig::default(),
            validation: ValidationConfig::default(),
            logging: LoggingConfig::default(),
            metrics: MetricsConfig::default(),
        };
        validate(&cfg).unwrap();
    }

    #[test]
    fn load_cee_cookie_config() {
        let f = write_toml(
            r#"
[daemon]
listen_socket = "/tmp/test.sock"

[rsyslog]

[validation]
mode = "off"
input_cee = "always"
output_cee = "optional"
"#,
        );
        let cfg = load(f.path()).unwrap();
        assert_eq!(cfg.validation.input_cee, CeeCookieMode::Always);
        assert_eq!(cfg.validation.output_cee, CeeCookieMode::Optional);
    }

    #[test]
    fn cee_cookie_mode_defaults_to_never() {
        let f = write_toml("[daemon]\nlisten_socket = \"/tmp/t.sock\"\n\n[rsyslog]\n");
        let cfg = load(f.path()).unwrap();
        assert_eq!(cfg.validation.input_cee, CeeCookieMode::Never);
        assert_eq!(cfg.validation.output_cee, CeeCookieMode::Never);
    }

    #[test]
    fn load_canonical_json_config() {
        let f = write_toml(
            "[daemon]\nlisten_socket = \"/tmp/t.sock\"\n\n[rsyslog]\n\
             \n[validation]\ncanonical_json = true\n",
        );
        let cfg = load(f.path()).unwrap();
        assert!(cfg.validation.canonical_json);
    }

    #[test]
    fn canonical_json_defaults_to_false() {
        let f = write_toml("[daemon]\nlisten_socket = \"/tmp/t.sock\"\n\n[rsyslog]\n");
        let cfg = load(f.path()).unwrap();
        assert!(!cfg.validation.canonical_json);
    }

    #[test]
    fn sender_defaults_to_original() {
        let f = write_toml("[daemon]\nlisten_socket = \"/tmp/t.sock\"\n\n[rsyslog]\n");
        let cfg = load(f.path()).unwrap();
        assert_eq!(cfg.daemon.sender, SenderMode::Original);
    }

    #[test]
    fn sender_logfenced_parses() {
        let f = write_toml(
            "[daemon]\nlisten_socket = \"/tmp/t.sock\"\nsender = \"logfenced\"\n\n[rsyslog]\n",
        );
        let cfg = load(f.path()).unwrap();
        assert_eq!(cfg.daemon.sender, SenderMode::Logfenced);
    }

    #[test]
    fn sender_original_parses() {
        let f = write_toml(
            "[daemon]\nlisten_socket = \"/tmp/t.sock\"\nsender = \"original\"\n\n[rsyslog]\n",
        );
        let cfg = load(f.path()).unwrap();
        assert_eq!(cfg.daemon.sender, SenderMode::Original);
    }

    #[test]
    fn listen_transport_defaults_to_unix_stream() {
        let f = write_toml("[daemon]\nlisten_socket = \"/tmp/t.sock\"\n\n[rsyslog]\n");
        let cfg = load(f.path()).unwrap();
        assert_eq!(cfg.daemon.listen_transport, ListenTransport::UnixStream);
    }

    #[test]
    fn listen_transport_unix_dgram_parses() {
        let f = write_toml(
            "[daemon]\nlisten_socket = \"/tmp/t.sock\"\nlisten_transport = \"unix_dgram\"\n\n[rsyslog]\n",
        );
        let cfg = load(f.path()).unwrap();
        assert_eq!(cfg.daemon.listen_transport, ListenTransport::UnixDgram);
    }

    #[test]
    fn metrics_enabled_defaults_to_false() {
        let f = write_toml("[daemon]\nlisten_socket = \"/tmp/t.sock\"\n\n[rsyslog]\n");
        let cfg = load(f.path()).unwrap();
        assert!(!cfg.metrics.enabled);
    }

    #[test]
    fn metrics_enabled_parses() {
        let f = write_toml(
            "[daemon]\nlisten_socket = \"/tmp/t.sock\"\n\n[rsyslog]\n\n[metrics]\nenabled = true\n",
        );
        let cfg = load(f.path()).unwrap();
        assert!(cfg.metrics.enabled);
    }

    #[test]
    fn dgram_max_attempts_defaults_to_4() {
        let f = write_toml("[daemon]\nlisten_socket = \"/tmp/t.sock\"\n\n[rsyslog]\n");
        let cfg = load(f.path()).unwrap();
        assert_eq!(cfg.rsyslog.dgram_max_attempts, 4);
    }

    #[test]
    fn dgram_max_attempts_parses() {
        let f = write_toml(
            "[daemon]\nlisten_socket = \"/tmp/t.sock\"\n\n[rsyslog]\ndgram_max_attempts = 0\n",
        );
        let cfg = load(f.path()).unwrap();
        assert_eq!(cfg.rsyslog.dgram_max_attempts, 0);
    }

    #[test]
    fn dgram_exhausted_defaults_to_drop() {
        let f = write_toml("[daemon]\nlisten_socket = \"/tmp/t.sock\"\n\n[rsyslog]\n");
        let cfg = load(f.path()).unwrap();
        assert_eq!(cfg.rsyslog.dgram_exhausted, DgramExhausted::Drop);
    }

    #[test]
    fn dgram_exhausted_terminate_parses() {
        let f = write_toml(
            "[daemon]\nlisten_socket = \"/tmp/t.sock\"\n\
             \n[rsyslog]\ndgram_exhausted = \"terminate\"\n",
        );
        let cfg = load(f.path()).unwrap();
        assert_eq!(cfg.rsyslog.dgram_exhausted, DgramExhausted::Terminate);
    }
}
