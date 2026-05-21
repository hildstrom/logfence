//! logfenced — validating syslog filter daemon.
//!
//! Reads a TOML configuration file, loads JSON schemas, binds a Unix domain
//! socket, and dispatches each accepted connection to a session handler that
//! validates and forwards syslog messages to rsyslog.
//!
//! Signal handling (Unix only):
//! - `SIGTERM` — initiates graceful shutdown; active sessions drain before exit.
//! - `SIGHUP`  — atomically reloads JSON schemas; no connections are dropped.
//! - `SIGUSR1` — logs a metrics snapshot (received/forwarded/dropped/errors).

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use clap::Parser;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

mod config;
mod datagram_listener;
mod forwarder;
mod listener;
mod metrics;
mod session;
mod validator;

use metrics::MetricsStore;

// ── CLI ───────────────────────────────────────────────────────────────────────

/// logfenced — validating syslog filter daemon.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(
        short,
        long,
        default_value = "/etc/logfenced/logfenced.toml",
        value_name = "FILE"
    )]
    config: PathBuf,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> ExitCode {
    // Parse CLI arguments before any I/O so --help / --version work without a
    // config file.
    let args = Args::parse();

    // Load the config first (without logging active) so we can initialise
    // logging exactly once with the file's settings. If loading fails, default
    // to info/stderr so the error is still visible.
    let cfg_result = config::load(&args.config);
    let (log_level, log_output) = match &cfg_result {
        Ok(c) => (c.logging.level.clone(), c.logging.output.clone()),
        Err(_) => ("info".to_owned(), "stderr".to_owned()),
    };
    init_logging(&log_level, &log_output);

    let cfg = match cfg_result {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to load configuration");
            return ExitCode::FAILURE;
        }
    };

    info!(
        socket = %cfg.daemon.listen_socket,
        listen_transport = ?cfg.daemon.listen_transport,
        forward_transport = ?cfg.rsyslog.transport,
        validation = ?cfg.validation.mode,
        "logfenced starting"
    );

    // Compile JSON schemas into the initial validator.
    let validator = match build_validator(&cfg.validation) {
        Ok(v) => Arc::new(v),
        Err(e) => {
            error!(error = %e, "failed to build validator");
            return ExitCode::FAILURE;
        }
    };

    // The watch channel carries the live validator. SIGHUP sends a new
    // Arc<Validator>; sessions pick it up on their next message.
    let (validator_tx, validator_rx) = watch::channel(validator);

    // Shared atomic counters — incremented per message by session tasks.
    let store = MetricsStore::new();

    // Build the rsyslog forwarder.
    let forwarder = match forwarder::Forwarder::from_config(&cfg.rsyslog) {
        Ok(f) => f,
        Err(e) => {
            error!(error = %e, "failed to create rsyslog forwarder");
            return ExitCode::FAILURE;
        }
    };

    let listen_transport = cfg.daemon.listen_transport;

    let shutdown = CancellationToken::new();

    // Optional metrics stats socket.
    if cfg.metrics.enabled {
        tokio::spawn(metrics::serve_stats_socket(
            cfg.metrics.socket.clone(),
            Arc::clone(&store),
            shutdown.child_token(),
        ));
    }

    // Bind the listening socket and spawn the accept loop as a task so the
    // signal handler can run concurrently.
    let listener_task = match listen_transport {
        config::ListenTransport::UnixStream => {
            let listener = match listener::Listener::bind(cfg.daemon, forwarder) {
                Ok(l) => l,
                Err(e) => {
                    error!(error = %e, "failed to bind socket");
                    return ExitCode::FAILURE;
                }
            };
            tokio::spawn(listener.run(shutdown.child_token(), validator_rx, Arc::clone(&store)))
        }
        config::ListenTransport::UnixDgram => {
            let listener = match datagram_listener::DatagramListener::bind(cfg.daemon, forwarder) {
                Ok(l) => l,
                Err(e) => {
                    error!(error = %e, "failed to bind socket");
                    return ExitCode::FAILURE;
                }
            };
            tokio::spawn(listener.run(shutdown.child_token(), validator_rx, Arc::clone(&store)))
        }
    };

    // Block until SIGTERM (or Ctrl-C on non-Unix), handling SIGHUP / SIGUSR1.
    handle_signals(
        args.config.as_path(),
        &validator_tx,
        &shutdown,
        &cfg.validation,
        &store,
    )
    .await;

    // Wait for the listener to finish draining active sessions.
    if let Err(e) = listener_task.await {
        error!(error = ?e, "listener task panicked");
    }

    ExitCode::SUCCESS
}

// ── Signal handling ───────────────────────────────────────────────────────────

#[cfg(unix)]
async fn handle_signals(
    config_path: &Path,
    validator_tx: &watch::Sender<Arc<validator::Validator>>,
    shutdown: &CancellationToken,
    current_validation: &config::ValidationConfig,
    store: &MetricsStore,
) {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to register SIGTERM handler");
            return;
        }
    };
    let mut sighup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to register SIGHUP handler");
            return;
        }
    };
    let mut sigusr1 = match signal(SignalKind::user_defined1()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to register SIGUSR1 handler");
            return;
        }
    };

    let mut validation = current_validation.clone();

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                info!("SIGTERM received; initiating graceful shutdown");
                shutdown.cancel();
                break;
            }
            _ = sighup.recv() => {
                info!("SIGHUP received; reloading schemas");
                match reload_validator(config_path) {
                    Ok((new_cfg, v)) => {
                        validation = new_cfg;
                        let _ = validator_tx.send(Arc::new(v));
                        info!("schemas reloaded successfully");
                    }
                    Err(e) => {
                        error!(error = %e, "schema reload failed; keeping current validator");
                    }
                }
            }
            _ = sigusr1.recv() => {
                let snap = store.snapshot();
                info!(
                    received = snap.received,
                    forwarded = snap.forwarded,
                    dropped = snap.dropped,
                    errors = snap.errors,
                    "metrics snapshot"
                );
            }
        }
    }

    let _ = validation;
}

#[cfg(not(unix))]
async fn handle_signals(
    _config_path: &Path,
    _validator_tx: &watch::Sender<Arc<validator::Validator>>,
    shutdown: &CancellationToken,
    _current_validation: &config::ValidationConfig,
    _store: &MetricsStore,
) {
    match tokio::signal::ctrl_c().await {
        Ok(()) => info!("Ctrl-C received; initiating graceful shutdown"),
        Err(e) => error!(error = %e, "failed to register Ctrl-C handler"),
    }
    shutdown.cancel();
}

// ── Config reload ─────────────────────────────────────────────────────────────

fn reload_validator(
    config_path: &Path,
) -> Result<(config::ValidationConfig, validator::Validator), String> {
    let cfg = config::load(config_path).map_err(|e| e.to_string())?;
    let v = build_validator(&cfg.validation)?;
    Ok((cfg.validation, v))
}

// ── Logging setup ─────────────────────────────────────────────────────────────

fn init_logging(level: &str, output: &str) {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

    let result = if output == "stderr" {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .try_init()
    } else {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(output)
        {
            Ok(file) => tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .with_writer(std::sync::Mutex::new(file))
                .try_init(),
            Err(e) => {
                // Fall back to stderr and note the failure after the subscriber
                // is initialised below.
                let init_result = tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_target(false)
                    .try_init();
                warn!(path = %output, error = %e, "cannot open log file; using stderr");
                init_result
            }
        }
    };

    if let Err(e) = result {
        // A subscriber is already set. This is harmless — it happens only in
        // tests where multiple components call init_logging.
        let _ = e;
    }
}

// ── Validator builder ─────────────────────────────────────────────────────────

fn build_validator(cfg: &config::ValidationConfig) -> Result<validator::Validator, String> {
    let docs = load_schema_files(&cfg.schemas)?;
    let v = validator::Validator::from_values(cfg.mode, &docs)
        .map_err(|e| format!("invalid JSON schema: {e}"))?
        .with_input_cee(cfg.input_cee)
        .with_output_cee(cfg.output_cee)
        .with_canonical_json(cfg.canonical_json);

    if let Some(field) = &cfg.discriminator {
        let disc_docs = load_schema_files_map(&cfg.schema_map)?;
        return v
            .with_discriminator_docs(field.clone(), disc_docs)
            .map_err(|e| format!("invalid discriminator schema: {e}"));
    }

    Ok(v)
}

fn load_schema_files(paths: &[String]) -> Result<Vec<serde_json::Value>, String> {
    let mut docs = Vec::with_capacity(paths.len());
    for path in paths {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read schema '{path}': {e}"))?;
        let doc: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("cannot parse schema '{path}': {e}"))?;
        docs.push(doc);
    }
    Ok(docs)
}

fn load_schema_files_map(
    schema_map: &HashMap<String, String>,
) -> Result<HashMap<String, serde_json::Value>, String> {
    let mut docs = HashMap::with_capacity(schema_map.len());
    for (key, path) in schema_map {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read discriminator schema '{path}': {e}"))?;
        let doc: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("cannot parse discriminator schema '{path}': {e}"))?;
        docs.insert(key.clone(), doc);
    }
    Ok(docs)
}
