//! Forwarding validated syslog messages to rsyslog.
//!
//! [`Forwarder`] wraps the configured rsyslog transport and serializes
//! [`SyslogMessage`] values to the wire format expected by rsyslog.
//!
//! Two transports are supported:
//!
//! - `unix_dgram` — sends each message as a Unix datagram (default; matches
//!   rsyslog `imuxsock` on Linux/macOS).
//! - `unix_stream` — sends each message with RFC 6587 octet-count framing
//!   over a Unix stream socket.

use std::{path::Path, sync::Arc};

use thiserror::Error;
use tokio::{io::AsyncWriteExt, net::UnixStream, sync::Mutex};
use tracing::debug;

use logfence_proto::syslog::SyslogMessage;

use crate::config::{ForwardTransport, RsyslogConfig};

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors that can occur while forwarding a message.
#[derive(Debug, Error)]
pub enum ForwardError {
    /// An I/O error occurred while sending to rsyslog.
    #[error("I/O error forwarding to rsyslog: {0}")]
    Io(#[from] std::io::Error),
}

// ── Forwarder ─────────────────────────────────────────────────────────────────

/// Sends validated syslog messages to rsyslog.
///
/// The underlying connection is managed internally and reconnected on error.
/// `Forwarder` is cheaply cloneable (`Arc`-backed) and safe to share across
/// Tokio tasks.
#[derive(Clone)]
pub struct Forwarder(Arc<Inner>);

enum Inner {
    UnixDgram {
        socket: tokio::net::UnixDatagram,
        path: String,
    },
    UnixStream {
        path: String,
        stream: Mutex<Option<UnixStream>>,
    },
}

impl Forwarder {
    /// Build a [`Forwarder`] from a [`RsyslogConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`ForwardError::Io`] if the socket cannot be created.
    pub fn from_config(cfg: &RsyslogConfig) -> Result<Self, ForwardError> {
        let inner = match cfg.transport {
            ForwardTransport::UnixDgram => {
                let socket = tokio::net::UnixDatagram::unbound()?;
                Inner::UnixDgram {
                    socket,
                    path: cfg.socket.clone(),
                }
            }
            ForwardTransport::UnixStream => Inner::UnixStream {
                path: cfg.socket.clone(),
                stream: Mutex::new(None),
            },
        };
        Ok(Self(Arc::new(inner)))
    }

    /// Forward a validated [`SyslogMessage`] to rsyslog.
    ///
    /// # Errors
    ///
    /// Returns [`ForwardError::Io`] on any I/O failure. Unix stream connections
    /// are re-established automatically on the next call after a failure.
    pub async fn forward(&self, msg: &SyslogMessage) -> Result<(), ForwardError> {
        let wire = msg.to_string();
        match self.0.as_ref() {
            Inner::UnixDgram { socket, path } => {
                socket.send_to(wire.as_bytes(), Path::new(path)).await?;
                debug!(bytes = wire.len(), "forwarded via unix_dgram");
            }
            Inner::UnixStream { path, stream } => {
                let frame = format!("{} {wire}", wire.len());
                let mut guard = stream.lock().await;
                if guard.is_none() {
                    *guard = Some(UnixStream::connect(path).await?);
                }
                let Some(s) = guard.as_mut() else {
                    return Err(ForwardError::Io(std::io::Error::other(
                        "internal: unix stream not initialised",
                    )));
                };
                if let Err(e) = s.write_all(frame.as_bytes()).await {
                    *guard = None;
                    return Err(ForwardError::Io(e));
                }
                debug!(bytes = wire.len(), "forwarded via unix_stream");
            }
        }
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
    use std::time::Duration;

    use tokio::io::AsyncReadExt;
    use tokio::net::{UnixDatagram, UnixListener};

    use logfence_proto::syslog::{Facility, Priority, Severity};

    use super::*;
    use crate::config::{ForwardTransport, RsyslogConfig};

    fn sample_msg() -> SyslogMessage {
        SyslogMessage {
            priority: Priority(Facility::Local0, Severity::Info),
            timestamp: None,
            hostname: None,
            app_name: Some("test".into()),
            proc_id: None,
            msg_id: None,
            structured_data: "-".into(),
            msg: r#"{"k":"v"}"#.into(),
        }
    }

    fn rsyslog_cfg(transport: ForwardTransport, socket: &str) -> RsyslogConfig {
        RsyslogConfig {
            transport,
            socket: socket.to_owned(),
        }
    }

    #[tokio::test]
    async fn unix_dgram_forward() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("rsyslog.sock");

        let receiver = UnixDatagram::bind(&sock_path).unwrap();
        let cfg = rsyslog_cfg(ForwardTransport::UnixDgram, sock_path.to_str().unwrap());
        let forwarder = Forwarder::from_config(&cfg).unwrap();

        let msg = sample_msg();
        let expected = msg.to_string();
        forwarder.forward(&msg).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let received = std::str::from_utf8(&buf[..n]).unwrap();
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn unix_stream_forward_octet_count() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("rsyslog.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();

        let cfg = rsyslog_cfg(ForwardTransport::UnixStream, sock_path.to_str().unwrap());
        let forwarder = Forwarder::from_config(&cfg).unwrap();

        let msg = sample_msg();
        let expected_wire = msg.to_string();

        let send_task = tokio::spawn(async move { forwarder.forward(&msg).await.unwrap() });
        let (mut conn, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(1), conn.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let received = std::str::from_utf8(&buf[..n]).unwrap();

        let (count_str, body) = received.split_once(' ').unwrap();
        assert_eq!(count_str.parse::<usize>().unwrap(), expected_wire.len());
        assert_eq!(body, expected_wire);

        send_task.await.unwrap();
    }
}
