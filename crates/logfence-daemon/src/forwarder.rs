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
//!
//! ## Cloning behaviour
//!
//! `Forwarder` is cheaply cloneable and safe to pass to Tokio tasks.
//!
//! For `unix_dgram` output, all clones share a single unconnected socket via
//! `Arc`; no per-message connection setup is needed and `send_to` is lock-free.
//!
//! For `unix_stream` output, each clone holds an **independent** connection
//! slot (`Mutex<None>` on construction, lazily connected on first use).
//! Session tasks and worker tasks that each hold their own cloned `Forwarder`
//! therefore maintain separate persistent connections to rsyslog, allowing
//! writes to proceed in parallel without contending on a shared mutex.

use std::{path::Path, sync::Arc};

use thiserror::Error;
use tokio::{io::AsyncWriteExt, net::unix::OwnedWriteHalf, net::UnixStream, sync::Mutex};
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
/// See the module-level documentation for cloning behaviour.
#[derive(Clone)]
pub struct Forwarder(Inner);

// Datagram state is shared across all clones (one unconnected socket).
struct DgramConn {
    socket: tokio::net::UnixDatagram,
    path: String,
}

// Stream state is NOT shared: each clone of `Forwarder` holds its own
// independent connection slot.
struct StreamConn {
    path: String,
    /// Only the write half is retained after connecting.  The read half is
    /// dropped (and `shutdown(SHUT_RD)` issued) immediately after the OS
    /// connection is established.
    stream: Mutex<Option<OwnedWriteHalf>>,
}

impl Clone for StreamConn {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            stream: Mutex::new(None), // fresh, independent connection slot
        }
    }
}

enum Inner {
    UnixDgram(Arc<DgramConn>),
    UnixStream(StreamConn),
}

impl Clone for Inner {
    fn clone(&self) -> Self {
        match self {
            Inner::UnixDgram(arc) => Inner::UnixDgram(Arc::clone(arc)),
            Inner::UnixStream(conn) => Inner::UnixStream(conn.clone()),
        }
    }
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
                // Enforce write-only direction: logfenced never reads from the
                // rsyslog socket.
                socket.shutdown(std::net::Shutdown::Read)?;
                Inner::UnixDgram(Arc::new(DgramConn {
                    socket,
                    path: cfg.socket.clone(),
                }))
            }
            ForwardTransport::UnixStream => Inner::UnixStream(StreamConn {
                path: cfg.socket.clone(),
                stream: Mutex::new(None),
            }),
        };
        Ok(Self(inner))
    }

    /// Forward a validated [`SyslogMessage`] to rsyslog.
    ///
    /// # Errors
    ///
    /// Returns [`ForwardError::Io`] on any I/O failure. Unix stream connections
    /// are re-established automatically on the next call after a failure.
    pub async fn forward(&self, msg: &SyslogMessage) -> Result<(), ForwardError> {
        let wire = msg.to_string();
        match &self.0 {
            Inner::UnixDgram(conn) => {
                conn.socket
                    .send_to(wire.as_bytes(), Path::new(&conn.path))
                    .await?;
                debug!(bytes = wire.len(), "forwarded via unix_dgram");
            }
            Inner::UnixStream(conn) => {
                let frame = format!("{} {wire}", wire.len());
                let mut guard = conn.stream.lock().await;
                if guard.is_none() {
                    // Connect, then enforce write-only direction by shutting
                    // down the read half at the OS level before splitting.
                    let raw = UnixStream::connect(&conn.path).await?;
                    let std_raw = raw.into_std()?;
                    std_raw.shutdown(std::net::Shutdown::Read)?;
                    let raw = UnixStream::from_std(std_raw)?;
                    let (_, write_half) = raw.into_split();
                    *guard = Some(write_half);
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

    #[tokio::test]
    async fn clone_creates_independent_stream_connection() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("rsyslog.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();

        let cfg = rsyslog_cfg(ForwardTransport::UnixStream, sock_path.to_str().unwrap());
        let f1 = Forwarder::from_config(&cfg).unwrap();
        let f2 = f1.clone();

        let msg = sample_msg();

        // Forward from both clones concurrently.
        let m1 = msg.clone();
        let m2 = msg.clone();
        let (r1, r2) = tokio::join!(
            tokio::spawn(async move { f1.forward(&m1).await.unwrap() }),
            tokio::spawn(async move { f2.forward(&m2).await.unwrap() }),
        );
        r1.unwrap();
        r2.unwrap();

        // Both clones must have established independent connections: the listener
        // should have accepted exactly two connections.
        let mut accepted = 0usize;
        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(1), listener.accept())
                .await
                .unwrap()
                .unwrap();
            accepted += 1;
        }
        assert_eq!(accepted, 2, "expected two independent stream connections");
    }
}
