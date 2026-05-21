//! Transport trait and implementations for delivering syslog messages.
//!
//! Two transports are provided:
//!
//! - [`UnixTransport`] — connects to a Unix stream socket and sends messages
//!   using RFC 6587 §3.4.1 octet-count framing. This is the correct transport
//!   for talking to a running `logfenced` daemon or to rsyslog's `imuxsock`.
//!   The connection is established lazily on first send and re-established
//!   automatically after any I/O error.
//!
//! - [`UnixDatagramTransport`] — sends each message as a single datagram to a
//!   Unix socket. This is the correct transport for talking to rsyslog's
//!   standard `imuxsock` datagram input, or to a `logfenced` instance
//!   configured with `listen_transport = "unix_dgram"`. No framing is added;
//!   the datagram boundary is the message boundary.

use std::path::PathBuf;

use tokio::{
    io::AsyncWriteExt, net::unix::OwnedWriteHalf, net::UnixDatagram, net::UnixStream, sync::Mutex,
};

use logfence_proto::syslog::SyslogMessage;

use crate::error::ClientError;

// ── Transport trait ───────────────────────────────────────────────────────────

/// Deliver a [`SyslogMessage`] to a syslog endpoint.
///
/// Implementors must be `Send + Sync` so they can be shared across Tokio tasks.
/// The default implementation ([`UnixTransport`]) handles connection management
/// internally.
#[allow(
    async_fn_in_trait,
    reason = "Transport is only implemented within this crate; \
              the implementation produces Send futures due to its Send-safe state"
)]
pub trait Transport: Send + Sync {
    /// Send a single syslog message.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Io`] on I/O failure or
    /// [`ClientError::MessageTooLarge`] if the rendered message exceeds the
    /// transport's configured size limit.
    async fn send(&self, msg: &SyslogMessage) -> Result<(), ClientError>;
}

// ── UnixTransport ─────────────────────────────────────────────────────────────

/// RFC 6587 §3.4.1 octet-count framing over a Unix stream socket.
///
/// Connects lazily on the first [`send`](Transport::send) call. If the
/// connection is lost, the next `send` re-establishes it automatically.
///
/// Only the write half of the underlying socket is retained.  The read half
/// is shut down (`SHUT_RD`) immediately after connecting, enforcing write-only
/// direction at both the type level and the OS level.
///
/// Thread-safe: the socket is protected by a [`tokio::sync::Mutex`].
pub struct UnixTransport {
    path: PathBuf,
    max_size: usize,
    stream: Mutex<Option<OwnedWriteHalf>>,
}

impl UnixTransport {
    /// Create a transport that will connect to the Unix socket at `path`.
    ///
    /// `max_size` is the maximum accepted wire message size in bytes.
    /// Use `65536` for the logfenced default.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, max_size: usize) -> Self {
        Self {
            path: path.into(),
            max_size,
            stream: Mutex::new(None),
        }
    }
}

impl Transport for UnixTransport {
    async fn send(&self, msg: &SyslogMessage) -> Result<(), ClientError> {
        let wire = msg.to_string();
        if wire.len() > self.max_size {
            return Err(ClientError::MessageTooLarge {
                max: self.max_size,
                got: wire.len(),
            });
        }
        // RFC 6587 §3.4.1: prepend "<byte-count> " before the message.
        let frame = format!("{} {wire}", wire.len());
        let frame_bytes = frame.as_bytes();

        let mut guard = self.stream.lock().await;

        if guard.is_none() {
            // Connect, then enforce write-only direction by shutting down the
            // read half at the OS level before splitting.
            let conn = UnixStream::connect(&self.path).await?;
            let std_conn = conn.into_std()?;
            std_conn.shutdown(std::net::Shutdown::Read)?;
            let conn = UnixStream::from_std(std_conn)?;
            let (_, write_half) = conn.into_split();
            *guard = Some(write_half);
        }

        // `guard` is `Some` — we just set it above if it was `None`.
        let Some(stream) = guard.as_mut() else {
            return Err(ClientError::Io(std::io::Error::other(
                "internal: Unix stream not initialised",
            )));
        };

        if let Err(e) = stream.write_all(frame_bytes).await {
            // Drop the broken connection; next call will reconnect.
            *guard = None;
            return Err(ClientError::Io(e));
        }

        Ok(())
    }
}

// ── UnixDatagramTransport ─────────────────────────────────────────────────────

/// Write-only Unix datagram transport.
///
/// Sends each [`SyslogMessage`] as a single datagram to the configured socket
/// path.  This matches the framing expected by rsyslog's `imuxsock` datagram
/// input and by a `logfenced` instance configured with
/// `listen_transport = "unix_dgram"`.
///
/// The socket is created unbound and its read half is shut down (`SHUT_RD`)
/// immediately, enforcing write-only direction at both the type level and the
/// OS level.  There is no framing — the datagram boundary is the message
/// boundary.
///
/// Thread-safe: the socket is protected by a [`tokio::sync::Mutex`].
pub struct UnixDatagramTransport {
    path: PathBuf,
    max_size: usize,
    socket: Mutex<Option<UnixDatagram>>,
}

impl UnixDatagramTransport {
    /// Create a transport that will send to the Unix datagram socket at `path`.
    ///
    /// `max_size` is the maximum accepted wire message size in bytes.
    /// Use `65536` for the standard datagram limit.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, max_size: usize) -> Self {
        Self {
            path: path.into(),
            max_size,
            socket: Mutex::new(None),
        }
    }
}

impl Transport for UnixDatagramTransport {
    async fn send(&self, msg: &SyslogMessage) -> Result<(), ClientError> {
        let wire = msg.to_string();
        if wire.len() > self.max_size {
            return Err(ClientError::MessageTooLarge {
                max: self.max_size,
                got: wire.len(),
            });
        }

        let mut guard = self.socket.lock().await;

        if guard.is_none() {
            // Create an unbound socket and enforce write-only direction.
            let sock = UnixDatagram::unbound()?;
            sock.shutdown(std::net::Shutdown::Read)?;
            *guard = Some(sock);
        }

        // `guard` is `Some` — we just set it above if it was `None`.
        let Some(sock) = guard.as_ref() else {
            return Err(ClientError::Io(std::io::Error::other(
                "internal: Unix datagram socket not initialised",
            )));
        };

        if let Err(e) = sock.send_to(wire.as_bytes(), &self.path).await {
            // Drop the socket; next call will recreate it.
            *guard = None;
            return Err(ClientError::Io(e));
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
    use tokio::net::UnixListener;

    use logfence_proto::syslog::{Facility, Priority, Severity};

    use super::*;

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

    #[tokio::test]
    async fn unix_transport_sends_octet_count_frame() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();

        let transport = UnixTransport::new(&sock_path, 65536);
        let msg = sample_msg();
        let expected_wire = msg.to_string();

        let send_task = tokio::spawn(async move { transport.send(&msg).await.unwrap() });

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

        // Frame must be "<count> <message>"
        let (count_str, body) = received.split_once(' ').unwrap();
        assert_eq!(count_str.parse::<usize>().unwrap(), expected_wire.len());
        assert_eq!(body, expected_wire);

        send_task.await.unwrap();
    }

    #[tokio::test]
    async fn unix_transport_reconnects_after_error() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("reconnect.sock");

        let transport = UnixTransport::new(&sock_path, 65536);
        let msg = sample_msg();

        // First send fails — no listener yet.
        assert!(transport.send(&msg).await.is_err());

        // Start listener, second send should succeed.
        let listener = UnixListener::bind(&sock_path).unwrap();
        let send_task = tokio::spawn({
            let msg = msg.clone();
            async move { transport.send(&msg).await }
        });

        let accept = tokio::time::timeout(Duration::from_secs(1), listener.accept()).await;
        assert!(accept.is_ok());
        assert!(send_task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn unix_transport_rejects_oversized_message() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("oversize.sock");
        let transport = UnixTransport::new(&sock_path, 10); // tiny limit

        let err = transport.send(&sample_msg()).await.unwrap_err();
        assert!(matches!(err, ClientError::MessageTooLarge { .. }));
    }

    #[tokio::test]
    async fn unix_datagram_transport_sends_raw_wire() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("dgram.sock");
        let receiver = UnixDatagram::bind(&sock_path).unwrap();

        let transport = UnixDatagramTransport::new(&sock_path, 65536);
        let msg = sample_msg();
        let expected_wire = msg.to_string();

        transport.send(&msg).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let received = std::str::from_utf8(&buf[..n]).unwrap();

        // No framing — the raw RFC 5424 wire format is sent as-is.
        assert_eq!(received, expected_wire);
    }

    #[tokio::test]
    async fn unix_datagram_transport_rejects_oversized_message() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("oversize_dgram.sock");
        let transport = UnixDatagramTransport::new(&sock_path, 10); // tiny limit

        let err = transport.send(&sample_msg()).await.unwrap_err();
        assert!(matches!(err, ClientError::MessageTooLarge { .. }));
    }
}
