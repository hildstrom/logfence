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

use std::{path::PathBuf, time::Duration};

use tokio::{
    io::AsyncWriteExt, net::unix::OwnedWriteHalf, net::UnixDatagram, net::UnixStream, sync::Mutex,
};

use logfence_proto::syslog::SyslogMessage;

use crate::error::ClientError;

// ── Datagram retry ────────────────────────────────────────────────────────────

fn is_buffer_full(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::WouldBlock) || matches!(e.raw_os_error(), Some(105 | 55))
}

// Delay before the Nth attempt (1-indexed; no delay before attempt 1).
// Attempts 2–4 use short exponential back-off; attempt 5+ uses 1 s.
fn dgram_attempt_delay(attempt: u32) -> Duration {
    match attempt {
        2 => Duration::from_micros(100),
        3 => Duration::from_micros(500),
        4 => Duration::from_millis(2),
        _ => Duration::from_secs(1),
    }
}

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
/// The socket is created unbound.  On Linux, `SHUT_RD` is issued immediately
/// to enforce write-only direction at the OS level; macOS rejects that call on
/// unconnected sockets, so write-only is type-enforced only on that platform.
/// There is no framing — the datagram boundary is the message boundary.
///
/// Thread-safe: the socket is protected by a [`tokio::sync::Mutex`].
pub struct UnixDatagramTransport {
    path: PathBuf,
    max_size: usize,
    /// Total send attempts on `ENOBUFS`.  `0` = unlimited.  Default: `4`.
    max_attempts: u32,
    socket: Mutex<Option<UnixDatagram>>,
}

impl UnixDatagramTransport {
    /// Create a transport that will send to the Unix datagram socket at `path`.
    ///
    /// `max_size` is the maximum accepted wire message size in bytes.
    /// Use `65536` for the standard datagram limit.
    ///
    /// The default retry limit is 4 attempts.  Use [`max_attempts`] to change
    /// it.
    ///
    /// [`max_attempts`]: UnixDatagramTransport::max_attempts
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, max_size: usize) -> Self {
        Self {
            path: path.into(),
            max_size,
            max_attempts: 4,
            socket: Mutex::new(None),
        }
    }

    /// Set the maximum number of datagram send attempts.
    ///
    /// `0` means unlimited — retry until the send succeeds or a non-retryable
    /// error occurs.  Attempts 1–4 use a short exponential back-off (immediate
    /// → 100 µs → 500 µs → 2 ms); attempt 5 and above wait 1 s each.
    #[must_use]
    pub fn max_attempts(mut self, n: u32) -> Self {
        self.max_attempts = n;
        self
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
            let sock = UnixDatagram::unbound()?;
            // Enforce write-only direction at OS level. macOS returns ENOTCONN
            // for unconnected datagram sockets; safe to ignore since an unbound
            // socket has no address and cannot receive unsolicited data.
            if let Err(e) = sock.shutdown(std::net::Shutdown::Read) {
                if e.kind() != std::io::ErrorKind::NotConnected {
                    return Err(ClientError::Io(e));
                }
            }
            *guard = Some(sock);
        }

        // `guard` is `Some` — we just set it above if it was `None`.
        let Some(sock) = guard.as_ref() else {
            return Err(ClientError::Io(std::io::Error::other(
                "internal: Unix datagram socket not initialised",
            )));
        };

        // Use try_send_to (non-blocking) so buffer-full errors (EAGAIN on Linux,
        // ENOBUFS on macOS) reach is_buffer_full and the retry schedule runs
        // under our control instead of Tokio's internal re-queue.
        let mut last_err = match sock.try_send_to(wire.as_bytes(), &self.path) {
            Ok(_) => return Ok(()),
            Err(e) if !is_buffer_full(&e) => {
                *guard = None;
                return Err(ClientError::Io(e));
            }
            Err(e) => e,
        };
        let mut attempt = 2u32;
        loop {
            if self.max_attempts != 0 && attempt > self.max_attempts {
                break;
            }
            tokio::time::sleep(dgram_attempt_delay(attempt)).await;
            match sock.try_send_to(wire.as_bytes(), &self.path) {
                Ok(_) => return Ok(()),
                Err(e) if !is_buffer_full(&e) => {
                    *guard = None;
                    return Err(ClientError::Io(e));
                }
                Err(e) => last_err = e,
            }
            attempt = attempt.saturating_add(1);
        }
        *guard = None;
        Err(ClientError::Io(last_err))
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

    /// Fill the receiver's buffer with the minimum `SO_RCVBUF`, spawn a drain
    /// thread that waits 200 µs (past the 100 µs first-retry delay), and verify
    /// that `send()` recovers via the retry loop.
    #[tokio::test]
    async fn unix_datagram_retries_on_buffer_full() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("dgram_retry.sock");

        let receiver = std::os::unix::net::UnixDatagram::bind(&sock_path).unwrap();
        socket2::SockRef::from(&receiver)
            .set_recv_buffer_size(4096)
            .unwrap();

        let filler = std::os::unix::net::UnixDatagram::unbound().unwrap();
        filler.set_nonblocking(true).unwrap();
        let mut fill_count = 0usize;
        loop {
            match filler.send_to(&[0u8], &sock_path) {
                Ok(_) => {
                    fill_count += 1;
                    assert!(fill_count < 100_000, "socket buffer never filled");
                }
                Err(ref e) if super::is_buffer_full(e) => break,
                Err(ref e) => {
                    assert!(super::is_buffer_full(e), "unexpected fill error: {e}");
                    break;
                }
            }
        }
        assert!(fill_count > 0);

        let drainer = receiver.try_clone().unwrap();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_micros(200));
            let mut buf = vec![0u8; 65_536];
            drainer.set_nonblocking(true).unwrap();
            while drainer.recv(&mut buf).is_ok() {}
        });

        let transport = UnixDatagramTransport::new(&sock_path, 65_536);
        tokio::time::timeout(Duration::from_millis(200), transport.send(&sample_msg()))
            .await
            .unwrap()
            .unwrap();
    }
}
