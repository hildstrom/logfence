//! C API for the logfence-client library.
//!
//! Provides a simple, blocking API for C programs to send RFC 5424 syslog
//! messages with JSON object payloads to a running `logfenced` daemon or
//! directly to rsyslog.
//!
//! # Quick start (C)
//!
//! ```c
//! #include "logfence.h"
//!
//! LfClient *client = lf_client_new("/run/logfenced/logfenced.sock",
//!                                  LF_MAX_MSG_SIZE_DEFAULT);
//! if (!client) { /* handle allocation or path error */ }
//!
//! LfMsgAttr attr = {0};
//! attr.app_name = "myapp";
//! attr.msg_id   = "LOGIN";
//!
//! int rc = lf_send(client, LF_FACILITY_LOCAL0, LF_SEVERITY_INFO,
//!                  &attr, "{\"user\":\"alice\",\"result\":\"ok\"}");
//! if (rc != LF_OK)
//!     fprintf(stderr, "lf_send: %s\n", lf_strerror(rc));
//!
//! lf_client_free(client);
//! ```

// This crate is the FFI boundary between Rust and C. Raw pointer operations
// are required to implement the opaque-handle pattern and to read C strings.
// Every unsafe block carries a SAFETY comment that identifies the invariant
// the caller must uphold.
#![allow(
    unsafe_code,
    reason = "FFI boundary requires raw pointer operations for C interop"
)]

use std::ffi::{c_char, c_int, CStr};

use logfence_client::now_rfc3339;
use logfence_client::transport::{Transport, UnixTransport};
use logfence_proto::syslog::{Facility, Priority, Severity, SyslogMessage};
use tokio::runtime::Runtime;

// ── Error codes ───────────────────────────────────────────────────────────────

/// No error; the message was delivered successfully.
pub const LF_OK: c_int = 0;
/// A required pointer argument was `NULL` (e.g. `client` in `lf_send`).
pub const LF_ERR_NULL: c_int = 1;
/// `facility` is outside 0–23, or `severity` is outside 0–7.
pub const LF_ERR_INVALID: c_int = 2;
/// `json_body` is not a valid JSON object string.
pub const LF_ERR_BUILD: c_int = 3;
/// The message could not be delivered (socket unavailable, broken pipe, etc.).
pub const LF_ERR_IO: c_int = 4;

// ── Opaque client handle ──────────────────────────────────────────────────────

/// Opaque client handle.
///
/// Created by [`lf_client_new`] and freed by [`lf_client_free`].
/// All fields are private; interact with the handle only through the API functions.
pub struct LfClient {
    transport: UnixTransport,
    runtime: Runtime,
}

// ── Message attributes ────────────────────────────────────────────────────────

/// Optional RFC 5424 header attributes for [`lf_send`].
///
/// Zero-initialise the struct (`LfMsgAttr attr = {0}`) and set only the fields
/// you need. `NULL` in any pointer field selects the default value described
/// in the field documentation. Passing `NULL` for the struct pointer itself is
/// equivalent to zero-initialising all fields.
#[repr(C)]
pub struct LfMsgAttr {
    /// RFC 5424 HOSTNAME. `NULL` → nil value (`-`).
    pub hostname: *const c_char,
    /// RFC 5424 APP-NAME. `NULL` → nil value (`-`).
    pub app_name: *const c_char,
    /// RFC 5424 MSGID. `NULL` → nil value (`-`).
    pub msg_id: *const c_char,
    /// RFC 5424 PROCID. `NULL` → current process ID.
    pub proc_id: *const c_char,
    /// RFC 3339 timestamp, e.g. `"2026-05-19T12:00:00Z"`. `NULL` → current UTC time.
    pub timestamp: *const c_char,
    /// Prefix the JSON body with the MITRE CEE cookie (`@cee:`). `0` = no, `1` = yes.
    pub cee_cookie: c_int,
}

// ── Exported functions ────────────────────────────────────────────────────────

/// Create a client for delivering syslog messages to a Unix domain socket.
///
/// `socket_path` must be a valid NUL-terminated C string; it must not be `NULL`.
/// `max_msg_size` is the maximum accepted message size in bytes; use `65536`
/// (`LF_MAX_MSG_SIZE_DEFAULT`) for logfenced's default limit.
///
/// Returns a heap-allocated `LfClient` handle on success, or `NULL` on failure
/// (`NULL` path, non-UTF-8 path, or Tokio runtime allocation failure).
///
/// The caller must free the returned handle with [`lf_client_free`] when done.
/// The handle is not safe to free concurrently with an `lf_send` call on the
/// same handle from another thread.
///
/// # Safety
///
/// `socket_path`, if non-`NULL`, must point to a valid NUL-terminated C string
/// that remains live for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn lf_client_new(
    socket_path: *const c_char,
    max_msg_size: usize,
) -> *mut LfClient {
    if socket_path.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: socket_path is non-NULL. The caller guarantees it is a valid
    // NUL-terminated C string that remains live for the duration of this call.
    let path_cstr = unsafe { CStr::from_ptr(socket_path) };
    let Ok(path_str) = path_cstr.to_str() else {
        return std::ptr::null_mut();
    };
    let Ok(runtime) = Runtime::new() else {
        return std::ptr::null_mut();
    };
    Box::into_raw(Box::new(LfClient {
        transport: UnixTransport::new(path_str, max_msg_size),
        runtime,
    }))
}

/// Free a client handle returned by [`lf_client_new`].
///
/// Safe to call with `NULL` (no-op). After this call the pointer is invalid
/// and must not be passed to any API function.
///
/// # Safety
///
/// `client`, if non-`NULL`, must have been returned by [`lf_client_new`] and
/// must not have been freed already. Must not be called concurrently with
/// [`lf_send`] on the same handle.
#[no_mangle]
pub unsafe extern "C" fn lf_client_free(client: *mut LfClient) {
    if !client.is_null() {
        // SAFETY: client was returned by lf_client_new (Box::into_raw) and has
        // not been freed. Reconstructing the Box transfers ownership so it is
        // dropped correctly.
        drop(unsafe { Box::from_raw(client) });
    }
}

/// Send a syslog message with a JSON object body.
///
/// Blocks until the message is delivered or an error occurs. Safe to call
/// concurrently from multiple threads with the same handle.
///
/// `client` must not be `NULL`. `facility` must be 0–23 and `severity` must be
/// 0–7; use the `LF_FACILITY_*` and `LF_SEVERITY_*` constants. `attr` may be
/// `NULL` to use all defaults. `json_body` must be a valid JSON object string
/// (e.g. `{"key":"value"}`); `NULL` is treated as `{}`.
///
/// Returns [`LF_OK`] (0) on success, or one of the `LF_ERR_*` codes on failure.
/// Call [`lf_strerror`] for a human-readable description.
///
/// # Safety
///
/// `client` must have been returned by [`lf_client_new`] and must not have been
/// freed. `attr`, if non-`NULL`, must point to a valid `LfMsgAttr` whose pointer
/// fields, if non-`NULL`, must be valid NUL-terminated C strings. `json_body`, if
/// non-`NULL`, must be a valid NUL-terminated C string. All pointers must remain
/// live for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn lf_send(
    client: *mut LfClient,
    facility: u8,
    severity: u8,
    attr: *const LfMsgAttr,
    json_body: *const c_char,
) -> c_int {
    if client.is_null() {
        return LF_ERR_NULL;
    }
    let Ok(fac) = Facility::from_integer(facility) else {
        return LF_ERR_INVALID;
    };
    if severity > 7 {
        return LF_ERR_INVALID;
    }
    let sev = Severity::from_integer(severity);

    let body: String = if json_body.is_null() {
        "{}".to_owned()
    } else {
        // SAFETY: json_body is non-NULL. The caller guarantees it is a valid
        // NUL-terminated C string that remains live for the duration of this call.
        let cstr = unsafe { CStr::from_ptr(json_body) };
        match cstr.to_str() {
            Ok(s) => s.to_owned(),
            Err(_) => return LF_ERR_BUILD,
        }
    };

    if !is_json_object(&body) {
        return LF_ERR_BUILD;
    }

    let msg = build_msg(fac, sev, attr, &body);

    // SAFETY: client is non-NULL, was allocated by lf_client_new (Box::into_raw),
    // and has not been freed. We take a shared reference — lf_client_free is the
    // only function that produces exclusive access and it must not be called
    // concurrently with lf_send (as documented).
    let c = unsafe { &*client };
    match c.runtime.block_on(c.transport.send(&msg)) {
        Ok(()) => LF_OK,
        Err(_) => LF_ERR_IO,
    }
}

/// Return a human-readable description of a return code.
///
/// The returned pointer references static storage and is valid for the
/// lifetime of the program. It must not be freed or written through.
#[no_mangle]
pub extern "C" fn lf_strerror(code: c_int) -> *const c_char {
    match code {
        0 => c"ok".as_ptr(),
        1 => c"null argument: client must not be NULL".as_ptr(),
        2 => c"invalid code: facility must be 0-23, severity must be 0-7".as_ptr(),
        3 => c"build error: json_body must be a valid JSON object string".as_ptr(),
        4 => c"I/O error: message could not be delivered to the socket".as_ptr(),
        _ => c"unknown error code".as_ptr(),
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Return `true` if `s` parses as a JSON object, `false` otherwise.
#[allow(
    clippy::match_like_matches_macro,
    reason = "explicit match is preferred over matches! per project style"
)]
fn is_json_object(s: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(s) {
        Ok(serde_json::Value::Object(_)) => true,
        _ => false,
    }
}

/// Convert a nullable C string pointer to `Option<String>`.
///
/// Returns `None` for `NULL` or invalid UTF-8; `Some(s)` for a valid string.
///
/// The caller must ensure that `ptr`, if non-`NULL`, is a valid NUL-terminated
/// C string that remains live for the duration of this call.
fn cstr_to_opt(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: ptr is non-NULL. The caller guarantees it is a valid NUL-terminated
    // C string live for the duration of this call.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(String::from)
}

/// Assemble a [`SyslogMessage`] from validated inputs.
///
/// When `attr` is `NULL`, all optional header fields use their defaults
/// (auto-timestamp, auto-PID, nil hostname/app-name/msg-id, no CEE prefix).
fn build_msg(fac: Facility, sev: Severity, attr: *const LfMsgAttr, body: &str) -> SyslogMessage {
    let priority = Priority(fac, sev);

    let (ts_override, hostname, app_name, proc_id_override, msg_id, cee) = if attr.is_null() {
        (None, None, None, None, None, false)
    } else {
        // SAFETY: attr is non-NULL. The caller (lf_send) guarantees it is a valid
        // LfMsgAttr whose pointer fields, if non-NULL, are valid C strings live
        // for the duration of this call.
        let a = unsafe { &*attr };
        (
            cstr_to_opt(a.timestamp),
            cstr_to_opt(a.hostname),
            cstr_to_opt(a.app_name),
            cstr_to_opt(a.proc_id),
            cstr_to_opt(a.msg_id),
            a.cee_cookie != 0,
        )
    };

    let timestamp = Some(ts_override.unwrap_or_else(now_rfc3339));
    let proc_id = Some(proc_id_override.unwrap_or_else(|| std::process::id().to_string()));
    let msg = if cee {
        format!("@cee:{body}")
    } else {
        body.to_owned()
    };

    SyslogMessage {
        priority,
        timestamp,
        hostname,
        app_name,
        proc_id,
        msg_id,
        structured_data: "-".to_owned(),
        msg,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "unwrap is appropriate in test assertions"
)]
mod tests {
    use std::ffi::CString;

    use logfence_proto::syslog::{Facility, Severity};

    use super::*;

    // ── is_json_object ────────────────────────────────────────────────────────

    #[test]
    fn json_object_accepts_empty_object() {
        assert!(is_json_object("{}"));
    }

    #[test]
    fn json_object_accepts_populated_object() {
        assert!(is_json_object(r#"{"action":"login","user_id":42}"#));
    }

    #[test]
    fn json_object_rejects_array() {
        assert!(!is_json_object("[]"));
    }

    #[test]
    fn json_object_rejects_primitives() {
        assert!(!is_json_object("null"));
        assert!(!is_json_object("42"));
        assert!(!is_json_object(r#""string""#));
        assert!(!is_json_object("true"));
    }

    #[test]
    fn json_object_rejects_malformed_json() {
        assert!(!is_json_object("{not json}"));
        assert!(!is_json_object(""));
    }

    // ── cstr_to_opt ───────────────────────────────────────────────────────────

    #[test]
    fn cstr_to_opt_null_returns_none() {
        assert_eq!(cstr_to_opt(std::ptr::null()), None);
    }

    #[test]
    fn cstr_to_opt_valid_returns_some() {
        let s = CString::new("myapp").unwrap();
        assert_eq!(cstr_to_opt(s.as_ptr()), Some("myapp".to_owned()));
    }

    // ── build_msg ─────────────────────────────────────────────────────────────

    #[test]
    fn build_msg_null_attr_uses_defaults() {
        let msg = build_msg(Facility::Local0, Severity::Info, std::ptr::null(), "{}");
        assert_eq!(msg.priority.as_integer(), 134); // Local0=16, Info=6 → 16*8+6=134
        assert!(
            msg.timestamp.is_some(),
            "timestamp should be auto-generated"
        );
        assert!(msg.proc_id.is_some(), "proc_id should be auto-generated");
        assert!(msg.hostname.is_none());
        assert!(msg.app_name.is_none());
        assert!(msg.msg_id.is_none());
        assert_eq!(msg.structured_data, "-");
        assert_eq!(msg.msg, "{}");
    }

    #[test]
    fn build_msg_cee_cookie_prefixes_body() {
        let attr = LfMsgAttr {
            hostname: std::ptr::null(),
            app_name: std::ptr::null(),
            msg_id: std::ptr::null(),
            proc_id: std::ptr::null(),
            timestamp: std::ptr::null(),
            cee_cookie: 1,
        };
        let msg = build_msg(
            Facility::Daemon,
            Severity::Warning,
            std::ptr::addr_of!(attr),
            r#"{"k":"v"}"#,
        );
        assert_eq!(msg.msg, r#"@cee:{"k":"v"}"#);
    }

    #[test]
    fn build_msg_attr_fields_propagate() {
        let app = CString::new("testapp").unwrap();
        let mid = CString::new("AUDIT").unwrap();
        let ts = CString::new("2026-05-19T00:00:00Z").unwrap();
        let attr = LfMsgAttr {
            hostname: std::ptr::null(),
            app_name: app.as_ptr(),
            msg_id: mid.as_ptr(),
            proc_id: std::ptr::null(),
            timestamp: ts.as_ptr(),
            cee_cookie: 0,
        };
        let msg = build_msg(
            Facility::Auth,
            Severity::Notice,
            std::ptr::addr_of!(attr),
            "{}",
        );
        assert_eq!(msg.app_name.as_deref(), Some("testapp"));
        assert_eq!(msg.msg_id.as_deref(), Some("AUDIT"));
        assert_eq!(msg.timestamp.as_deref(), Some("2026-05-19T00:00:00Z"));
    }

    // ── lf_send error paths ───────────────────────────────────────────────────

    #[test]
    fn lf_send_null_client_returns_err_null() {
        // SAFETY: deliberately passing NULL client to test the null-check path.
        assert_eq!(
            unsafe {
                lf_send(
                    std::ptr::null_mut(),
                    16,
                    6,
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            LF_ERR_NULL
        );
    }

    #[test]
    fn lf_send_invalid_facility_returns_err_invalid() {
        // SAFETY: socket_path is a valid CString for the duration of the call.
        let client = unsafe {
            lf_client_new(
                CString::new("/tmp/nonexistent.sock").unwrap().as_ptr(),
                65536,
            )
        };
        assert!(!client.is_null());
        // SAFETY: client is valid; facility 24 is out of range (tests error path).
        assert_eq!(
            unsafe { lf_send(client, 24, 6, std::ptr::null(), std::ptr::null()) },
            LF_ERR_INVALID
        );
        // SAFETY: client was returned by lf_client_new and has not been freed.
        unsafe { lf_client_free(client) };
    }

    #[test]
    fn lf_send_invalid_severity_returns_err_invalid() {
        // SAFETY: socket_path is a valid CString for the duration of the call.
        let client = unsafe {
            lf_client_new(
                CString::new("/tmp/nonexistent.sock").unwrap().as_ptr(),
                65536,
            )
        };
        assert!(!client.is_null());
        // SAFETY: client is valid; severity 8 is out of range (tests error path).
        assert_eq!(
            unsafe { lf_send(client, 16, 8, std::ptr::null(), std::ptr::null()) },
            LF_ERR_INVALID
        );
        // SAFETY: client was returned by lf_client_new and has not been freed.
        unsafe { lf_client_free(client) };
    }

    #[test]
    fn lf_send_non_object_json_returns_err_build() {
        // SAFETY: socket_path is a valid CString for the duration of the call.
        let client = unsafe {
            lf_client_new(
                CString::new("/tmp/nonexistent.sock").unwrap().as_ptr(),
                65536,
            )
        };
        assert!(!client.is_null());
        let bad_json = CString::new("[1,2,3]").unwrap();
        // SAFETY: client is valid; bad_json is a valid CString for this call.
        assert_eq!(
            unsafe { lf_send(client, 16, 6, std::ptr::null(), bad_json.as_ptr()) },
            LF_ERR_BUILD
        );
        // SAFETY: client was returned by lf_client_new and has not been freed.
        unsafe { lf_client_free(client) };
    }

    #[test]
    fn lf_send_no_socket_returns_err_io() {
        // SAFETY: socket_path is a valid CString for the duration of the call.
        let client = unsafe {
            lf_client_new(
                CString::new("/tmp/logfence_test_nonexistent.sock")
                    .unwrap()
                    .as_ptr(),
                65536,
            )
        };
        assert!(!client.is_null());
        // SAFETY: client is valid; all other pointers are NULL (use defaults).
        assert_eq!(
            unsafe { lf_send(client, 16, 6, std::ptr::null(), std::ptr::null()) },
            LF_ERR_IO
        );
        // SAFETY: client was returned by lf_client_new and has not been freed.
        unsafe { lf_client_free(client) };
    }

    // ── lf_strerror ───────────────────────────────────────────────────────────

    #[test]
    fn lf_strerror_returns_nonnull_for_all_codes() {
        for code in [
            LF_OK,
            LF_ERR_NULL,
            LF_ERR_INVALID,
            LF_ERR_BUILD,
            LF_ERR_IO,
            99,
        ] {
            assert!(!lf_strerror(code).is_null());
        }
    }

    // ── Success path helpers ──────────────────────────────────────────────────

    /// Accept one connection on `listener`, read the RFC 6587 §3.4.1 octet-count
    /// frame, and return the syslog message that follows the `"<count> "` prefix.
    fn recv_one_frame(listener: &std::os::unix::net::UnixListener) -> String {
        use std::io::Read;
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 4096];
        let n = conn.read(&mut buf).unwrap();
        let raw = std::str::from_utf8(&buf[..n]).unwrap();
        // Frame format: "<byte-count> <syslog-line>"
        raw.split_once(' ').unwrap().1.to_owned()
    }

    // ── lf_client_new success ─────────────────────────────────────────────────

    #[test]
    fn lf_client_new_with_valid_path_returns_nonnull() {
        // The socket does not need to exist for the handle to be created.
        let path = CString::new("/tmp/lf_unit_create_test.sock").unwrap();
        // SAFETY: path is a valid NUL-terminated CString.
        let client = unsafe { lf_client_new(path.as_ptr(), 65536) };
        assert!(
            !client.is_null(),
            "lf_client_new should return a non-null handle"
        );
        // SAFETY: client was just returned by lf_client_new.
        unsafe { lf_client_free(client) };
    }

    // ── lf_send success paths ─────────────────────────────────────────────────

    #[test]
    fn lf_send_ok_with_default_attrs() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("send_default.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        let recv_handle = std::thread::spawn(move || recv_one_frame(&listener));

        let path = CString::new(sock_path.to_str().unwrap()).unwrap();
        // SAFETY: path is a valid CString.
        let client = unsafe { lf_client_new(path.as_ptr(), 65536) };
        assert!(!client.is_null());

        let json = CString::new(r#"{"event":"unit-success"}"#).unwrap();
        // SAFETY: client is valid; json is a valid CString; attr is NULL (use defaults).
        let rc = unsafe { lf_send(client, 16, 6, std::ptr::null(), json.as_ptr()) };
        assert_eq!(rc, LF_OK, "lf_send should return LF_OK");

        let syslog_msg = recv_handle.join().unwrap();
        // Local0(16) × 8 + Info(6) = 134
        assert!(
            syslog_msg.starts_with("<134>1 "),
            "expected RFC 5424 priority header: {syslog_msg}"
        );
        assert!(
            syslog_msg.contains(r#""event":"unit-success""#),
            "JSON payload missing from forwarded message: {syslog_msg}"
        );

        // SAFETY: client was returned by lf_client_new and has not been freed.
        unsafe { lf_client_free(client) };
    }

    #[test]
    fn lf_send_null_json_body_defaults_to_empty_object() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("send_null_json.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        let recv_handle = std::thread::spawn(move || recv_one_frame(&listener));

        let path = CString::new(sock_path.to_str().unwrap()).unwrap();
        // SAFETY: path is a valid CString.
        let client = unsafe { lf_client_new(path.as_ptr(), 65536) };
        assert!(!client.is_null());

        // SAFETY: client is valid; NULL json_body should default to "{}".
        let rc = unsafe { lf_send(client, 16, 6, std::ptr::null(), std::ptr::null()) };
        assert_eq!(rc, LF_OK, "lf_send should return LF_OK");

        let syslog_msg = recv_handle.join().unwrap();
        assert!(
            syslog_msg.ends_with(" {}"),
            "expected empty JSON object at end of RFC 5424 message: {syslog_msg}"
        );

        // SAFETY: client was returned by lf_client_new and has not been freed.
        unsafe { lf_client_free(client) };
    }

    #[test]
    fn lf_send_with_all_attrs_populates_header_fields() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("send_attrs.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        let recv_handle = std::thread::spawn(move || recv_one_frame(&listener));

        let path = CString::new(sock_path.to_str().unwrap()).unwrap();
        // SAFETY: path is a valid CString.
        let client = unsafe { lf_client_new(path.as_ptr(), 65536) };
        assert!(!client.is_null());

        let app = CString::new("myapp").unwrap();
        let mid = CString::new("AUDIT").unwrap();
        let ts = CString::new("2026-05-19T00:00:00Z").unwrap();
        let attr = LfMsgAttr {
            hostname: std::ptr::null(),
            app_name: app.as_ptr(),
            msg_id: mid.as_ptr(),
            proc_id: std::ptr::null(),
            timestamp: ts.as_ptr(),
            cee_cookie: 0,
        };
        let json = CString::new(r#"{"action":"login"}"#).unwrap();
        // SAFETY: client is valid; attr fields are valid CStrings live for this call.
        let rc = unsafe { lf_send(client, 3, 4, std::ptr::addr_of!(attr), json.as_ptr()) };
        assert_eq!(rc, LF_OK, "lf_send should return LF_OK");

        let syslog_msg = recv_handle.join().unwrap();
        // Daemon(3) × 8 + Warning(4) = 28
        assert!(
            syslog_msg.starts_with("<28>1 "),
            "expected RFC 5424 priority header: {syslog_msg}"
        );
        assert!(
            syslog_msg.contains("2026-05-19T00:00:00Z"),
            "expected timestamp in header: {syslog_msg}"
        );
        assert!(
            syslog_msg.contains("myapp"),
            "expected app_name in header: {syslog_msg}"
        );
        assert!(
            syslog_msg.contains("AUDIT"),
            "expected msg_id in header: {syslog_msg}"
        );
        assert!(
            syslog_msg.contains(r#""action":"login""#),
            "expected JSON payload: {syslog_msg}"
        );

        // SAFETY: client was returned by lf_client_new and has not been freed.
        unsafe { lf_client_free(client) };
    }

    #[test]
    fn lf_send_with_cee_cookie_adds_at_cee_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("send_cee.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        let recv_handle = std::thread::spawn(move || recv_one_frame(&listener));

        let path = CString::new(sock_path.to_str().unwrap()).unwrap();
        // SAFETY: path is a valid CString.
        let client = unsafe { lf_client_new(path.as_ptr(), 65536) };
        assert!(!client.is_null());

        let attr = LfMsgAttr {
            hostname: std::ptr::null(),
            app_name: std::ptr::null(),
            msg_id: std::ptr::null(),
            proc_id: std::ptr::null(),
            timestamp: std::ptr::null(),
            cee_cookie: 1,
        };
        let json = CString::new(r#"{"event":"cee-test"}"#).unwrap();
        // SAFETY: client is valid; attr is stack-allocated and valid for this call.
        let rc = unsafe { lf_send(client, 16, 6, std::ptr::addr_of!(attr), json.as_ptr()) };
        assert_eq!(rc, LF_OK, "lf_send should return LF_OK");

        let syslog_msg = recv_handle.join().unwrap();
        assert!(
            syslog_msg.contains(r#"@cee:{"event":"cee-test"}"#),
            "expected @cee: prefix in message body: {syslog_msg}"
        );

        // SAFETY: client was returned by lf_client_new and has not been freed.
        unsafe { lf_client_free(client) };
    }
}
