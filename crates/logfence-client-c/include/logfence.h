/**
 * logfence C client API
 *
 * Simple, blocking API for sending RFC 5424 syslog messages with JSON object
 * payloads to a running logfenced daemon or directly to rsyslog.
 *
 * Usage
 * -----
 *   LfClient *client = lf_client_new("/run/logfenced/logfenced.sock",
 *                                    LF_MAX_MSG_SIZE_DEFAULT);
 *   if (!client) { ... }
 *
 *   LfMsgAttr attr = {0};
 *   attr.app_name = "myapp";
 *   attr.msg_id   = "LOGIN";
 *
 *   int rc = lf_send(client, LF_FACILITY_LOCAL0, LF_SEVERITY_INFO,
 *                    &attr, "{\"user\":\"alice\",\"result\":\"ok\"}");
 *   if (rc != LF_OK)
 *       fprintf(stderr, "lf_send: %s\n", lf_strerror(rc));
 *
 *   lf_client_free(client);
 *
 * Thread safety
 * -------------
 * lf_send is safe to call concurrently from multiple threads with the same
 * LfClient handle. lf_client_free must not be called while lf_send is
 * executing on the same handle from another thread.
 */

#ifndef LOGFENCE_H
#define LOGFENCE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Opaque handle ──────────────────────────────────────────────────────────── */

/** Opaque client handle. Create with lf_client_new; free with lf_client_free. */
typedef struct LfClient LfClient;

/* ── Error codes ────────────────────────────────────────────────────────────── */

#define LF_OK           0  /**< Success. */
#define LF_ERR_NULL     1  /**< A required pointer argument was NULL. */
#define LF_ERR_INVALID  2  /**< facility (0–23) or severity (0–7) out of range. */
#define LF_ERR_BUILD    3  /**< json_body is not a valid JSON object string. */
#define LF_ERR_IO       4  /**< Transport error; message was not delivered. */

/* ── RFC 5424 facility codes (§6.2.1) ──────────────────────────────────────── */

#define LF_FACILITY_KERN      0   /**< kernel messages */
#define LF_FACILITY_USER      1   /**< user-level messages */
#define LF_FACILITY_MAIL      2   /**< mail system */
#define LF_FACILITY_DAEMON    3   /**< system daemons */
#define LF_FACILITY_AUTH      4   /**< security/authorization messages */
#define LF_FACILITY_SYSLOG    5   /**< syslogd internal messages */
#define LF_FACILITY_LPR       6   /**< line printer subsystem */
#define LF_FACILITY_NEWS      7   /**< network news subsystem */
#define LF_FACILITY_UUCP      8   /**< UUCP subsystem */
#define LF_FACILITY_CRON      9   /**< clock daemon */
#define LF_FACILITY_AUTHPRIV  10  /**< security/authorization messages (private) */
#define LF_FACILITY_FTP       11  /**< FTP daemon */
#define LF_FACILITY_NTP       12  /**< NTP subsystem */
#define LF_FACILITY_LOGAUDIT  13  /**< log audit */
#define LF_FACILITY_LOGALERT  14  /**< log alert */
#define LF_FACILITY_CLOCK     15  /**< clock daemon */
#define LF_FACILITY_LOCAL0    16  /**< local use 0 */
#define LF_FACILITY_LOCAL1    17  /**< local use 1 */
#define LF_FACILITY_LOCAL2    18  /**< local use 2 */
#define LF_FACILITY_LOCAL3    19  /**< local use 3 */
#define LF_FACILITY_LOCAL4    20  /**< local use 4 */
#define LF_FACILITY_LOCAL5    21  /**< local use 5 */
#define LF_FACILITY_LOCAL6    22  /**< local use 6 */
#define LF_FACILITY_LOCAL7    23  /**< local use 7 */

/* ── RFC 5424 severity codes (§6.2.1) ──────────────────────────────────────── */

#define LF_SEVERITY_EMERGENCY  0  /**< system is unusable */
#define LF_SEVERITY_ALERT      1  /**< action must be taken immediately */
#define LF_SEVERITY_CRITICAL   2  /**< critical conditions */
#define LF_SEVERITY_ERROR      3  /**< error conditions */
#define LF_SEVERITY_WARNING    4  /**< warning conditions */
#define LF_SEVERITY_NOTICE     5  /**< normal but significant condition */
#define LF_SEVERITY_INFO       6  /**< informational messages */
#define LF_SEVERITY_DEBUG      7  /**< debug-level messages */

/* ── Constants ──────────────────────────────────────────────────────────────── */

/** Default maximum message size in bytes. Matches logfenced's built-in limit. */
#define LF_MAX_MSG_SIZE_DEFAULT  65536

/* ── Message attributes ─────────────────────────────────────────────────────── */

/**
 * Optional RFC 5424 header attributes for lf_send.
 *
 * Zero-initialise the struct and set only the fields you need:
 *   LfMsgAttr attr = {0};
 *   attr.app_name = "myapp";
 *
 * NULL in any pointer field selects the documented default. Passing NULL for
 * the struct pointer itself to lf_send is equivalent to zero-initialising all
 * fields.
 */
typedef struct LfMsgAttr {
    const char *hostname;   /**< RFC 5424 HOSTNAME.  NULL = nil value (-). */
    const char *app_name;   /**< RFC 5424 APP-NAME.  NULL = nil value (-). */
    const char *msg_id;     /**< RFC 5424 MSGID.     NULL = nil value (-). */
    const char *proc_id;    /**< RFC 5424 PROCID.    NULL = current process ID. */
    const char *timestamp;  /**< RFC 3339 timestamp. NULL = current UTC time. */
    int         cee_cookie; /**< Prefix body with @cee:. 0 = no, 1 = yes. */
} LfMsgAttr;

/* ── Functions ──────────────────────────────────────────────────────────────── */

/**
 * Create a client for sending syslog messages to a Unix domain socket.
 *
 * @param socket_path   Path to the logfenced or rsyslog Unix socket. Must not be NULL.
 * @param max_msg_size  Maximum message size in bytes. Use LF_MAX_MSG_SIZE_DEFAULT.
 * @return              Heap-allocated LfClient handle, or NULL on failure.
 *
 * Reasons for NULL return: NULL socket_path, non-UTF-8 path, or runtime
 * allocation failure.
 *
 * The socket connection is established lazily on the first lf_send call and
 * re-established automatically after any I/O error.
 *
 * Free the returned handle with lf_client_free when it is no longer needed.
 */
LfClient *lf_client_new(const char *socket_path, size_t max_msg_size);

/**
 * Free a client handle returned by lf_client_new.
 *
 * Safe to call with NULL (no-op). After this call the pointer is invalid.
 * Must not be called concurrently with lf_send on the same handle.
 */
void lf_client_free(LfClient *client);

/**
 * Send a syslog message with a JSON object body.
 *
 * Blocks until the message is delivered or an error occurs. Safe to call
 * concurrently from multiple threads with the same client handle.
 *
 * @param client    Handle from lf_client_new. Must not be NULL.
 * @param facility  RFC 5424 facility code (0–23). Use LF_FACILITY_* constants.
 * @param severity  RFC 5424 severity code (0–7). Use LF_SEVERITY_* constants.
 * @param attr      Optional header attributes. NULL uses all defaults.
 * @param json_body JSON object string, e.g. {"key":"value"}. NULL uses {}.
 * @return          LF_OK on success, or an LF_ERR_* code on failure.
 *
 * lf_strerror(return_value) provides a human-readable description.
 */
int lf_send(LfClient       *client,
            uint8_t         facility,
            uint8_t         severity,
            const LfMsgAttr *attr,
            const char      *json_body);

/**
 * Return a human-readable description of a return code.
 *
 * The returned pointer references static storage; it must not be freed or
 * written through, and is valid for the lifetime of the program.
 *
 * @param code  A return code from lf_send or lf_client_new.
 * @return      NUL-terminated description string.
 */
const char *lf_strerror(int code);

#ifdef __cplusplus
}
#endif

#endif /* LOGFENCE_H */
