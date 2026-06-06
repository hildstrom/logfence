# logfence-client-c

C API wrapper for `logfence-client`, providing a blocking interface for sending
structured syslog messages from C (and C++) programs.

Part of the [logfence](https://github.com/hildstrom/logfence) project.

## Overview

This crate compiles to both a shared library (`.so`/`.dylib`) and a static
library (`.a`). All unsafe FFI code is isolated here; the underlying Rust
client remains fully safe.

The API consists of four functions:

| Function | Description |
|---|---|
| `lf_client_new` | Create a client handle (lazy connection) |
| `lf_client_free` | Free a client handle |
| `lf_send` | Send a syslog message (blocking, thread-safe) |
| `lf_strerror` | Map an error code to a description string |

## Usage

### Building

```bash
cargo build --release -p logfence-client-c
```

The build produces:
- `target/release/liblogfence_client_c.so` (Linux) or `.dylib` (macOS)
- `target/release/liblogfence_client_c.a`

### C header

Include [`include/logfence.h`](include/logfence.h) in your C project.

### Example

```c
#include "logfence.h"
#include <stdio.h>

int main(void) {
    LfClient *client = lf_client_new("/run/logfenced/logfenced.sock",
                                     LF_MAX_MSG_SIZE_DEFAULT);
    if (!client) {
        fprintf(stderr, "failed to create logfence client\n");
        return 1;
    }

    LfMsgAttr attr = {0};
    attr.app_name = "myapp";
    attr.msg_id   = "LOGIN";

    int rc = lf_send(client, LF_FACILITY_LOCAL0, LF_SEVERITY_INFO,
                     &attr, "{\"user\":\"alice\",\"result\":\"ok\"}");
    if (rc != LF_OK)
        fprintf(stderr, "lf_send: %s\n", lf_strerror(rc));

    lf_client_free(client);
    return rc;
}
```

### Linking

```bash
gcc -o myapp myapp.c -L target/release -llogfence_client_c
```

### Thread safety

`lf_send` is safe to call concurrently from multiple threads with the same
`LfClient` handle. `lf_client_free` must not be called while `lf_send` is
executing on the same handle from another thread.

## Error codes

| Code | Constant | Description |
|---|---|---|
| 0 | `LF_OK` | Success |
| 1 | `LF_ERR_NULL` | A required pointer argument was NULL |
| 2 | `LF_ERR_INVALID` | Facility or severity out of range |
| 3 | `LF_ERR_BUILD` | `json_body` is not a valid JSON object |
| 4 | `LF_ERR_IO` | Transport error; message not delivered |

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or
[MIT license](../../LICENSE-MIT) at your option.
