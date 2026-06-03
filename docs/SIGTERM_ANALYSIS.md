# SIGTERM shutdown analysis

## Bug fixed

The stream listener's accept loop (`listener.rs`) blocked on
`listener.accept().await` outside any `select!`, so SIGTERM was never
observed while the daemon was idle. The fix wraps `accept()` in a
`biased` select alongside `shutdown.cancelled()`, matching the pattern
already used in the datagram listener.

## Verified scenarios

**Idle (no active connections).** The `select!` on `accept()` detects
the cancelled token immediately. Drain succeeds instantly because all
semaphore permits are available. Exits in under 1 ms.

**Under load, clients disconnect cooperatively.** The accept loop
breaks. Active sessions continue processing their streams until they
read EOF, then drop their semaphore permits. Drain completes as soon as
the last session finishes. Exits within ~100 ms of the last client
close.

**Under load, clients stay connected.** The accept loop breaks. Active
sessions remain blocked in `read_buf()`. The 30-second
`SHUTDOWN_DRAIN_TIMEOUT` fires and the process exits. This is the
expected graceful-degradation path.

## `dgram_max_attempts = 0` makes sessions un-drainable

When a datagram forward hits EAGAIN (for example because the
`net.unix.max_dgram_qlen` kernel queue is full), `dgram_max_attempts = 0`
(unlimited retries) loops forever inside `forwarder.forward()`. The
session never returns to `read_buf()`, so it cannot detect client
disconnect. The session holds its semaphore permit indefinitely, and the
drain can only exit via the 30-second timeout even if every client has
already closed its connection.

**Do not set `dgram_max_attempts = 0` in production or tests.** The
default of 4 (retry budget ~2.6 ms) lets the session fail fast, detect
EOF, and drain cleanly.

## `concurrent_connections` test flakiness

The intermittent failure (`expected 100 forwarded messages, got 88`)
is caused by the `net.unix.max_dgram_qlen` kernel parameter, which
defaults to 10 on many Linux systems. This limits the Unix datagram
receive queue to ~11 pending datagrams regardless of `SO_RCVBUF` size.
When 100 session tasks burst-send simultaneously, some exhaust the
forwarder's 4-attempt retry budget before the test's concurrent drain
clears queue space.

The test's `tokio::join!` drain usually keeps up (verified 30/30 on an
unloaded system with `max_dgram_qlen = 10`), but can lose the race
under CPU pressure. Raising the sysctl eliminates the issue:

    sudo sysctl net.unix.max_dgram_qlen=512
