# High Level Overview
**logfence** provides a validating filter daemon, aka man in the middle, for applications logging structured messages to rsyslog.
logfence also provides a simple client library for applications logging structured messages to rsyslog or the logfence daemon.
logfence is implemented in Rust and Tokio.
logfence communicates with host based sockets only and it never sends or receives IP network traffic.

The purpose of this validating filter is to provide a layer of isolation between high assurance/security applications and rsyslog, which may be communicating with the network, compromised applications, etc.

Target operating systems are:
* RHEL 10
* Ubuntu 24.04 LTS
* macOS 26

# Structured Message Validation
All syslog fields are validated.
The syslog protocol message content is required to be JSON key value pairs.
The JSON KVP message may optionally conform to a JSON schema.
When JSON schemas are specified, the message must conform to one of the schemas to be considered valid.

# The Daemon (logfenced)
logfence implements a daemon process that listens on a unix domain socket for syslog compliant messages from applications.
Validated incoming messages are forwarded to rsyslog.
Invalid incoming messages are dropped and relevant errors are reported to rsyslog.

# The Client Library (logfence-client)
logfence implements a client library API that makes creating JSON KVP syslog messages simple and easy.
The library can be used to send syslog protocol messages to rsyslog or to the logfence daemon.

# Implementation Goals
Rust is chosen for safety, stability, and performance.
Tokio is chosen for performance when handling a high log rate from many applications.
Stability and performance are paramount.
Other dependencies should be kept to a minimum and they should only be used when they meet the other goals and when they greatly simplify the implementation.

# Code Cleanliness
Cargo fmt and clippy should be considered after all successful code changes.

