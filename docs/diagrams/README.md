# PlantUML Diagrams

| File | Diagram type | What it shows | Output |
|---|---|---|---|
| `01-system-context.puml` | Component | High-level usage: Application → logfence-client → logfenced → rsyslog, with socket types noted | [system-context.svg](system-context.svg) |
| `02-crate-dependencies.puml` | Package/Component | The three crates, their key contents, and which depends on which | [crate-dependencies.svg](crate-dependencies.svg) |
| `03-daemon-modules.puml` | Component | All seven modules inside logfenced and how they call each other | [daemon-modules.svg](daemon-modules.svg) |
| `04-key-types.puml` | Class | Key structs, enums, and traits across all crates with relationships | [key-types.svg](key-types.svg) |
| `05-message-sequence.puml` | Sequence | Full message lifecycle from `MessageBuilder.send()` through validation and forwarding to rsyslog | [message-sequence.svg](message-sequence.svg) |
| `06-sighup-reload.puml` | Sequence | SIGHUP hot-reload: config reload → watch channel update → active sessions pick up new validator without dropping connections | [sighup-reload.svg](sighup-reload.svg) |
| `07-validation-pipeline.puml` | Activity/Flowchart | Every decision in `validate()` and `prepare_for_forwarding()`: CEE cookie check, JSON parse, discriminator routing, schema matching, canonical JSON, output CEE, forwarding | [validation-pipeline.svg](validation-pipeline.svg) |
| `08-concurrency-model.puml` | Component | Tokio tasks, Semaphore, CancellationToken, watch channel, Arc<Forwarder>, AtomicU64 metrics — how all the concurrency primitives connect | [concurrency-model.svg](concurrency-model.svg) |
