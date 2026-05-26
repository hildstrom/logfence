# JALoP Audit Format (JAF) and XML Schemas

This analysis is of the latest JALoP Reference Implementation 2.x.x.x in May 2026.

This document records what is known about the JALoP Audit Format and
the XML schemas used by the JALoP reference implementation, based on
examination of the source code and schema files in the JALoP repository.

---

## JAF Event Schema

The JALoP Audit Format (JAF) defines the XML schema that audit records
must conform to when submitted via `jalp_audit()`. The JPL code
(`src/producer_lib/src/jalp_audit.c`) attempts to load the schema from
two filenames under the configured `schema_root` directory:

1. `eventList.xsd` (preferred, newer)
2. `event.xsd` (fallback, older)

**Neither schema is included in the open-source repository.** Both
files contain only:

```
Contact cds_tech@nsa.gov to obtain this JAF schema.
```

The JAF event schemas are controlled by NSA/NCDSMO and are not
publicly distributed with the JALoP reference implementation.

### Schema validation behavior

Schema validation of audit records is **opt-in**. The application must
set the `JAF_VALIDATE_XML` flag on the JPL context:

```c
jalp_context_set_flag(ctx, JAF_VALIDATE_XML);
```

When the flag is set, `jalp_audit()`:
1. Parses the `audit_buffer` as XML using `xmlReadMemory`.
2. Loads and caches the JAF XSD schema context on first use.
3. Validates the parsed document against the schema.
4. Returns `JAL_E_XML_PARSE` or `JAL_SCHEMA_VALIDATION_FAILURE` on
   failure.

When the flag is **not** set (the default), no parsing or validation
occurs. The buffer is sent to the local store as-is.

The local store itself performs **no** schema validation on ingest.
The `jalls_handle_audit` handler in
`src/local_store/src/jalls_handle_audit.cpp` contains
`// TODO: Parse the audit data if needed` and stores the buffer
directly.

Log records (`jalp_log`) and journal records (`jalp_journal`) are
never schema-validated at any point in the pipeline.

---

## Schemas included in the repository

The JALoP repository includes schemas under `schemas/` for the XML
documents that the JPL and local store generate. These are distinct
from the JAF event schema — they define the metadata envelopes that
wrap around payloads, not the payloads themselves.

### applicationMetadata.xsd

A thin wrapper that imports `applicationMetadataTypes.xsd`:

```xml
<schema targetNamespace="http://www.dod.mil/jalop-1.0/applicationMetadata">
  <import schemaLocation="./applicationMetadataTypes.xsd"
          namespace="http://www.dod.mil/jalop-1.0/applicationMetadataTypes"/>
  <element name="ApplicationMetadata" type="jam:ApplicationMetadataType"/>
</schema>
```

### applicationMetadataTypes.xsd

Defines the `ApplicationMetadata` XML document that the JPL generates
from the C structs the application provides. Namespace:
`http://www.dod.mil/jalop-1.0/applicationMetadataTypes`.

**Root type: `ApplicationMetadataType`**

- Required attribute: `JID` (type `ID`) — used for XML-DSig signing.
- Sequence:
  1. `EventID` (string, optional) — application-defined correlation ID.
  2. Choice of one:
     - `Syslog` — syslog-style metadata.
     - `Logger` — log4j-style metadata.
     - `Custom` (anyType) — arbitrary XML.
  3. `JournalMetadata` (optional) — file info and transforms for
     journal entries.
  4. `ds:Signature` (optional) — XML-DSig enveloped signature.
  5. `ds:Manifest` (optional) — digests of the associated payload.

**SyslogType** (maps to `jalp_syslog_metadata`):

| XML attribute/element | Type | Notes |
|---|---|---|
| `@Facility` | 0–23 | Syslog facility code |
| `@Severity` | 0–7 | Syslog severity code |
| `@Timestamp` | dateTime | Optional; JPL generates if NULL |
| `@Hostname` | string | From context or struct |
| `@ApplicationName` | string | From context or struct |
| `@ProcessID` | integer | Auto-generated |
| `@MessageID` | string | Corresponds to RFC 5424 MSGID |
| `Entry` | string | The log entry text (optional) |
| `StructuredData` | 0..* | SD_ID attribute + Field elements (Key/value pairs) |

**LoggerType** (maps to `jalp_logger_metadata`):

| XML element | Type | Notes |
|---|---|---|
| `LoggerName` | string | Logger identifier |
| `Severity` | integer + `@Name` | Numeric level with optional string name |
| `Timestamp` | dateTime | Optional; JPL generates if NULL |
| `Hostname` | string | |
| `ApplicationName` | string | |
| `ProcessID` | integer | |
| `ThreadID` | string | |
| `Message` | string | The log message |
| `Location` | sequence of `StackFrame` | Call stack |
| `NestedDiagnosticContext` | string | Log4j NDC |
| `MappedDiagnosticContext` | string | Log4j MDC |
| `StructuredData` | 0..* | Same as SyslogType |

**StackFrameType:**

| XML element/attribute | Type |
|---|---|
| `CallerName` | string |
| `FileName` | string |
| `LineNumber` | positiveInteger |
| `ClassName` | string |
| `MethodName` | string |
| `@Depth` | nonNegativeInteger |

**JournalMetadataType:**

- `FileInfo` (required):
  - `@FileName` (string, required)
  - `@OriginalSize` (nonNegativeInteger) — size before transforms
  - `@Size` (nonNegativeInteger) — size after transforms
  - `@ThreatLevel` — `unknown` (default), `safe`, or `malicious`
  - `Content-Type` (optional) — `@MediaType` (application, audio,
    example, image, message, model, text, video) + `@SubType`
    (string) + `Parameter` elements (Name/value)
- `Transforms` (optional) — ordered list (reverse order of
  application) of:
  - `AES128` — optional 16-byte Key + 16-byte IV
  - `AES192` — optional 24-byte Key + 16-byte IV
  - `AES256` — optional 32-byte Key + 16-byte IV
  - `XOR` — 4-byte Key
  - Custom — any URI + optional XML snippet

### systemMetadata.xsd

Defines the `JALRecord` system metadata document that the local store
generates for each record. Namespace:
`http://www.dod.mil/jalop-1.0/systemMetadata`.

**Root type: `JALRecordType`**

| XML element | Type | Notes |
|---|---|---|
| `JALDataType` | `journal`, `audit`, or `log` | Record type discriminator |
| `RecordID` | UUID (36-char pattern) | Generated by the local store |
| `Hostname` | string | Machine that generated the data |
| `HostUUID` | UUID | Assigned outside of JALoP |
| `Timestamp` | dateTime | When the local store processed the record |
| `ProcessID` | nonNegativeInteger | PID of the process that submitted data to the local store |
| `User` | nonNegativeInteger + `@name` | Effective UID and username of the submitting process (optional) |
| `SecurityLabel` | string | Security label of the submitting process (optional) |
| `ds:Signature` | XML-DSig | Optional enveloped signature |
| `ds:Manifest` | XML-DSig Manifest | Digests of the payload and application metadata |

- Required attribute: `JID` (type `ID`) — used for XML-DSig signing.

The `Manifest` contains two `Reference` elements:
1. URI `jalop:application-metadata` — digest of the application
   metadata, with XML canonicalization transform.
2. URI `jalop:paylod` (sic — typo in the schema documentation) —
   digest of the payload. Audit payloads use XML canonicalization;
   journal and log payloads have no transform.

### External schemas

The `schemas/externalSchemas/` directory contains standard schemas
referenced by the JALoP schemas:

- `xmldsig-core-schema.xsd` — W3C XML-DSig schema
- `XMLSchema.xsd` and `XMLSchema.dtd` — W3C XML Schema schema
- `datatypes.dtd` — W3C datatypes
- `xml.xsd` — XML namespace schema

---

## How records are structured in storage

Each record in the JALoP local store (LMDB) consists of three parts:

1. **System metadata** — XML conforming to `systemMetadata.xsd`,
   generated by the local store. Contains the record UUID, timestamp,
   host identity, process identity, and optionally a signed manifest
   with digests of the other two parts.

2. **Application metadata** — XML conforming to
   `applicationMetadata.xsd`, generated by the JPL from the
   `jalp_app_metadata` structs the application provided (or NULL if
   none were provided).

3. **Payload** — the raw data:
   - For audit records: the byte buffer from `jalp_audit`, expected
     to be JAF-conformant XML (but not enforced by the local store).
   - For log records: the byte buffer from `jalp_log`, free-form.
   - For journal records: the byte buffer or file contents from
     `jalp_journal` / `jalp_journal_fd` / `jalp_journal_path`,
     opaque binary.
