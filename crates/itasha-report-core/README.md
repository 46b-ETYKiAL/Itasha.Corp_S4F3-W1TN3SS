# itasha-report-core

The safe, `#![forbid(unsafe_code)]` spine of the W1TN3SS reporting SDK. It turns
the five W1TN3SS privacy invariants into code and **transmits nothing on its
own** — the host application calls its APIs only after the user consents.

## The five privacy invariants

1. **Opt-in, default-OFF** — `ReportingConfig` defaults both the crash-report
   and manual-issue streams to `ReportingMode::Off`. The two streams are never
   bundled under one toggle.
2. **Sanitized** — `Sanitizer` normalizes the home directory to `<HOME>`, drops
   the username and hostname, scrubs environment values, and caps sizes.
   Backtrace redaction is **allowlist-not-denylist**.
3. **No persistent identifier** — the transport attaches no install-id /
   fingerprint / session-id. Each report carries an **ephemeral per-report
   nonce** only.
4. **No client network identity** — a static User-Agent, zero redirects, no
   `X-Forwarded` / geo headers.
5. **Consent-gated** — every `IngestBackend::send` requires a `ConsentToken`
   the host mints only after the user agrees; `Preview` returns the literal
   editable payload first.

## Module map

| Module | Responsibility |
|---|---|
| `config` | Two-stream `ReportingMode` model (serde, default `Off`). |
| `report` | The in-memory `Report` model (Tier-1 text + opaque Tier-2 attachments). |
| `sanitize` | The privacy core — home/username/host/env scrubbing + size caps. |
| `spool` | Local-first atomic file-per-report spool with count + byte budgets. |
| `envelope` | Sentry envelope wire serialization (round-trip). |
| `backend` | `IngestBackend` trait + hardened `ureq` lean-pipeline impl + Sentry stub. |
| `consent` | The `ConsentToken` capability gate (non-forgeable, ephemeral nonce). |
| `preview` | The literal editable Tier-1 payload + user redaction. |
| `intake` | GitHub Issue-Form URL builder, `mailto:`, clipboard fallback, browser launch. |

## Integration snippet — how a host wires consent → preview → send

```rust
use itasha_report_core::{
    backend::{IngestBackend, LeanPipelineBackend, TransportConfig},
    consent::ConsentToken,
    preview::Preview,
    report::Report,
    sanitize::Sanitizer,
    spool::Spool,
};

// 1. Build + sanitize a report (strips home/username/host/env).
let raw = Report::crash("thread 'main' panicked at /home/ada/notes.rs:12");
let report = Sanitizer::new().sanitize(raw);

// 2. Spool it locally first (durable, offline-first; transmits nothing).
let spool = Spool::open("/path/to/app/config/dir")?;
spool.enqueue(&report)?;

// 3. Show the user the literal, editable Tier-1 text. They may redact spans.
let preview = Preview::of(&report).redact_default("any-span-the-user-picks");
println!("{}", preview.text());
let approved = preview.into_edited_report(&report);

// 4. The host gets explicit user consent, THEN mints a token and sends.
let user_agreed = true; // ← from the consent dialog
if user_agreed {
    let token = ConsentToken::granted();
    let backend = LeanPipelineBackend::new(
        TransportConfig::new("https://ingest.example.invalid/api/1/envelope/"),
    );
    let outcome = backend.send(&approved, &token)?;
    // Log the structured outcome (counts/enums only, no PII).
    eprintln!("report outcome: {outcome:?}");
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

`send` cannot even be *called* without a `&ConsentToken` — a consent-free send
is a type error, which is the static proof of the consent gate.

## external_dependencies

This crate calls **no external service of its own**. The transport has **no
default endpoint** — a host must configure one, so a mis-build cannot phone
home. The wire format is the open Sentry envelope, ingested today by a
self-hosted lean pipeline and (unchanged) by a future self-hosted Sentry. There
is **no vendor LLM / telemetry / SaaS SDK** (AES Clause 5).

| Dependency | Purpose | Service implied |
|---|---|---|
| `serde` / `serde_json` | Config + envelope (de)serialization | none |
| `ureq` (rustls, pure-Rust) | The single hardened HTTP transport | a self-hosted endpoint the **host** configures |
| `webbrowser` | Launch the user's browser for the GitHub Issue-Form | none (hands off to the user's browser) |
| `directories` | Platform-aware home / config-dir detection | none |
| `proptest` (dev-only) | Sanitizer property tests | none |

All dependencies are pinned exact in `Cargo.toml`.
