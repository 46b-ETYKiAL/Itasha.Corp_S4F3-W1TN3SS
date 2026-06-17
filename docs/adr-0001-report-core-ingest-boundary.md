# ADR-0001 — itasha-report-core: IngestBackend boundary, Sentry-envelope wire, and the consent-gated send contract

- Status: Accepted
- Date: 2026-06-17
- Scope: `crates/itasha-report-core`

## Context

W1TN3SS needs one reusable, safe, privacy-implementing client crate that every
fleet app consumes. The design (RECOMMENDATION.md § A/C) fixes five privacy
invariants — opt-in default-OFF, sanitized payloads, no persistent identifier,
no client network identity, consent-gated transmission — and an architecture
goal: a pluggable backend so the lean in-house ingest pipeline can be swapped
for a self-hosted Sentry **with no client change**.

## Decision

### 1. The `IngestBackend` boundary

Transmission is abstracted behind the `IngestBackend` trait. Its single method
is:

```rust
fn send(&self, report: &Report, consent: &ConsentToken) -> Result<SendOutcome, SendError>;
```

Two implementations ship: `LeanPipelineBackend` (hardened `ureq`, the build-now
transport) and `SentryStubBackend` (the future self-hosted Sentry, which speaks
the identical wire and verifies wire-format parity without transmitting). The
seam is the single integration point — promoting Sentry is a config/endpoint
change, never a client rebuild.

### 2. The Sentry-envelope wire is the contract from day one

The client serializes every report to the **Sentry envelope format** (a
newline-delimited header line + per-item header/payload, each item carrying an
explicit `length` so binary minidump bytes containing newlines survive). The
lean in-house pipeline ingests these bytes today; a future self-hosted Sentry
ingests the identical bytes. `envelope::Envelope::{to_bytes, from_bytes}` are
inverses, asserted by a round-trip contract test (including the
minidump-with-embedded-newlines case).

### 3. The consent-gated send contract

`send` requires a `&ConsentToken` **at the type level** — there is no overload
that omits it. A `ConsentToken` is constructible only via
`ConsentToken::granted()`, which the host calls only after the user explicitly
agrees. It is deliberately not `Default`, not `Deserialize`, and carries no
identifying data — only an ephemeral per-report nonce used once for receive-side
de-duplication. Because every transmission path passes through this token, a
consent-free send is unrepresentable; a runtime test
(`consent_send_contract.rs`) plus the commented-out non-compiling call document
the guarantee.

### 4. No persistent identifier; no client network identity

The transport sets a static User-Agent (`itasha-report-core/<version>`), forbids
redirects (`max_redirects(0)`), enforces a bounded timeout and a size cap, and
attaches no `X-Forwarded` / geo / install-id headers. The only per-report id is
a 32-hex Sentry `event_id` derived solely from the ephemeral consent nonce, so
two sends of the same report under fresh tokens carry different ids — there is
no stable per-install identifier.

### 5. The sanitizer rules

`Sanitizer` is a pure deterministic transform: home → `<HOME>`, drop username
and hostname, scrub environment **values** wholesale, and size-cap every field.
Backtrace redaction is **allowlist-not-denylist** — a line is kept only if it
matches a known-safe shape; anything unrecognized is replaced with
`<redacted>`. The invariant (no home-path / username / hostname / env leak for
arbitrary inputs) is property-tested with `proptest`.

## Consequences

- One sanitizer + one transport + one envelope, reused fleet-wide, amortizes
  across every app and keeps the audited surface small.
- The pluggable backend future-proofs the server swap.
- The crate stays `#![forbid(unsafe_code)]`; native crash capture (which needs
  `unsafe`) is the isolated sibling crate `itasha-crash-capture`.
- Hosts pin a released tag, so an SDK change cannot break them until they bump.

## Wiring

The integration point is `IngestBackend::send`. See `WIRING.md` for the
declarative wiring contract and the test that proves the seam fires.
