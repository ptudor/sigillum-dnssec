# REVIEW_53 Implementation Plan And Tracking

This document is the execution plan for the three-track review:

- Production-readiness
- Security hardening
- UI/UX expert usage

It is also the source of truth for implementation status.

## Status Legend

- `TODO`: not started
- `IN_PROGRESS`: actively being implemented
- `DONE`: implemented and verified
- `BLOCKED`: needs decision or dependency

## Execution Order

1. Close security correctness gaps that can produce false validation results.
2. Eliminate crash/panic and service-hardening risks.
3. Improve operational behavior and diagnostics.
4. Improve expert UX workflow and accessibility.

## Work Items

### A. Security And Correctness

- `R53-001` `DONE` Fail-closed DS digest verification (remove fail-open path on digest computation errors).
- `R53-002` `TODO` Replace partial DS/A/CNAME "verified" signals with full cryptographic verification or explicit "partial check" semantics.
- `R53-003` `DONE` Tighten proxy trust model to explicit configured CIDRs only.
- `R53-004` `DONE` Reduce error-detail leakage to clients while preserving request-id traceability.
- `R53-005` `TODO` Add metrics endpoint exposure controls guidance and optional guard (auth/IP allowlist/reverse-proxy only).

### B. Production-Readiness

- `R53-101` `DONE` Validate all ticker/time values (`rate_limit.cleanup_seconds`, heartbeat interval) to prevent runtime panics.
- `R53-102` `DONE` Harden HTTP server timeouts (`ReadHeaderTimeout`, `MaxHeaderBytes`, bounded write policy for non-SSE routes).
- `R53-103` `DONE` Ensure `/healthz` reflects true readiness policy for missing anchors.
- `R53-104` `TODO` Implement `base_path` routing support consistently for API, SSE, static UI, and docs examples.
- `R53-105` `DONE` Stop unnecessary validation work after SSE disconnect/write failures.
- `R53-106` `TODO` Scope cache headers: long-lived cache for immutable static assets, no-store only for API/SSE.

### C. UI/UX For Expert Usage

- `R53-201` `DONE` Persist/share full query state (`domain` + `mode`) in URL.
- `R53-202` `DONE` Align client-side domain validation pattern with backend accepted format.
- `R53-203` `DONE` Fix keyboard/tab semantics for zone navigation and focus styling for current interactive elements.
- `R53-204` `TODO` Clarify verification labels in UI to avoid overstating cryptographic guarantees.

## Immediate Sprint (Now)

- `R53-001` fail-closed DS digest verification + tests. `DONE`
- `R53-101` config validation for ticker safety + tests. `DONE`
- `R53-102` server timeout/header hardening (`ReadHeaderTimeout`, `MaxHeaderBytes`, per-route non-SSE write deadlines). `DONE`
- `R53-105` SSE disconnect/write-failure cancellation to stop wasted validation work. `DONE`

## Change Log

- `2026-02-09`: Created tracking document and started `R53-001`, `R53-101`.
- `2026-02-09`: Completed `R53-001` with fail-closed behavior and regression tests.
- `2026-02-09`: Completed `R53-101` with config validation + tests for ticker-safe values.
- `2026-02-09`: Started `R53-102`; added `ReadHeaderTimeout` and `MaxHeaderBytes` to server config.
- `2026-02-09`: Completed `R53-004`; API/SSE now return request-id based validation errors and log full internal details server-side.
- `2026-02-09`: Completed `R53-102`; applied bounded write deadlines on non-SSE routes while keeping SSE long-lived behavior.
- `2026-02-09`: Completed `R53-105`; SSE write failures now cancel validation promptly.
- `2026-02-09`: Completed `R53-003`; trusted proxy headers are now gated by explicit configured CIDRs with validation and tests.
- `2026-02-09`: Completed `R53-103`; `/healthz` now reports non-ready when anchors are unavailable.
- `2026-02-09`: Completed `R53-201`; URL state now preserves validation mode (`quick`/`extended`) alongside domain.
- `2026-02-09`: Completed `R53-202`; removed restrictive client-side pattern to match backend domain acceptance rules.
- `2026-02-09`: Completed `R53-203`; added keyboard tab navigation semantics and corrected focus styling to active zone elements.
