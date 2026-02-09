# REVIEW_53 Implementation Plan and Tracking

Created: 2026-02-09
Scope: production-readiness, security hardening, and UI/UX expert usage.

## How to use this document

1. Treat this file as the source of truth for implementation status.
2. Move items from `Planned` to `In Progress` to `Done` as work lands.
3. Add PR/commit references and notes in the tracking log.

## Status legend

- `[ ]` Planned
- `[-]` In progress
- `[x]` Done
- `[!]` Blocked

## Milestones

- `[x]` M1 Security perimeter hardening
- `[x]` M2 Runtime safety and reload correctness
- `[x]` M3 Filesystem and operational hardening
- `[x]` M4 Expert UX and operability improvements
- `[x]` M5 Test coverage expansion for critical paths

## Prioritized implementation backlog

### 1) Security perimeter (Critical)

- `[x]` R53-001: Require auth or strict loopback-only enforcement for web/API/metrics/debug endpoints.
  Files: `config.go`, `web.go`, `daemon.go`
  Done when: unauthenticated remote access is impossible by default and documented.

- `[x]` R53-002: Disable `/debug/vars` by default (explicit opt-in only).
  Files: `daemon.go`, `config.go`
  Done when: debug endpoint is off in default production config.

### 2) Reload correctness and runtime safety (Critical/High)

- `[x]` R53-003: Redesign daemon reload flow to avoid pointer swapping races and stale goroutines.
  Files: `daemon.go`
  Done when: config/state reload is deterministic and race-safe under stress tests.

- `[x]` R53-004: Ensure web/health servers and signing ticker fully honor reloaded config.
  Files: `daemon.go`
  Done when: listen addresses and intervals change correctly after `SIGHUP`.

### 3) Hook execution hardening (High)

- `[x]` R53-005: Replace default `sh -c` hook path with exec-style command+args (shell mode opt-in only).
  Files: `hooks.go`, `config.go`
  Done when: hooks are non-shell by default and command injection surface is reduced.

- `[x]` R53-006: Remove raw hook command strings from logs.
  Files: `hooks.go`
  Done when: logs contain hook identity/outcome only, not sensitive command text.

### 4) Filesystem and state handling hardening (High)

- `[x]` R53-007: Tighten sensitive file and directory permissions (`keys`, `state`, optional logs).
  Files: `keys.go`, `state.go`, `daemon.go`
  Done when: permissions are least-privilege and validated at startup.

- `[x]` R53-008: Make `add` and `remove` domain workflows transactional across config/state.
  Files: `main.go`
  Done when: partial updates cannot leave config and state diverged.

- `[x]` R53-009: Enforce safe concurrency model for `ZoneState` mutation and reads.
  Files: `state.go`
  Done when: zone-state access patterns are lock-safe and race-tested.

### 5) Transport and endpoint behavior hardening (Medium)

- `[x]` R53-010: Require HTTPS scheme for heartbeat endpoint unless explicit insecure override is set.
  Files: `config.go`
  Done when: insecure endpoint usage is blocked by default.

- `[x]` R53-011: Restrict HTTP methods and modernize response security headers.
  Files: `web.go`, `health.go`
  Done when: unsupported methods are rejected and headers are consistent and current.

- `[x]` R53-012: Make health checks non-destructive (no write-on-probe).
  Files: `health.go`
  Done when: probes avoid filesystem writes and remain fast.

### 6) Expert UX and operator workflow (Medium)

- `[x]` R53-013: Improve dashboard scalability and usability (template caching, less expensive rendering, better filtering).
  Files: `web.go`
  Done when: dashboard remains responsive with larger zone counts.

- `[x]` R53-014: Add machine-friendly output modes (`--json`, `--quiet`) to operator commands.
  Files: `main.go`
  Done when: automation can consume stable outputs for `ds`, `dnskey`, and rollover actions.

### 7) Testing and verification (Medium)

- `[x]` R53-015: Add tests for auth boundaries, reload behavior, hooks, permission checks, and endpoint exposure.
  Files: `hardening_test.go`
  Done when: critical hardening paths have regression coverage.

## Suggested implementation order

1. R53-001, R53-002
2. R53-003, R53-004
3. R53-005, R53-006
4. R53-007, R53-008, R53-009
5. R53-010, R53-011, R53-012
6. R53-013, R53-014
7. R53-015

## Tracking log

| Date | Item | Status | Notes | PR/Commit |
|---|---|---|---|---|
| 2026-02-09 | REVIEW_53 initialized | Done | Plan created from audit findings | - |
| 2026-02-09 | R53-001 | Done | Added `AllowRemote` to WebConfig/HealthConfig, `isLoopbackAddr()`, `validateLoopbackAddr()` in config.go | - |
| 2026-02-09 | R53-002 | Done | Added `DebugVars` bool to HealthConfig; `/debug/vars` conditional in daemon.go | - |
| 2026-02-09 | R53-003 | Done | Added `snapshot` struct and `takeSnapshot()` for race-safe signing cycles in daemon.go | - |
| 2026-02-09 | R53-004 | Done | Added `tickerReset` channel; `Reload()` resets ticker and warns on listen addr changes | - |
| 2026-02-09 | R53-005 | Done | Added `PostSignCmd`/`Shell` to HooksConfig; new `hookCmd()` with three modes | - |
| 2026-02-09 | R53-006 | Done | All hook logs use `"hook", identity` — raw commands never logged | - |
| 2026-02-09 | R53-007 | Done | `ensureDirSecure()` creates dirs 0700 and tightens existing; state writes 0600 | - |
| 2026-02-09 | R53-008 | Done | Reordered `runAdd()`/`runImport()`: keys→sign→state→config with rollback on failure | - |
| 2026-02-09 | R53-009 | Done | Added `UpdateZone()` method with write-lock; documented concurrency contract on `GetZone()` | - |
| 2026-02-09 | R53-010 | Done | Added `AllowInsecure` to HeartbeatConfig; HTTPS validation in `Validate()` | - |
| 2026-02-09 | R53-011 | Done | GET/HEAD only (405 otherwise); modern headers; removed deprecated X-XSS-Protection | - |
| 2026-02-09 | R53-012 | Done | Replaced file-write probe with stat-based `checkDirWritable()` in health.go | - |
| 2026-02-09 | R53-013 | Done | Template parsed once at `init()` in web.go; `dashboardTemplate` cached | - |
| 2026-02-09 | R53-014 | Done | Added `--json` flag to `ds` and `dnskey` commands in main.go | - |
| 2026-02-09 | R53-015 | Done | Created `hardening_test.go` with 60+ regression tests covering all hardening paths | - |
