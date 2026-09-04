# DNSSEC codebase review — Astra 6, XHigh

Review date: 2026-09-04. Baseline: `4354f33` on `main`.

Analysis only. No implementation files are changed. This report is being developed in checkpoints; the final checkpoint will contain the complete coverage record, verification results, severity table, and dependency-aware fix order. Findings describe the baseline code, irrespective of claims in earlier reviews. Locations are relative to the repository root. “Confirmed” means the code path establishes the defect; “Needs investigation” identifies a remaining assumption to test.

Initial validation: `go test -race ./...` passed in both Go modules using Go 1.27.0 on darwin/arm64. Passing regression tests do not establish safety of the untested failure sequences below.

## RA6X-001 — Ordinary KSK rollover can unintentionally change algorithm

- **Severity:** High
- **Status:** Confirmed
- **Location:** `Golang-tudor-dnssec-signer/internal/signer/rollover.go`, `StartKSKRollover`; `keys.go`, `generateKey`; `sign.go`, `loadKeysForSigning`, `verifySignedZone`; `main.go`, `runRolloverAlgorithm`.
- **Problem:** KSK rollover generates with the current configuration algorithm, while the existing ZSK retains its algorithm. Changing the configuration, importing keys with an algorithm different from the default, or completing an explicit algorithm rollover without editing the configuration can make the next ordinary KSK rollover create an algorithm-incomplete zone. After retiring the old KSK, a parent DS for the new KSK cannot authenticate data signed only with the old ZSK algorithm on validators that only support the new algorithm.
- **Evidence:** `StartKSKRollover` calls `keyGen.GenerateKSK(domain)`; the automatic ZSK path explicitly uses `GenerateZSKWithAlgorithm(domain, oldZSK.Algorithm)`. The KSK branch adds both KSKs but only the current ZSK signs ordinary data. Self-verification checks one covering signature, not coverage for every advertised algorithm. `runRolloverAlgorithm` does not persist an algorithm override to configuration.
- **Fix specification:** Generate ordinary KSK replacements with the existing KSK's algorithm and reject inconsistent live KSK/ZSK algorithm sets outside explicit algorithm rollover. Only the algorithm-rollover command may introduce another algorithm. Add a post-sign invariant that every required algorithm signs every authoritative RRset with the appropriate role. Keep explicit dual-algorithm rollover, CLI syntax, key filenames, and existing state compatibility.
- **Verification:** Import ECDSA keys under the default ED25519 configuration, then start/complete ordinary KSK rollover; the new KSK must remain ECDSA. Repeat after an explicit ED25519→ECDSA rollover without changing the global configuration. Inject an incomplete algorithm set and require rejection before output replacement. See [RFC 6840 §5.11](https://www.rfc-editor.org/rfc/rfc6840#section-5.11).

## RA6X-002 — Key rotation and rollover state are not one recoverable transaction

- **Severity:** High
- **Status:** Confirmed
- **Location:** `Golang-tudor-dnssec-signer/internal/signer/rollover.go`, `StartKSKRollover`, `startZSKRollover`, `StartAlgorithmRollover`; `keys.go`, `SaveKeyFiles`, `RecoverKeyState`; `sign.go`, `loadKeysForSigning`.
- **Problem:** Live keys are replaced before a durable rollover record identifies both generations. A crash in that window leaves old state with new keys. An algorithm rollover also returns immediately if ZSK generation fails after KSK replacement. ZSK rollover does not undo a failed state save. On restart, signing trusts the live filenames without checking them against persisted key identities; it can omit a KSK still referenced by the parent or skip ZSK prepublication.
- **Evidence:** Algorithm rollover invokes `GenerateKSKWithAlgorithm`, then `GenerateZSKWithAlgorithm`, then creates/saves `zoneState.Rollover`. The second generation error returns without restoring the KSK. KSK/algorithm rollback exists only for the final `state.Save()` error, not process death or earlier failures. `startZSKRollover` ends with `return rm.state.Save()` after changing files. `loadKeysForSigning` loads current keys by role and does not compare their tags to persisted state.
- **Fix specification:** Stage and verify replacement keys before changing live references; durably record the transition intent and identities before activation, with deterministic restart recovery. Treat both algorithm-rollover key pairs as one transaction. On any failed step, preserve a verifiable old generation and either restore it or fail closed until recovery. Signing must check the expected phase-specific key identity (including the new live ZSK during prepublish), not merely accept any same-domain key. Preserve old backups, existing command behavior, and backward readability of state; additive recovery metadata is acceptable if explicitly versioned/documented.
- **Verification:** Fault-inject each write/rename/save and terminate a subprocess after each activation boundary. Restart with the unchanged configuration; it must publish the complete old or intended rollover key set, never a third interpretation. Specifically fail new ZSK creation after successful new KSK creation, and fail persistence immediately after ZSK replacement.

## RA6X-003 — KSK/algorithm completion does not wait out cached parent DS records

- **Severity:** High
- **Status:** Confirmed
- **Location:** `Golang-tudor-dnssec-signer/main.go`, `verifyNewKSKDSAtParent`, `runRolloverComplete`; `internal/signer/rollover.go`, `CompleteKSKRollover`, `CompleteAlgorithmRollover`.
- **Problem:** Observing the new DS once permits immediate removal of all old keys. Other recursive resolvers can still cache the old-only DS RRset. Those resolvers then receive a DNSKEY RRset without the key their cached DS authenticates, causing a DNSSEC outage until their DS cache expires. Algorithm retirement also removes old data signatures and keys together without a cache-drain phase.
- **Evidence:** `runRolloverComplete` checks only `res.MatchesKSK`; successful completion sets `Rollover = nil`, immediately calls `SignZone`, and only afterwards invokes registrar completion. There is no persisted DS first-observed time, parent DS TTL, propagation interval, or old-signature retirement gate. The state comments explicitly describe single-step completion.
- **Fix specification:** Implement explicit safe publication/retirement phases. Establish new-key publication and parent DS propagation, retain old key material in the served DNSKEY RRset through the applicable DS/DNSKEY/data-signature cache windows, and retire old algorithms only after their dependencies have expired. Start timers from verified authoritative publication, not command execution. Account for all authoritative servers and failure/restart paths. Keep `--force` as an explicit override and existing entry-point syntax; migrate old in-progress state conservatively. See [RFC 6781 §4.1](https://www.rfc-editor.org/rfc/rfc6781#section-4.1).
- **Verification:** Use two validating resolver caches: prime one with old-only DS, publish new DS, and complete from the other. Both must resolve continuously throughout KSK and algorithm rollover. Verify persisted waits survive restart and cannot be shortened by a TTL decrease.

## RA6X-004 — Successful file signing is mistaken for successful authoritative publication

- **Severity:** High
- **Status:** Confirmed
- **Location:** `Golang-tudor-dnssec-signer/internal/signer/sign.go`, `SignZone`; `internal/signer/rollover.go`, `handleZSKRolloverState`; `main.go`, `runPostSignHook`; `daemon.go`, `checkAndSignZone`, `signAllZones`.
- **Problem:** Rollover timers use `LastSigned`, although it only means the output file was written. Reload hooks may fail or still be running. A long publication failure can let automatic ZSK rollover advance through prepublish and signing while authoritative servers continue serving the old generation. When reloading finally succeeds, the new generation can become visible without the required prepublication interval. CLI rollover also proceeds to DS automation despite hook failure.
- **Evidence:** `SignZone` sets `LastSigned` immediately after `writeSignedZone`. `handleZSKRolloverState` interprets it as actual publication. CLI hook failures are logged and discarded; daemon hooks run asynchronously. No publication acknowledgment gates phase advancement.
- **Fix specification:** Track output generation separately from successful deployment. Gate transitions on confirmed publication of the relevant generation; preserve/retry a pending deployment after hook failure and restart. For deployments without hooks, define and enforce an explicit publication assumption or authoritative probe. Do not fail signing of unrelated zones or delete previously served output. Preserve existing hook environment and allow operators to retain manual deployment with documented gates.
- **Verification:** Make the reload hook fail longer than both configured rollover windows while the authoritative server keeps serving the old zone. Neither phase may advance based solely on file timestamps. Restore the hook; require the full cache-safe dwell after actual publication. Test asynchronous hook completion and process restart with a pending deployment.

## RA6X-005 — Source-path reconciliation happens too late and is absent from CLI signing

- **Severity:** High
- **Status:** Confirmed
- **Location:** `Golang-tudor-dnssec-signer/daemon.go`, `checkAndSignZone`; `internal/signer/sign.go`, `NeedsSign`, `SignAll`, `SignZone`; `main.go`, `runResign`.
- **Problem:** Changing a configured source path does not reliably cause the new file to be signed. The daemon checks the new path's mtime/size against the old file's bookkeeping before detecting the path change. An older same-size replacement can be skipped until signature refresh. One-shot `sign` and explicit `resign` continue reading the old `ZoneState.Path` even when the configuration points elsewhere, so the operator can receive success while obsolete data is republished.
- **Evidence:** The daemon returns on `!needsSign` before `zoneState.Path != zoneCfg.Path`. `SignAll` uses `zoneCfg.Path` only during key initialization. `SignZone` always parses `zoneState.Path`. `runResign` loads the current `zoneCfg` but uses its path only for the hook.
- **Fix specification:** Reconcile source selection centrally for every signing entry point. Treat a configured path change as a forced sign independent of mtime/size and reset the old source reference only after successful parsing/publication. Preserve the prior signed file on failure. Keep explicit source paths and public command syntax; signing must always use the same source that change detection and hook metadata identify.
- **Verification:** Sign source A, change configuration to source B with an older mtime and equal size but different RR data, then exercise daemon reload, `sign`, and `resign`. Each must publish B. A missing/invalid B must produce a per-zone error while retaining A's last good signed output.

## RA6X-006 — Daemon startup writes state outside the cross-process lock

- **Severity:** High
- **Status:** Confirmed
- **Location:** `Golang-tudor-dnssec-signer/main.go`, `runServe`, `loadConfigAndState`; `daemon.go`, `Run`, `validateStartup`; `internal/state/state.go`, `Save`.
- **Problem:** Starting a daemon can overwrite a concurrent CLI or existing daemon's newly committed state with its stale startup snapshot. Startup writes before binding the health port, so even a duplicate daemon that ultimately fails to start can corrupt active state. Losing a rollover record while the keys have rotated can break the parent trust chain.
- **Evidence:** `runServe` loads state without `acquireStateLock`. `Run` calls `validateStartup`, which calls `d.state.Save()`, before `net.Listen`. The lock is acquired only later inside regular signing cycles.
- **Fix specification:** Make the initial state load/check/write participate in the same lock protocol as all other writers, loading under the lock immediately before any write. Prefer a nondestructive writability check and avoid writing an unchanged startup snapshot. Reject duplicate instances before any shared-state mutation; port binding alone must not authorize unprotected writes. Preserve existing startup diagnostics and supported CLI concurrency.
- **Verification:** Pause startup after its initial load, commit a CLI rollover/add, resume startup, and confirm the newer state survives. Repeat with an already-running daemon occupying the listen port; failed startup must leave state and key files byte-for-byte unchanged.

## Checkpoint summary

| Severity | Findings |
|---|---|
| Critical | None recorded yet |
| High | RA6X-001–RA6X-006 |
| Medium | None recorded yet |
| Low | None recorded yet |

Provisional fix order: RA6X-006 → RA6X-002 → RA6X-001 and RA6X-005 → RA6X-004 → RA6X-003. Persistence and publication tracking must be established before adding cache-dependent rollover phases.
