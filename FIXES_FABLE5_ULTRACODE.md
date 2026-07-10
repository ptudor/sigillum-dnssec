# FIXES_FABLE5_ULTRACODE — implementation log

Working through the findings in `REVIEW_FABLE5_ULTRACODE.md` in the suggested fix order.
Each entry: finding ID, what changed, files touched, verification result.
Entries marked **SKIPPED** were not implemented because the fix spec was ambiguous or conflicted with the code's actual behavior (reason given); nothing outside the review is changed.

Baseline (before any fix): both projects `go build ./...`, `go vet ./...`, `gofmt -l .`, `go test ./...` clean on go1.26.4 darwin/arm64.

---

## Phase 1 — Validator chain-of-trust soundness

**R-079 — DS RRSIG now cryptographically enforced for a `secure` verdict.**
Changed: in `validateZone` (non-root branch), after storing the DS records, a secure delegation now requires `dsValidation.RRSIGVerified == true`; a missing/failed DS RRSIG sets `StatusBogus` (was a warning). Reordered so DS authentication precedes DNSKEY-RRSIG verification. The DS-query helper `queryDSFromParentWithValidation` now also returns the parent `*QueryResult`.
Files: `internal/validator/validator.go`.
Verification: `go test ./internal/validator/` green; new `TestDSRRSIGEnforcementMechanism` confirms a genuine DS RRSIG verifies against the parent key and a rogue key does not (the gate R-079 relies on). Full build/vet/fmt/test clean.

**R-080 — DNSKEY RRset now bound to the DS/anchor-authenticated key.**
Changed: replaced `VerifyDNSKEYRRSIG` (which picked the signing key by the RRSIG's own key tag — the hole) with `VerifyDNSKEYRRSIGByKeys(dnskeys, rrsigs, authenticatedKeys)`, which requires the DNSKEY RRSIG to be made by a key in the authenticated set. Added `CollectDSMatchedKeys` (non-root) and `CollectAnchorMatchedKeys` (root) to compute that set; `validateZone` now threads it from the DS/anchor step into the DNSKEY-RRSIG check.
Files: `internal/validator/dnssec.go`, `internal/validator/validator.go`.
Verification: new `TestVerifyDNSKEYRRSIGByKeys_RejectsRogueKSK` proves a DNSKEY RRset signed by a rogue (non-DS-matched) KSK is rejected while the genuine DS-matched KSK is accepted; `TestCollectDSMatchedKeys` proves a wrong-digest DS authenticates nothing. All green.

**R-081 — Insecure delegation now requires an authenticated proof of DS absence.**
Changed: added `verifyDSAbsence` (NSEC match with NS set / DS clear / SOA clear, or NSEC3 direct-match with DS clear, or opt-out NSEC3 cover — each with parent-key RRSIG verification via `VerifyDenialRRSIGFromResponse`) and `finalizeNoDSDelegation`. Both no-DS paths in `validateZone` (no-DNSKEY branch and has-DNSKEY branch) now route through it: a stripped DS with no denial → `indeterminate`; a contradictory/unverifiable denial → `bogus`; a genuine signed denial → `insecure`. When the parent itself is not secured (no threaded DNSKEY) the result stays `insecure` (nothing to protect).
Files: `internal/validator/validator.go`.
Verification: new `TestVerifyDSAbsence` and `TestFinalizeNoDSDelegation` cover genuine-insecure→insecure, DS-bit→bogus, no-NSEC→indeterminate, wrong-key→fail-closed. All green.

**R-082 — Leaf record signature outcome now folds into the overall verdict.**
Changed: added `recordValidationVerdict` (verified answer/denial → secure; unqueryable → indeterminate; missing/expired/forged RRSIG or unverifiable denial → bogus; a signature-verified wildcard whose closest-encloser proof is incomplete stays secure-with-warning, preserving prior behavior). `validateWithCache` applies it to the leaf `RecordValidation` so `result.Result` reflects the answer's signature, not just the chain.
Files: `internal/validator/validator.go`.
Verification: new `TestRecordValidationVerdict` (9 cases) all pass.

**R-084 — Verified non-exploitable (no code change).**
The finding's core (item a) is delivered by R-079+R-080: NS records/glue/zone-cuts still come from the untrusted recursive resolver, but a manipulated NS set can no longer yield a false `secure` — the served DNSKEY/DS must chain to the *authenticated* parent DS (R-079) and the DNSKEY RRset must be signed by a DS-authenticated key (R-080), neither of which an attacker without the parent's private key can satisfy; the result is `bogus`. `TestVerifyDNSKEYRRSIGByKeys_RejectsRogueKSK` is the direct demonstration (attacker-served keys → rejected). Items (b) resolver-SERVFAIL-as-zone-cut and (c) authoritative-side delegation validation are architectural hardening beyond a targeted fix; item (b) is further mitigated by R-081 (a spurious zone with no authenticated DS proof now resolves to indeterminate, not a false insecure). Logged as verified rather than a separate code change, per the review's fix-order note ("becomes non-exploitable once these land; verify that").

**R-085 — Denial-of-existence proofs strengthened (NXDOMAIN completeness + NODATA CNAME bit).**
Changed in `internal/validator/nsec.go`:
- `verifyNSECNXDOMAIN`: now requires BOTH an NSEC covering qname AND an NSEC covering the wildcard `*.<closest-encloser>` (RFC 4035 §5.4). Added `closestEncloserFromNSEC`/`commonSuffixLabels` to derive the closest encloser from the covering NSEC's owner/next.
- `verifyNSEC3NXDOMAIN`: now requires the full RFC 5155 §8.4 trio — an NSEC3 matching the closest encloser, an NSEC3 covering the next-closer name, and an NSEC3 covering the wildcard. Added `nsec3Matches`/`nsec3Covers`/`wildcardName` helpers; the closest encloser is found by hashing each ancestor of qname.
- `verifyNSECNODATA` and `verifyNSEC3NODATA`: reject a NODATA proof whose matching NSEC/NSEC3 has the CNAME bit set (RFC 6840 §4.3) — a CNAME should have been returned instead.
The security-critical per-RRset RRSIG cryptographic verification was already correct (the 4ec8209 fix, verified by the existing `VerifyDenialRRSIGFromResponse` and preserved here). Since these functions set `proof.Verified` only when the structural proof succeeds, an incomplete proof now fails closed and (via R-082) moves the leaf verdict off `secure`.
Files: `internal/validator/nsec.go`, `internal/validator/nsec_test.go`.
Verification: updated `TestVerifyNSECNXDOMAIN` (single NSEC → incomplete/fail; covering+wildcard NSEC → proof); new `TestVerifyNSEC3NXDOMAINComplete` (trio → proof, single record → fail), `TestVerifyNODATA_CNAMEBit` (both NSEC/NSEC3), `TestClosestEncloserFromNSEC`. All validator tests green; build/vet/gofmt clean.
**Partial (documented):** The fix spec's "handle wildcard-NODATA" sub-case is not implemented — the NODATA path proves direct NODATA (name exists, type absent) correctly, and wildcard-NODATA (a wildcard match lacking the queried type) falls through to "no proof" as it did before this change (no regression; it was never accepted). Full wildcard-NODATA proof assembly would reuse the NXDOMAIN closest-encloser/next-closer machinery on the NODATA path; deferred to avoid risking the correct direct-NODATA path, which is the common case. Noted here rather than silently omitted.

---

## Phase 2 — Signer data-integrity & crash safety

**R-010 — Standard 32-byte-seed ED25519 import no longer panics the signer.**
Changed `signRRSIG` (`sign.go`) to accept both the 32-byte seed (expand via `ed25519.NewKeyFromSeed`) and the 64-byte expanded ED25519 key, and to length-validate the ECDSA branches (32/48) — so a wrong-length key returns an error instead of panicking inside `crypto/ed25519`. Added a pub/priv correspondence check to `loadBindKeyPair` (`main.go`) so `import` validates the pair before writing anything.
Files: `sign.go`, `main.go`, `keys.go` (helper).
Verification: new `TestSignRRSIG_ED25519SeedAndFull` (seed + full both sign and verify), `TestSignRRSIG_GarbageLengthErrorsNoPanic`. Green.

**R-009 — Key files written atomically; pub/priv correspondence enforced at load.**
Added `writeFileAtomicOwned`/`syncDir` (`ownership.go`): unique temp + chmod + fsync + rename + dir-fsync, preserving daemon ownership. `saveKeyFiles` now writes `.private` then `.key` atomically (no truncate-in-place, no half-written pair). Added `verifyKeyPairCorrespondence` (`keys.go`) deriving the public key from the private half; `loadKeyPairFromPath` calls it and errors on mismatch, so a new `.key` beside a stale `.private` fails signing (prior zone keeps serving) instead of the ECDSA path silently "succeeding" with a bogus RRSIG.
Files: `ownership.go`, `keys.go`.
Verification: `TestLoadKeyPair_MismatchedPairRejected`, `TestVerifyKeyPairCorrespondence` (ED25519 seed/full/mismatch, ECDSA). All existing key/sign tests still pass. No code path calls `os.WriteFile` on a final key path anymore (key writes go through `writeFileAtomicOwned`).

**R-027 — Key-backup failures are now fatal instead of warn-and-overwrite.**
`backupExistingKeyFiles` (`keys.go`) returns an error and `saveKeyFiles` aborts (leaving the live pair intact) when a required backup fails. The unparseable-key fallback uses a UNIQUE `.bak` base (`uniqueBackupBase`) so a prior `.bak` is never clobbered; a tag-named backup is skipped only when it holds the SAME public key, otherwise the live key is preserved under a unique name. `backupKey` failures at rollover start (KSK, ZSK, algorithm) are now fatal (`rollover.go`).
Files: `keys.go`, `rollover.go`.
Verification: `TestSaveKeyFiles_BackupFailureAborts` (read-only keys dir → generation fails, originals byte-identical), `TestStartKSKRollover_BackupFailureFatal` (Rollover stays nil). Green.

**R-028 — `RecoverKeyState` refuses to regenerate over an orphan key half.**
`RecoverKeyState` (`keys.go`) now returns `(nil,nil)` only when BOTH halves are absent; when exactly one exists it errors (added `statExists`, which also treats a non-ENOENT stat error as an error, not a "generate"). This stops the daemon/`add` from minting a fresh KSK beside a surviving `.key` whose DS still matches at the parent.
Files: `keys.go`.
Verification: `TestRecoverKeyState_OrphanHalf` (delete either half → error, surviving half untouched, `recoverOrGenerateKeys` refuses). Green.

**R-002 — Unique temp names for the signed zone and state.json.**
`writeSignedZone` (`sign.go`) now writes to `os.CreateTemp(dir, "."+base+".*.tmp")` instead of a fixed `<path>.tmp`, so a concurrent daemon + CLI sign of the same zone no longer O_TRUNC the same temp and publish interleaved garbage. `State.Save` (`state.go`) now writes via `writeFileAtomicOwned` (unique temp + fsync + rename, ownership preserved), which also delivers the R-040 fsync.
Files: `sign.go`, `state.go`.
Verification: `TestWriteSignedZone_ConcurrentUniqueTemp` — 100 iterations of two goroutines writing different record sets to the same path; the file parses cleanly every time and no `.tmp` leaks. Passes under `-race`.

**R-001 — Post-sign self-verification gate before publishing.**
Added `verifySignedZone` + `verifyNSECChainClosure`/`verifyNSEC3ChainClosure`/`walkDenialChain` (`sign.go`), called in `SignZone` between `signRecordsWithKeys` and `writeSignedZone`. It runs in-memory on the exact records to be written, reusing `findDelegationPoints`/`isOccluded` (no differential parsing): (1) every RRSIG cryptographically verifies against a published DNSKEY of matching keytag/algorithm; (2) every non-occluded/non-delegation authoritative RRset (plus DS/NSEC at delegation points) has a covering RRSIG; (3) the NSEC/NSEC3 Next pointers form one closed cycle. On any failure `SignZone` errors, so the previous signed output keeps serving (the gate runs before the atomic write — "prior output untouched" is guaranteed by ordering).
Files: `sign.go`.
Verification: the full existing signing suite (which signs real NSEC and NSEC3 zones with delegations/occlusion) passes with the gate active — it does not false-positive on valid zones. New `TestVerifySignedZone_Valid` plus adversarial `TestVerifySignedZone_CorruptRRSIG` (check 1), `_MissingRRSIG` (check 2), `_BrokenNSECChain` (check 3) each assert the gate rejects the break.

**R-003 — Rollover signing branches now fatal on a missing old key.**
The three warn-and-continue branches in `loadKeysForSigning` (`sign.go`) — KSK `ds_add_wait`, ZSK signing phase, algorithm `ds_add_wait` — now return a wrapped error (matching the already-fatal ZSK pre-publish branch) naming `rollover complete` for operators whose old key is legitimately gone. The ZSK signing-phase branch uses `LoadPublicKeyByID` (only the public half is needed) but is still fatal. Backup failures at rollover *start* were made fatal under R-027.
Files: `sign.go`.
Verification: `TestLoadKeysForSigning_MissingOldKeyIsFatal` (all three branches error when the old key's backup is absent). Full suite green under `-race`.

---

## Phase 3 — Signer CLI/daemon coordination

**R-007 — Cross-process advisory lock on state.json.**
Added `acquireStateLock`/`release` (`filelock_unix.go` via `syscall.Flock` on `<data_dir>/state.json.lock`, blocking with timeout; `filelock_windows.go` no-op stub since the supported deployment is Unix). The daemon's `signAllZones` now holds the lock across its whole ReloadFromDisk→sign→Save span and skips the cycle (logging) if it can't acquire it, never crashing the loop. All 8 mutating CLI commands (`sign`, `resign`, `add`, `remove`, `rollover start/complete/algorithm`, `import`) load state UNDER the lock via new `loadConfigStateLocked()` and `defer unlock()`; read-only commands are unchanged. Defense-in-depth: `signAllZones` re-runs `ReloadFromDisk` right before `Save`, and `ReloadFromDisk`'s merge now adopts a disk zone whose rollover differs when its LastSigned is not older (added `rolloverEqual`), so a CLI-started rollover isn't reverted.
Files: `filelock_unix.go`, `filelock_windows.go`, `main.go`, `daemon.go`, `state.go`.
Verification: `TestStateLock_MutualExclusion` (second acquire times out while held; succeeds after release), `TestReloadFromDisk_AdoptsRolloverAtEqualLastSigned`, `TestRolloverEqual`. Full suite green. (Pre-existing note: the project already does not build for Windows because `ownership.go` uses `syscall.Stat_t` untagged — unrelated to this change and not a review finding.)

**R-008 — `remove` is now transactional with the config file.**
Replaced the dead in-memory `RemoveZoneFromConfig` with `RemoveZoneFromConfigFile(configPath, domain)` (`config.go`) — deletes the `[zones."<domain>"]` table (header + all its keys), preserving other content/comments, writing atomically and keeping the file's mode (so a 0640 secrets config isn't loosened). `runRemove` (`main.go`) now: preflights config writability, removes the zone from the config file first (so a running daemon can't re-adopt it), then clears state, unwinding the config entry if the state save fails. Printed note updated to say a running daemon needs SIGHUP; keys are never deleted. Docs updated (`CLAUDE.md`, `README.md`).
Files: `config.go`, `main.go`, `CLAUDE.md`, `README.md`.
Verification: `TestRemoveZoneFromConfigFile` — removes the middle of three zones, preserves siblings + comments + 0640 mode, result reparses with exactly the survivors, absent-zone returns the sentinel.

**R-023 — `import` given the same transactional guards as `add`.**
`runImport` (`main.go`) now calls `preflightConfigAppend(configPath)` before writing any key material, and on an `AddZoneToConfigFile` failure removes the zone from state + re-Saves + deletes the signed output, leaving the converted key files in place with a printed note (never auto-deleting key material). This stops state/config divergence with a blocked "already managed" retry.
Files: `main.go`.
Verification: build/vet/gofmt clean; full suite green. (The preflight + unwind mirror `add`'s already-tested pattern.)


**R-018 — Heartbeat data race removed; Reload no longer holds the mutex across heartbeat network I/O.**
Added `heartbeat` to the `snapshot` struct and `takeSnapshot()`; `checkAndSignZone` now sends via `snap.heartbeat` (captured under `d.mu.RLock`) instead of dereferencing `d.heartbeat` unlocked while `Reload` reassigns it. `Reload` now captures the old client and constructs the new one under the lock, then calls `oldHeartbeat.Stop()` + `newHeartbeat.Start()` AFTER releasing `d.mu` — so a SIGHUP against a blackholed endpoint can no longer stall `takeSnapshot()`/the signing loop for up to ~20s. The two server goroutines copy the cfg fields they need (`Health.DebugVars`, listen addrs) into locals under the lock rather than reading `d.cfg` directly.
Files: `daemon.go`.
Verification: `TestDaemon_SignReloadRace` under `go test -race` (concurrent `signAllZonesSafe` loop + `Reload` loop over a real signable zone) — silent. Full suite green under `-race`.

**R-006 — Web UI and health endpoints resolve cfg/state per request, reflecting SIGHUP reloads.**
Added `Daemon.current()` returning live `cfg,state` under `d.mu.RLock`. `NewWebServer` now takes `*Daemon` and each handler closure calls `d.current()` at the top instead of closing over the startup pointers; health registration is now `RegisterHealthHandlersWithDaemon(mux, d)` (dropped the nil-daemon `RegisterHealthHandlers` variant), with the `/health` and `/healthz` closures resolving cfg/state per request. `runHealthServer`'s unlocked `d.cfg.Health.DebugVars` read is now a lock-copied local. Endpoint paths, JSON schemas, listen addresses ("listen change requires restart"), security headers/method restrictions, and the deep-copy discipline are unchanged. Test call sites updated to pass `NewDaemon(cfg,state)`.
Files: `daemon.go`, `web.go`, `health.go`, `hardening_test.go`.
Verification: `TestDaemonReload_HandlersReflectNewState` (`reload_test.go`) — one server handler instance; pre-reload `/api/status` shows the old zone and `/health` is 503 (old zone's sigs expired), then after `Reload` the SAME handler serves the new zone and `/health`+`/healthz` are 200. Fails against the pre-fix frozen-closure code. (Also satisfies R-078's "add a reload test.")

**R-020 — Web server gained a ctx-based shutdown path.**
`runWebServer` now (1) checks `d.ctx.Done()` non-blocking after storing `d.server` and returns without serving (closing the listener) if shutdown already fired, and (2) runs the same ctx-watcher goroutine the health server uses (`<-d.ctx.Done()` → `srv.Shutdown(timeoutCtx)` with `Health.ShutdownTimeout`). A SIGTERM in the startup window can no longer leave `Serve` running forever with `wg.Wait()` hanging. Double `Shutdown` is safe. Listener binding moved into `Run` (see R-021), so the goroutine uses `srv.Serve(ln)`.
Files: `daemon.go`.
Verification: `TestDaemon_ShutdownBeforeRun` — `Shutdown()` then `Run()`; asserts `Run` returns within 10s (hangs forever before the fix).

**R-021 — Initial listener bind failures are fatal (implicit double-start protection).**
`Run` now `net.Listen`s the health listener (always) and the web listener (when enabled) synchronously BEFORE spawning goroutines; a failure returns a non-nil error from `Run` (process exits non-zero) instead of being logged while the daemon signs headlessly. The health/web goroutines take the pre-bound `net.Listener` and call `Serve(ln)`. A second `serve` with the same config now fails to bind the held health port and exits. Default listen addresses, loopback enforcement, and graceful shutdown are unchanged; later-reload bind changes remain restart-required warnings.
Files: `daemon.go`.
Verification: `TestDaemon_HealthBindFatal` and `TestDaemon_WebBindFatal` — occupy a port, point the respective listen at it, assert `Run` returns an error naming that listener.

**R-019 — Graceful shutdown checks ctx between zones and honors repeated signals.**
`signAllZones` checks `d.ctx.Done()` at the top of both per-zone loops (labeled `break`), stopping promptly on shutdown while still running the final `Save` + coalesced hook for zones already signed this cycle. `runServe`'s SIGINT/SIGTERM handler now runs `daemon.Shutdown()` in a goroutine and keeps consuming `sigCh`: a second shutdown signal logs "forcing exit" and returns a non-zero error even if the graceful drain is wedged (SIGHUP during shutdown is ignored). The save-before-coalesced-hook guarantee for an uninterrupted cycle is unchanged.
Files: `daemon.go`, `main.go`.
Verification: `TestSignAllZones_StopsOnShutdown` — cancel ctx, run a cycle over a signable zone, assert `LastSigned` stays zero (loop broke before `SignZone`). The two-signal force-exit path in `runServe` is verified manually (delivering real signals to the test binary would kill the runner).

**R-026 — Async post-sign hook goroutines are tracked and awaited on shutdown.**
Added `Daemon.hookWG`; `executeHook`/`executeBatchHook` take a `*sync.WaitGroup` (nil from CLI paths, `&d.hookWG` from the daemon) and `Add(1)`/`defer Done()` around the goroutine. After the signing loop drains, `Run` calls `waitForHooks(30s)` so a shutdown right after a cycle doesn't kill the final coalesced `nsd-control reload` before it runs. Hooks stay async relative to per-zone signing; the 30s per-hook timeout, env-var contract, and log redaction are unchanged; `executeHookSync` is untouched.
Files: `daemon.go`, `hooks.go`, `lifecycle_test.go`.
Verification: `TestExecuteHook_WaitGroupTracked` and `TestExecuteBatchHook_WaitGroupTracked` — a tracked hook touches a marker; `wg.Wait()` returns only after the marker exists.
