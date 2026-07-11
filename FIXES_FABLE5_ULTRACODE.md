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

---

## Phase 4 — validator hardening (R-086, R-087, R-088, R-089, R-091, R-092)

**R-086 — Global concurrent-validation cap.**
Added `max_concurrent_validations` config (TOML `max_concurrent_validations` / env `MAX_CONCURRENT_VALIDATIONS`, default 100, validated > 0). `Handlers` gained a buffered-channel semaphore sized to it; `HandleValidateSSE`/`HandleValidateJSON` acquire a slot near the top (before SSE headers / before anchors+DNS work) and reject with 503 + `Retry-After: 5` when full, rather than fanning out into unbounded outbound DNS/goroutines. The in-flight gauge is now bumped/decremented exactly with the slot (via `acquireValidationSlot`/`releaseValidationSlot`), wiring it to the real live count. Per-validation `MaxConcurrent` and the SSE contract are unchanged.
Files: `config.go`, `handlers.go`.
Verification: `TestValidationConcurrencyCap_RejectsWhenFull` (N+1th request → 503 + Retry-After + "capacity" body), `TestAcquireValidationSlot_HardCap`, `TestValidate_MaxConcurrentValidationsPositive`.

**R-087 — Trust-anchor HTTPS requirement + known-root-tag sanity floor.**
`Config.Validate` now rejects a non-`https://` `root_anchors_url` (enforced at config validation, per the fix spec, so the httptest-based function tests keep working; the only production loader path is fed by validated config). `internal/dns/anchors.go` gained `knownRootKSKTags{20326 (KSK-2017), 38696 (KSK-2024)}` and refuses an anchor set whose keys carry none of them (a wholesale-swap floor) in both `LoadAnchors` and `LoadAnchorsFromURL`; an empty set still falls through to the URL fallback. The digest-match-against-live-root check and file→URL order are unchanged.
Files: `config.go`, `internal/dns/anchors.go`.
Verification: `TestValidate_RootAnchorsURLRequiresHTTPS` (http:// rejected, https://+empty accepted), `TestLoadAnchors_RejectsUnknownRootTags` (tag-6666-only rejected, tag-20326 accepted). Existing anchor tests (fixtures carry 20326) still pass.

**R-088 — NSEC3 iteration cap (RFC 9276).**
Added `nsec3IterationsOverCap` (reusing `NSEC3MaxRecommendedIterations = 100`) and call it at the top of every NSEC3-hashing entry point — `VerifyNSEC3Denial`, `VerifyNSEC3DenialWithRRSIG` (before the RRSIG crypto too), and `VerifyWildcardDenial` — refusing the proof before any `computeNSEC3Hash` runs. A hostile zone can no longer force up to 65536 SHA-1 ops/name. Compliant zones (≤100) are unaffected.
Files: `internal/validator/nsec.go`.
Verification: `TestNSEC3IterationCap` — iterations=1000 rejected at all three entry points (no hashing); iterations=10 never trips the cap.

**R-089 — Trust-anchor load recovers via backoff, not only the 24h refresh.**
`main.go` captures the initial `Load()` error; when it failed, the anchor-management goroutine now retries with exponential backoff (30s → 5m ceiling) until anchors load, then enters the existing 24h steady-state refresh. Readiness is already surfaced by `/health`'s `root_anchors` check (degraded/503 until loaded), so a transient boot-time failure recovers within the backoff window instead of causing up to 24h of 503s. Shutdown (`anchorDone`) interrupts the backoff.
Files: `main.go`.
Verification: build/vet/test/-race clean; the backoff loop drives `AnchorsStore.Load()` (covered by existing anchor-load tests) and stops on `anchorDone`. Full recovery timing verified by inspection (retry cadence + `/health` readiness gate).

**R-091 — Rate-limiter bucket map is bounded.**
`RateLimiter` gained `maxBuckets` (default 50000). `Allow` calls `evictLocked` before inserting a new IP once at the cap: it first drops idle buckets (idle > cleanup interval), then — under active churn where all buckets are fresh — sheds ~10% by evicting to a low-water mark so a fresh insert always fits. Evicting a live bucket only resets that IP's tokens to burst (more lenient, never a bypass), so bounding memory is safe. An attacker rotating source addresses within a /64 can no longer grow the map without limit between cleanup ticks.
Files: `ratelimit.go`.
Verification: `TestRateLimiter_BoundedByMaxBuckets` — 5000 unique fresh IPs with cap 100 → map stays ≤ 100.

**R-092 — RDAP response body size-limited.**
`internal/rdap/client.go` wraps `resp.Body` in `io.LimitReader(…, 1<<20)` (mirroring the anchors loader), so a compromised/oversized RDAP endpoint can't exhaust memory.
Files: `internal/rdap/client.go`.
Verification: `TestQueryDomain_ResponseSizeLimited` — a valid but >1 MiB JSON object is truncated at the cap and no longer parses (fails without the limit only by buffering the whole body).

---

## Phase 4 — signer config validation (R-005, R-013, R-014, R-015, R-016, R-054)

**R-013 — Operational durations validated positive.**
`Config.Validate` now rejects `poll_interval <= 0`, `health.shutdown_timeout <= 0`, `validate.timeout <= 0`, and `registrar.dynadot.timeout <= 0` (all default positive via DefaultConfig). A zero/negative `poll_interval` no longer panics `time.NewTicker` at startup or crashes a running daemon on SIGHUP; zero timeouts no longer silently disable the http.Client / graceful-shutdown deadlines. Three test config builders (which bypass DefaultConfig) were updated to set the now-required durations.
Files: `config.go`, `dnssec_test.go`, `hardening_test.go`.
Verification: `TestConfigValidate_OperationalDurationsPositive` (each of the four zero/negative → error; defaults pass).

**R-014 — Rollover durations validated and ordered; Action string de-hardcoded.**
`Validate` now requires `rollover_prepublish > 0`, `rollover_switch > 0`, and `rollover_switch < rollover_prepublish` (naming both keys) so a swapped/collapsed pre-publish window is rejected at load. The `startZSKRollover` Action message is built from the configured `RolloverSwitch` via a new `humanizeRolloverDelay` helper instead of the literal "in 7 days".
Files: `config.go`, `rollover.go`.
Verification: `TestConfigValidate_RolloverDurations` (switch≥prepublish, negative, zero all rejected; defaults pass), `TestHumanizeRolloverDelay` (7d→"7 day(s)", 1s→"1s").

**R-015 — Strict TOML decoding.**
`LoadConfig` now decodes via `toml.NewDecoder(...).DisallowUnknownFields()` and surfaces `*toml.StrictMissingError`, so a typo like `signture_validity` or a key in the wrong table is a load-time error instead of a silent revert to defaults. Confirmed the signer uses `pelletier/go-toml/v2` (not BurntSushi as the docs claim — R-055), so the go-toml/v2 strict API is correct. Every key in testdata/README/QUICKSTART maps to a struct tag, so valid configs still load.
Files: `config.go`.
Verification: `TestLoadConfig_StrictUnknownKey` (typo'd key → error naming it), `TestLoadConfig_TestdataStillLoads` (shipped testdata/config.toml still loads).

**R-016 — `digest_type` documentation corrected to the [registrar] table.**
CLAUDE.md's `# digest_type = 2` example moved out from under `[registrar.dynadot]` to a `[registrar]` table with a note that it is registrar-agnostic (and that misplacing it is now a strict-decode error). README gained a `[registrar]`/`[registrar.dynadot]` config section (it previously documented none). The field was NOT moved in code (registrar-level is the deliberate design).
Files: `CLAUDE.md`, `README.md`.
Verification: `TestLoadConfig_RegistrarDigestType` — `[registrar] digest_type = 4` → `Registrar.DigestType() == 4`; `[registrar.dynadot] digest_type = 4` → strict-decode error.

**R-054 — CLAUDE.md zone examples quoted.**
Changed the three `[zones.ptudor.net]`/`[zones.ptudor.com]`/`[zones.example.org]` unquoted dotted headers to the quoted `[zones."…"]` form (the unquoted form parses as nested tables and silently registers zero zones), with a note. README already used the quoted form.
Files: `CLAUDE.md`.
Verification: adopting R-015 makes the unquoted form a load-time error; the quoted form matches the working `add`/testdata convention.

**R-005 — `serve --web` re-enforces the loopback guard the flag bypassed.**
`runServe` now calls `checkWebFlagListen(cfg)` after applying the `--web` override (which happens after `Config.Validate` already ran): a non-loopback `--web` address is refused unless `web.allow_remote = true`, closing the hole where `--web :8053` bound the unauthenticated dashboard on all interfaces. Docs updated to loopback forms: `CLAUDE.md`, `README.md`, `apache.conf.example`, `dnssec_signer.rc.d`.
Files: `main.go`, `CLAUDE.md`, `README.md`, `apache.conf.example`, `dnssec_signer.rc.d`.
Verification: `TestCheckWebFlagListen` (`:8053` rejected; `allow_remote` permits; `127.0.0.1:8053` allowed; disabled web skips).

---

## Phase 5 — signer `validate` command verdicts (R-012, R-045, R-046, R-047, R-048)

**R-045 / R-046 / R-047 — DS check: both digests, rollover-aware, no fail-open.**
`checkDSAtParent` now takes the set of acceptable KSKs (the current KSK plus, during a KSK/algorithm rollover, the old KSK loaded by `LoadPublicKeyByID` — mirroring `BuildDSSet`) and a `kskUnloadable` flag. The pure `evaluateDSMatch` helper computes each acceptable KSK's DS in BOTH SHA-256 and SHA-384 and matches the parent DS against any of them (R-045: a SHA-384-only parent no longer false-fails; R-046: an `ds_add_wait` parent holding only the old DS no longer false-fails). When no local KSK can be loaded but a DS exists, the status is `error`, not a fail-open `pass` (R-047).
Files: `validate.go`, `validate_test.go` (call-site signature).
Verification: `TestEvaluateDSMatch` — SHA-384 DS matches; old-KSK DS matches during rollover; unloadable KSK → error (not pass); no/non-matching DS → fail.

**R-048 — bogus zone no longer reported "partial".**
`bogusWhenDSPresent` downgrades the overall verdict to `fail` when the parent publishes a DS but the DNSKEY or RRSIG check failed (a SERVFAIL/bogus condition), applied as an override in `ValidateZone`. The `{pass,partial,fail,error}` vocabulary and `computeOverall` are unchanged.
Files: `validate.go`.
Verification: `TestBogusWhenDSPresent` — DS-found + DNSKEY/RRSIG fail → fail; DS-found + both pass → unchanged; no DS → unchanged.

**R-012 — expired signatures are no longer a false "pass".**
`checkRRSIGPresent` now evaluates temporal validity via the pure `evalRRSIGCover` (RFC 1982 arithmetic through `RRSIG.ValidityPeriod`), and — when the local key tag is known — only counts an RRSIG whose KeyTag matches (SOA↔ZSK, DNSKEY↔KSK). An out-of-window RRSIG sets neither `SOASigned` nor `DNSKEYSigned`; a present-but-expired signature is a hard `fail` naming the expiry (resolvers SERVFAIL); a valid signature within `signature_refresh` of expiry is `partial`. JSON field names / status vocabulary unchanged.
Files: `validate.go`.
Verification: `TestEvalRRSIGCover` — in-window counts; expired does not; foreign key tag ignored when tag known; unknown tag accepts any signer.

---

## Phase 5 — signer rollover correctness (R-011, R-037, R-038, R-039, R-041)

**R-039 — auto ZSK rollover keeps the existing key's algorithm.**
`startZSKRollover` now generates the new ZSK via `GenerateZSKWithAlgorithm(domain, oldZSK.Algorithm)` instead of `GenerateZSK` (which used the current config default). If the operator changed `[dnssec].algorithm` after signing, the auto ZSK rollover no longer mints a mismatched-algorithm ZSK; algorithm changes must go through the dedicated `rollover algorithm` flow.
Files: `rollover.go`.
Verification: `TestStartZSKRollover_KeepsExistingAlgorithm` — ED25519 zone, config flipped to ECDSAP256SHA256, ZSK rollover → the new live ZSK is still ED25519.

**R-011 — ZSK phase transitions gated on real per-phase progress, not wall clock.**
Added `RolloverState.PhaseStarted` (`phase_started,omitempty`; falls back to `Started` for old state files). `handleZSKRolloverState` now advances each ZSK phase only when ALL hold: (1) the phase has dwelled at least its duration; (2) the phase's DNSKEY RRset was actually signed after the phase began (`LastSigned > phaseStart`); (3) a DNSKEY-TTL floor (`DNSKEYTtl`, or 24h when 0) has elapsed since that publish. `PhaseStarted` is stamped on the pre_publish→signing switch. This stops the "collapsed after downtime" failure where both transitions fire in consecutive polls, signing with a key validators never cached. JSON field names / state strings unchanged.
Files: `rollover.go`, `state.go`.
Verification: `TestZSKRollover_PhaseGating` — pre_publish with `Started` 30d ago but never signed in-phase does NOT advance; once signed in-phase + TTL floor elapsed, it advances to signing and stamps PhaseStarted.

**R-041 — a pending KSK/algorithm rollover no longer silently stalls the ZSK.**
`CheckZSKRollover` now, when a non-ZSK rollover occupies the single Rollover slot and the ZSK is within its pre-publish window, records a clear zone warning ("ZSK rollover is due … but is blocked by the in-progress ksk rollover …") instead of silently doing nothing. The KSK/algorithm flow is untouched.
Files: `rollover.go`.
Verification: `TestCheckZSKRollover_BlockedByKSKRolloverWarns` — KSK rollover in ds_add_wait + a due ZSK → the zone gets the blocked warning and the KSK rollover is left intact.

**R-038 — rollover start rolls back key rotation if the state Save fails.**
`StartKSKRollover` and `StartAlgorithmRollover` now, on a `state.Save()` failure after the key files were already rotated on disk, revert the in-memory rollover and restore the old key files from the tag-suffixed backup (new `restoreKeyFromBackup`). This prevents the divergence where the live key is the new one but state.json has no rollover — which the next sign would turn into a published-key-without-matching-DS SERVFAIL. A restore failure is logged CRITICAL for manual recovery.
Files: `rollover.go`.
Verification: `TestStartKSKRollover_RollsBackOnSaveFailure` — inject a Save failure (state path → nonexistent dir); the in-memory KSK/rollover revert and the live `.ksk.key` is restored to the old key.

**R-037 — rollover completion requires the new DS to be live at the parent.**
`runRolloverComplete` now, for KSK/algorithm rollovers, performs a live parent-DS query (`verifyNewKSKDSAtParent`, reusing the validator's `checkDSAtParent` against the new KSK only) before retiring the old KSK, and refuses with a clear message if the new DS isn't visible. A new `--force` flag is the explicit escape hatch (prints a SERVFAIL warning). The parent's live DS is the ground truth, so this covers both registrar-automated and manual zones; the manual workflow keeps working via `--force`.
Files: `main.go`.
Verification: `TestVerifyNewKSKDSAtParent_UnreachableIsNotPresent` — an unreachable/unconfirmable parent reports not-present, so completion refuses. (Full "DS present → proceeds" path is verified manually against a live/mocked parent.)

---

## Phase 5 — signer input hygiene (R-034, R-035)

**R-034 — stale DNSSEC records in the input zone are stripped before signing.**
`parseZoneFile` now calls `stripInputDNSSEC`, which drops any RRSIG/NSEC/NSEC3/NSEC3PARAM and any apex DNSKEY present in the input (a WARN logs the count) before validation and chain generation. Feeding an already-signed file (wrong path, or re-processing) no longer produces a duplicated/self-referential chain or an RRSIG-over-RRSIG. DS records at delegations are preserved.
Files: `sign.go`.
Verification: `TestSignZone_StripsInputDNSSEC` — input with a stray RRSIG(A)/NSEC3PARAM/apex DNSKEY → output has exactly one NSEC3PARAM, no RRSIG-over-RRSIG, and the stale key-tag-1111 RRSIG and input DNSKEY are gone.

**R-035 — out-of-zone owner names are rejected.**
`validateZone` now verifies every record's owner is at or below the apex (`dns.IsSubDomain(apex, name)`) and rejects with an error naming the offending owner, so a stray/typo'd out-of-zone name can't be signed into a broken NSEC/NSEC3 chain. Occlusion/delegation/glue handling (all in-zone) is unaffected.
Files: `sign.go`.
Verification: `TestSignZone_RejectsOutOfZoneOwner` — a zone containing `evil.org. A` → `SignZone` errors naming `evil.org`.

---

## Phase 5 — validator record type & leaf multi-server (R-083, R-100)

**R-083 — the documented `type` parameter is honored.**
Added a `queryType` field to `Validator` (default A) with `SetQueryType`, `leafType`, `leafTypeName`, and a package-level `SupportedQueryType` that parses/validates the type string against a supported set (A, AAAA, MX, TXT, NS, SOA, SRV, CAA, PTR, NAPTR, CNAME, SPF; empty→A; unsupported→rejected). Both handlers now read `type`, 400 on unsupported, and `SetQueryType`. The leaf query (`verifyActualRecord`, `checkAndFollowCNAME`), the denial `qtype`, `FindRRSIGForType`, and `VerifyRRsetRRSIGFromResponse` all use the configured type instead of hardcoded `dns.TypeA`; `result.QueryType` reflects it.
Files: `internal/validator/validator.go`, `handlers.go`.
Verification: `TestSupportedQueryType`, `TestValidatorLeafTypeName`. Full suite green.

**R-100 — leaf record queried across all servers with disagreement reporting.**
Replaced `verifyActualRecord`'s break-on-first-success loop with `queryLeafAllServers`: in quick mode it returns the first usable answer; in extended mode it queries EVERY authoritative server, uses the first usable answer for cryptographic verification, and records any server whose answer disagrees (via a TTL-insensitive `leafFingerprint` over RCODE + sorted leaf/CNAME rdata) in the new `RecordValidation.ServerDisagreements`. This extends the "query every NS, flag inconsistencies" feature — previously only the DNSKEY step — to the leaf answer.
Files: `internal/validator/validator.go`, `internal/validator/result.go`.
Verification: `TestLeafFingerprint` — same answer/different TTL fingerprints identically (no false disagreement); different answers fingerprint differently.

---

## Phase 6 — docs, dead code, tests, maintainability

**R-055 — doc drift: BurntSushi → go-toml corrected.**
Both projects use `github.com/pelletier/go-toml/v2` (go.mod: signer v2.1.1, validator v2.2.4); nothing here is on BurntSushi. `daemons/dnssec/CLAUDE.md:21` now reads `github.com/pelletier/go-toml/v2` with an explicit "no project here is on BurntSushi" note, and the signer `CLAUDE.md:457` dependency bullet reads `pelletier/go-toml/v2` (noting the strict `DisallowUnknownFields` decoding from R-015). `~/Git/CLAUDE.md` never named BurntSushi. This removes the misdirection that R-015 flagged (the two libraries have different strict-mode APIs).
Files: `CLAUDE.md`, `Golang-tudor-dnssec-signer/CLAUDE.md`.
Verification: `grep -rn BurntSushi --include='*.md'` across the repo returns only the review/FIXES logs and the "not on BurntSushi" disclaimer — no doc claims BurntSushi is used.
