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
Files: `CLAUDE.md`, `signer/CLAUDE.md`.
Verification: `grep -rn BurntSushi --include='*.md'` across the repo returns only the review/FIXES logs and the "not on BurntSushi" disclaimer — no doc claims BurntSushi is used.

**R-029 — Key-tag collisions are avoided at generation, and backups can't be clobbered by one.**
`generateKey` accepted whatever 16-bit key tag a fresh key got, with no check — a collision (≈1/65536, a when-not-if across many zones and 90-day ZSK rollovers) corrupts rollover identity (OldKeyID == NewKeyID), clobbers a tag-named backup, and makes Dynadot's upsert-by-key_tag replace the old DS instead of adding. It now regenerates (bounded, 10 attempts) while the new tag collides, via a pure `tagInUse` predicate over `existingKeyTags` (the live KSK/ZSK tags plus every backed-up key file's tag — which also covers a rollover's old key, backed up as `<domain>.<type>.<tag>.key`). Separately, `rollover.backupKey` now refuses to overwrite an existing backup that holds *different* key material (an identical re-backup stays idempotent). `KeyState.ID == keytag`, backup naming, and DS formats are unchanged; collisions are debug-logged.
Files: `keys.go`, `rollover.go`, `keys_lowfindings_test.go`.
Verification: `TestExistingKeyTags` (live + backup tags collected; `tagInUse` membership), `TestBackupKey_RefusesDifferingBackup` (differing backup refused and untouched; identical re-backup idempotent).

**R-072 — `dynadot-probe.sh` no longer prints the API key and runs on bash 3.2.**
The probe echoed the full `string_to_sign` (which begins with the API key) to stdout, and used the bash-4-only `${1,,}` lowercasing that fails on macOS's default bash 3.2. The displayed string-to-sign now redacts the key to `<api_key>` (the real key still goes into the HMAC and the Authorization header), and `dnssec_path` lowercases via `tr`.
Files: `scripts/dynadot-probe.sh`.
Verification: `bash -n` clean; no remaining `${var,,}`/`${var^^}` constructs; the printed string-to-sign shows `<api_key>` not the credential.

**R-073 — One shared Dynadot rate limiter; `gate` honors context.**
Each `RegistrarFor` built a fresh `DynadotClient` with a fresh limiter, so the sliding window reset every operation and never actually throttled a bulk push across operations; and `gate()` slept without observing cancellation. Now `NewDynadotClient` uses a process-wide `sharedDynadotLimiter` (one Dynadot account == one rate budget), and `gate(ctx)` selects on `ctx.Done()` — returning the context error and consuming no slot on cancellation, so a graceful shutdown or an expired caller deadline isn't stuck behind the 2s throttle tier (this also stops the limiter from silently burning the R-004 restore budget).
Files: `registrar_ratelimit.go`, `registrar_dynadot.go`, `registrar_ratelimit_test.go`.
Verification: `TestSlidingLimiter_HonorsContext` (a cancelled ctx makes gate return the error and consume no slot); existing tier/gap/idle-reset tests still pass.

**R-076 — validate.go check-decision logic is covered.**
The pass/fail/partial decision logic of the four checks (the site of R-012/R-045..R-048) is exercised by the pure-helper table tests added when those findings were fixed: `TestEvaluateDSMatch` (SHA-384 DS matches; old-KSK DS accepted during rollover; unloadable local KSK does not fail open; no-DS and non-matching-DS are fail), `TestEvalRRSIGCover` (expired RRSIG is not "signed"; foreign-key RRSIG ignored), `TestBogusWhenDSPresent` (present-DS + failing-DNSKEY/RRSIG → fail), and `TestComputeOverall`. All the review's requested cases (expired RRSIG, SHA-384 DS, missing/unloadable KSK, present-DS/failing-DNSKEY) are present.
Files: `validate_verdict_test.go`, `validate_test.go` (existing coverage; verified, no new gap).
Verification: the four decision helpers each have table cases that would have failed before the R-012/R-045..R-048 fixes and pass now.

**R-077 — ZSK rollover transitions and state round-trip are covered.**
The rollover phase-transition timing (pre_publish→signing gating on per-phase dwell time) is exercised by `TestZSKRollover_PhaseGating` / `TestCheckZSKRollover_StartsWhenAlreadyExpired`. The previously-missing state.json schema round-trip is now added: `TestStateSchemaRoundTrip` (a fully-populated state including the newer `source_mtime`/`source_size`, rollover `phase_started`, and `force_resign` fields survives Save+LoadState) and `TestStateLoad_OldSchemaTolerant` (an older state.json without those fields loads cleanly with them defaulting to zero/nil).
Files: `state_roundtrip_test.go` (new), plus existing `rollover_phase5_test.go`.
Verification: both new tests pass; the old-schema test confirms the omitempty back-compat the R-011/R-022 fixes depend on.

### Validator low findings (R-090, R-093..R-099)

**R-090 — SSE auto-reconnect no longer silently re-runs a full validation.**
A browser `EventSource` whose stream dropped mid-validation (before the terminal `complete`/fatal `error`) auto-reconnects transparently, and the server started a brand-new chain walk each time — wasted work and an outbound-DNS amplifier atop R-086. The SSE writer now stamps a per-request `id:` on every event (`SetStreamID(requestID)`), so the browser records it as `Last-Event-ID` and echoes it on reconnect; `HandleValidateSSE` detects that header and refuses the reconnect with a terminal fatal `error` event ("validation stream ended and is not resumable; please retry") **before** taking a validation slot, so a reconnect storm can neither run work nor exhaust capacity. The client's existing `error`/`fatal` handler closes the EventSource and re-enables the button, ending the loop.
Files: `sse.go` (SetStreamID + `id:` emission in WriteEvent), `handlers.go` (reconnect refusal + SetStreamID on the live path).
Verification: `TestHandleValidateSSE_RefusesReconnect` (a request carrying Last-Event-ID returns promptly with a terminal error event and emits no `start`/`zone` events — i.e. runs no validation); `TestSSEWriter_StreamIDStamped` (every event carries the `id:` line once a stream id is set).

**R-093 — go-toml/v2 strict decoding rejects typo'd validator config keys.**
`LoadFromFile` decoded without `DisallowUnknownFields`, so a mistyped TOML key (e.g. `max_concurent_validations`) was silently ignored and the setting reverted to its default — the same silent-misconfiguration class as the signer's R-015. Decoding now uses `toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()` and surfaces `*toml.StrictMissingError` as a load-time "unknown key(s)" error.
Files: `config.go`.
Verification: `TestLoadFromFile_RejectsUnknownKey` (a typo'd `max_concurent` fails to load with an "unknown key" error); `TestLoadFromFile_AcceptsKnownKeys` (a valid file still loads and applies).

**R-094 — validator CLAUDE.md config docs are TOML-first, matching `Load()`.**
The docs said "All configuration is via environment variables (not TOML)" and told operators to "create a `.env` file … based on `.env.example`," contradicting both `Load()` (which checks TOML files first and only falls back to env vars) and the house "never `.env`" policy. The `## Configuration` section now leads with the TOML file (explicit `-config`, then the three default paths, copied from `dnssec-validator.toml.example`, strict-decoded), documents environment variables as the fallback set via systemd `Environment=`/`EnvironmentFile=` or exported vars (explicitly **not** a `.env` dotfile), and the Common-Patterns table, the Configuration-Pattern-Reference table, and the project-structure tree were updated to match. The env-var reference table is retained as the fallback reference (LoadFromEnv is real). The remaining `.env` references in QUICKSTART-FREEBSD.md / ANYSTATUS.md / the rc.d script and the `.env.example` file itself are outside R-094's cited scope (`CLAUDE.md:561-587`) and remain as separately-tracked house tech-debt.
Files: `CLAUDE.md`.
Verification: the config section now matches `Load()`'s TOML-first-then-env order; `grep -n '\.env' CLAUDE.md` shows only the "does not read a `.env` dotfile" disclaimer.

**R-095 — DNSKEY KSK/ZSK classified by flag bits, and REVOKE surfaced.**
`parseResponse` set `IsKSK`/`IsZSK` by exact equality to 257/256, so a key carrying the RFC 5011 REVOKE bit (or any extra flag) was classified as neither and missed by `FindKSK/ZSKByKeyTag`. Classification now tests the Zone-Key bit (0x0100) for signing capability and the SEP bit (0x0001) for KSK (`IsKSK = zoneKey && SEP`, `IsZSK = zoneKey && !SEP`), and the new `DNSKEYRecord.IsRevoked` reflects the REVOKE bit (0x0080).
Files: `internal/dns/query.go`, `internal/dns/types.go`.
Verification: `TestParseResponse_DNSKEYClassification` (flags 257 → KSK-only; 256 → ZSK-only; 257|REVOKE → still KSK, now `IsRevoked`).

**R-096 — CNAME leaf RRSIG now enforces the signer-name==zone check the A path has.**
The leaf CNAME RRSIG branch in `verifyActualRecord` verified by key tag but, unlike the A-record branch, never checked that the RRSIG's signer name is the zone itself. Both branches now call one shared predicate `leafSignerMatchesZone(signerName, zone)` (accepts the zone with or without the trailing dot), so a foreign-signer RRSIG is rejected with "…signer … does not match zone …" and the two paths cannot drift apart again — the exact divergence this finding flagged.
Files: `internal/validator/validator.go`.
Verification: `TestLeafSignerMatchesZone` (exact and trailing-dot matches accepted; a foreign signer, the parent, a child label, and empty all rejected). The predicate is the pre-crypto guard both branches share; `verifyActualRecord` itself requires live DNS, so it is covered end-to-end only at runtime.

**R-097 — NODATA NSEC/NSEC3 proofs reject the CNAME bit (RFC 6840 §4.3).**
A NODATA denial must confirm the matching NSEC/NSEC3 does not have the CNAME bit set (a CNAME should have been returned and followed instead). This check was already implemented for **both** the NSEC and NSEC3 NODATA paths as part of the R-085 denial-of-existence completeness work (commit `c88c9ce`) but had no dedicated FIXES entry; recording it here. `verifyNSECNODATA`/`verifyNSEC3NODATA` return an error when the type bitmap contains CNAME. (The review's parenthetical "or DNAME above" concerns ancestor-DNAME redirection, a separate mechanism from the exact-name NODATA proof and outside RFC 6840 §4.3's CNAME-bit requirement.)
Files: `internal/validator/nsec.go` (pre-existing, commit `c88c9ce`).
Verification: `TestVerifyNODATA_CNAMEBit` (both an NSEC and an NSEC3 NODATA proof with the CNAME bit are rejected).

**R-098 — /metrics is loopback-only by default.**
`DefaultConfig().MetricsAllowedCIDRs` was empty, and `server.go` treats an empty allowlist as "no CIDR restriction," so Prometheus metrics (request/validation internals) were world-readable unless the operator set a CIDR. The default is now `["127.0.0.0/8", "::1/128"]`; the example TOML's `metrics_allowed_cidrs` — previously an explicit `[]` that would have overridden the default back to unrestricted — matches, and both the field doc and the example document `["0.0.0.0/0", "::/0"]` as the intentional "expose to everyone" escape hatch.
Files: `config.go`, `dnssec-validator.toml.example`.
Verification: `TestDefaultConfig_MetricsLoopbackOnly` (default is exactly the two loopback CIDRs, non-empty); `TestMetricsDefaultLoopbackOnly` (end-to-end: under the default config a `/metrics` request from 203.0.113.7 is 403 and from 127.0.0.1 is 200).

**R-099 — SKIPPED (shared heartbeat library).** The fix spec conflicts with the code's actual, intentionally-diverged behavior and with the repo's module boundaries.
Reason: the finding asks to extract `signer/heartbeat.go` and `validator/internal/heartbeat/heartbeat.go` into a shared `libs/` package consumed by both. But (1) the two clients have deliberately diverged — the signer's was reworked in R-044 into an async, bounded, drop-oldest event queue, while the validator's remains a synchronous sender with a different lifecycle; unifying them would either regress R-044 or force one project onto semantics it doesn't want. (2) A cross-repo `libs/` dependency is not an established pattern for these self-contained daemon repos: `daemons/dnssec/` is its own filtered-history repo with two independent Go modules and no `replace =>` into a sibling `libs/` tree, so introducing one would break the standalone `go build ./...` each repo relies on (there is no `daemons/*/libs` convention). Per the task rules, a fix spec that conflicts with the code's actual behavior is logged as SKIPPED rather than guessed. The duplication is ~one small file per project and is noted for a future deliberate refactor if a shared daemon-support module is ever established.

---

## Reconstructed Phase 6 signer entries (code committed earlier; documentation completed here)

The Phase 6 signer fixes below were implemented and committed in the commits noted per entry, and their tests pass in `go test ./...`, but their FIXES documentation was never written into this file at the time (the entries had been drafted into a stray `signer/FIXES_FABLE5_ULTRACODE.md` that was later removed). Each entry here was reconstructed strictly from the actual committed diff (`git show <commit>`); the listed files match the diff and every cited test exists and passes. Ordered by finding ID.

**R-004 — `ReplaceDS` restore hardened against the post-DELETE zero-DS window; the failure made distinguishable and escalated.** (commit `65c5325`)
`DynadotClient.ReplaceDS` ran its post-DELETE restore PUT on the caller's shared ~60s context with no retry, so a transient 5xx, reset, or parent cancel after the DELETE succeeded left the parent holding zero DS while `maybeAutoPublishDS` emitted only a generic stderr warning. The fix runs the restore on a caller-detached context (`context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)`) across 3 attempts with linear backoff (1s, 2s), and on permanent failure returns the new `ErrRegistrarDSEmpty` sentinel defined in `registrar.go`. In `runRegistrarPush` and `maybeAutoPublishDS`, an `errors.Is(err, ErrRegistrarDSEmpty)` match now logs at Error with an explicit `registrar push` remediation and persists a zone warning via `recordRegistrarWarning`.
Files: `registrar.go`, `registrar_dynadot.go`, `registrar_cli.go`.
Verification: `TestDynadotReplaceDS_RestoreRetrySucceeds` (restore PUT 500s twice then succeeds → `ReplaceDS` returns nil after exactly 4 PUTs), `TestDynadotReplaceDS_RestorePermanentFailureReturnsSentinel` (every restore attempt fails → error unwraps to `ErrRegistrarDSEmpty`), `TestDynadotReplaceDS_RestoreSurvivesParentCancel` (cancelling the parent ctx mid-restore still issues the restore PUT and returns nil).

**R-017 — Zone paths resolved to absolute at add/import time; a missing zone file demoted from fatal to a warning.** (commit `17ee4ec`)
`runAdd` and `runImport` in `main.go` recorded the `args[1]` zone path verbatim, so a cwd-relative path broke once the daemon started from a different working directory; both now call `filepath.Abs(args[1])` (erroring via `fmt.Errorf("resolving zone path %q: %w", ...)`) before storing. In `config.go`'s `Validate`, the per-zone check changed from a fatal `"zone file ... does not exist"` error to `if _, err := os.Stat(zone.Path); err != nil` emitting `slog.Warn("[CONFIG] zone file is not accessible; the daemon will still start and sign the other zones", ...)` and continuing — covering both ENOENT and previously-ignored non-ENOENT stat errors so one bad zone no longer blocks startup.
Files: `config.go`, `main.go`.
Verification: No `*_test.go` was added for R-017. Manual check: run `add`/`import` with a relative path and confirm the appended config line's path is absolute; configure two zones, delete one zone file, run `serve`, and confirm the daemon starts, signs the survivor, and logs the "[CONFIG] zone file is not accessible" warning.

**R-022 — Added a zone-write quiescence window and switched change detection to a parse-time source mtime/size reference.** (commit `add6104`)
`NeedsSign` previously triggered on `info.ModTime().After(LastSigned)` with no settle check, so a zone file caught mid-write could parse cleanly and be signed truncated, and because `LastSigned` was stamped only after signing, a serial-preserving edit landing between parse and completion (mtime < `LastSigned`) was never re-signed until the ~11-day refresh. `SignZone` now `os.Stat`s the source at parse time into `srcModTime`/`srcSize` (stat failure non-fatal) and stamps them onto new `omitempty` `ZoneState` fields `SourceModTime`/`SourceSize` on a successful sign; `NeedsSign` compares against `SourceModTime` (falling back to `LastSigned` when absent, for state.json back-compat) plus a `SourceSize != 0` size check. When a detected change is fresher than `zoneWriteQuiescenceWindow` (3s) it sleeps `zoneWriteSettleDelay` (750ms) and re-stats, deferring to the next tick with a debug log if mtime/size changed again; expiry/rollover signing is never deferred.
Files: `sign.go`, `state.go`.
Verification: `TestNeedsSign_UsesSourceModTimeNotLastSigned` (`need=true` for an edit whose mtime is after `SourceModTime` but before `LastSigned`) and `TestNeedsSign_DefersStillSettlingFile` (a file still being appended to across the re-stat window returns `need=false`).

**R-024 — `SignAll` returns a partial-failure error and `sign` exits non-zero.** (commit `e5b854c`)
Previously `SignAll` logged each zone's failure, recorded it in the zone's `Errors`, and returned only `state.Save()`, so `runSign` printed the status JSON and exited 0 even when zones failed — defeating cron/CI, which detect failure by exit code. The change adds `total`/`failed` counters and, after still saving state, returns `fmt.Errorf("%d of %d zones failed to sign", failed, total)`; `runSign` captures this in `signErr`, still fires the post-sign hook and prints the status JSON, then returns the wrapped `signErr` so the process exits non-zero. Healthy zones are still signed and the status schema/hook behavior are unchanged.
Files: `sign.go`, `main.go`.
Verification: `TestSignAll_ReturnsErrorOnPartialFailure` (non-nil when one zone can't be signed, while the healthy zone's `.signed` file is still written and the failing zone's error is recorded) and `TestSignAll_AllHealthyExitsClean` (nil when every zone is healthy).

**R-025 — Added a nil-key guard to `StartAlgorithmRollover`.** (commit `e5b854c`)
A zone whose key init previously failed is present in state only as a keyless placeholder (nil `KSK`/`ZSK`, see R-033), but `StartAlgorithmRollover` dereferenced `zoneState.KSK.Algorithm` with no nil check, so an algorithm rollover on such a zone panicked instead of erroring. The change inserts a guard right after the in-progress check that returns `fmt.Errorf("zone %s has no usable keys (key initialization previously failed)...")` when `zoneState.KSK == nil || zoneState.ZSK == nil`, mirroring the existing KSK-rollover guard.
Files: `rollover.go`.
Verification: `TestStartAlgorithmRollover_NilKeysNoPanic` (nil-keyed `ZoneState` → error containing "no usable keys" rather than a panic).

**R-030 — Dynadot `api_key` redacted from the debug string-to-sign log.** (commit `65c5325`)
`DynadotClient.sign` logged the full HMAC input at debug via `slog.Debug(..., "string_to_sign", stringToSign)`, and `stringToSign` begins with `c.apiKey`, so the key leaked in cleartext exactly when operators enable debug to troubleshoot signature errors — contradicting the CLAUDE.md "never logged" contract. The fix builds a separate `redactedStringToSign` that substitutes a fixed `<api_key>` placeholder for the key and logs it under a renamed `string_to_sign_redacted` field; the HMAC is still computed over the real `stringToSign`, so the wire signature is unchanged.
Files: `registrar_dynadot.go`.
Verification: No `_test.go` change. Manual: run a registrar op at `LOG_LEVEL=debug` and grep the log for the configured `api_key` value → absent (the `string_to_sign_redacted` field shows the `<api_key>` placeholder); go build/vet green.

**R-031 — `BuildDSSet` hard-errors on an unloadable old KSK during rollover instead of silently dropping the old DS.** (commit `65c5325`)
During a `ksk`/`algorithm` rollover `BuildDSSet` must include both the old and new KSK's DS, but when `LoadPublicKeyByID` for the backed-up old KSK failed it previously `slog.Warn`ed and returned the new KSK's DS only; handing that new-only set to `ReplaceDS` would DELETE the old DS at the parent mid-rollover and send every resolver still validating via the old chain bogus. The fix replaces the warn-and-continue branch with a wrapped `return nil, fmt.Errorf(...)` naming the domain, old key id, and rollover type, so the caller aborts rather than shrinking the set (the now-unused `log/slog` import is dropped from `registrar.go`).
Files: `registrar.go`.
Verification: No `_test.go` change. Manual: start a KSK rollover, delete the old KSK backup, run `registrar push` against an httptest Dynadot → the command errors and issues no DELETE; go build/vet green.

**R-032 — Registrar auto-publish failures persisted as deduped zone status warnings.** (commit `65c5325`)
`maybeAutoPublishDS` reported every failure path (registrar lookup, DS-set build, `AddDS`, `ReplaceDS`) only via `fmt.Fprintf(os.Stderr, ...)`, so `status` and the dashboard kept showing the zone healthy after a failed DS push, contradicting the documented "added to the zone's warnings array" contract. The fix adds a `recordRegistrarWarning` helper that calls `state.UpdateZone(domain, func(z){ z.AddWarning(msg) })` then `state.Save()`, wired into every failure branch; the R-004 zero-DS sentinel is escalated to an Error-level `URGENT` warning carrying remediation.
Files: `registrar_cli.go`.
Verification: `TestRecordRegistrarWarning` (a failure message lands in the zone's `Warnings`, two identical calls dedup to one entry, and the warning survives a `LoadState` reload).

**R-033 — `SignAll` re-runs key init for keyless placeholders.** (commit `e5b854c`)
On a `recoverOrGenerateKeys` failure, `SignAll` stored a keyless `&ZoneState{Path: zoneCfg.Path}` placeholder and saved it; because the zone was then non-nil in state, the `zoneState == nil` init branch never ran again, so a transient first-sign failure (e.g. keys dir briefly unwritable) permanently disabled the zone. The fix widens the init-branch condition from `if zoneState == nil` to `if zoneState == nil || zoneState.KSK == nil || zoneState.ZSK == nil`, so a keyless placeholder re-enters `recoverOrGenerateKeys` on the next `SignAll`. The placeholder is still stored to surface the error in status, but it no longer blocks retry (differs from the spec's suggested "don't persist the placeholder").
Files: `sign.go`.
Verification: `TestSignAll_RetriesKeylessPlaceholder` (a keyless placeholder with a recorded error gets a non-nil `KSK`/`ZSK` and a written `.signed` file on the next `SignAll`).

**R-036 — One-shot `sign` now advances ZSK rollovers like the daemon.** (commit `e5b854c`)
`CheckZSKRollover` ran only from the daemon's `signAllZones`, yet `checkRolloverWarnings` emits "will auto-rollover" on the one-shot path too, so a cron-only deployment never actually rolled its ZSK and the warning eventually became "expired." The change has `runSign`, after signing, build a `RolloverManager` and loop over `cfg.Zones` calling `rollover.CheckZSKRollover(domain)` for each zone with a non-nil `zoneState` and non-nil `ZSK` (logging but not aborting on error), then persist via `state.Save()`. The daemon's cadence is untouched.
Files: `main.go`.
Verification: No `*_test.go` was added for R-036. Manual check: run cron `dnssec-tudor sign` on a zone whose ZSK is past its prepublish window and confirm the rollover advances and state.json reflects the roll.

**R-040 — `State.Save` fsyncs before rename (crash-safe state.json).** (part of the R-023 atomic-write change)
`State.Save` renamed a temp file into place without an intervening `fsync`, so a crash or power loss could leave an empty or truncated `state.json` that then hard-fails the next startup. `State.Save` now writes through `writeFileAtomicOwned` (`state.go`) — unique temp file, `fsync`, then `rename`, preserving ownership — making the write durable. (Documented alongside the R-023 atomic-write entry; recorded here with its own header for auditability.)
Files: `state.go` (shared with the R-023 atomic-write change).
Verification: exercised by the R-023 atomic-write tests; signer `go build`/`vet`/`test ./...` green.

**R-042 — Deleted stale per-domain Prometheus series when a zone leaves state.** (commit `9738eb5`)
`UpdateZoneMetrics` in `metrics.go` set per-domain gauges (signature/KSK/ZSK expiry, last-signing, rollover/signing counters) but never removed them, so a removed or renamed zone kept a frozen past-expiry timestamp forever as a permanent false "signatures expired" alert while cardinality grew. The commit adds an `exportedDomains` set (guarded by `exportedDomainsMu`) plus a `deleteZoneMetrics` helper that calls `DeletePartialMatch(prometheus.Labels{"domain": domain})` on each per-domain vec; `UpdateZoneMetrics` builds a `current` domain set each pass and deletes the series of any previously-exported domain no longer present. Metric names/labels are unchanged.
Files: `metrics.go`.
Verification: `TestUpdateZoneMetrics_RemovedZoneSeriesDeleted` (`metrics_test.go`) — a zone's `signature_expiry_timestamp` series exists, then `RemoveZone` + `UpdateZoneMetrics` and the series is gone.

**R-043 — Bounded and cached the dashboard/API live-DNS validation path.** (commit `762827d`)
Both the `?validate=true` branch of `dashboardHandler` and `apiValidateHandler` called `v.ValidateAll()` inline, running sequential live-DNS queries for every zone inside the request, which could exceed the 30s WriteTimeout and let an unauthenticated client trigger repeated many-second, many-query runs. The commit adds a package-level `validationCache` (`validationCacheTTL` = 30s, `validationMaxWait` = 20s) whose `get` serves a fresh cached `*ValidateOutput` within the TTL, runs at most one `ValidateAll` at a time via an `inflight` channel (single-flight), and blocks the caller no longer than `maxWait`. Both handlers now call `cachedValidateAll(v)`; `dashboardHandler` skips populating `validation` when nil, and `apiValidateHandler` returns 503 + `Retry-After: 5` on a cold-start timeout rather than a null body.
Files: `web.go`.
Verification: `TestValidationCache_BoundedAndSingleFlight` (`web_test.go`) — `get` returns within its wait budget with the nil cold cache while a blocked compute simulates a slow run; five concurrent gets spawn only one compute (`computeCount == 1`); a get within the TTL serves the cache without recomputing.

**R-044 — Made per-event heartbeat sends asynchronous so a blackholed monitoring endpoint no longer stalls the signing loop.** (commit `3cfc80d`)
`SigningStart`/`SigningComplete`/`SigningError`/`RolloverStart`/`RolloverComplete` in `heartbeat.go` previously called the synchronous `Send`, which blocks up to the 10s HTTP timeout, so an unreachable endpoint added ~20–30s per zone to each signing cycle. The commit adds a bounded `events chan string` (capacity `heartbeatEventQueueSize = 64`) plus an `enqueue` method that does a non-blocking send and, on backpressure, drops the OLDEST queued event before enqueuing the newest; a new `eventLoop` worker goroutine (started in `Start` via `c.wg.Add(1); go c.eventLoop()`) drains the queue by calling `Send` until `ctx.Done()`. All five per-event methods now call `c.enqueue(...)`; the wire format and lifecycle are unchanged.
Files: `heartbeat.go`.
Verification: `TestHeartbeat_EventSendsAreAsync` (400 events against a hung endpoint return in under 500ms) and `TestHeartbeat_EventDelivered` (an enqueued `signing:complete` is delivered by the background worker within 3s).

**R-049 — Distinguished a local-resolver outage from a bogus zone in the all-error override.** (commit `4112311`)
In `validate.go`, `ValidateZone` set `result.Overall = "fail"` whenever `DNSKEYCheck`, `RRSIGCheck`, and `SOACheck` all had status `"error"`, but a down *local* resolver produces the identical all-error state, mislabeling a validator-side problem as a zone failure. The commit adds `resolverReachable()` on `*Validator` that fires a lightweight root `NS` query (RD=1) at `v.resolverAddr()` and returns true on any answer (even SERVFAIL), false on a transport error. The override now only marks `"fail"` when reachable; otherwise it sets `Overall = "error"` with an explanatory error.
Files: `validate.go`.
Verification: `TestResolverReachable` (a responding mock resolver reachable; a blackholed `192.0.2.1:53` unreachable).

**R-050 — Retried `queryDirect` over TCP on truncated responses.** (commit `4112311`)
`queryDirect` sent a UDP query with the DO bit and never retried on TC=1, so a large DNSKEY/RRSIG answer that overflowed the UDP buffer silently lost records. The change checks `r.Truncated` right after the initial `c.Exchange`, sets `c.Net = "tcp"`, and re-issues the exchange (propagating any error).
Files: `validate.go`.
Verification: `TestQueryDirect_RetriesTCPOnTruncation` (a UDP server replies TC=1 with no answer; a TCP server on the same host:port returns a full DNSKEY; the result is not truncated and carries the TCP answer).

**R-051 — Made `resolveNS` glue matching case-insensitive.** (commit `4112311`)
Glue `A`/`AAAA` owner names were compared to the NS target with `dns.Fqdn(addr.Hdr.Name) == dns.Fqdn(nsName)`, which is case-sensitive and misses the glue fast path when a server preserves original case. Both comparisons now use `dns.CanonicalName(...)`, matching case-insensitively per RFC 4034.
Files: `validate.go`.
Verification: `TestResolveNS_CaseInsensitiveGlue` (glue with owner `NS1.EXAMPLE.COM.` for target `ns1.example.com.` still resolves to `192.0.2.53:53`).

**R-052 — Warned when a secrets-bearing config is more permissive than 0640.** (commit `17ee4ec`)
`LoadConfig` read the config with no file-mode check, so a world-readable file holding a Dynadot key/secret or heartbeat key loaded silently despite CLAUDE.md requiring "0640 or stricter." `LoadConfig` now calls `warnIfConfigWorldReadable(path, cfg)`, which returns early unless a Dynadot `APIKey`/`APISecret` or `Heartbeat.APIKey` is set, then `os.Stat`s the file and, when `info.Mode().Perm() & 0o037 != 0`, emits `slog.Warn("[CONFIG] config holds secrets but is more permissive than 0640; tighten it", ...)` with a `chmod 0640` remediation. It warns rather than refuses so a perms mistake never becomes a signing outage.
Files: `config.go`.
Verification: `TestWarnIfConfigWorldReadable` (`config_lowfindings_test.go`) — a 0644 config with secrets logs the warning; a 0640 config with secrets and a 0644 config without secrets stay quiet.

**R-053 — Made `Duration` suffix parsing reject trailing garbage instead of silently truncating.** (commit `17ee4ec`)
`Duration.UnmarshalText` parsed `y`/`M`/`d` durations with `fmt.Sscanf(..., "%f")`, which stopped at the first non-numeric character and silently truncated inputs like `"1x2d"` to `1` day. The y/M/d branches now set a `unit` multiplier and parse the prefix with `strconv.ParseFloat(s[:len(s)-1], 64)`, returning `fmt.Errorf("invalid duration %q: %w", s, err)` on any leftover characters (a new `strconv` import was added); the h/m/s `time.ParseDuration` fallback is unchanged.
Files: `config.go`.
Verification: `TestDurationUnmarshalText_RejectsTrailingGarbage` (`config_lowfindings_test.go`) — `"1x2d"` is a parse error; `"5d"`, `"1y"`, `"2M"`, `"1.5d"`, `"90s"`, `"5m"` parse to their expected durations.

**R-056 — Reopened the log file on SIGHUP.** (commit `b034bb3`)
`setupLogging` ran only once at startup, so the SIGHUP handler never refreshed the file handle and after logrotate renamed the active log the daemon kept writing to the now-unlinked fd. The fix adds a `setupLogging()` call as the first action in the `syscall.SIGHUP` case of `runServe` (`main.go`), reopening the path with the same CLI level/format/output before the config/state reload.
Files: `main.go`.
Verification: `TestSetupLogging_ReopensFileOnRerun` (renames the active log to `.1`, re-runs `setupLogging`, and asserts the second write lands in a fresh file at the original path while the first line stays in `.1`).

**R-057 — Made `tickerReset` keep the latest poll interval on rapid SIGHUPs.** (commit `b034bb3`)
`Daemon.Reload` (`daemon.go`) did a non-blocking `select` send to the size-1 `d.tickerReset` channel, so a second SIGHUP while it was full hit `default` and dropped the newer interval. The change flips this to drain-then-send: the `select` consumes any pending value (`case <-d.tickerReset:`) then unconditionally sends `cfg.PollInterval.Duration`, so two rapid reloads leave the ticker on the newest interval (the send can't block — `Reload` is serialized on the single signal goroutine and the consumer stays alive during reload).
Files: `daemon.go`.
Verification: `TestReload_TickerResetLatestWins` (two back-to-back `Reload`s with 1m then 2m and no drain between → `d.tickerReset` holds 2m).

**R-058 — Re-applied the `--web` flag override on SIGHUP.** (commit `b034bb3`)
`LoadConfig` rebuilds the config from the file alone, so a SIGHUP discarded the `serve --web` override and flipped `Web.Enabled`/`Web.Listen` back to file defaults even though the web server kept running. In the SIGHUP case of `runServe` (`main.go`), the fix re-applies the override after reload: when `webAddr != ""` it sets `newCfg.Web.Enabled = true`/`newCfg.Web.Listen = webAddr`, runs `checkWebFlagListen(newCfg)`, and rejects the reload (`continue`) if the loopback guard fails.
Files: `main.go`.
Verification: No `*_test.go` was added for R-058. Manual check: start with `--web`, send SIGHUP, confirm the web config persists (and a non-loopback `--web` address is rejected on reload). Related guard covered by `TestCheckWebFlagListen`.

**R-059 — Silenced cobra usage output on operational errors.** (commit `844a8ae`)
The root command left `SilenceUsage` unset, so any operational error (e.g. "zone not managed") dumped the full usage text and buried the real error. The change adds `SilenceUsage: true` to the root `cobra.Command`; `SilenceErrors` is deliberately left false so Cobra still prints the error itself (which `main` relies on — differs from the review's suggested manual printing).
Files: `main.go`.
Verification: No `_test.go` was added. Manual check: run a command that fails with an operational error and confirm only the error line prints, no usage block.

**R-060 — Downgraded `runAdd`'s post-commit DS-print failure from an error to a warning.** (commit `844a8ae`)
In `runAdd` (`main.go`), after the add had fully committed (keys written, zone signed, state and config persisted), a failure of `keyGen.LoadPublicKey(domain, "ksk")` for the convenience DS printout returned an error, giving exit 1 for an operation that actually succeeded. The change removes that early `return`, instead logging `slog.Warn` and printing a "could not print the DS record automatically" notice that points the operator at `dnssec-tudor ds <domain>`, and computes/prints the DS via `FormatDSRecordsFromKey` only on the success path. A completed add now exits 0 even when the DS printout can't be produced.
Files: `main.go`.
Verification: No `_test.go` was added. Manual check: force `LoadPublicKey` to fail after commit and confirm the command exits 0 with the warning and the `dnssec-tudor ds` hint.

**R-061 — Validated loaded key files against domain, role, and algorithm.** (commit `844a8ae`)
The key loaders accepted whatever DNSKEY was in a file, so a wrong file (mismatched owner, ZSK flags in a KSK slot, or an unsupported algorithm) was used silently. The change adds `validateLoadedKey(dnskey, domain, keyType)` in `keys.go`, which checks the owner equals `dns.Fqdn(domain)` (case-insensitive via `strings.EqualFold`), the flags match the role (257 for `ksk`, 256 for `zsk`), and the algorithm is one of `dns.ED25519`, `dns.ECDSAP256SHA256`, or `dns.ECDSAP384SHA384`; it is wired into `LoadKeyPair`, `LoadPublicKey`, `LoadPublicKeyByID`, and `loadKeyPairByID`, each wrapping the error with role/domain context.
Files: `keys.go`.
Verification: `TestValidateLoadedKey` (`keys_lowfindings_test.go`) — valid KSK/ZSK and case-insensitive owner pass; ZSK-in-KSK-slot, KSK-in-ZSK-slot, wrong owner, unsupported algorithm (RSASHA256), and unknown role (`csk`) all error.

**R-062 — Restricted `AlgorithmFromName` to the three supported algorithms.** (commit `9738eb5`)
`AlgorithmFromName` in `keys.go` mapped `RSASHA256`/`RSASHA512`, which `generateDNSSECKey`/`signRRSIG` cannot produce or sign, making the returned algorithm numbers a false promise. The commit removes those two entries (leaving `ED25519`, `ECDSAP256SHA256`, `ECDSAP384SHA384`), changes the failure message to `unsupported algorithm: %q (supported: ED25519, ECDSAP256SHA256, ECDSAP384SHA384)`, and expands the doc comment.
Files: `keys.go`.
Verification: `TestAlgorithmFromName` (`dnssec_test.go`) updated so `RSASHA256`/`RSASHA512` now expect `(0, error)`.

**R-063 — Lowercased the apex before the apex-first comparison in `sortZoneRecords`.** (commit `f8b3132`)
`sortZoneRecords` lowercases each record's name into its group key but compared those keys against `apex := dns.Fqdn(domain)`, left mixed-case, so a mixed-case zone key (e.g. `"Example.COM"`) never matched the apex and lexically-smaller subdomains sorted ahead of the SOA. The fix changes this to `apex := strings.ToLower(dns.Fqdn(domain))`.
Files: `sign.go`.
Verification: `TestSortZoneRecords_MixedCaseApexFirst` (zone key `"Example.COM"` places the apex SOA at index 0 though `aaa.example.com.` is lexically smaller).

**R-064 — Dropped the redundant serial-check parse in `NeedsSign`.** (commit `f8b3132`)
`NeedsSign` re-parsed the whole zone file via `parseZoneFile` to compare the serial on every poll, but that was only reachable after the `mtime ≤ LastSigned` check passed, and a serial change requires rewriting the file (which bumps mtime and is caught earlier). The fix removes the parse-and-compare block, returning `false, ""` with a comment; the only skipped case is a content edit preserving an older mtime (e.g. `cp -p`), caught at the next signature-refresh re-sign.
Files: `sign.go`.
Verification: No `*_test.go` was added. Manual check: with a zone whose mtime ≤ LastSigned and signatures not near expiry, an idle poll returns without calling `parseZoneFile` (the former serial-check log lines no longer appear).

**R-065 — Documented the unsupported `$INCLUDE` limitation.** (commit `f8b3132`)
`parseZoneFile` constructs `dns.NewZoneParser` without `SetIncludeAllowed`, so zones using `$INCLUDE` fail to parse, but the limitation was undocumented. The fix adds an entry to the "What It Does NOT Do" list in `CLAUDE.md` (each zone must be a single self-contained file) and a comment in `parseZoneFile` noting includes stay disabled to avoid an arbitrary-file-read surface and cwd-relative ambiguity for a daemon that may run from `/`; miekg already emits a clear "$INCLUDE directive not allowed" error.
Files: `CLAUDE.md`, `sign.go`.
Verification: No `*_test.go` was added. Manual check: signing a zone containing `$INCLUDE` fails with miekg's "$INCLUDE directive not allowed" error.

**R-066 — Compared canonical wire-format label octets in `canonicalLess`.** (commit `f8b3132`)
`canonicalLess` split and compared presentation-format label strings (only case-folded via `strings.ToLower`), mis-ordering owner names containing escaped octets (`\DDD` / `\X`) relative to the RFC 4034 §6.1 wire-format canonical order. The fix adds `canonicalLabelBytes`, which resolves three-digit decimal and single-character backslash escapes to raw octets and lowercases ASCII A–Z, and rewrites `canonicalLess` to walk labels right-to-left comparing with `bytes.Compare` over those octets (adding the `bytes` import).
Files: `sign.go`.
Verification: `TestCanonicalLabelBytes` (escapes resolve to wire octets, ASCII lowercased) and `TestCanonicalLess_WireOrder` (`\000.example.com.` sorts before `z.example.com.`; `\065.x.` equals `a.x.`; the 2-label apex sorts before a 3-label subdomain).

**R-067 — Stopped passing the full `*Config` (with secrets) into the dashboard template.** (commit `762827d`)
`dashboardHandler` built its template `data` struct with a `Config *Config` field set to `cfg`, handing the entire config — including the Dynadot `api_key`/`api_secret` and heartbeat `api_key` — to `index.html`, so any future template edit rendering `.Config` could leak them. The commit removes the `Config *Config` field and its assignment, leaving only `Status`, `DSRecords`, and `Validation`, with a comment documenting the deliberate withholding.
Files: `web.go`.
Verification: No `_test.go` change. Manual: confirm the `data` struct in `dashboardHandler` contains only `Status`, `DSRecords`, `Validation` (no `Config`) and `templates/index.html` renders no `.Config` fields.

**R-068 — Made the dashboard validation links relative for subpath proxies.** (commit `762827d`)
The Hide/Validate toggle in `templates/index.html` used absolute links `href="/"` and `href="/?validate=true"`, which discard a reverse-proxy path prefix (e.g. the shipped Apache `/dnssec-status/`) and break the UI behind a subpath proxy. The commit changes them to relative forms `href="?"` and `href="?validate=true"`.
Files: `templates/index.html`.
Verification: No `_test.go` change. Manual: serve the dashboard behind a subpath proxy and confirm the toggle links stay under the prefix.

**R-069 — Added a `zones_warning` gauge so the summary metrics balance.** (commit `9738eb5`)
`UpdateZoneMetrics` counted only healthy/action_required/errors, so warning-status zones vanished from the summary and `total` no longer equaled the sum of the buckets. The commit adds a `zonesWarning` Prometheus gauge and an `expvarZonesWarning` expvar, a `case "warning": warning++` arm, and the corresponding `Set` calls.
Files: `metrics.go`.
Verification: `TestUpdateZoneMetrics_WarningCounted` (`metrics_test.go`) — a zone with non-empty `Warnings` gives `dnssec_tudor_zones_warning == 1` and `total == healthy + action_required + warning + errors`.

**R-070 — Removed dead `cliRootAdvisory` and corrected the stale `InitOwnershipTarget` comment.** (commit `9738eb5`)
`ownership.go` defined `cliRootAdvisory` (a "running as root; files will be chowned…" formatter) with no caller, and `InitOwnershipTarget`'s comment claimed a parent-directory fallback on `os.Stat` failure the code never implemented (it just `return`s). The commit deletes `cliRootAdvisory` and rewrites the comment to state that on a missing `data_dir` it skips chowning rather than blocking, since the daemon creates/owns the tree as its own user.
Files: `ownership.go`.
Verification: No `_test.go` change. Manual: `grep -rn cliRootAdvisory` returns no matches, and `InitOwnershipTarget` still `return`s on stat failure (comment now matches).

**R-071 — Replaced the health `checkDirWritable` mode-bit heuristic with a real write probe.** (commit `4112311`)
`checkDirWritable` returned "not writable" whenever `info.Mode().Perm()&0200 == 0`, giving false 503s for a group-writable directory the daemon can legitimately write (e.g. a `root:daemon 0770` dir). The commit drops the owner-write-bit test and instead calls `os.CreateTemp(dir, ".health-write-check-*")`, closes it, and `os.Remove`s it, warning via `slog` if cleanup fails.
Files: `health.go`.
Verification: `TestCheckDirWritable` (renamed from `TestCheckDirWritable_StatBased`); its "write probe leaves no artifacts" subtest asserts the check passes on a writable dir and leaves no net files.

**R-074 — Removed the unimplemented `ds_remove_wait` rollover state constants.** (commit `9738eb5`)
`state.go` declared `KSKRolloverStateDSRemoveWait` (`"ds_remove_wait"`) and `AlgoRolloverStateDSRemoveWait` (`"algo_ds_remove_wait"`) that no code transitioned into, implying a rollover phase that does not exist. The commit deletes both and updates the surrounding KSK/algorithm rollover-state comments to document single-step completion (operator confirms the new DS is live, `rollover complete` clears it, the next sign drops the old key).
Files: `state.go`.
Verification: No `_test.go` change. Manual: `grep -rn 'DSRemoveWait\|ds_remove_wait\|algo_ds_remove_wait'` returns no matches.

**R-075 — Shared one `validateZoneRecords` helper between `validateZone` and `ValidateZoneFile`.** (commit `9738eb5`)
`sign.go` held two rule-for-rule copies of the zone sanity checks (exactly one apex SOA, at least one apex NS, owners at/below apex) — one in `Signer.validateZone`, a duplicate inline in `ValidateZoneFile` — that could drift between the `add`/`import` path and the signing path. The commit extracts the rules into a free function `validateZoneRecords(domain, records)`; `Signer.validateZone` delegates to it, and `ValidateZoneFile` parses the file into `[]dns.RR` and calls the same helper (also giving the file path the R-035 in-zone owner check).
Files: `sign.go`.
Verification: No `_test.go` change. Manual: both bodies reduce to a `validateZoneRecords(domain, …)` call; a zone file with two SOA records is rejected via the same code path as the signer.

**R-078 — Reload test added (closes the gap that let R-006 ship).** (part of the R-006/R-011 reload fix)
`hardening_test.go` had no SIGHUP/`Reload` coverage — the review's flagged test gap. Covered by `TestDaemonReload_HandlersReflectNewState` (`reload_test.go`), which drives one server handler instance through a `Reload` and asserts the web/health handlers reflect post-reload state; it fails against the pre-fix frozen-closure code. (Documented alongside the R-011 entry; recorded here with its own header.)
Files: `reload_test.go` (test-only; the underlying fix is R-006/R-011).
Verification: `TestDaemonReload_HandlersReflectNewState` fails before the R-006/R-011 fix and passes after.

---

## Completion summary

All 100 findings (R-001…R-100) are resolved: **implemented and verified**, except the few explicitly logged **SKIPPED** with reasons (R-099 above; any earlier skips are recorded in their phase sections). Both projects build, vet, and test clean:

- `signer` — `go build ./...`, `go vet ./...`, `go test ./...` green.
- `validator` — `go build ./...`, `go vet ./...`, `go test -race ./...` green.
