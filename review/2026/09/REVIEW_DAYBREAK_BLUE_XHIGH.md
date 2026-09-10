# Deep code review — Daybreak Blue XHigh

Review date: 2026-09-09  
Scope: the complete repository at commit `3a43241`, including both Go modules, packaging, service definitions, workflows, scripts, browser assets, documentation, and tests.  
Method: static data-flow and lifecycle tracing, cross-module consistency checks, `go vet ./...` in both modules, and `go test -race ./...` in both modules. The race suites and vet checks passed. `govulncheck` call-graph and module scans also completed for both modules by running the installed scanner with its compatible Go 1.26 source loader; all four scans reported no known vulnerability. That result is limited to the vulnerability database and dependency/code reachability understood by that scanner on the review date.

The review is analysis only. No source files were changed.

## Findings

### RDAYBLUEX-001 — An unauthenticated first parent response can determine the DS result

**Severity:** High

**Location:** `validator/internal/validator/validator.go:1602-1670`, function `queryDSFromParentWithValidation`; `validator/internal/validator/validator.go:1673-1730`, function `judgeParentDSServer`

**Problem:** In extended mode the validator selects the first transport-successful `NOERROR` parent response before proving that response authentic. All subsequent parent servers are reduced to diagnostics and can never replace the selected response. A faulty, stale, or hostile first authoritative address can therefore force a false Bogus or Indeterminate result even when another parent server returns the authentic DS RRset or authentic denial. An unauthenticated `NXDOMAIN` is even more decisive: it returns immediately without consulting the remaining parent addresses. This contradicts the function's security purpose and makes address ordering security-significant.

**Evidence:** At lines 1631-1634, the code describes and initializes a first-usable-answer policy. Lines 1644-1650 assign `out` as soon as a response has no transport error, no internal error string, and `RCode == 0`. Signature verification occurs only after the assignment at lines 1652-1655. Once `out` is non-nil, lines 1637-1642 only append a disagreement for every later server. Lines 1661-1663 immediately return the first `NXDOMAIN`, with no denial authentication and no extended-mode comparison. Thus `[bad unsigned response, good signed response]` always chooses the bad response.

**Fix specification:** Make candidate selection authentication-aware. Query candidates within the existing mode and timeout policy, authenticate each positive DS RRset under the already-authenticated parent DNSKEY set, and authenticate negative answers with the applicable NSEC/NSEC3 proof before they can become the selected result. In extended mode, select an authenticated candidate and retain every other response as a diagnostic comparison; a bad earlier response must not block a later good one. In quick mode, "first" must mean the first response that completes the required authentication, not merely the first `NOERROR`. Never treat `NXDOMAIN` or an empty DS response as authoritative absence until its denial proof is validated. If no candidate authenticates, return enough evidence for the existing verdict machinery to report the failure rather than silently choosing a different meaning. Preserve the public JSON structures, quick/extended configuration surface, verification budget, and disagreement diagnostics.

**Verification:** Add table-driven resolver tests with ordered responses: malformed/unsigned DS then valid signed DS; wrong signed DS then valid signed DS; unsigned `NXDOMAIN` then valid signed DS; invalid denial then authenticated denial; and all-invalid responses. Assert that a later authentic response is selected, all bad responders remain visible in diagnostics, quick mode stops only after an authentic result, and all-invalid cases remain non-Secure. Run `go test -race ./...` in `validator`.

### RDAYBLUEX-002 — Leaf selection treats unverified denial and DNAME paths as verified

**Severity:** High

**Location:** `validator/internal/validator/validator.go:587-667`, functions `queryLeafAllServers` and `leafSignatureError`; `validator/internal/validator/validator.go:569-584`, function `discoverAliasTarget`

**Problem:** Extended leaf selection promises to prefer a response whose data verifies, but its predicate returns success for every response that is not a directly handled positive RRset or ordinary CNAME. That includes denial responses and the DNAME/synthesized-CNAME path, before their required proofs have been checked by later validation stages. A malformed first denial or DNAME response can therefore be selected over a later cryptographically valid positive response. Separately, cancellation at line 600 does not terminate the loop because `break` exits only the `select`, so cancelled validations continue issuing queries.

**Evidence:** Lines 616-623 choose the first result for which `leafSignatureError` returns `nil`. Lines 648-650 explicitly state that denials return `nil`; lines 652-654 also return `nil` for non-`NOERROR` responses; lines 659-662 return `nil` for a CNAME synthesized through DNAME; and line 666 returns `nil` for every unrecognized answer shape. Consequently, those candidates rank as verified. At lines 598-603, `<-ctx.Done()` executes an unlabeled `break`, after which `QueryRecordAuthoritative` still runs. `discoverAliasTarget` has a related first-success issue at lines 575-582: the first successful response without a CNAME returns `""` instead of checking later authoritative servers.

**Fix specification:** Replace the permissive error predicate with a candidate classifier that fully validates the path the candidate represents: queried positive RRset, ordinary CNAME, DNAME RRset plus synthesized CNAME relationship, or authenticated NSEC/NSEC3 denial. Only a candidate whose complete path authenticates may outrank another candidate. Unsupported or structurally empty response shapes must be failures, not implicit successes. Preserve the later detailed validation output and disagreement diagnostics; do not change the public result schema or make disagreement alone change the verdict. Use a labeled break or immediate return when the context is cancelled. Make alias discovery continue past usable responses that contain no applicable alias and accept only a structurally valid owner match.

**Verification:** Add ordered multi-server tests for invalid denial then valid positive, invalid DNAME then valid positive, invalid ordinary CNAME then valid CNAME, and no-alias first then alias second. Add a resolver spy proving that no query starts after cancellation is observed. Assert the valid candidate is selected and the invalid responder is reported as a disagreement. Run `go test -race ./...` in `validator`.

### RDAYBLUEX-003 — Rollover and publication gates can operate on a partial delegation

**Severity:** High

**Location:** `signer/internal/validate/parentds.go:18-100`, function `resolveAllNS`; `signer/internal/validate/parentds.go:103-195`, functions `ProbeParentDS` and `ProbePublishedSerial`; `signer/internal/validate/validate.go:852-882`, function `queryDirect`

**Problem:** The signer labels its probes as covering every authoritative server, but discovery can silently omit nameservers and addresses. The recursive NS lookup does not retry a truncated response over TCP, validate the response code/question, or require every NS name to resolve. If glue supplies either address family, independent address resolution is skipped entirely. Once at least one address exists, discovery succeeds even when other NS names failed. Rollover completion, old-key retirement, and publication confirmation can therefore advance based on a partial view of the delegation, risking premature key removal or falsely confirmed deployment.

**Evidence:** The NS query at lines 23-31 uses plain UDP and consumes the response without checking `Truncated`, `Rcode`, or the echoed question. Lines 60-77 accept any matching Additional-section A/AAAA data and skip all further resolution for that NS if one record was found. Lines 82-85 ignore address-query errors, and lines 96-100 return success if the aggregate contains any address, not if every NS name was covered. `ProbeParentDS` and `ProbePublishedSerial` then iterate only that aggregate while their comments and callers rely on every-server semantics. `queryDirect` retries TC but checks only `Rcode`; it does not verify `AA`, the echoed question, or that accepted DS/SOA owners match the requested name.

**Fix specification:** Represent discovery by canonical NS identity, not just a flat address slice. Validate response ID/question/rcode and retry NS, A, and AAAA queries over TCP on TC. Accept glue only when it is bailiwick-appropriate and owner-matched; still resolve missing address families according to a documented policy. Require every delegated NS identity to have at least one usable address, or return an error that names the unresolved NS so no safety gate advances. De-duplicate addresses without losing the NS identities they represent. Direct probes must require authoritative responses, validate the question, and accept only owner-correct DS/SOA records (following only explicitly supported DNS alias semantics). Preserve configured resolver and custom DNS port behavior, the existing observation/public APIs, and the fail-closed behavior for transport errors.

**Verification:** Add deterministic DNS fixtures for truncated NS/A/AAAA responses, three NS names with the third unresolvable, one-family glue plus a separately resolved second family, unrelated Additional records, non-authoritative answers, wrong echoed questions, and wrong-owner DS/SOA records. Assert discovery errors identify incomplete coverage and that KSK/algorithm rollover, old-key retirement, and publication confirmation do not advance. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-004 — `data_dir` hot reload moves state without moving the lifetime lock

**Severity:** High

**Location:** `signer/main.go:601-627`, function `runServe`; `signer/main.go:675-697`, SIGHUP reload loop; `signer/daemon.go:247-318`, method `Daemon.Reload`; `signer/internal/fsutil/ownership.go`, process-wide ownership target

**Problem:** The process lifetime instance lock protects only the startup `data_dir`, but SIGHUP reload accepts a configuration with a different `data_dir` and swaps the daemon to state loaded from that new location. Subsequent signing cycles use the new directory without holding its instance lock. A second signer can then start normally against the same new directory, allowing concurrent state, key, output, and hook operations. The process-wide ownership target is also initialized only for the original directory. This defeats the repository's principal split-brain defense.

**Evidence:** `runServe` initializes ownership and acquires the lifetime lock from `cfg.DataDir` at lines 608-621. The lock is released only when `runServe` exits. The SIGHUP path loads an entirely new config/state and calls `daemon.Reload`; `Reload` replaces its config and state snapshot while only treating web and health listener changes as restart-only. There is no equality check or lock transfer for `DataDir`. Signing operations subsequently derive state locks and paths from the reloaded snapshot, while the retained `instance` still references the old directory.

**Fix specification:** Treat `data_dir` as restart-required and reject a reload that changes its canonical, symlink-resolved identity. On rejection, keep the complete previous config/state snapshot active; do not partially apply zones, paths, ownership, listeners, hooks, or state from the rejected configuration. Log a precise restart-required error without exposing secrets. If hot migration is intentionally required in the future, it must atomically acquire the new directory's lifetime lock and initialize ownership before publishing the new snapshot, retain the old lock until no old-snapshot operation remains, and roll back fully on any failure. Do not alter the config schema, CLI flags, on-disk state schema, or startup locking behavior.

**Verification:** Add a reload test that changes only `data_dir` and asserts the reload fails, the old config/state pointer or generation remains active, and subsequent signing reads/writes only the old directory. Add an integration test proving a second instance cannot operate on whichever directory the daemon actively uses. Include symlink-equivalent and relative/absolute-equivalent paths so harmless textual differences do not trigger a false migration. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-005 — A post-sign hook can confirm publication in the wrong reload generation

**Severity:** High

**Location:** `signer/hooks.go:245-313`, function `firePostSignHooks`; `signer/daemon.go:857-899`, method `Daemon.confirmPublication`; `signer/daemon.go:247-318`, method `Daemon.Reload`

**Problem:** Asynchronous post-sign hooks carry zone references from the snapshot that launched them, but their completion callback obtains the daemon's current snapshot. If a reload occurs while a hook is running, a successful old-generation hook can clear pending publication and update publication/cache timing fields in the newly loaded state. Rollover and signing gates consume those fields. A stale process completion can therefore certify output that the active configuration never deployed, or mutate a state object unrelated to the invocation.

**Evidence:** `firePostSignHooks` captures `inv.zones` and calls the generic `onDone` only after the child process exits at lines 280-287. Daemon hook invocations use `d.confirmPublication` as that callback. `confirmPublication` calls `d.takeSnapshot()` at completion time rather than receiving the originating snapshot, then applies each old `SignedZoneRef` to `snap.state`. `Daemon.Reload` can replace both config and state while those goroutines remain in flight. There is no generation token, state identity check, output identity check, or comparison against the active zone's pending signed timestamp.

**Fix specification:** Bind every asynchronous hook invocation to an immutable daemon generation and the exact state/output generation it is intended to confirm. On completion, mutate publication state only if the active generation, domain configuration, output path, signed serial/timestamp, and pending-publication token still match; otherwise log and discard the stale completion. A failure from a stale hook must likewise not overwrite a newer generation's status. Coordinate the identity check and mutation under the daemon/state synchronization already used for snapshot replacement, and persist only the matched state. Preserve the hook environment contract, synchronous CLI behavior, public state/JSON schema where possible, and at-least-once retry behavior for the still-current generation.

**Verification:** Use a blocking hook test: launch a hook for generation A, reload generation B with a fresh pending publication for the same domain, release A successfully, and assert B remains pending and all B timestamps/cache horizons are unchanged. Repeat with a removed/re-added domain, a changed output path, and a newer signing of the same domain. Then complete B and assert exactly B is confirmed and persisted. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-006 — Hook execution is not conditioned on durable state publication

**Severity:** High

**Location:** `signer/daemon.go:604-632`, method `Daemon.signAllZones`; `signer/daemon.go:739-744`, method `Daemon.checkAndSignZone`; `signer/daemon.go:851-899`, method `Daemon.confirmPublication`

**Problem:** The daemon can deploy a newly signed zone even though the state describing that generation was not saved. Non-coalesced hooks are launched inline before the end-of-cycle state reload/save, and coalesced hooks are launched after the save attempt regardless of whether it failed. The asynchronous confirmation then replaces memory from the older disk file before recording success. If a pre-commit save failure left the old valid `state.json` in place, a successful deployment callback can discard the newer in-memory signing and rollover state, add a confirmation to the older state, and save that regression. The served zone and authoritative state can then disagree, and `lastSaveFailed` cannot repair the loss because memory has already been replaced.

**Evidence:** Lines 739-744 invoke a non-coalesced hook immediately after `SignZone`, whereas the cycle's `ReloadFromDisk` and `Save` do not occur until lines 610-626. Lines 628-632 invoke a coalesced hook without checking which branch of the preceding reload/save chain ran. A non-committed `Save` error sets `lastSaveFailed` but does not suppress the hook. When either hook finishes, `confirmPublication` unconditionally calls `ReplaceFromDisk` at lines 865-868 and later saves that adopted state. The cycle's cross-process lock serializes these operations but does not make the unsaved state durable; it merely causes the callback to run after the older file remains on disk.

**Fix specification:** Treat successful state publication as a prerequisite for deployment hooks. Collect both per-zone and coalesced hook invocations during the cycle, but launch them only after the merged state file has been successfully committed; a post-rename durability warning may proceed because the file is visible, while a pre-commit save or pre-save reload failure must leave every affected generation pending and retry the entire save/deploy sequence on a later cycle. A publication callback must never replace known-newer unsaved memory with an older disk snapshot. Apply confirmation through a generation-aware state transaction that merges only the matching publication fields. Preserve synchronous CLI ordering, hook arguments/environment, coalescing semantics, on-disk schema compatibility, and at-least-once deployment retries.

**Verification:** Inject a pre-commit state-save failure while an older valid state file exists. Assert that no hook starts, the old disk file is not rewritten as confirmed, the new in-memory signing/rollover fields remain intact, and the generation remains pending. Repair the save path and assert that a later cycle saves first, runs the hook once, and confirms the same generation. Cover coalesced and non-coalesced modes plus the post-rename durability-warning path. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-007 — Registrar automation never constructs the phase-correct final DS set

**Severity:** High

**Location:** `signer/internal/registrar/registrar.go:60-102`, function `BuildDSSet`; `signer/registrar_cli.go:341-390`, function `MaybeAutoPublishDS`; `signer/main.go:1364-1405`, rollover completion path; `signer/internal/signer/rollover.go:715-778`, method `CheckAlgorithmRollover`

**Problem:** `BuildDSSet` includes the old KSK whenever any KSK or algorithm rollover object exists, regardless of phase. The `rollover_complete` path says it removes the old DS and calls `ReplaceDS`, but supplies this both-old-and-new set. KSK automation therefore leaves the old DS behind, and an explicit later `registrar push` can re-add it throughout retirement. Algorithm automation also performs its only replace too early with the same two-record set; when the state later reaches `algo_old_ds_removal_wait`, no registrar action is triggered. With `auto_publish` enabled, the workflow can wait forever for an old DS it never removes.

**Evidence:** Lines 84-100 of `BuildDSSet` append the backed-up old KSK based only on rollover type. `MaybeAutoPublishDS` lines 369-377 describe a new-only final set but use that builder unchanged. `runRolloverComplete` invokes `MaybeAutoPublishDS(..., "rollover_complete")` immediately after moving a KSK or algorithm rollover into its DS-propagation phase. For algorithms, `CheckAlgorithmRollover` lines 726-735 later changes the phase to `AlgoRolloverStateOldDSRemoval`, but that automatic transition only saves state; it does not invoke registrar automation. Lines 736-766 then require observing the old DS absent before progress can continue.

**Fix specification:** Make desired-DS construction explicitly phase-aware. For KSK rollover, retain old+new through DS-add waiting, then construct new-only once the new DS has been observed on all parents and the workflow authorizes old-DS removal; continue returning new-only through retirement so `registrar push` cannot resurrect the old DS. For algorithm rollover, retain both records through the first parent-DS propagation wait, perform the new-only replace when entering old-DS-removal waiting, and keep it new-only thereafter. Invoke auto-publication at that safe phase transition, make it idempotent across daemon restarts/retries, and persist a visible warning without advancing past a failed registrar update. Do not change registrar interfaces, CLI command names/output contracts, configuration keys, state schema compatibility, or manual operation for zones without auto-publication.

**Verification:** Add a phase table test for ordinary, KSK, and algorithm states asserting the exact desired DS identities. Add end-to-end fake-registrar tests proving KSK completion replaces with new-only, algorithm completion initially retains both, the later automatic transition replaces with new-only exactly once, a transient failure retries without retiring keys, and `registrar push` never re-adds old DS in a removal/retirement phase. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-008 — Old-DS absence ignores records using an unexpected digest type

**Severity:** High

**Location:** `signer/internal/validate/parentds.go:103-163`, function `Validator.ProbeParentDS`; `signer/internal/signer/rollover.go:736-778`, algorithm rollover old-DS-removal phase

**Problem:** The signer declares an old KSK's DS absent only by failing to find the exact SHA-256 or SHA-384 DS values it computed. A parent can still hold a DS for the same key tag and algorithm using SHA-1, an unknown future digest type, or a malformed/wrong digest. Such a record still affects resolver behavior, but the probe reports `AbsentOnAll=true` and can begin the final TTL before retiring the old algorithm. Retirement while a residual old-algorithm DS is served can make clients selecting that record go Bogus.

**Evidence:** Lines 114-123 generate expected records only for digest types 2 and 4. Lines 141-157 increment `presentCount` only for a full key-tag, algorithm, digest-type, and digest match. Lines 159-162 equate a zero exact-match count with absence. `CheckAlgorithmRollover` consumes `AbsentOnAll[oldKeyID]` at lines 745-766 as the safety gate for starting old-key retirement. A DS with the old key tag and algorithm but digest type 1 is present in the answer and nevertheless produces a zero count.

**Fix specification:** Separate two predicates: new-key presence must continue to require an exact supported digest derived from the DNSKEY, while old-key absence must conservatively require that no DS with the old DNSKEY's key tag and algorithm exists on any parent response, irrespective of digest type or digest value. Treat key-tag collisions conservatively as still present; waiting is safer than retiring a potentially referenced key. Preserve the `ParentDSObservation` API if possible, its every-parent fail-closed requirement, supported positive digest policy, and TTL behavior. Document and test the distinction so future digest support cannot weaken removal safety.

**Verification:** Return parent RRsets containing only an old-key SHA-1 DS, an unknown digest type, a wrong digest with the matching tag/algorithm, and a colliding tag/algorithm. Assert `AbsentOnAll` is false and algorithm retirement does not advance. Also assert an unrelated tag/algorithm does not block absence and that exact SHA-256/SHA-384 still establishes `PresentOnAll` for a new key. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-009 — SSE flush failures are invisible to cancellation and concurrency accounting

**Severity:** Medium

**Location:** `validator/sse.go:18-46`, type `SSEWriter`; `validator/sse.go:68-135`, methods `WriteEvent`, `WriteRawEvent`, `WriteComment`, `WriteRetry`, and `WriteID`; validation stream handlers that cancel work on returned write errors

**Problem:** Each SSE method checks buffered writes but flushes through `http.Flusher.Flush`, whose interface returns no error. The same writer already has a `ResponseController`, whose `Flush` reports errors from the underlying connection. If writes enter a buffer but the actual socket flush times out or fails, the method returns nil, so handler logic cannot cancel the validation. Expensive DNS work and a global validation semaphore slot can remain occupied until the independent validation timeout, amplifying slow/disconnected-client load.

**Evidence:** `NewSSEWriter` stores both `flusher` and `rc`. Every write method arms a deadline and checks `fmt.Fprintf`, then calls `s.flusher.Flush()` at lines 94, 104, 114, 124, or 134 and returns nil unconditionally. The comments at lines 10-15 explicitly rely on write/flush errors releasing validation work, but the flush path cannot satisfy that contract.

**Fix specification:** Flush through `http.ResponseController.Flush` and return a wrapped error from every SSE method when it fails. Keep the existing `http.Flusher` capability check if required for compatibility, and retain the per-event sliding deadline, headers, exact wire framing, stream IDs, and public handler behavior. Handler cancellation must occur on either write or flush failure and release activity/semaphore accounting exactly once. Writers that genuinely cannot expose flush errors may retain best-effort behavior only where the Go HTTP abstraction provides no stronger signal.

**Verification:** Add a response-writer wrapper for which `Write` succeeds and `FlushError` returns a sentinel error. Assert every SSE method returns that error. In a stream-handler test, block validation after the first event, inject the flush error, and assert its context is cancelled, the active-validation count drops, and another request can acquire the global slot promptly. Run `go test -race ./...` in `validator`.

### RDAYBLUEX-010 — A delegation can create unbounded per-request DNS fan-out

**Severity:** Medium

**Location:** `validator/internal/dns/resolver.go:160-215`, functions `ResolveAddressesDetailed` and `ResolveNSWithAddresses`; `validator/internal/validator/validator.go:1956-2012`, function `ValidateMultipleServers`; validation orchestration paths that flatten NS addresses

**Problem:** Extended validation accepts an unbounded number of NS records and address records from DNS, does not de-duplicate them before work scheduling, and creates one goroutine per resulting address. `max_concurrent` limits only goroutines that have acquired the local semaphore; all others remain allocated and blocked, and semaphore acquisition is not context-aware. A client-chosen zone with a very large delegation/address set can therefore consume large numbers of goroutines, memory, resolver queries, and timeout-length waiters per validation. The global validation limit multiplies rather than bounds that fan-out.

**Evidence:** `ResolveNSWithAddresses` iterates every returned NS and performs A and AAAA lookups with no count limit at lines 199-213. Address slices are appended without de-duplication at lines 168-187. `ValidateMultipleServers` sizes a result for every address and starts a goroutine for each at lines 1970-2008. Each goroutine blocks on `semaphore <- struct{}{}` at line 1981 without selecting on `ctx.Done()`. Quick mode caps the final server slice at two, but extended mode has no equivalent resource ceiling.

**Fix specification:** Canonicalize and de-duplicate NS names and IP addresses, introduce explicit defensible per-validation maxima, and schedule authoritative queries through a bounded worker pool rather than one goroutine per input. Queue acquisition and result collection must observe context cancellation. If DNS data exceeds a limit, expose truncation/resource-budget exhaustion and return an Indeterminate outcome; do not claim consensus from an undisclosed partial set. Account for IPv4/IPv6 duplicates, repeated RRs, one IP shared by multiple NS names, and deterministic ordering. Preserve quick-mode semantics, public JSON field shapes, global validation limiting, and configured resolver/timeouts.

**Verification:** Construct a fake delegation with thousands of NS/address records and duplicates. Assert goroutine growth and simultaneous queries remain within fixed bounds, cancellation prevents queued queries from starting, duplicates are queried once, the result reports the exceeded budget, and it cannot become Secure based only on the truncated subset. Run `go test -race ./...` in `validator`, including a repeated stress test under the race detector.

### RDAYBLUEX-011 — Packaged validator startup has no offline last-known-good trust anchors

**Severity:** Medium

**Location:** `validator/internal/config/config.go:131-146`, default anchor sources; `validator/internal/dns/anchors.go:173-273`, anchor loading functions; `validator/anchors_store.go:27-44`, method `AnchorsStore.Load`; `.goreleaser.yaml:83-120`, validator package contents; `packaging/sigillum-validator-postinstall.sh:1-13`; `packaging/sigillum-validator.service:7-27`

**Problem:** The packaged configuration points first to `/etc/sigillum-validator/root-anchors.json`, but packages neither install that file nor persist a validated URL result there or in the created state directory. Last-known-good behavior exists only in process memory. A clean installation, or any restart after a previously successful network fetch, has no anchors when the mirror or network is unavailable; the service starts but validation remains unavailable. This turns a transient external outage during startup into a complete validation outage despite having authenticated the same anchor set previously.

**Evidence:** `LoadAnchorsWithFallback` reads the configured file and then fetches the URL, returning the downloaded object only in memory. `AnchorsStore.Load` assigns it to `s.anchors` but performs no atomic persistence. The validator package contents include configuration, service, and documentation but no anchor JSON. Post-install creates `/var/lib/sigillum-validator` but does not seed it, and the service's strict filesystem policy declares no validator-writable state path. Startup deliberately continues after anchor load failure and retries, while requests cannot validate without anchors.

**Fix specification:** Provide an offline authenticated last-known-good path. Either ship a release-reviewed anchor document that passes the binary pins or atomically persist every successfully parsed, structurally valid, currently usable, pinned download to a dedicated state file, preferring that cache before the network on later starts. Persistence must use restrictive permissions, fsync/rename discipline, size limits, and never replace the previous good file on fetch, parse, pin, or durability failure. If runtime persistence is chosen, configure the service with the minimum writable state directory and use that path rather than making `/etc` writable. Keep the embedded pins as the trust boundary, preserve operator-supplied anchor-file precedence and config compatibility, and do not silently trust network content merely because it was cached.

**Verification:** Build and inspect both package formats for the selected bootstrap/cache mechanism. Test clean installation with network unavailable, a successful fetch followed by restart with network unavailable, corrupt/truncated replacement attempts, expired/future-only documents, and cache-write failures. Assert a valid prior set survives every failed refresh, file owner/mode and service sandbox permit only the intended writes, and validation/readiness work offline. Run `go test -race ./...` in `validator` plus package-install tests in an isolated image.

### RDAYBLUEX-012 — Malformed typed environment values silently activate defaults

**Severity:** Medium

**Location:** `validator/internal/config/config.go:243-300`, function `LoadFromEnv`; `validator/internal/config/config.go:462-494`, functions `getEnvInt` and `getEnvBool`

**Problem:** When the validator runs without a configuration file, a present but malformed integer environment variable is logged and replaced with the default, while a malformed boolean is replaced silently. A deployment typo can therefore change timeouts, request/query concurrency, rate limits, shutdown behavior, heartbeat enablement, or heartbeat cadence without preventing startup. This is especially dangerous for resource controls: an intended lower limit can become a much larger default while the orchestrator reports the service healthy.

**Evidence:** `LoadFromEnv` uses `getEnvInt` for every duration/count/limit and `getEnvBool` for heartbeat enablement. `getEnvInt` lines 471-481 logs that it is ignoring a malformed present value and returns the default, despite the adjacent comment saying such values should not fall back silently. `getEnvBool` lines 484-493 returns the default for every unrecognized nonempty value with no log or error. The later `Validate` sees only valid defaults, so it cannot detect the original misconfiguration.

**Fix specification:** Make typed environment parsing return an error that names the variable and expected syntax whenever a nonempty value cannot be parsed; accumulate multiple errors if practical so operators can repair a deployment in one pass. Continue applying defaults only when variables are absent or intentionally empty according to the existing contract. Preserve currently accepted boolean aliases, environment variable names, file-first configuration precedence, default values, and the `Config` public fields. Never log secret-valued environment variables while reporting parse errors.

**Verification:** Add table-driven `LoadFromEnv` tests for malformed, overflow, whitespace, and valid integer values plus every accepted and rejected boolean spelling. Assert malformed `MAX_CONCURRENT`, rate-limit, timeout, shutdown, heartbeat interval, and heartbeat enabled values fail startup rather than use defaults; absent values must still receive existing defaults. Run `go test -race ./...` in `validator`.

### RDAYBLUEX-013 — A configured hook defeats explicit publication modes

**Severity:** High

**Location:** `signer/daemon.go:739-744`, method `Daemon.checkAndSignZone`; `signer/daemon.go:548-568`, method `Daemon.signAllZones`; `signer/daemon.go:851-899`, method `Daemon.confirmPublication`; `signer/main.go:419-447`, function `runPostSignHook`; `signer/internal/config/config.go:126-163`, publication-mode contract

**Problem:** Whenever a post-sign hook is configured, daemon and single-zone CLI paths treat its success as publication confirmation even when the operator explicitly selected `publication = "probe"` or `publication = "immediate"`. In probe mode this bypasses the required every-authoritative-server SOA check and lets rollover cache timers start from a local command's completion. A stale or ineffective deployment hook can therefore authorize key retirement before the new generation is actually served everywhere. In immediate mode a later hook confirmation moves `PublishedAt` and cache horizons a second time, while a hook failure is reported as a deployment failure even though the selected policy says the file write itself is publication.

**Evidence:** `PublicationMode` documents three mutually distinct confirmation authorities. `SignZone` correctly confirms only immediate mode and marks hook/probe modes pending at `signer/internal/signer/sign.go:333-340`. However, `checkAndSignZone` launches every configured hook with `d.confirmPublication` as the completion callback without checking the effective mode. The later mode switch also runs the probe, but an earlier or later hook completion can independently clear the same pending flag. The CLI helper similarly calls `confirmPublicationCLI` after any successful hook and is used by `resign`, rollover, add, and import commands regardless of mode.

**Fix specification:** Decouple “run a post-sign command” from “this command is the publication authority.” Continue running configured hooks as the deployment mechanism where that is the established hook contract, but attach the confirmation callback only in effective hook mode. In probe mode, leave the generation pending until the existing every-authoritative-server serial probe succeeds; CLI commands may run that probe synchronously or leave a clearly reported pending state for the daemon, but must not substitute hook success. In immediate mode, the atomic file replacement remains the sole confirmation event; later hook success/failure must not move publication timestamps/cache horizons or block DS automation on the false premise that publication failed. Preserve hook environment, coalescing, config syntax/default auto-selection, state schema, and the rule that an unspecified mode plus a configured hook resolves to hook mode.

**Verification:** Add a mode-by-hook matrix covering daemon and CLI signing. With explicit probe mode and a successful hook but a failing/partial serial probe, assert publication remains pending and rollover gates do not advance. With immediate mode, assert `PublishedAt` is set exactly by signing, hook completion does not move it, and a hook failure does not convert the published generation back to pending. With hook mode, retain current success/failure and retry behavior. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-014 — Registrar credentials can be sent over cleartext or across redirects

**Severity:** High

**Location:** `signer/internal/config/config.go:64-82`, type `RegistrarDynadotConfig`; `signer/internal/config/config.go:409-458`, method `Config.Validate`; `signer/internal/registrar/registrar_dynadot.go:75-113`, function `NewDynadot`; `signer/internal/registrar/registrar_dynadot.go:220-264`, method `DynadotClient.do`

**Problem:** The registrar endpoint override accepts an arbitrary URL and the HTTP client uses Go's default redirect behavior. Every request carries the API key in `Authorization` and an HMAC in `X-Signature`. A mistaken cleartext override exposes credentials on the network. A same-origin HTTPS-to-HTTP redirect can also replay sensitive headers over cleartext; 307/308 redirects can replay the request body without recomputing the path-bound signature. This is a credential-compromise risk in the component authorized to replace or delete parent DS records.

**Evidence:** `Config.Validate` validates the digest type and other registrar settings but never parses or constrains `RegistrarDynadotConfig.BaseURL`. `NewDynadot` copies a nonempty override verbatim after trimming `/` and creates `http.Client{Timeout: timeout}` without `CheckRedirect`. `do` concatenates the endpoint and signed path, then sets `Authorization: Bearer <apiKey>` and `X-Signature` before calling that client. The standard client follows redirects; the adapter neither enforces HTTPS on the redirect target nor re-signs a redirected path.

**Fix specification:** Parse the override as an absolute URL at configuration validation time and require HTTPS for production use. If existing local test/proxy workflows require HTTP, permit it only for a loopback literal/localhost behind an explicit insecure-development setting that is disabled by default; do not infer safety from an arbitrary hostname resolving locally. Install a bounded `CheckRedirect` policy that rejects scheme downgrade, userinfo, host/port changes, and unexpected paths. If any redirects remain supported, build and sign a fresh request for the approved target rather than allowing automatic replay. Apply the same rule to every method, including destructive DS replacement/recovery. Preserve default and sandbox endpoint selection, registrar interfaces, timeout/user-agent settings, config compatibility for valid HTTPS overrides, and test-double support through an explicit safe test mechanism.

**Verification:** Add client/config tests for an HTTP override, malformed/relative URL, HTTPS-to-HTTP redirect, cross-origin redirect, same-origin changed-path 307/308, redirect loops, and an approved no-redirect HTTPS request. A capture server must prove the API key, signature, and body never reach a rejected target. Retain local integration tests using the explicit test path. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-015 — Oversized signature lifetimes wrap DNSSEC time and pass self-verification

**Severity:** Medium

**Location:** `signer/internal/config/config.go:491-509`, method `Config.Validate`; `signer/internal/signer/sign.go:1084-1090`, method `Signer.signRecordsWithModel`; `signer/internal/signer/sign.go:1197-1236`, method `Signer.verifySignedZoneWithModel`; `signer/internal/signer/sign.go:1431-1458`, method `Signer.createRRSIG`; `signer/internal/signer/sign.go:307-326`, method `Signer.recordSignedZone`

**Problem:** Configuration requires only a positive signature validity and a smaller refresh interval. Go durations can represent centuries, but RRSIG inception/expiration are 32-bit serial times and their unambiguous interval is limited by serial arithmetic. An accepted large validity can wrap the expiration into the past or an unintended future epoch. The post-sign verifier checks only the cryptographic signature, not its validity period, so it can publish the unusable zone. Even for normal values, state records `now + configured validity` after signing work completes rather than the actual expiration encoded into the signatures, overstating their usable lifetime.

**Evidence:** `signRecordsWithModel` computes expiration from the unrestricted duration. `createRRSIG` truncates `expiration.Unix()` and inception to `uint32`. `verifySignedZoneWithModel` calls only `sig.Verify`; it never calls the library's validity-period check or compares the serial-time window with the intended policy. `recordSignedZone` independently stamps `SignaturesExp` from a later `now`, so the state deadline does not derive from the records that were written.

**Fix specification:** Reject signature-validity values that are not safely representable under DNSSEC serial arithmetic (strictly less than half the 32-bit serial space), and impose a documented operational maximum well below that boundary. Validate the complete inception/expiration window, including the fixed one-hour backdate. During post-sign verification, require every RRSIG to be currently valid within the intended skew policy and to have the expected bounded window in addition to verifying cryptographically. Carry the minimum actual RRSIG expiration from the constructed signed zone into `recordSignedZone`; state must never claim validity later than the earliest published signature. Preserve normal default behavior, config keys, state JSON field names/backward readability, and public CLI output.

**Verification:** Add config tests for the exact representability boundary, very large values such as 100 years, refresh values near the limit, and ordinary defaults. Mutate a valid signed zone to contain expired, not-yet-valid, wrapped, and unexpectedly long RRSIG windows and assert post-sign verification rejects each before output replacement. Assert persisted `signatures_expire` equals the minimum actual RRSIG expiration, not a later recomputation. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-016 — Same-size source replacements can remain unsigned for days

**Severity:** Medium

**Location:** `signer/internal/state/state.go:51-59`, type `ZoneState`; `signer/internal/signer/sign.go:755-802`, method `Signer.NeedsSign`; `signer/internal/signer/sign.go:813-912`, source-snapshot path

**Problem:** Steady-state change detection persists and compares only source mtime and byte size. Replacing a zone with different same-length content while preserving or restoring its timestamp is deliberately treated as unchanged until periodic signature refresh. With the default validity/refresh relationship, a restored backup, reproducible build, synchronization tool, or adversarial local writer can leave materially changed DNS data unpublished for many days. This is a correctness and data-freshness failure, not merely an optimization tradeoff.

**Evidence:** `ZoneState` stores `SourceModTime` and `SourceSize` but no content identity. `NeedsSign` triggers only when the current mtime is later or the size differs. Lines 796-801 explicitly acknowledge that `cp -p` of different content with the same size is skipped until signature refresh. The read path already holds a consistent regular-file descriptor and buffers the exact bytes, so a digest could be attached to the same snapshot without a second-file TOCTOU.

**Fix specification:** Persist a cryptographic digest of the exact source bytes successfully parsed and published, and use it when metadata alone cannot establish identity. A straightforward safe policy is to digest on every poll; if that is too costly, use a documented metadata fast path plus a reliable mechanism for replacement detection, but equal/older mtime and equal size must not imply equality indefinitely. Compute the digest from the same descriptor snapshot used for parsing, store it only after successful output publication, and make the new state field optional so old files load safely and establish a baseline without losing current output. Retain quiescence checks, atomic-producer guidance, source path semantics, state schema backward compatibility, and avoidance of needless re-signs for genuinely unchanged bytes.

**Verification:** Sign a zone, replace it atomically with different equal-length content while preserving the exact mtime, and assert the next check requests signing. Repeat with an older mtime, an unchanged byte-for-byte replacement, an in-place write observed during digest/read, and an old state file lacking the digest. Assert only changed complete snapshots are signed and failed/incomplete reads do not update the stored identity. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-017 — Zone-file input has no memory or record-count bound

**Severity:** Medium

**Location:** `signer/internal/signer/sign.go:837-912`, method `Signer.readSourceSnapshot`; `signer/internal/signer/sign.go:1048-1074`, function `ValidateZoneFile`; signing and import CLI paths that call them

**Problem:** The daemon reads each source file completely into memory and then accumulates an unbounded record slice. The standalone validation path also accumulates every parsed record without a byte or record cap. A mistakenly huge generated zone, sparse-file read, or writer with access to a configured source can exhaust process memory and terminate signing for all zones. The per-zone panic recovery does not protect against operating-system OOM termination.

**Evidence:** `readSourceSnapshot` verifies only that the descriptor is regular, then calls `io.ReadAll(f)` and appends every parser result to `records`. It does not reject a large `before.Size()` or use a limited reader. `ValidateZoneFile` streams the parser input but likewise appends all records to a slice before semantic validation. No config or package constant bounds either dimension.

**Fix specification:** Define and enforce explicit maximum source bytes and record counts before allocation and throughout parsing. Reject a known oversized descriptor before reading; also use a reader limited to `max+1` to handle growth and special filesystem behavior, and stop record accumulation at `max+1`. Limits should be configurable only if operational requirements demand it, with safe nonzero hard ceilings. A rejected zone must retain its last-known-good signed output/state, record a per-zone signing error, and not prevent other zones from being processed. Apply equivalent protection to `validate`, `add`, and `import` paths. Preserve accepted zone-file syntax, include prohibition, public command APIs, and behavior below the limits.

**Verification:** Add boundary tests at `max-1`, `max`, and `max+1` bytes and records, including a single extremely long record, a sparse oversized regular file, and a file that grows during reading. In a multi-zone daemon test, assert the oversized zone fails visibly while a normal zone still signs and the previous oversized-zone output is unchanged. Measure that allocation stays bounded. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-018 — Pending hooks can overlap without a process-wide bound

**Severity:** Medium

**Location:** `signer/hooks.go:245-313`, function `firePostSignHooks`; `signer/daemon.go:541-566`, pending-publication retry loop; `signer/daemon.go:739-744`, post-sign dispatch

**Problem:** Non-coalesced dispatch starts one goroutine and child process per signed zone with no concurrency bound. Pending publication is retried every signing cycle without tracking whether the same generation already has a hook in flight. If the poll interval is shorter than hook duration or timeout, repeated identical deployments overlap; a large zone set can multiply that into a process/goroutine storm. Coalescing limits a cycle to one child but still permits the same batch to overlap across cycles.

**Evidence:** `firePostSignHooks` constructs an invocation per zone and immediately starts a goroutine for every invocation when a wait group is supplied. It has no worker semaphore or in-flight registry. The daemon retry loop dispatches every pending zone on every cycle solely from persisted state; publication remains pending until callback completion, so a still-running hook qualifies again. No key combines daemon generation, domain, and `SignedAt` to single-flight an invocation.

**Fix specification:** Route asynchronous hooks through a bounded dispatcher with a configurable or defensible fixed process-wide concurrency limit. Maintain single-flight identity for each exact publication generation (and batch identity when coalesced): a cycle must not enqueue or start a duplicate while that identity is queued/running. On completion, clear the identity and let failures become eligible for a later retry with bounded backoff; newer generations should supersede queued obsolete work without allowing stale completion to confirm them. Shutdown must remain bounded and terminate tracked process groups as today. Preserve synchronous CLI execution, hook environment and order contract, coalescing behavior, timeout, and at-least-once retry for current failed generations.

**Verification:** Use blocking hooks across multiple short poll cycles. Assert a single generation has at most one queued/running invocation, total simultaneous child processes never exceeds the configured bound, a failed invocation retries only after completion/backoff, and a newer generation is eventually deployed without stale confirmation. Cover coalesced/non-coalesced operation and shutdown while work is queued. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-019 — State merge can erase same-generation CLI diagnostics

**Severity:** Medium

**Location:** `signer/internal/state/state.go:507-598`, methods `State.ReloadFromDisk` and `rolloverEqual`; `signer/daemon.go:499-504` and `signer/daemon.go:604-626`, failed-save recovery and pre-save merge; `signer/registrar_cli.go:21-31`, function `recordRegistrarWarning`

**Problem:** Cross-process state merge adopts a disk zone only when its `LastSigned` is newer or a small subset of rollover fields differs. Same-generation mutations to warnings, operation errors, publication metadata, rollover timestamps/actions, or other fields are otherwise ignored. After a daemon pre-commit save failure, a CLI can persist an urgent registrar warning while the daemon retains newer unsaved work in memory. The next daemon reload keeps its memory object because signing and core rollover identity are equal, then saves it over disk, silently deleting the CLI warning. This can hide the repository's urgent “parent has zero DS” recovery signal.

**Evidence:** `ReloadFromDisk` replaces a present zone only in two cases at lines 576-583. `rolloverEqual` compares only type, phase string, and four key IDs; it omits algorithms, phase timestamps/horizons, parent-observation fields, action, warnings/errors, publication fields, and force-resign state. `recordRegistrarWarning` intentionally mutates and saves warnings without changing `LastSigned`. The daemon's `lastSaveFailed` path reuses the in-memory snapshot and relies on `ReloadFromDisk` to merge intervening CLI writes, but this mutation class is not merged.

**Fix specification:** Introduce an explicit monotonic revision or per-field transactional merge protocol rather than inferring causality from signing time. Every persisted mutation must carry enough version information to merge CLI and daemon changes without dropping either; warning/error removal requires a revision or tombstone so a union does not resurrect cleared diagnostics. Preserve fresher signing/key/publication state while adopting later independent diagnostics and deletion markers. Older state documents must load with a safe baseline revision and remain backward compatible. All read-merge-save operations stay under the existing cross-process lock, but the implementation must not assume that locking alone identifies which snapshot is newer.

**Verification:** Inject a daemon pre-commit save failure, then under the lock persist an urgent CLI registrar warning at the same `LastSigned`; allow the next cycle to merge/save and assert both the daemon's unsaved signing changes and the CLI warning survive on disk. Repeat for setting/clearing operation errors, publication confirmation, rollover timestamp/action changes, zone removal/re-addition, and upgrades from an old revisionless state file. Run concurrent sequences repeatedly under `go test -race ./...` in `signer`.

### RDAYBLUEX-020 — RDAP endpoint and redirects create a blind HTTP egress path

**Severity:** Medium

**Location:** `validator/internal/config/config.go:243-299` and `validator/internal/config/config.go:334-459`, environment loading and validation; `validator/internal/rdap/client.go:25-83`, functions `NewClient` and `Client.QueryDomain`; `validator/handlers.go:53-59`, RDAP client construction

**Problem:** The optional RDAP base URL is accepted without URL or scheme validation, and its client follows redirects by default. Every public validation can therefore trigger a server-side GET to an arbitrary configured origin or to a redirect target selected by the configured service. A compromised public endpoint can redirect the validator into loopback, link-local, private, or metadata services reachable from its network. The response is parsed only as RDAP and no secrets are attached, so this is principally blind request forgery and internal service interaction rather than direct response exfiltration.

**Evidence:** `LoadFromEnv` copies `RDAP_BASE_URL` directly and `Config.Validate` constrains trust-anchor and heartbeat URLs but not RDAP. `NewClient` only removes a trailing slash and constructs a default `http.Client`. `QueryDomain` formats `<base>/domain/<validated-domain>` and calls `Do`; no redirect or dial destination policy is installed. The DNS egress policy is scoped to DNS queries and is not reused by this HTTP client.

**Fix specification:** Validate RDAP configuration as an absolute HTTPS URL and reject userinfo, fragments, and ambiguous path forms. Keep local HTTP test support only through an explicit loopback-only development option or injected test transport. Reject redirects by default, or allow only a bounded same-origin HTTPS policy whose final resolved destinations also pass a public-egress check at dial time. If hostname endpoints are permitted, defend at the actual dial boundary against DNS rebinding and every resolved non-public address, while retaining an explicit operator allowlist for intentional internal deployments. Preserve RDAP optionality, current default URL/path contract, response-size/time limits, and public validation result schema.

**Verification:** Add config/client tests for cleartext, relative, userinfo, cross-origin and scheme-downgrade redirects; direct and hostname-resolved loopback/private/link-local destinations; a DNS-rebinding-style resolver; redirect loops; and an allowed normal HTTPS endpoint. Assert rejected targets receive no request and validation continues with a visible RDAP diagnostic rather than failing DNSSEC validation itself. Run `go test -race ./...` in `validator`.
