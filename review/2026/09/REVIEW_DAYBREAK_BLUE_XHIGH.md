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

### RDAYBLUEX-021 — The refresh window can be shorter than the daemon's polling interval

**Severity:** Medium

**Location:** `signer/internal/config/config.go:491-509`, method `Config.Validate`; `signer/internal/signer/sign.go:699-716`, method `Signer.NeedsSign`; `signer/daemon.go:402-423`, method `Daemon.runSigningLoop`

**Problem:** Configuration only requires `signature_refresh < signature_validity`; it does not require the refresh window to cover the interval between signing checks. `NeedsSign` evaluates the refresh threshold only when the daemon's fixed poll ticker runs. If `signature_refresh` is shorter than `poll_interval` (or does not also cover one worst-case multi-zone signing pass), a signature can cross its expiration between checks. The signer then knowingly serves expired signatures until that zone is reached in the next pass. Small positive values, including sub-second validity/refresh pairs, pass validation and make this deterministic.

**Evidence:** `Config.Validate` checks positivity and ordering at lines 491-509 but never relates either value to `PollInterval`. `NeedsSign` returns true only once `now` is after `SignaturesExp - SignatureRefresh`; it does not schedule a timer at that instant. `runSigningLoop` calls the check on one `PollInterval` ticker, and zones are processed serially during a cycle. For example, validity `10m`, refresh `1m`, and poll `5m` can first notice the refresh threshold at or after expiration depending on ticker phase and cycle duration.

**Fix specification:** Enforce or schedule a safety margin that guarantees an unchanged, healthy zone is considered for re-signing before its earliest actual RRSIG expiration. At minimum, reject `signature_refresh < poll_interval`; the safe constraint should additionally include documented clock/ticker jitter and an upper bound or measured allowance for one full signing pass. A stronger implementation may schedule the next wake-up from the minimum persisted signature expiration rather than relying solely on the poll interval, but ordinary source-change polling behavior must remain unchanged. Define a sensible minimum signature validity and refresh granularity so sub-second configurations cannot produce effectively expired output. Preserve the TOML keys, normal defaults, output format, and manual `sign`/`resign` behavior.

**Verification:** Add boundary config tests for refresh just below/equal/above the required margin, sub-second pairs, and a multi-zone worst-case allowance. With a fake clock/ticker, sign just before a poll, advance through `expiration-refresh`, and assert a signing pass starts and publishes before expiration. Include a deliberately slow earlier zone and assert a later zone still does not expire. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-022 — The public-only DNS egress policy permits deprecated site-local IPv6 destinations

**Severity:** Medium

**Location:** `validator/internal/dns/egress.go:78-133`, variables `reservedV4`, `reservedV6` and function `NonPublic`; `validator/internal/dns/egress.go:135-160`, method `EgressPolicy.Permit`

**Problem:** The public validator's SSRF defense is a hand-maintained denylist, but the IPv6 list omits `fec0::/10`, the deprecated site-local range. `NonPublic` consequently returns false for an address such as `fec0::1`, and an attacker-controlled delegation can make the service attempt UDP/TCP port 53 on that destination. A host or network that still routes site-local space exposes an internal DNS interaction despite the documented public-only default. **Needs investigation:** the complete denylist should also be compared with the current IPv4 and IPv6 special-purpose registries; the implementation has no mechanism to keep classification synchronized as special ranges change.

**Evidence:** `reservedV6` contains unspecified, loopback, mapped, well-known translation, discard, documentation, unique-local, link-local, and multicast ranges, but no `fec0::/10`. `NonPublic` accepts every non-nil IPv6 address not contained in that slice. `Permit` then allows it when `AllowPrivate` is false because `!NonPublic(ip)` is true. Authoritative addresses originate in the submitted domain's NS address data.

**Fix specification:** Classify destinations from an explicit globally reachable/forwardable policy rather than assuming all addresses absent from a short denylist are public. At minimum add `fec0::/10`; audit both address families against the current authoritative special-purpose registries and add regression vectors for every non-global category. Canonicalize and classify embedded/translated address forms at the actual dial boundary so alternate representations cannot bypass the result. Keep the configured recursive resolver trusted, retain explicit CIDR allowlisting and `allow_private_destinations`, and do not block ordinary global-unicast authoritative servers.

**Verification:** Add a table-driven test asserting `fec0::1` is rejected by both `NonPublic` and `Permit`, then add one vector per special-purpose category and representative global-unicast controls. Drive a real validator request whose delegation supplies the site-local address and use a dial spy to prove neither UDP nor TCP is attempted unless that exact range is explicitly allowlisted. Run `go test -race ./...` in `validator`.

### RDAYBLUEX-023 — Positive integer settings can overflow into invalid `time.Duration` values

**Severity:** Medium

**Location:** `validator/internal/config/config.go:243-299`, function `LoadFromEnv`; `validator/internal/config/config.go:307-331`, method `Config.applyNestedToFlat`; `validator/internal/config/config.go:352-380` and `validator/internal/config/config.go:428-431`, method `Config.Validate`; `validator/ratelimit.go:35-49` and `validator/ratelimit.go:117-120`, rate-limiter startup

**Problem:** The validator validates the positive integer source fields but not the derived durations after multiplication. A sufficiently large positive seconds/minutes value overflows `time.Duration` into zero, a negative duration, or an unrelated small positive duration while the source integer still passes validation. A negative `rate_limit.cleanup_seconds` result reaches `time.NewTicker` in a goroutine and panics the entire service. Wrapped query, total, shutdown, or heartbeat durations silently disable, shorten, or immediately expire their intended time bounds.

**Evidence:** `applyNestedToFlat` directly multiplies `int` values by `time.Second`/`time.Minute` at lines 310-317 and 331. `Validate` checks only that `QueryTimeoutSec`, `TotalTimeoutSec`, `ShutdownTimeoutSec`, `RateLimit.CleanupSec`, and enabled `Heartbeat.IntervalMinutes` are greater than zero. It never checks the derived `time.Duration` fields or guards multiplication. `NewRateLimiter` immediately starts `cleanupLoop`, whose first statement constructs `time.NewTicker(rl.cleanup)` and panics for a non-positive wrapped value.

**Fix specification:** Perform checked integer-to-duration conversion before assigning any derived field. Reject values greater than `math.MaxInt64 / unit`, reject any derived non-positive value, and impose defensible operational maxima so technically representable multi-century timeouts are not accepted accidentally. Apply the same helper to seconds and minutes from both TOML and environment loading. Return a field-specific configuration error before constructing the server or any goroutine. Preserve the integer config/env interfaces, existing normal values, and the current duration fields consumed by the rest of the program.

**Verification:** Add tests at `max/unit`, `max/unit+1`, `MaxInt`, and representative ordinary values for every converted field through both file and environment loaders. Assert overflow is a load error and that no goroutine or ticker is started. Include a subprocess regression proving a huge positive cleanup value exits with a configuration error rather than a runtime panic. Run `go test -race ./...` in `validator`.

### RDAYBLUEX-024 — `parent_ds_ttl` can truncate to zero or wrap before a key-retirement gate

**Severity:** Medium

**Location:** `signer/internal/config/config.go:165-170`, method `Config.ParentDSTTLFallback`; `signer/internal/config/config.go:476-478`, method `Config.Validate`; `signer/main.go:1337-1362`, forced rollover completion; `signer/internal/signer/rollover.go:172-237` and `signer/internal/signer/rollover.go:676-728`, rollover completion/checks

**Problem:** `parent_ds_ttl` is accepted at any non-negative `time.Duration`, then converted to whole seconds and narrowed to `uint32`. A positive duration below one second becomes zero. A duration above `math.MaxUint32` seconds wraps modulo 2^32. Either result can reduce the required parent-DS cache wait to zero or a much shorter interval, allowing old KSK/algorithm material to be retired while resolvers can still hold the old DS RRset. The path is especially relevant to `rollover complete --force`, whose safety depends entirely on this fallback.

**Evidence:** Validation rejects only negative values. `runRolloverComplete` and both `Complete*KSK/Algorithm*Rollover` paths use `uint32(cfg.ParentDSTTLFallback() / time.Second)`. The resulting value is persisted as `RolloverState.ParentDSTTL`, and `CheckKSKRollover`/`CheckAlgorithmRollover` add that many seconds to the observation time. With `500ms`, integer division yields zero and the `DSPropagation` branch can transition immediately; large values wrap during the cast.

**Fix specification:** Validate `parent_ds_ttl` as an exact whole-second value in the representable `uint32` range before any rollover begins. Reject nonzero values below one second, fractional-second values if the format is intended to be second-granular, and values above `math.MaxUint32` seconds; also impose a documented operational maximum appropriate for DS TTLs. Centralize the checked conversion and make every fallback caller use it without a second narrowing cast. Old state containing zero must continue to use the conservative default rather than mean “no wait”; out-of-policy nonzero legacy values must fail closed and require operator repair. Preserve the TOML key, state JSON field type/name, observed parent TTL behavior, and the explicit `--force` surface.

**Verification:** Add config and rollover tests for `500ms`, `1s`, fractional seconds, exactly `MaxUint32` seconds, one second above it, and a normal 24-hour value. With a fake clock, assert invalid values cannot enter propagation and that legacy zero uses 24 hours. Confirm the old KSK/algorithm remains published until the full accepted delay elapses. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-025 — Dashboard validation caches are not scoped to a daemon generation

**Severity:** Low

**Location:** `signer/web.go:36-103`, global `dashboardValidationCache`; `signer/web.go:105-178`, global `dashboardZoneValidationCache`; `signer/web.go:212-239`, reload-aware handler construction; `signer/daemon.go:247-318`, method `Daemon.Reload`

**Problem:** The web handlers intentionally fetch the current config/state on every request, but both live-DNS caches are process globals keyed by neither config nor state generation. Immediately after reload, the aggregate endpoint can return the previous zone set and the per-zone endpoint can return a result computed with the previous resolver, keys, paths, and state. An old in-flight computation can also populate the cache after reload. Per-zone entries are never evicted; although only currently managed domains can create entries, repeated remove/re-add churn grows the map for the lifetime of the process.

**Evidence:** `dashboardValidationCache` has one result/in-flight slot for the process. `zoneValidationCache.byZone` is keyed only by the domain string and has no delete/expiry sweep. `NewWebServer` calls `d.current()` for fresh pointers, then `cachedValidateAll`/`cachedValidateZone` consult these globals without an identity argument. `Daemon.Reload` swaps config and state but does not invalidate them. Their 30-second TTL therefore applies across configuration generations.

**Fix specification:** Key validation results and single-flight work by an immutable daemon generation plus the relevant domain; increment the generation only after a successful reload is published. A completion from an old generation must not fill a current-generation entry. Invalidate aggregate results immediately on reload, remove per-zone entries for removed zones, and bound/evict superseded generations. Preserve the 30-second within-generation caching/single-flight behavior, endpoint schemas, live validation semantics, and the rule that handlers resolve current state per request. This can share the generation token required by RDAYBLUEX-005.

**Verification:** Prime both caches under generation A, reload generation B with a changed resolver and zone set, and assert the next request computes B rather than serving A. Hold an A computation in flight across reload and prove its completion cannot populate B. Repeatedly add/remove unique domains and assert the entry count remains bounded. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-026 — A cold per-zone validation timeout returns `200 null`

**Severity:** Low

**Location:** `signer/web.go:124-170`, method `zoneValidationCache.get`; `signer/web.go:365-380`, aggregate API handler; `signer/web.go:382-403`, per-zone API handler

**Problem:** When the first per-zone validation exceeds the 20-second wait budget, the cache returns its nil stale value and the handler JSON-encodes it as `null` with HTTP 200. Clients cannot distinguish “validation is still running” from a successful nullable result. The aggregate endpoint detects the identical condition and correctly returns 503 with `Retry-After`, so the sibling APIs have contradictory contracts.

**Evidence:** `zoneValidationCache.get` explicitly returns `stale`, which may be nil, on timeout. `apiValidateZoneHandler` unconditionally calls `Encode(result)`. In contrast, `apiValidateHandler` checks `output == nil` at lines 368-373 and returns `503 Service Unavailable` plus `Retry-After: 5`.

**Fix specification:** Make the per-zone handler treat a nil cache result exactly like the aggregate handler: return 503 and a bounded `Retry-After`, with a non-JSON-null error body consistent with the signer's API conventions. Let the background validation finish and seed the cache. Do not change successful response JSON, cache timing, or the distinction between unknown zone (404) and validation in progress (503).

**Verification:** Block a cold per-zone computation beyond `validationMaxWait` and assert status 503, `Retry-After`, and no `null` success body. Release the computation and assert the next request returns the normal JSON result with 200. Add the equivalent stale-result case and preserve the intended stale fallback if that remains part of the contract. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-027 — Unknown validation modes silently select the more expensive mode

**Severity:** Low

**Location:** `validator/handlers.go:139-143` and `validator/handlers.go:262-264`, SSE handler; `validator/handlers.go:330-334` and `validator/handlers.go:417-419`, JSON handler

**Problem:** The public handlers document `quick` and `extended`, but validate neither. Only exact `quick` enables quick mode; every other nonempty token silently runs extended validation. Typos therefore change both semantics and outbound work rather than producing a client error, and the SSE and JSON routes consume a global validation slot before the mistake is reported—because it is never reported.

**Evidence:** Both handlers default an empty value to `extended`. Their only subsequent branch is `if mode == "quick" { SetQuickMode(true) }`; no branch rejects a value such as `quik`, `EXTENDED`, or an arbitrarily long token. The validator consequently uses its default extended behavior.

**Fix specification:** Parse the mode once through a shared helper before acquiring a validation slot. Accept exactly the documented canonical values (and empty as the existing default); return the existing 400 problem-details shape for everything else. If case-insensitivity is intentionally supported, normalize and document it consistently for both endpoints. Preserve the default, successful quick/extended behavior, metrics endpoint labels, and response schemas.

**Verification:** Add identical handler tables for empty, `quick`, `extended`, case variants, typo, and oversized values. Assert invalid modes return 400 without calling the validation seam or consuming a semaphore slot, while valid modes reach the seam with the expected normalized value. Run `go test -race ./...` in `validator`.

### RDAYBLUEX-028 — RDAP DS integers and digests are narrowed without validation

**Severity:** Low

**Location:** `validator/internal/rdap/types.go:18-24`, type `DSData`; `validator/internal/validator/validator.go:2115-2163`, method `Validator.queryRDAPSecureDNS`

**Problem:** RDAP supplies DS fields as signed, machine-width integers and arbitrary strings, but the validator casts them directly to DNS wire-width unsigned values. Negative and oversized values wrap modulo 2^16 or 2^8 and can accidentally equal a real DNS DS tuple. Digest text is uppercased without checking supported digest type, exact length, or hexadecimal encoding. Since RDAP is a diagnostic cross-check rather than the trust chain, this cannot make DNSSEC cryptographically Secure, but it can produce a false `DSMatch` and misleading troubleshooting output from malformed or hostile RDAP data.

**Evidence:** `DSData` declares `KeyTag`, `Algorithm`, and `DigestType` as `int`. Lines 2152-2155 convert with `uint16(...)` and `uint8(...)` and copy the digest. No range or structure check precedes `compareDSRecords`. For example, key tag `65537` narrows to `1`, and algorithm `271` narrows to `15`.

**Fix specification:** Validate every RDAP DS record before conversion: key tag 0..65535, algorithm and digest type 0..255, a supported digest type where semantic comparison is claimed, and exact hexadecimal length/decodability for that type. Malformed entries must be excluded from matching and surfaced in `RDAPSecureDNS.Error` or a compatible diagnostic field; they must not turn the core DNSSEC verdict Bogus or Indeterminate. Preserve the public result schema if possible, uppercase normalization for valid digests, and all valid RDAP comparison behavior.

**Verification:** Add RDAP fixtures with negative, one-above-maximum, wrapping-to-a-real-value, unknown digest type, odd/non-hex digest, wrong digest length, and a valid control. Assert none of the malformed records match DNS data and the diagnostic identifies the rejected record, while the core DNSSEC status is unchanged. Run `go test -race ./...` in `validator`.

### RDAYBLUEX-029 — Signer zone-name validation does not enforce DNS wire limits

**Severity:** Low

**Location:** `signer/internal/config/config.go:558-562`, config zone loop; `signer/internal/config/config.go:703-728`, functions `CanonicalZoneIdentity` and `ValidateDomainName`; `signer/internal/state/state.go:329-339`, function `validateZoneEntry`

**Problem:** The configuration boundary calls a path-safety character filter rather than a DNS-name validator. It accepts labels longer than 63 octets, names longer than 255 wire octets, leading empty labels, leading/trailing hyphens without an explicit policy, and the root spelling without explicitly deciding whether root-zone management is supported. Some accepted names later fail miekg/dns parsing or state validation after key/signing work has begun, producing deferred, inconsistent failures across config, state, filenames, and registrar paths.

**Evidence:** `ValidateDomainName` checks nonempty, `".."`, path separators, and a character allowlist only. It never measures labels or the encoded name and never delegates to `dns.IsDomainName`. Persisted state separately calls `dns.IsDomainName`, so the two abstraction boundaries disagree. The validator HTTP boundary already enforces 63-character labels and a total length, demonstrating the repository has a stricter parallel rule.

**Fix specification:** Define the exact supported managed-zone name grammar, then apply one canonical validator before any filesystem or state mutation. Enforce DNS wire limits and empty-label rules; decide and test whether underscores, leading/trailing hyphens, escaped octets, IDNA A-labels, trailing root dots, and the root zone are supported rather than changing them accidentally. Continue the existing path-separator/traversal defense. Preserve canonical collision rejection, existing valid ASCII zone spellings, output/key filename conventions, config schema, and backward handling of already persisted valid names.

**Verification:** Add shared config/CLI tables at 63/64-byte label and 255/256-byte wire boundaries, leading/trailing hyphens, empty labels, underscore service-style labels, case/trailing dot, IDNA, escaped characters, and root. Assert invalid names fail before key, output, config-edit, or state files change, and every name accepted by config is also accepted by state validation and the DNS parser. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-030 — Negative per-zone key lifetimes silently mean “inherit”

**Severity:** Low

**Location:** `signer/internal/config/config.go:188-196`, type `ZoneConfig`; `signer/internal/config/config.go:485-509` and `signer/internal/config/config.go:558-587`, method `Config.Validate`; `signer/internal/config/config.go:657-670`, methods `GetZoneKSKLifetime` and `GetZoneZSKLifetime`

**Problem:** Global key lifetimes must be positive, but zone-specific overrides are not validated. The getters apply an override only when it is greater than zero, so a negative configured value silently becomes the global default. Zero has a legitimate “unset/inherit” meaning; negative values almost certainly indicate a typo and should not be indistinguishable from unset in a security-timing setting.

**Evidence:** `ZoneConfig` exposes both duration overrides. `Config.Validate` checks the two global values but its per-zone loop checks only name, path, registrar, algorithm, and serial policy. The getters use `zone.KSKLifetime.Duration > 0` and `zone.ZSKLifetime.Duration > 0`; all non-positive values fall through to the global value without a warning or error.

**Fix specification:** Preserve zero as the backward-compatible inherit sentinel and reject every negative per-zone KSK/ZSK lifetime with a zone-qualified configuration error. Apply any operational upper/lower bounds chosen for global lifetimes equally to nonzero per-zone values. Do not change existing positive overrides, getter APIs, TOML keys, or the meaning of omitted/zero values.

**Verification:** Add per-zone tables for omitted, zero, negative, and positive lifetimes for both roles. Assert omitted/zero inherit, negative fails configuration loading, and positive overrides. Include reload and config-edit validation so an invalid override cannot partially replace a live daemon snapshot. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-031 — `resign` and `import` exit successfully after deployment-hook failure

**Severity:** Low

**Location:** `signer/main.go:419-447`, function `runPostSignHook`; `signer/main.go:835-877`, function `runResign`; `signer/main.go:1613-1815`, function `runImport`; compare `signer/main.go:1129-1138` and other rollover callers

**Problem:** `runPostSignHook` returns false specifically so callers can report that the signed generation was not deployed, but `resign` and `import` discard it and return nil. `resign` then prints “re-signed successfully”; `import` prints its success block before the hook even runs. Automation using exit status therefore treats a pending/failed deployment as complete, unlike the `sign` command's hook error behavior and rollover commands that withhold downstream DS automation.

**Evidence:** `runPostSignHook` records a deployment operation error and returns false on hook failure. `runResign` assigns its result to `_` at line 872 and returns nil. `runImport` does the same at line 1813 after printing success. Other mutation paths capture `hookOK` and avoid registrar progression; the all-zones `sign` path returns its hook error.

**Fix specification:** Establish one documented CLI contract for a committed signing/import followed by failed deployment. `resign` and `import` should return a distinct non-nil error (or an explicitly documented partial-success exit code) after preserving all committed key/config/state/output files and the pending-publication marker; they must not roll back a valid signed generation merely because deployment failed. Print wording that distinguishes “signed/imported” from “confirmed served” and gives the retry path. Preserve hook environment/coalescing, on-disk transaction semantics, daemon retries, and command arguments/output paths.

**Verification:** Run each command with a successful sign/import and a failing hook. Assert files/state remain committed and pending, the deployment error is persisted, the process status is nonzero, and stdout/stderr does not claim unqualified success. Repeat with a successful hook and no configured hook to retain existing successful exits. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-032 — Enabled signer integrations are not fully validated at startup

**Severity:** Low

**Location:** `signer/internal/config/config.go:409-616`, method `Config.Validate`; `signer/internal/registrar/registrar_dynadot.go:62-113`, function `NewDynadotClient`; `signer/heartbeat.go:42-68` and `signer/heartbeat.go:133-202`, heartbeat construction/start

**Problem:** The signer accepts an enabled registrar without credentials and an enabled heartbeat with an empty URL/API key/app or non-positive interval. Those conditions are discovered only when a command constructs the registrar or after the daemon has started heartbeat work. The registrar then fails after the source-of-truth signing operation, and heartbeat monitoring may continuously fail while the daemon logs itself as started. This is inconsistent with the validator module, which rejects incomplete enabled-heartbeat configuration.

**Evidence:** `Config.Validate` checks registrar timeout/digest/zone binding but not enabled adapter credentials. `NewDynadotClient` later rejects an empty key or secret. Signer validation only checks heartbeat scheme when a nonempty URL exists; it does not require URL, key, app, or interval. `HeartbeatClient.Start` announces the configured app/interval and runs even though `Send` can fail to build the empty URL request; its loop silently replaces non-positive/overflowed intervals with five minutes.

**Fix specification:** When an integration is enabled, validate all fields required for it to function before daemon startup or any signing mutation: registrar key/secret and endpoint invariants; heartbeat URL, API key, app, and a checked positive interval. Trim/normalize exactly once and never echo secret values in errors. Keep disabled integrations permissive, preserve defaults where they are explicitly documented, and do not change credential storage, config keys, adapter interfaces, or heartbeat payloads. Endpoint transport/redirect hardening remains covered by RDAYBLUEX-014.

**Verification:** Add config-load matrices for enabled/disabled integrations with each required field missing, whitespace-only secrets, invalid intervals, valid defaults, and valid complete settings. Assert enabled invalid cases fail before daemon listeners/workers or signer mutations start and that errors identify only the field, never its value. Run `go test -race ./...` in `signer`.

### RDAYBLUEX-033 — Boolean existence checks fail open in key rollback and backup naming

**Severity:** Low — **Needs investigation**

**Location:** `signer/internal/signer/keys.go:305-315`, function `uniqueBackupBase`; `signer/internal/signer/keys.go:580-584`, function `FileExists`; `signer/internal/signer/keytx.go:113-128`, function `setAside`; `signer/main.go:483-535`, functions `keyPairAbsent` and `unwindAdd`

**Problem:** `FileExists` maps every `os.Stat` error to “absent.” Callers use that boolean for decisions that are safe only after a confirmed `ENOENT`: selecting a supposedly unused backup name, renaming an unusable private key to that name, and deciding that failed `add` rollback may delete live key filenames. A transient I/O error, permission/ACL anomaly, symlink loop, or other non-`ENOENT` failure can therefore make preservation logic proceed as if data did not exist. On platforms where rename replaces an existing destination, `setAside` can overwrite the file it intended to preserve. The practical exploitability depends on which stat failures can coexist with later successful rename/remove in the deployment filesystems; that is the investigation item, not the fail-open logic itself.

**Evidence:** `FileExists` is exactly `_, err := os.Stat(path); return err == nil`. `uniqueBackupBase` and `setAside` treat false as a free destination, then eventually use atomic writes or `os.Rename` that can replace. `keyPairAbsent` returns true when both calls return false, and `unwindAdd` later removes those live names. In contrast, `RecoverKeyState`, `pairFiles`, and other key-transaction paths use `statExists`, which distinguishes `os.IsNotExist` from other errors and fails closed.

**Fix specification:** Replace boolean existence queries in every preservation/destruction decision with `(exists, error)` semantics: only `ENOENT` means absent; all other errors abort the operation while leaving source and destination untouched. Allocate backup destinations with no-clobber creation/rename semantics where available, or reserve a unique destination atomically before moving data. `add` rollback must remove a key pair only when the transaction records that it created that exact generation, not merely from a preflight absence guess. Preserve exported `FileExists` behavior if tests/external callers require it, but do not use it at safety boundaries. Do not delete or rewrite existing backup/key artifacts during migration.

**Verification:** Inject `EACCES`, `EIO`, symlink-loop, and transient-stat errors separately into source/destination checks, followed by a would-succeed rename/remove seam. Assert no existing key or backup is overwritten/deleted and the operation returns the stat error. Add a destination race/no-clobber test and a failed-add test proving only transaction-created key IDs are removed. Run on Linux, macOS, and FreeBSD under `go test -race ./...` in `signer`.

### RDAYBLUEX-034 — HTTP body limits do not reject responses larger than the advertised maximum

**Severity:** Low

**Location:** `validator/internal/dns/anchors.go:214-252`, function `LoadAnchorsFromURL`; `validator/internal/rdap/client.go:15-17` and `validator/internal/rdap/client.go:71-83`, RDAP response loading; `signer/internal/registrar/registrar_dynadot.go:268-291`, registrar response loading

**Problem:** Each loader reads through `io.LimitReader(limit)` but never reads `limit+1` or otherwise detects truncation. Memory remains bounded, but a response larger than the stated maximum is accepted whenever its first exactly-limited bytes form valid JSON (for example a valid object padded to end exactly at the boundary, followed by ignored bytes). That defeats the intended “oversized endpoint is rejected” contract and can make diagnostics or trust-source provenance claim a malformed upstream response loaded successfully. Anchor authenticity remains protected by binary pins, so the impact is robustness rather than a new root of trust.

**Evidence:** Anchor loading reads exactly `1<<20`, RDAP reads `maxRDAPResponseBytes`, and registrar reads `1<<20`; each immediately unmarshals the returned prefix. None checks whether one more response byte exists. Existing comments describe oversized responses as hostile and the limit as protection, but the implementation is a truncation cap only.

**Fix specification:** Read at most `limit+1`, reject when the byte count exceeds `limit`, and unmarshal only a confirmed complete body. Use a shared bounded-read helper if practical, with field/source-specific error context and no body contents that may contain secrets. Keep the current limits, timeouts, valid response parsing, anchor pin requirement, and registrar uncertain-dispatch classification; a registrar oversize response occurs after dispatch and must remain an uncertain outcome for destructive recovery logic.

**Verification:** For all three clients, serve valid JSON whose closing byte is at the limit followed by one extra byte and assert an explicit oversized-response error. Test exactly-at-limit valid content, limit-minus-one, large non-JSON content, and short-read errors. For a destructive registrar call, assert oversize is still wrapped as dispatched and triggers the existing reconciliation path. Run `go test -race ./...` in both modules.

### RDAYBLUEX-035 — Remote health checks perform unthrottled filesystem mutations

**Severity:** Low

**Location:** `signer/internal/config/config.go:180-186` and `signer/internal/config/config.go:604-613`, remote health configuration; `signer/health.go:51-119` and `signer/health.go:149-186`, health handlers; `signer/health.go:202-226`, function `checkDirWritable`

**Problem:** Every detailed health request creates and deletes temporary files in the output, data, and keys directories; every simple health request does so in output and data. When `health.allow_remote` intentionally exposes the unauthenticated listener, any reachable client can drive sustained write/journal/inode churn on the same filesystems used for state, keys, and signed output. There is no rate limit, result cache, or single-flight check. Even on loopback, aggressive orchestrator probes multiply disk writes and can contend with signing.

**Evidence:** Both handlers call `checkDirWritable` on every request. That function uses `os.CreateTemp` and `os.Remove`; the detailed route calls it three times and the simple route twice. The configuration permits non-loopback binding with `allow_remote = true`, and these health handlers have no request throttling.

**Fix specification:** Retain a real effective-permission write probe, but bound its frequency and concurrency: single-flight the check and cache its result for a short documented interval shorter than operational alert tolerances. Invalidate/recompute on reload or a write failure from real signing/state operations. Consider a hard request rate limit when remote exposure is allowed. Preserve endpoint paths, status/body contracts, ACL-sensitive checking (do not replace it solely with mode-bit inspection), and immediate reporting of known state/signing-loop failures.

**Verification:** Issue hundreds of concurrent health requests with instrumented filesystem calls and assert at most one probe set occurs per cache interval while every caller gets a consistent result. Change permissions after expiry and assert the next probe reports unhealthy. Test reload invalidation, real write-failure invalidation, remote mode, and the current loopback default. Run `go test -race ./...` in `signer`.

## Summary by severity

| ID | Severity | Finding |
|---|---|---|
| RDAYBLUEX-001 | High | First unauthenticated parent response determines DS result |
| RDAYBLUEX-002 | High | Leaf selection promotes unverified denial/DNAME paths |
| RDAYBLUEX-003 | High | Publication and rollover gates accept partial delegation coverage |
| RDAYBLUEX-004 | High | `data_dir` reload moves work outside the lifetime lock |
| RDAYBLUEX-005 | High | Old-generation hook completion mutates new-generation state |
| RDAYBLUEX-006 | High | Hooks can deploy output whose state was not durably published |
| RDAYBLUEX-007 | High | Registrar automation builds the wrong final DS set |
| RDAYBLUEX-008 | High | Old-DS absence ignores colliding/unsupported DS records |
| RDAYBLUEX-013 | High | Configured hook overrides explicit publication modes |
| RDAYBLUEX-014 | High | Registrar credentials can cross cleartext/redirect boundaries |
| RDAYBLUEX-009 | Medium | SSE flush failures are invisible |
| RDAYBLUEX-010 | Medium | One request can create unbounded DNS fan-out |
| RDAYBLUEX-011 | Medium | Packaged validator has no durable offline anchor source |
| RDAYBLUEX-012 | Medium | Malformed environment values silently fall back |
| RDAYBLUEX-015 | Medium | Signature times can wrap and evade self-verification |
| RDAYBLUEX-016 | Medium | Same-size, preserved-mtime changes remain unsigned |
| RDAYBLUEX-017 | Medium | Zone input has no byte/record bound |
| RDAYBLUEX-018 | Medium | Hook processes overlap without a process-wide bound |
| RDAYBLUEX-019 | Medium | State merge can erase same-generation CLI mutations |
| RDAYBLUEX-020 | Medium | RDAP URL/redirects provide blind HTTP egress |
| RDAYBLUEX-021 | Medium | Refresh window can be shorter than polling interval |
| RDAYBLUEX-022 | Medium | IPv6 site-local destinations bypass public-only egress |
| RDAYBLUEX-023 | Medium | Integer duration conversion can overflow and panic |
| RDAYBLUEX-024 | Medium | Parent-DS TTL narrowing can collapse retirement delay |
| RDAYBLUEX-025 | Low | Validation cache crosses daemon generations and retains churn |
| RDAYBLUEX-026 | Low | Cold per-zone validation returns `200 null` |
| RDAYBLUEX-027 | Low | Unknown mode silently selects extended validation |
| RDAYBLUEX-028 | Low | RDAP DS fields narrow/wrap without validation |
| RDAYBLUEX-029 | Low | Managed zone names are not fully DNS-validated |
| RDAYBLUEX-030 | Low | Negative per-zone lifetimes silently inherit defaults |
| RDAYBLUEX-031 | Low | `resign`/`import` succeed after deployment failure |
| RDAYBLUEX-032 | Low | Enabled integrations are validated only when first used |
| RDAYBLUEX-033 | Low | Key existence checks fail open on `Stat` errors |
| RDAYBLUEX-034 | Low | HTTP body caps accept some oversized responses |
| RDAYBLUEX-035 | Low | Health checks cause unthrottled filesystem writes |

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 10 |
| Medium | 14 |
| Low | 11 |
| **Total** | **35** |

## Suggested fix order and dependencies

1. **Make state and publication transitions transactional:** RDAYBLUEX-019 first (explicit revisions/merge semantics), then RDAYBLUEX-013 (mode ownership), RDAYBLUEX-006 (save-before-deploy), RDAYBLUEX-005 (generation-bound completion), and RDAYBLUEX-018 (bounded single-flight dispatch). RDAYBLUEX-025 should reuse the same daemon generation token. These changes touch the same state/hook lifecycle and should land together or behind compatibility tests.
2. **Correct DS lifecycle gates before further registrar automation:** RDAYBLUEX-003 establishes trustworthy all-server observations; then fix RDAYBLUEX-007 and RDAYBLUEX-008 together so phase-correct desired sets and absence semantics agree. Apply RDAYBLUEX-024 before exercising forced completion. RDAYBLUEX-031 can then align CLI partial-success reporting with the corrected publication model.
3. **Repair validator candidate authentication:** implement RDAYBLUEX-001 and RDAYBLUEX-002 as one authentication-aware multi-server selection design. Their candidate classifier should reuse the existing positive/denial/DNAME verification paths rather than introduce a second crypto implementation. Keep RDAYBLUEX-009 in the same integration test pass so transport cancellation cannot hide the corrected result.
4. **Close credential and outbound-network boundaries:** fix RDAYBLUEX-014 first for credential-bearing registrar requests. Fix RDAYBLUEX-022's shared IP classification next, then use that classification at the RDAP dial boundary for RDAYBLUEX-020. RDAYBLUEX-028 and RDAYBLUEX-034 finish validation of data returned by those endpoints. RDAYBLUEX-032 should enforce the resulting endpoint requirements at startup.
5. **Bound attacker/operator-controlled work:** land RDAYBLUEX-017 before RDAYBLUEX-016 so content hashing never reintroduces unbounded reads. Then address RDAYBLUEX-010's DNS graph/query/goroutine budgets, RDAYBLUEX-023's checked duration conversion, and RDAYBLUEX-035's filesystem-probe single-flight/cache. RDAYBLUEX-011 belongs here because anchor size/durability rules should match the bounded loaders.
6. **Make signing time policy internally consistent:** fix RDAYBLUEX-015 first so state records actual verified RRSIG expirations; then RDAYBLUEX-021 can safely schedule refresh from those values. Apply RDAYBLUEX-030 to all key-lifetime bounds at the same config boundary.
7. **Finish fail-closed input and file handling:** RDAYBLUEX-029 before any key/path derivation changes, followed by RDAYBLUEX-033's no-clobber/stat-error work. RDAYBLUEX-012 should be fixed alongside RDAYBLUEX-023 so every typed environment/config input follows the same reject-invalid policy.
8. **Normalize remaining API contracts:** RDAYBLUEX-026 and RDAYBLUEX-027 are independent, low-risk handler changes. Verify them together with RDAYBLUEX-009 because all affect public response/error semantics.
