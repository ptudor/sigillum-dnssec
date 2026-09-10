# Deep code review — Daybreak Blue XHigh

Review date: 2026-09-09  
Scope: the complete repository at commit `3a43241`, including both Go modules, packaging, service definitions, workflows, scripts, browser assets, documentation, and tests.  
Method: static data-flow and lifecycle tracing, cross-module consistency checks, `go vet ./...` in both modules, and `go test -race ./...` in both modules. The race suites and vet checks passed. Vulnerability scanning could not produce a result because the installed scanner was built with an older Go source-processing stack than the Go 1.27 toolchain used by this repository; that tooling failure is not evidence that the dependency graph is vulnerability-free.

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

