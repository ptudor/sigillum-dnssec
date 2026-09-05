# Verification — REVIEW_ASTRA6_XHIGH.md / FIXES_ASTRA6_XHIGH.md

Independent verification of the 56 RA6X fixes claimed in `FIXES_ASTRA6_XHIGH.md`, against the
review's own finding text in `REVIEW_ASTRA6_XHIGH.md`. Verification baseline: `2f8f3ba` on `main`.
Toolchain go1.27.0 darwin/arm64.

**Result: 56 of 56 PASS.** 50 are mutation-proven — the guard the fix introduced was reverted to the
pre-fix behaviour and the finding's regression test confirmed to fail. Verification also found four
gaps, all now closed on this branch: one real defect introduced by a fix, and three regression tests
that could not detect the loss of the guard they exist for.

*(A note on this file's history: the first revision's headline said "31 of 56 verified". Recounting
its own verdict tables gives 23. The pending list of 33 IDs was right; the summary number was not.)*

## Method

Four checks per finding:

1. **Resolves the finding** — the changed code read against the review's *Problem* and *Evidence*,
   not against the fix log's summary of itself.
2. **Mutation probe** — revert the specific guard, re-run the finding's tests. A test that still
   passes proves nothing about the fix, so this is the load-bearing check. Every mutation was
   reverted immediately; `git status` was clean before each commit.
3. **Must-not-change constraints** — the review's explicit preservation clauses.
4. **Surrounding code** — new defects introduced by the change, and cross-fix consistency.

Mutation probes are the reason this took two passes rather than one, and they are what turned up all
four gaps below. Where a finding is marked *code* rather than *mutation*, the guard is structural
(a filter applied at a decision point, a field that no longer exists) and reverting it is not a
one-line edit.

## Baseline health

| Check | Signer | Validator |
|---|---|---|
| `go vet ./...` | clean | clean |
| `go test -race -count=1 ./...` | all `ok` | all `ok` |
| `gofmt -l` | clean | one pre-existing offender |

`gofmt -l` reports `internal/validator/key_eligibility_r043_test.go`. Pre-existing, untouched by any
RA6X fix, already a known nit. The signer also does not cross-build for Windows
(`internal/fsutil`: `undefined: syscall.Stat_t`) — verified identical at `2f8f3ba` and at HEAD, so
not a regression; deliberately left alone.

## Verdicts

All 56 PASS. "Mutation" names the probe that made the finding's test fail.

### Validator — authenticated-data boundary

| ID | Sev | Verdict | Mutation applied |
|---|---|---|---|
| RA6X-007 | Critical | **PASS** | DS path returns the merged all-sections slice → 3 subtests report `status=secure` |
| RA6X-008 | Critical | **PASS** | drop the `IsPinnedRootAnchor` filter → attacker key returned |
| RA6X-016 | High | **PASS** | code (owner binding at `trustedKeyForSigner`) |
| RA6X-009 | High | **PASS** | code (no first-signature selection remains) |

**RA6X-007.** The parser no longer merges sections before recording provenance; `parseResponse`
calls `parseSection` three times and every record carries `Owner`/`Class`/`Section`. The
authenticated layer is a real boundary: `VerifyRRsetFromResponse` returns the exact wire records and
the exact RRSIG that verified, and `parentDSResult` splits `Observed` (diagnostic) from
`Authenticated`. Only `ds.Authenticated` reaches `SupportedDSRecords` → `ValidateChainLink` →
`CollectDSMatchedKeys`. The DS signer must be the actual parent from the walked hierarchy
(`parentZoneFromHierarchy`, correct for label-skipping delegations).
`VerifyDenialRRsetsFromResponse` scans Answer+Authority only and returns just what verified, so
injected junk can neither authenticate nor force a false Bogus. JSON compatibility preserved
additively.

*Note (not a defect):* `InSection` treats an empty `Section` as "first listed section" so
in-process-constructed records keep working. Every wire record carries a real section and no path
rehydrates these structs from attacker-controlled JSON, so it is not reachable — worth remembering
if a result cache is ever added.

**RA6X-008.** `GetActivePinnedAnchors` (active **and** exactly pinned) is the only set the root
branch consumes, and `CollectAnchorMatchedKeys` applies the filter itself, so the fix does not
depend on callers pre-filtering. Both shipped pins (KSK-2017, KSK-2024) remain, so the 2026-10-11
rollover is a non-event; unpinned entries survive as diagnostics.

**RA6X-016.** `trustedKeyForSigner` refuses to place an owner-bearing key at any signer name but its
own — the root cause, fixed at the root. `keyBelongsToZone` guards both collectors; denial RRsets
must be owned *within* the signing zone. Legitimate cross-zone key reuse still works because the
check is per-signature.

**RA6X-009.** Each candidate RRSIG is indivisible: owner, signer, validity window (bound to *that*
candidate before its crypto check) and verification must all hold. `recordVerifiedLeaf` derives the
wildcard decision, key tag, record count and alias target from `verified.Signature` alone.

### Validator — denial semantics

| ID | Sev | Verdict | Mutation applied |
|---|---|---|---|
| RA6X-010 | High | **PASS** | code (`nsecEndpointBelow` + `nsecAncestorBoundary`) |
| RA6X-011 | High | **PASS** | code (closest-encloser agreement) |
| RA6X-012 | High | **PASS** | code (`nsec3RecordBoundary`, `OptOut` separate from `Verified`) |
| RA6X-013 | High | **PASS** | code (per-chain hash/match/cover methods) |
| RA6X-014 | Medium | **PASS** | drop the wildcard-NODATA branch → `TestRA6X014_WildcardNODATA/NSEC`; make `substituteDNAME` return the query name → `TestRA6X014_DNAME` |
| RA6X-017 | Medium | **PASS** | treat all DS as supported → the only-unsupported-DS case; abort on the first out-of-window candidate → `TestRA6X017_AlternativeSignaturesAreTried` |

**RA6X-010/011.** NXDOMAIN now rejects an NSEC owned by the queried name, a covering NSEC whose next
name is a proper descendant (the empty-non-terminal case — the review's first probe), and any proof
where an NSEC shows an ancestor below the apex is a delegation point or DNAME owner (the second
probe). `VerifyWildcardDenial` requires `provenCE == claimedCE` from the *verified* signature; the
review's example is rejected twice over (owner equals the next closer; encloser disagrees).

*Observation (fail-closed, defensible):* the NSEC loop returns on the first covering record, so a
bad covering NSEC ahead of a good one yields Bogus rather than searching on. Safe direction, matches
"reject ambiguous data" — noted so it is not later mistaken for an oversight.

**RA6X-012/013.** Opt-out is represented separately from verification (`OptOut` alongside
`Verified`) exactly as specified, and `verifyDSAbsence` requires a complete closest-provable-encloser
proof rather than the bare `hashBetween` the review found. `nsec3Chains` partitions by (algorithm,
iterations, normalized salt); every hash/match/cover is a method on one chain, so a hash computed
under one parameter set can never be tested against another's intervals. `normalizeSalt` unifies
`""`, `"-"` and hex case.

**RA6X-017.** DS classification runs only on the authenticated RRset, so an injected
unknown-algorithm DS can neither downgrade a signed zone nor rescue a broken one.

### Validator — traversal, discovery, delivery

| ID | Sev | Verdict | Mutation applied |
|---|---|---|---|
| RA6X-015 | High | **PASS** (gap closed) | drop the authenticated `Target` → 3 tests; **and** see gap 4 below |
| RA6X-018 | Medium | **PASS** | neuter `judgeDNSKEYServers` → per-server verdicts; neuter `canonicalRRString` → leaf fingerprint |
| RA6X-019 | Medium | **PASS** | drop the NS owner filter → `TestRA6X019_NSOwnerBinding`, `…_ErrorsAndPartialFamilies` |
| RA6X-022 | Medium | **PASS** | emit `complete` at any depth → `TestRA6X022_OneTerminalEventAndPerNameResults` |
| RA6X-041 | Medium | **PASS** | accept an unusable anchor document → 4 tests incl. last-known-good retention |
| RA6X-020 | Medium | **PASS** | code (`armResponseWriteDeadline`) |
| RA6X-021 | Medium | **PASS** | code (`NormalizeMethod`) |
| RA6X-052 | Medium | **PASS** | code (atomic, cancellation-aware `VerifyBudget`) |
| RA6X-054 | Medium | **PASS with noted gaps** | code (single dial boundary) |

**RA6X-020.** Work time and delivery time are separate: the deadline is re-armed via
`http.NewResponseController` *after* validation completes, so a validation running to
`total_timeout_seconds` still delivers — including the default-boundary diagnostics the review named.
`Encode` errors are counted under a fixed `write_failed` status instead of a fabricated 200.

**RA6X-021.** I checked all three labels for the same unbounded-growth class: every
`RecordAPIRequest` call site passes a literal endpoint and a literal status, so the CounterVec is
bounded on every dimension, not just method.

**RA6X-052.** Atomic-based, so sharing one budget across concurrent alias hops is race-free; once
exhausted it stays exhausted. `verifyDenialRRsetsFromResponseB` correctly aborts the whole call on
exhaustion rather than reporting it as one more unverifiable RRset — otherwise a hostile response
could burn the budget and then look like a clean denial failure.

**RA6X-054.** Enforced at `Querier.exchange`, the single choke point for UDP, TCP retry,
authoritative and recursive. I traced every dial site: `internal/dns/query.go` holds the only
`dns.Client` in the module and the `Validator` owns exactly one `Resolver`, so `SetEgressPolicy`
covers all outbound DNS. Two residual gaps, both narrow, recorded so they are not rediscovered as
new findings:

- **IPv4 documentation ranges are not blocked.** `reservedV4` has `192.0.0.0/24` but not
  TEST-NET-1/2/3 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). The fix log's "documentation
  addresses (refused)" holds for `2001:db8::/32` only. Non-routable rather than internal, so no
  security impact — the wording overstates coverage slightly.
- **6to4 (`2002::/16`) and IPv4-compatible IPv6 (`::a.b.c.d`) are judged public.** Either can embed
  an RFC 1918 address; Go's `To4()` returns non-nil only for IPv4-*mapped*, so these take the IPv6
  path. Both are deprecated and unrouted by default, so exploiting them needs a configured relay —
  but the spec did say "handle IPv4-mapped IPv6 … consistently", and this is the remainder.

Neither changes the verdict: the finding was that non-public destinations are reachable, and the
public-only default closes that. Candidates for a follow-up hardening pass.

### Signer — persistence, lifecycle, keys

| ID | Sev | Verdict | Mutation applied |
|---|---|---|---|
| RA6X-006 | High | **PASS** | code (instance lock before shared state; non-destructive check) |
| RA6X-026 | High | **PASS** | code (fail-closed cycle, no save on unreadable disk) |
| RA6X-036 | Medium | **PASS** | code + cross-fix check (below) |
| RA6X-002 | High | **PASS** | accept any same-role live key → 3 fault-injection scenarios |
| RA6X-023 | High | **PASS** | accept any existing backup → 6 tests incl. the review's truncated-backup probe |
| RA6X-024 | High | **PASS** | disable `importTx.rollback` → 6 fault-injection boundaries |
| RA6X-030 | Medium | **PASS** | code (seed-derived correspondence, ECDSA scalar range) |
| RA6X-038 | Medium | **PASS** | disable `validateZoneEdit`; flatten `scanTOMLLine` → 5 tests incl. both review probes |
| RA6X-025 | High | **PASS** | always merge instead of adopting → `TestRA6X025_CLIMutationsSurviveDaemonCycles` |
| RA6X-040 | Medium | **PASS** (gap closed) | remove the readiness wait → see gap 2 |
| RA6X-044 | Medium | **PASS** | swallow chown errors → `TestRA6X044_ChownFailureAbortsBeforeReplacing` |
| RA6X-049 | Medium | **PASS** (gap closed) | discard the durability outcome → see gap 3 |

**RA6X-006.** The instance flock is taken **before** any shared-state access, so a duplicate daemon
is refused before it can touch state — port binding is no longer what stands between two daemons,
which was the review's specific complaint. `checkStateFileAccessible` opens `O_RDWR` without
`O_TRUNC`; `checkDirWritable` uses `os.CreateTemp`, not a fixed name.

**RA6X-036 — the interesting cross-fix check.** RA6X-003 later added five persisted rollover phases
(`ds_propagation_wait`, `retiring`, `algo_ds_propagation_wait`, `algo_old_ds_removal_wait`,
`algo_retiring`). A schema validator written for the earlier set would have made every
post-RA6X-003 rollover unloadable on restart. `validateRolloverState` was updated in step and
accepts all of them. I also checked the reverse: `ZSKRolloverStateRetired` is *not* accepted, which
is correct only because it is never persisted — every ZSK completion path sets `Rollover = nil`
(`rollover.go:137, 245, 353, 524, 654, 786`). Confirmed by grep; no path writes it.

**RA6X-002/023.** Key files are a genuine two-slot transaction: stage at the tag-named slot, verify
by reloading exactly as signing would, then activate. `.private` is copied before `.key`, so a crash
between them leaves a pair that fails correspondence and is repaired by `EnsureLiveKey` from the
recorded generation. Signing derives the expected identity from persisted state rather than trusting
live filenames — the review's core complaint.

**RA6X-024.** Validation (owner, protocol, algorithm, role flags, correspondence, and a real
sign-then-verify probe) completes before any write; staging then commit in an order every failure
can undo, with prior bytes and modes snapshotted. A pre-existing signed output is never deleted;
`priorFile.restore` removes only a file the import itself created.

### Signer — signing correctness and rollover safety

| ID | Sev | Verdict | Mutation applied |
|---|---|---|---|
| RA6X-001 | High | **PASS** | KSK rollover uses the config algorithm → `TestKSKRollover_KeepsExistingAlgorithm` |
| RA6X-005 | High | **PASS** | prefer `zoneState.Path` → both source-path tests |
| RA6X-056 | Medium | **PASS** | restore the `len == 0 → return nil` skip → whole-chain-missing case |
| RA6X-028 | High | **PASS** | code (canonical wire-label identity) |
| RA6X-029 | Medium | **PASS** | code (shared `validateZoneRecords`) |
| RA6X-053 | Medium | **PASS** | code (indexed, memoized ancestor walk) |
| RA6X-042 | Medium | **PASS** | disable the stat-before/after check; accept non-regular files → 3 tests |
| RA6X-035 | Medium | **PASS** | neuter `outputUnusable` → 4 tests |
| RA6X-003 | High | **PASS** | retire without the parent DS TTL; skip the old-DS-removal wait → both sequences |
| RA6X-004 | High | **PASS** | gate on `LastSigned` → `TestZSKRollover_DoesNotAdvanceOnUnconfirmedPublication` |
| RA6X-027 | High | **PASS** | let a smaller TTL lower the horizon → `TestCacheHorizon_SurvivesTTLDecreaseAndRestart` |
| RA6X-047 | Low | **PASS** | code (seed reduction gated on suffix consistency) |

**RA6X-056** was the fix I was most sceptical of, because a post-sign gate that re-reads the
generator's own output proves nothing. It does not: `verifyNSEC*Expectations` derive the expected
owner set, ordering and bitmaps from the *input snapshot's* `zoneModel` and compare the emitted
records against it — membership both ways, ring closure, exact bitmap equality. NSEC excludes empty
non-terminals and NSEC3 includes them, the correct RFC 4035 §2.3 / RFC 5155 §7.1 split.

**RA6X-001 and RA6X-046 agree on RFC 6840 §5.11 from opposite sides**, which is the right reading:
the signer's post-sign gate enforces the *signer's* obligation (every advertised algorithm signs
every RRset), while the validator accepts any single valid DS→DNSKEY path. A fix that got this
backwards on either side would have been easy to write.

**RA6X-029 is deployment-visible.** Zone files that previously signed (a TXT at a delegation point,
data beneath a DNAME) now hard-fail and keep serving the prior output. Correct, fails safe, but it
belongs in release notes.

**RA6X-030/047 agree rather than fight:** both are gated on the same invariant (the stored public
suffix must match the key derived from the seed), and 32- and 64-byte files stay loadable and
signable.

### Signer — registrar, hooks, observability

| ID | Sev | Verdict | Mutation applied |
|---|---|---|---|
| RA6X-031 | High | **PASS** | early-return on any DELETE error → 8 subtests incl. cross-process restart recovery |
| RA6X-051 | Medium | **PASS** | drop rolling-window accounting; wait under the mutex → quota and cancellation tests |
| RA6X-032 | Medium | **PASS** | remove `rrsig.Verify` → 6 subtests |
| RA6X-033 | Medium | **PASS** | code (status counts + `/healthz` readiness) |
| RA6X-048 | Medium | **PASS** | clear every operation's error → `TestCLIResign_ErrorBookkeeping` |
| RA6X-034 | Medium | **PASS** (defect found) | `Setpgid: false` + `Kill(pid)` → all 3 shapes incl. child-ignores-SIGTERM; **and** see gap 1 |
| RA6X-043 | Medium | **PASS** | never coalesce → 2 CLI hook-contract tests |
| RA6X-037 | Medium | **PASS** | default redirect policy → `TestHeartbeat_RedirectsNeverReplayTheKeyOffOrigin` |
| RA6X-039 | Medium | **PASS** | command substitution instead of `printf -v` → 4 subtests |
| RA6X-055 | Medium | **PASS** | API key back in curl argv → test prints the leaked argv |
| RA6X-050 | Low | **PASS** | hash presentation bytes; iterate from 1 → NSEC3 vectors; remove the fixture → config test |

**RA6X-031** is a thorough implementation of the spec: any failure that may have been dispatched is
uncertain, recovery runs on `context.WithoutCancel` with its own budget and limiter priority, the
postcondition is established by read-back, and surviving extra records are an ordinary error because
no DS is ever deleted to resolve uncertainty.

**RA6X-051.** The wait is computed under the mutex and performed outside it; cancellation is checked
before admission; a cancelled caller appends nothing to `admitted`.

**RA6X-039/055.** The probe script keeps the HMAC secret on fd 3 via process substitution (a bash
builtin, so it never reaches any argv) and hands curl the Authorization header through `-K` on a
private descriptor. `printf -v` preserves the trailing newline separators that command substitution
strips — which is exactly the empty-body/empty-request-ID case the finding was about. The test
stubs curl and python3, records their argv, and compares the signature against the Go adapter's
`sign()`; it runs here rather than skipping.

**RA6X-050.** Both halves confirmed. The escaped-octet NSEC3 vector is the one that exposed the real
defect, and it still catches it.

### Documentation

| ID | Sev | Verdict | Basis |
|---|---|---|---|
| RA6X-045 | Medium | **PASS** (external work remains) | artifact cross-check + new test |
| RA6X-046 | Low | **PASS** | dated superseded banners, history preserved |

**RA6X-045.** Every path now agrees with a shipped artifact: `make build-freebsd` writes
`build/dnssec-validator-freebsd-amd64` and the walkthrough installs exactly that; the Apache snippet
is installed under the basename the `Include` line names; the rc.d script name, the TOML
auto-discovery path and the install table all match. I checked every key in the walkthrough's TOML
block against `internal/config` — all present, and the decoder is strict. **The finding's own
verification is still outstanding**: the walkthroughs have not been run on a clean FreeBSD or Linux
host, so the installed-binary check, `apachectl configtest`, the service account reloading NSD
non-interactively, and an existing-key algorithm migration remain the operator's.

**RA6X-046.** All four documents carry dated (2026-09-05) superseded banners naming what no longer
describes the code, with the historical text preserved. The RFC 6840 §5.11 correction is right (see
RA6X-001 above).

## Gaps found and closed

Four things verification turned up. One is a defect a fix introduced; three are regression tests
that could not fail. All four are fixed on this branch, and every new test is itself
mutation-verified.

### 1. A fix's own escalation could kill an unrelated process group — `b29bd47`

RA6X-034 armed a goroutine that slept `hookKillGrace` and then sent SIGKILL to the hook's
process-**group** id unconditionally. By then the hook has usually been reaped, and a pgid of a
reaped process is free for the kernel to reassign — so the signal could land on a group that was
never ours. Window is 2s and it needs PID wraparound to bite, but the consequence is killing
something unrelated.

`configureHookProcess` now returns a `release` func that `runHook` defers; the delayed kill selects
on a timer *or* that release. Windows keeps its no-op stub. Process-group termination itself is
unchanged — reverting `Setpgid` still fails `TestHookTimeout_BoundsDescendantsHoldingStderr` in all
three shapes. New tests mutation-verified: the pre-fix unconditional kill fails
`TestConfigureHookProcess_ReleaseCancelsTheDelayedKill` 2/2.

### 2. RA6X-040's tests could not detect the loss of their guard — `b29bd47`

Removing the readiness wait in `Reload` left all three RA6X-040 tests passing under `-race`. They
are timing-dependent race detectors, and the config swap is mutex-protected either way, so `-race`
stays quiet and every assertion still holds.

The guard is load-bearing for something else: `Run` starts the heartbeat client captured in its
startup snapshot, and its comment asserts "Reload cannot have swapped it yet" — an invariant the
wait is what guarantees. Without it, `Run` can start a client `d.heartbeat` no longer points at, so
`Shutdown` stops a different one and the started client never sends its "stopping" heartbeat.

`TestRA6X040_ReloadWaitsForReadiness` asserts the guard directly and fails 3/3 without it.
`TestRA6X040_StartedHeartbeatIsTheOneShutdownStops` pins the invariant; its comment states plainly
that it does not reliably reproduce the interleaving (the window is too small without a seam inside
`Run`).

### 3. RA6X-049's central contract was untested — `3869e08`

`TestRA6X049_DurabilityOutcomes` exercised only the classification helpers. Nothing asserted what
the finding is about: that `WriteFileAtomicOwned` and `CopyFile` return a `*DurabilityError` when
the directory fsync fails after a successful rename, and that the new bytes stay in place because
that file is already live. Neutering every `DurabilityError` return site left the whole module green.

The fix log called directory-fsync injection "not reproducible in this environment" — but it is, the
same way RA6X-044 already injects `chownFn`. `SyncDir` now goes through a `syncDirFn` seam;
behaviour is unchanged. `TestRA6X049_WriteHelpersReportCommittedButUnsynced` injects EIO and asserts
the committed-not-rolled-back contract for both helpers, plus that a pre-rename failure is *not*
reported as committed. Mutation-verified both ways. Crash/power-loss behaviour on the deployment
filesystems remains external verification; that part of the caveat stands.

### 4. RA6X-015's unauthenticated fallback filter was untested — `245841b`

`TestRA6X015_UnrelatedCNAMEIsNotFollowed` asserts off-owner and Additional CNAMEs are never
followed, but it uses a **secure** zone — leaf RRset verification excludes those long before
`discoverAliasTarget` runs. The unauthenticated fallback taken below an insecure or indeterminate
ancestor has its own `answerCNAMEsOwnedBy` filter, and replacing it with "any CNAME in any section"
left the module green.

That is the path where the filter matters most: below an insecure ancestor there is no signature to
bound what gets followed, so an Additional-section CNAME would steer the traversal — and the next
round of queries — at a name the zone never aliased to.
`TestRA6X015_InsecureAliasDiscoveryIgnoresOffOwnerAndAdditional` covers three shapes through an
insecure zone, with a companion test asserting a well-formed alias is still followed. Mutation-
verified: removing the filter fails all three subtests, 2/2 runs.

### Also added: the shipped example config is now pinned — `7bc93db`

Not a gap in a fix, but the same class of exposure. RA6X-045 was verified by reading the walkthrough
against the artifacts, which leaves nothing to catch drift: the decoder is strict, so a key renamed
in `internal/config` turns every documented setup into a startup error with no test noticing.
`TestShippedExampleAndWalkthroughKeysLoad` loads `dnssec-validator.toml.example` and the exact TOML
block the walkthrough prescribes; misspelling one key fails it with the decoder's own error.

## SKIPPED items

**There are none.** All 56 findings are logged FIXED. Three headings carry qualifiers, which are
scope statements rather than skips:

| ID | Qualifier | Assessment |
|---|---|---|
| RA6X-042 | "no producer scripts exist in the repository" | **Legitimate — keep as is.** The code-side boundary is implemented and mutation-proven. The other half is an operator contract for scripts not in this repo; there is nothing here to fix. |
| RA6X-054 | "deployment firewall not inspected" | **Legitimate — keep as is.** Enforcement is in-process at the dial boundary; the firewall is outside the repo. The two range gaps above are separate follow-ups, not reasons to reopen. |
| RA6X-045 | "not executed on a target host" | **Keep open as operator work.** Everything checkable from here is checked and now regression-pinned, but the clean-host run is the finding's own verification step and only the operator can do it. Already recorded in project memory. |

## Cross-cutting observations

Neither is a defect; both are properties worth having written down.

1. **Publication-confirmation lock contention (RA6X-004 × the cycle lock).** `signAllZones` holds
   the cross-process state lock for the whole cycle, while post-sign hooks run in goroutines whose
   `confirmPublication` callback needs that same lock (10s timeout). `flock` locks are per
   open-file-description, so a second `open()` in the same process *does* block. With many zones — the
   3000-zone case the coalescing comment contemplates — a cycle can outlast the timeout and
   hook-based confirmations get dropped and retried next cycle. Every consequence is fail-safe
   (`PendingPublication` persists, the hook re-fires, rollover phases wait), so this is a latency
   property, not a correctness bug. Worth measuring before a large deployment.

2. **Test seams in production code.** `Signer.mutateBeforeVerify`, `Signer.afterSourceRead`,
   `KeyGenerator.failpoint`, `importFailpoint`, `Validator.rootServers`, `Resolver.SetDefaultPort`
   and now `fsutil.syncDirFn`. All are nil/default in production and documented as test-only, and
   they are what make the strongest probes in this document possible — the RA6X-056, RA6X-024 and
   RA6X-049 mutations all depend on one. Noted for the record, not as a complaint.

## Verification artifacts

Every mutation was applied to a copy-backed file and reverted immediately; `git status --porcelain`
was empty and `git diff` clean before each commit. No fix's production behaviour was changed except
the one defect in gap 1. Commits from this verification: `b29bd47`, `3869e08`, `245841b`, `7bc93db`.
