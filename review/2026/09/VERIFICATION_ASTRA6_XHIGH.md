# Verification — REVIEW_ASTRA6_XHIGH.md / FIXES_ASTRA6_XHIGH.md

Independent verification of the 56 RA6X fixes claimed in `FIXES_ASTRA6_XHIGH.md`, against the
review's own finding text in `REVIEW_ASTRA6_XHIGH.md`. Verification baseline: `2f8f3ba` on `main`
(working tree clean). Toolchain go1.27.0 darwin/arm64.

**Session status: IN PROGRESS — partial.** 31 of 56 findings have a verdict below; the remaining 25
are listed in §"Not yet verified" and carry no verdict. Nothing in this file is a pass by
assumption: a finding gets a verdict only after the changed code was read against the review's fix
specification, and, where noted, after a mutation probe proved the accompanying regression test can
actually fail.

## Method

Four checks per finding, in this order:

1. **Resolves the finding** — the changed code is read against the review's *Problem* and *Evidence*,
   not against the fix log's own summary.
2. **Mutation probe** (where marked) — the specific guard the fix introduced is reverted to the
   pre-fix behaviour and the finding's regression test is re-run. A test that still passes proves
   nothing, so this is the strongest evidence available without a live deployment. Every mutation was
   reverted immediately; `git status` is clean and `git diff` empty at the time of writing.
3. **Must-not-change constraints** — the review's explicit preservation clauses (JSON compatibility,
   CLI syntax, state readability, existing statuses, supported deployments).
4. **Surrounding code** — new defects introduced by the change, and cross-fix consistency (a later
   fix invalidating an earlier one).

## Baseline health

| Check | Signer (`Golang-tudor-dnssec-signer`) | Validator (`Golang-dnssec-validator`) |
|---|---|---|
| `go vet ./...` | clean | clean |
| `go test -race -count=1 ./...` | all packages `ok` | all packages `ok` |
| `gofmt -l` | clean | one pre-existing offender (below) |

`gofmt -l` reports `Golang-dnssec-validator/internal/validator/key_eligibility_r043_test.go`. This is
pre-existing (it predates the Astra 6 work and no RA6X fix touched it) and is already recorded as a
known nit. Not a regression; left alone deliberately.

## Verdicts

### Validator — authenticated-data boundary

| ID | Sev | Verdict | Basis |
|---|---|---|---|
| RA6X-007 | Critical | **PASS** | Mutation-proven |
| RA6X-008 | Critical | **PASS** | Mutation-proven |
| RA6X-016 | High | **PASS** | Code |
| RA6X-009 | High | **PASS** | Code |

**RA6X-007 — Unsigned Additional DS records can authenticate an attacker-controlled child.**
The parser no longer merges sections before recording provenance: `internal/dns/records.go` converts
each section separately and stamps `Owner`/`Class`/`Section` on every record type, and
`parseResponse` calls `parseSection` three times rather than concatenating. The authenticated-data
layer (`internal/validator/authenticated.go`) is a genuine boundary, not a filter bolted onto the
display slice: `VerifyRRsetFromResponse` returns a `VerifiedRRset` holding *the exact wire records and
the exact RRSIG that verified*, and `parentDSResult` splits `Observed` (diagnostic, Answer-section,
child-owned) from `Authenticated` (the verified RRset). Only `ds.Authenticated` reaches
`SupportedDSRecords` → `ValidateChainLink` → `CollectDSMatchedKeys`
(`internal/validator/validator.go:1420-1460`), and `verifyDSRRSIGSetB` requires the signer to be the
actual parent from the walked hierarchy (`parentZoneFromHierarchy`, which handles label-skipping
delegations correctly). `VerifyDenialRRsetsFromResponse` scans Answer+Authority only — Additional is
never a candidate — and returns only RRsets that verified, reporting the rest in `rejected` so
injected junk can neither authenticate nor poison a genuine proof.

*Mutation probe:* replacing `dsRecordsFromVerified(verified)` in `verifyDSRRSIGSetB` with the merged
all-sections DS slice (the pre-fix behaviour) makes
`TestRA6X007_InjectedDSCannotAuthenticateAttackerChild` fail in all three placements
(`additional, same owner` / `additional, unrelated owner` / `authority, same owner`), each reporting
`status=secure`. The test therefore reproduces the review's probe through the real `validateZone`
path, not a helper-level shim.

*Constraints:* JSON compatibility is preserved additively — `Owner`/`Class`/`Section` are
`omitempty` fields, and `ZoneResult.DS` still carries the served RRset for display.

*Note (not a defect):* `dnspkg.InSection` treats an empty `Section` as "in the first listed section",
so in-process-constructed records keep working. Every record that comes off the wire carries a real
section, and no path deserializes attacker-controlled JSON back into these structs, so the escape
hatch is not reachable by an attacker. Worth keeping in mind if a result cache is ever rehydrated
from JSON.

**RA6X-008 — A mixed anchor document bypasses the root-anchor pinning boundary.**
`dns.GetActivePinnedAnchors` (active **and** exactly pinned) is the only anchor set the root branch of
`validateZone` consumes, for both the existential check and the DNSKEY-signing key set. Critically,
the filter is *also* applied at the final trust decision: `CollectAnchorMatchedKeys` itself skips any
anchor failing `IsPinnedRootAnchor`, so the fix does not depend on callers remembering to pre-filter.
`IsPinnedRootAnchor` matches key tag, algorithm, digest type and digest (hex, case-insensitive)
against two pinned constants.

*Mutation probe:* deleting the `if !dnspkg.IsPinnedRootAnchor(anchor) { continue }` guard from
`CollectAnchorMatchedKeys` makes `TestRA6X008_MixedAnchorsAuthenticateOnlyPinnedKey` fail, returning
the attacker's tag-44321 ECDSA key alongside the genuine KSK-2017.

*Constraints:* "Preserve acceptance of either currently shipped genuine root pin and supported
rollover overlap" — both KSK-2017 (20326) and KSK-2024 (38696) remain pinned, so either alone
satisfies the gate and the 2026-10-11 rollover is a non-event. Unpinned entries survive as
diagnostics via `GetActiveAnchors` / `/api/anchors`, as the spec required.

**RA6X-016 — Trusted key material loses its zone identity.**
`trustedKeyForSigner` refuses to place an owner-bearing key at any signer name but its own, so
verification can no longer rewrite a key's owner to make a signature fit — this is the root cause,
fixed at the root. `keyBelongsToZone` is applied in both `CollectDSMatchedKeys` and
`CollectAnchorMatchedKeys` (the latter requiring `.`), and `VerifyDenialRRsetsFromResponse` requires
every accepted denial RRset to be owned *within* the signing zone (`dns.IsSubDomain`) as well as
signed by it. Legitimate key reuse across two zones still works because the check is per-signature,
not per-material.

**RA6X-009 — Wildcard checks use metadata from a signature that never verified.**
`verifyRRsetInRecords` evaluates each candidate RRSIG as an indivisible unit: owner, signer, validity
window (`rrsigWireTimeValid`, bound to *that* candidate before its crypto check) and cryptographic
verification must all hold for one signature before it is returned. `recordVerifiedLeaf`
(`validator.go:859`) then derives `SigningKeyTag`, `RecordCount`, the alias `Target` and the wildcard
decision from `verified.Signature` alone. The forged-first-RRSIG path the review exploited no longer
exists: there is no "first covering RRSIG" selection left in the leaf path.

### Validator — denial semantics

| ID | Sev | Verdict | Basis |
|---|---|---|---|
| RA6X-010 | High | **PASS** | Code |
| RA6X-011 | High | **PASS** | Code |
| RA6X-012 | High | **PASS** | Code |
| RA6X-013 | High | **PASS** | Code |

**RA6X-010.** `verifyNSECNXDOMAIN` now rejects (a) an NSEC owned by the queried name, (b) a covering
NSEC whose next name is a proper descendant of the queried name — the empty-non-terminal case the
review's first probe used (`nsecEndpointBelow`, RFC 7129 §5.5), and (c) any proof where an NSEC shows
a strict ancestor below the apex is a delegation point (NS set, SOA clear) or DNAME owner
(`nsecAncestorBoundary`) — the review's second probe. The same ancestor rule guards
`verifyNSECNODATA`. `qnameWithinZone` in the `WithRRSIG` wrapper additionally refuses to let one
zone's records deny a name outside it.

**RA6X-011.** The NSEC branch of `VerifyWildcardDenial` derives the closest encloser from the covering
NSEC and requires `provenCE == claimedCE` where `claimedCE = lastNLabels(qname, Labels)` comes from
the *verified* signature (RA6X-009). The review's example (`foo.bar.example.com.`, Labels=2, NSEC
`bar.example.com. → z.bar.example.com.`) is rejected twice over: the NSEC owner equals the next closer
name, and the derived encloser disagrees with the claimed one. Labels values that do not describe an
expansion are rejected up front.

*Observation (fail-closed, defensible):* the NSEC loop returns on the **first** covering record, so a
response carrying a bad covering NSEC ahead of a good one yields Bogus rather than searching on. That
is the safe direction and matches the "reject ambiguous data" instruction; noted only so it is not
mistaken for an oversight later.

**RA6X-012.** `nsec3Chain.closestEncloser` performs the RFC 5155 §8.3 proof and retains the exact
closest-encloser and next-closer *records*; `nsec3RecordBoundary` rejects a matched encloser that is a
delegation point or DNAME owner. Unknown flag bits are ignored and reported (`nsec3UnknownFlags`,
`Ignored`), so flags 2/3 no longer participate. Opt-out is represented **separately from
verification** — `NSECProof.OptOut` alongside `Verified` — exactly as the spec demanded, and
`verifyDSAbsence` requires a complete closest-provable-encloser proof (matched encloser + opt-out
cover of the next closer) rather than the bare `hashBetween` the review found.

**RA6X-013.** `nsec3Chains` partitions authenticated records by (algorithm, iterations, normalized
salt) via `groupNSEC3ByParams`, `newNSEC3Chain` refuses a mixed group outright, and every
hash/match/cover is a method on one chain — so a hash computed under one parameter set can never be
tested against another chain's intervals. `VerifyWildcardDenial` and `verifyDSAbsence` iterate chains
independently instead of taking `records[0]`'s parameters. `normalizeSalt` unifies `""`, `"-"` and hex
case, as the spec required.

### Validator — service boundaries

| ID | Sev | Verdict | Basis |
|---|---|---|---|
| RA6X-020 | Medium | **PASS** | Code |
| RA6X-021 | Medium | **PASS** | Code |
| RA6X-052 | Medium | **PASS** | Code |
| RA6X-054 | Medium | **PASS with noted gaps** | Code |

**RA6X-020.** Work time and delivery time are now separate: `armResponseWriteDeadline` re-arms the
socket write deadline (`responseWriteBudget` = 10 s) via `http.NewResponseController` *after*
validation completes and before encoding, so a validation legitimately running to
`total_timeout_seconds` still delivers — including the default-boundary timeout diagnostics the review
called out. `Encode` errors are now handled: logged and counted under a fixed `write_failed` status
instead of a fabricated 200. `nonSSEWriteTimeout` became a variable purely as a test seam; slow-client
protection is unchanged.

**RA6X-021.** `RecordAPIRequest` funnels the method through `NormalizeMethod`, mapping the seven
standard methods to themselves and everything else to `OTHER`. I checked the other two labels for the
same class of unbounded growth: every `RecordAPIRequest` call site passes a string-literal endpoint
(`/validate`, `/api/validate`, `/api/anchors`) and a literal status, so the CounterVec is bounded on
all three dimensions. Metric names and label keys unchanged, as required.

**RA6X-052.** `VerifyBudget` is atomic-based (`atomic.Int64` / `atomic.Bool`), so sharing one budget
across concurrent alias hops is race-free, and it is context-aware: cancellation trips the same
sentinel. Once exhausted it *stays* exhausted, so a validation cannot resume verifying down another
code path. Exhaustion maps to Indeterminate with a resource-limit reason at every consumer, never to
Secure and never to a fabricated crypto failure — `verifyDenialRRsetsFromResponseB` correctly aborts
the whole call on exhaustion rather than reporting it as one more unverifiable RRset, which would have
let a hostile response burn the budget and then look like a clean denial failure. Candidate
signatures are de-duplicated by content and keys by material before any cryptography.

**RA6X-054.** The policy is enforced at `Querier.exchange` — the single choke point every query
passes, UDP and its TCP retry, authoritative and recursive (`exchangeRecursive` uses the same
transport). I traced every dial site: `internal/dns/query.go` holds the only `dns.Client` in the
module, and the `Validator` owns exactly one `Resolver`, so `SetEgressPolicy` covers all outbound DNS.
Both JSON and SSE handlers install it from config. The configured recursive resolver is always
trusted and `private_destination_allowlist` / `allow_private_destinations` preserve internal
deployments, as the spec required. IPv4-mapped IPv6 is judged as IPv4 (Go's `To4()`), and NAT64's
well-known prefix is refused.

Two residual gaps, both narrow, neither reachable without an unusual host configuration — recorded so
they are not rediscovered as new findings:

- **IPv4 documentation ranges are not blocked.** `reservedV4` contains `192.0.0.0/24` (IETF protocol
  assignments) but not TEST-NET-1/2/3 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). The fix
  log's verification line claims "documentation addresses (refused)", which holds for `2001:db8::/32`
  only. These are non-routable rather than internal, so the security impact is nil; the fix log's
  wording overstates coverage slightly.
- **6to4 (`2002::/16`) and IPv4-compatible IPv6 (`::a.b.c.d`) are not blocked.** Either can embed an
  RFC 1918 IPv4 address. Go's `To4()` returns non-nil only for IPv4-*mapped* addresses, so these fall
  through the IPv6 path and are judged public. Both mechanisms are deprecated and unrouted on a
  default modern host, so exploiting them needs a deliberately configured relay — but the review's
  spec did say "handle IPv4-mapped IPv6 … consistently", and this is the remaining inconsistency.

Neither gap changes the verdict: the finding was "non-public destinations are reachable", and the
public-only default closes that. They are candidates for a follow-up hardening pass.

### Signer — persistence and lifecycle

| ID | Sev | Verdict | Basis |
|---|---|---|---|
| RA6X-006 | High | **PASS** | Code |
| RA6X-026 | High | **PASS** | Code |
| RA6X-036 | Medium | **PASS** | Code + cross-fix check |

**RA6X-006.** `runServe` now takes an flock instance lock on `<data_dir>/serve.lock` **before** any
shared-state access, so a duplicate daemon is refused before it can touch state — port binding is no
longer what stands between two daemons, which was the review's specific complaint. The startup
snapshot is loaded through `loadStateLocked` under the cross-process state lock. `validateStartup` no
longer calls `state.Save()`: `checkStateFileAccessible` opens an existing file `O_RDWR` *without*
`O_TRUNC` and closes it, and a missing file is fine because `data_dir` writability was already probed
non-destructively by `checkDirWritable` (which uses `os.CreateTemp`, not a fixed name). A stale
startup snapshot can no longer be written at all.

**RA6X-026.** `signAllZones` fails closed: if the authoritative state cannot be loaded under the lock,
it signs nothing, mutates nothing, records `StateFault` and returns. The pre-save reload has the same
rule — on failure it skips `Save()` entirely rather than overwriting an unreadable or newer file with
the stale snapshot, and already-written signed output is left in place. `/healthz` reports 503 while
the fault stands.

**RA6X-036.** `validateAndNormalize` runs on both `LoadState` and `ReloadFromDisk`, normalizes
`{"zones":null}` to an empty map, and `validateRolloverState` accepts only phases the signer has a
defined interpretation for, cross-checking the record's key identities against the zone's live keys.

*Cross-fix check (the interesting one):* RA6X-003 later added five new persisted rollover phases
(`ds_propagation_wait`, `retiring`, `algo_ds_propagation_wait`, `algo_old_ds_removal_wait`,
`algo_retiring`). A schema validator written for the earlier phase set would have made every
post-RA6X-003 rollover unloadable on restart. `validateRolloverState` was updated in step and accepts
all of them. I also checked the reverse direction: `ZSKRolloverStateRetired` is *not* in the accepted
set, which is correct only because it is never persisted — every ZSK completion path sets
`Rollover = nil` (`rollover.go:137, 245, 353, 524, 654, 786`). Confirmed by grep; no path writes
`retired` to disk.

*Constraint:* old state without the new fields still loads — every added field is `omitempty` with a
conservative zero default, and old in-progress `ds_add_wait` records remain valid.

### Signer — zone model, signing correctness

| ID | Sev | Verdict | Basis |
|---|---|---|---|
| RA6X-001 | High | **PASS** | Mutation-proven |
| RA6X-005 | High | **PASS** | Mutation-proven |
| RA6X-056 | Medium | **PASS** | Mutation-proven |
| RA6X-028 | High | **PASS** | Code |
| RA6X-029 | Medium | **PASS** | Code |
| RA6X-053 | Medium | **PASS** | Code |
| RA6X-030 | Medium | **PASS** | Code |
| RA6X-047 | Low | **PASS** | Code |

**RA6X-001.** `StartKSKRollover` stages with `oldKSK.Algorithm`, not the configuration default, so only
`rollover algorithm` can introduce a second algorithm. `signingKeys.validateAlgorithms` fails closed on
a mixed live set outside an algorithm rollover, and the post-sign gate enforces RFC 6840 §5.11
completeness per advertised algorithm and role.

*Mutation probe:* reverting to `keyGen.StageKSK(domain, rm.cfg.DNSSEC.Algorithm)` makes
`TestKSKRollover_KeepsExistingAlgorithm` fail with `new KSK algorithm 15, want ECDSAP256SHA256` — the
review's exact scenario.

**RA6X-005.** `Signer.SourcePath` is the single reconciliation point (config path wins; state path
only for a zone the config does not list) and every entry point — `SignZone`, `SignAll`, `resign`, the
daemon cycle, import staging — reads through it. The state's `Path` is replaced only in
`recordSignedZone`, i.e. after parse + sign + self-verify + publish, so a bad new path keeps the prior
source reference *and* the prior signed output.

*Mutation probe:* preferring `zoneState.Path` (pre-fix order) fails both
`TestSourcePathChange_PublishesNewSourceOnEveryEntryPoint` and
`TestSourcePathChange_MissingOrInvalidNewSourceKeepsOldOutput`.

**RA6X-056.** This is the fix I was most sceptical of, because a post-sign gate that re-reads the
generator's own output list proves nothing. It does not: `verifyNSECExpectations` /
`verifyNSEC3Expectations` derive the expected owner set, ordering and type bitmaps from the *input
snapshot's* `zoneModel` (`authoritativeOwners`, `emptyNonTerminals`, `denialTypes`) and compare the
emitted records against it — membership both ways (missing owner, foreign owner), ring closure, and
exact bitmap equality. The zero-length chain that the review's probe slipped through is now an
explicit error in both modes. NSEC excludes empty non-terminals and NSEC3 includes them, which is the
correct RFC 4035 §2.3 / RFC 5155 §7.1 split.

*Mutation probe:* restoring the `len(...) == 0 → return nil` skip makes
`TestVerifySignedZone_DenialChainExpectations/nsec:_whole_chain_missing` fail with
`mutation must be rejected with "missing", got <nil>`.

**RA6X-028 / RA6X-053.** One canonical identity (`canonicalName` → wire octets, escapes resolved, case
folded, minimally re-escaped) keys every owner comparison, and signatures are computed over
`canonicalRRset` copies while the written records keep their original spelling — so `www`, `WWW` and
`\119ww` sign as one RRset without rewriting the output. Occlusion is a memoized bounded ancestor walk
against an indexed delegation/DNAME map, replacing the per-name full scan; `labelsWithin` compares
labels rather than string suffixes, so an escaped dot can no longer be mistaken for a separator
(`childish` vs `child` is handled by construction now, not by a special case).

**RA6X-029.** `validateZoneRecords` — shared by `ValidateZoneFile` (`add`/`import`) and every signing
path, so the rules cannot drift — rejects apex CNAME, multiple CNAMEs, CNAME beside non-DNSSEC data,
duplicate DNAME, DNAME beside CNAME, data beneath a DNAME, non-{NS,DS,glue} at a delegation point, and
DS without a delegation. `isDNSSECMetadataType` correctly allows a previously signed file to be fed
back as input.

*Behavioural note for operators:* this is a hard rejection of zone files that previously signed. A
zone with, say, a TXT record at a delegation point now fails to sign and keeps serving its previous
output. That is what the review asked for, and it fails in the safe direction, but it is a
deployment-visible change worth calling out in release notes.

**RA6X-030 / RA6X-047.** `VerifyKeyPairCorrespondence` derives the public half from the seed for the
64-byte form and rejects a mismatched stored suffix — closing exactly the "corrupted seed, intact
suffix" probe — then compares the derived key with the DNSKEY. ECDSA validates the scalar in
`[1, n-1]` before `ScalarBaseMult`, so a zero or over-order scalar can no longer be silently reduced
into a different key. `signRRSIG` derives from the seed in both cases, so the suffix is never used
directly. RA6X-047's `formatPrivateKey` reduces to the 32-byte seed **only when** the suffix is
consistent with it, which is the same invariant — the two fixes agree rather than fighting, and both
32- and 64-byte files stay loadable and signable.

## Findings with no verdict yet

Not examined in this session. No conclusion should be drawn from their absence.

`RA6X-002`, `RA6X-003`*, `RA6X-004`*, `RA6X-014`*, `RA6X-015`, `RA6X-017`*, `RA6X-018`, `RA6X-019`*,
`RA6X-022`, `RA6X-023`, `RA6X-024`, `RA6X-025`*, `RA6X-027`*, `RA6X-031`, `RA6X-032`, `RA6X-033`,
`RA6X-034`, `RA6X-035`*, `RA6X-037`, `RA6X-038`, `RA6X-039`, `RA6X-040`*, `RA6X-041`, `RA6X-042`*,
`RA6X-043`, `RA6X-044`*, `RA6X-045`, `RA6X-046`, `RA6X-048`, `RA6X-049`*, `RA6X-050`*, `RA6X-051`,
`RA6X-055`.

`*` = partially inspected in passing while verifying a neighbour (the relevant code was read but not
checked against its own finding text). Specifically: the RA6X-004/027/003 state fields and phase
constants were read and are additive and backward-compatible; RA6X-025's `ReplaceFromDisk` /
`lastSaveFailed` split and RA6X-049's `IsCommitted` reconciliation were seen at their `signAllZones`
call sites; RA6X-042's `readSourceSnapshot` and RA6X-035's output check were seen from
`prepareSignedZone`; RA6X-050's `toWireFormat`/`canonicalLabelBytes` escape fix was read and is
correct.

## SKIPPED items

**There are no SKIPPED entries.** All 56 findings are logged as FIXED. Three carry qualifiers in
their headings, which I read as scope statements rather than skips:

| ID | Qualifier | Assessment |
|---|---|---|
| RA6X-042 | "producer contract documented; no producer scripts exist in the repository" | Legitimate. The code-side boundary (`readSourceSnapshot`, non-blocking open, regular-file check, stat-before/after) is implemented; the un-implementable half is an operator contract for scripts that are not in this repo. |
| RA6X-054 | "public-only egress by default; deployment firewall not inspected" | Legitimate. Enforcement is in-process at the dial boundary; the firewall is outside the repo. See the two range gaps noted above. |
| RA6X-045 | "documentation; not executed on a target host" | Not yet assessed — RA6X-045 has no verdict this session. Recorded in project memory as an outstanding operator action (clean-host walkthrough run). |

These need a decision on whether to close or keep open, which is deferred to the next session along
with their verdicts.

## Cross-cutting observations

Neither of these is a defect in a claimed fix; both are properties of the fixed system worth having
written down.

1. **Publication-confirmation lock contention (RA6X-004 interacting with the cycle lock).**
   `signAllZones` holds the cross-process state lock for the whole cycle, while post-sign hooks run in
   goroutines whose `confirmPublication` callback needs that same lock (10 s timeout). `flock` locks
   are per open-file-description, so a second `open()` in the same process *does* block. With many
   zones — the 3000-zone case the coalescing comment contemplates — a cycle can outlast the timeout
   and hook-based confirmations will be dropped and retried next cycle. Every consequence is
   fail-safe (`PendingPublication` persists, the hook is re-fired, rollover phases simply wait), so
   this is a latency property, not a correctness bug. Worth measuring before a large deployment.

2. **A test seam lives in production code.** `Signer.mutateBeforeVerify` (`sign.go:33`) exists so a
   mutated generation can reach the real publication boundary. It is unexported, documented as
   test-only, nil in production and set only from an in-package test. This is defensible and it is
   what makes the RA6X-056 mutation probe meaningful — noted for the record rather than as a
   complaint. The sibling seam `SetAfterSourceRead` is exported but similarly documented and unused
   in production.

## Verification artifacts

Every mutation probe in this document was applied to a copy-backed file and reverted immediately;
`git status --porcelain` was empty and `git diff` clean before this file was written. No test,
fixture or source file was modified as part of verification.
