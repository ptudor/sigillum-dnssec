# DNSSEC codebase review — Astra 6, XHigh

Review date: 2026-09-04. Source baseline: `a22bfe8` on `main`, after fetching and reconciling the remote service-script update. Review-only commits follow that baseline.

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

## RA6X-007 — Unsigned Additional DS records can authenticate an attacker-controlled child

- **Severity:** Critical
- **Status:** Confirmed by an isolated executable probe
- **Location:** `Golang-dnssec-validator/internal/dns/query.go`, `parseResponse`; `internal/validator/validator.go`, `queryDSFromParentWithValidation`, `validateZone`; `internal/validator/dnssec.go`, `verifyDSRRSIGSet`, `CollectDSMatchedKeys`.
- **Problem:** The parser combines DS records from Answer, Authority, and Additional and discards their owner/section. DS signature verification authenticates the Answer RRset for the requested child, but subsequent chain construction consumes the combined list. An attacker who can alter DNS responses can append their own unsigned DS and use it to authenticate an entirely attacker-controlled child DNSKEY RRset and answers, while the genuine parent signature still passes.
- **Evidence:** A local UDP response containing a genuinely signed `example.com. DS` in Answer and an unsigned attacker-key DS owned by `unrelated.invalid.` in Additional passes `verifyDSRRSIGSet`. `CollectDSMatchedKeys(queryResult.DS, attackerKeys, "example.com.")` then returns the attacker key; its signature over an attacker-only child DNSKEY RRset passes `VerifyDNSKEYRRSIGByKeys`. The probe does not require forging the genuine parent's signature.
- **Fix specification:** Carry owner, class, and section through parsing, and return the exact authenticated DS RRset from verification. Only those records may enter chain matching; never use the unfiltered display/diagnostic slice as trusted data. Require the expected child owner and parent signer and reject ambiguous unrelated data without promoting it. Preserve JSON compatibility through additive metadata or separate internal authenticated objects. Apply the same authenticated-data boundary to DNSKEY and denial records, including Authority and Additional handling.
- **Verification:** Create two child keys and a parent signing key. Serve a signed DS for child key A in Answer, append unsigned DS for key B in Additional (test both matching and unrelated owner), and serve a child DNSKEY RRset signed only by B. Validation must be Bogus. The identical response with only A's authenticated chain must be Secure. Repeat with injected DS in Authority and with a legitimate Additional section containing unrelated records.

## RA6X-008 — A mixed anchor document bypasses the root-anchor pinning boundary

- **Severity:** Critical
- **Status:** Confirmed by an isolated executable probe; exploitation requires influence over an anchor document and DNS responses
- **Location:** `Golang-dnssec-validator/internal/dns/anchors.go`, `finalizeAnchors`; `internal/validator/dnssec.go`, `VerifyRootTrustAnchor`, `CollectAnchorMatchedKeys`; `internal/validator/validator.go`, root branch of `validateZone`.
- **Problem:** Loading requires that at least one anchor is pinned, but retains arbitrary additional anchors. The initial root check considers pinned anchors; the later list of keys allowed to authenticate the DNSKEY RRset considers all loaded anchors. A malicious mirror/file can preserve the genuine public anchor while adding its own root of trust. The root response can include the genuine public KSK and be signed only by the attacker key.
- **Evidence:** The probe loads JSON with the real pinned KSK-2017 DS plus a generated unpinned ECDSA DS. `VerifyRootTrustAnchor` succeeds because the response includes the genuine public KSK. `CollectAnchorMatchedKeys` includes the attacker key, and `VerifyDNSKEYRRSIGByKeys` accepts a signature made only by that key over the mixed DNSKEY RRset. Existing wholesale-replacement tests do not cover this mixed set.
- **Fix specification:** Make every root authentication path use only active, exact pinned anchors (or keys introduced through an explicitly authenticated update mechanism). Filter at the final trust decision as well as ingestion; do not rely on an earlier existential check. Unpinned loaded entries may be diagnostic data but cannot authenticate signatures. Preserve acceptance of either currently shipped genuine root pin and supported rollover overlap.
- **Verification:** Retain a genuine active pinned DS/key, add an attacker DS/key, and sign the mixed root RRset only with the attacker key: reject it. A genuine pinned-key signature must still succeed. Exercise both file and URL loaders, direct helper calls, future/expired anchors, and both shipped root pins.

## RA6X-009 — Wildcard checks use metadata from a signature that never verified

- **Severity:** High
- **Status:** Confirmed by an isolated executable probe
- **Location:** `Golang-dnssec-validator/internal/validator/validator.go`, `verifyActualRecord`, `verifyWildcard`; `internal/validator/dnssec.go`, `FindRRSIGForType`, `VerifyRRsetRRSIGFromResponseAnyKey`.
- **Problem:** Leaf validation selects the first RRSIG for metadata, while the raw-response helper can succeed using another RRSIG. The first signature's unauthenticated Labels value then decides whether wildcard denial proof is necessary. An attacker can replay a legitimate wildcard signature and prepend an invalid signature claiming an exact-name answer, bypassing the required denial proof.
- **Evidence:** The probe signs `*.example.com. A`, expands it to `www.example.com.`, and prepends a copy with `Labels=3` and invalid signature bytes. Raw verification succeeds using the genuine wildcard signature. `verifyWildcard` uses the forged first record, leaves `Wildcard=false`, and `recordValidationVerdict` returns Secure despite no NSEC/NSEC3 proof.
- **Fix specification:** Return the exact verified signature and RRset from the crypto layer and use only their authenticated fields for wildcard, owner, signer, algorithm, and timing decisions. Evaluate each candidate signature as an indivisible candidate; a candidate's successful crypto check must not validate another candidate's metadata. Preserve acceptance of legitimate multi-signature responses and the current public result shape.
- **Verification:** Prepend and append invalid same-tag RRSIGs with different Labels/SignerName to an authentic wildcard response. Missing or invalid denial proof must remain Bogus regardless of ordering. Authentic wildcard proof must succeed, as must an ordinary exact-name answer with a valid signature.

## RA6X-010 — NSEC NXDOMAIN accepts existing empty nonterminals and crosses delegation cuts

- **Severity:** High
- **Status:** Confirmed by isolated semantic probes
- **Location:** `Golang-dnssec-validator/internal/validator/nsec.go`, `VerifyNSECDenial`, `verifyNSECNXDOMAIN`, `closestEncloserFromNSEC`.
- **Problem:** Canonical interval coverage alone is treated as name absence. An NSEC endpoint below the queried name proves that the query is an existing empty nonterminal; a parent NSEC at a delegation cannot deny names inside the child. These distinctions are missing, allowing replay of authentic signed parent-zone records to justify false NXDOMAIN conclusions.
- **Evidence:** `VerifyNSECDenial("a.example.com.", A, [{Owner:"example.com.", NextDomain:"x.a.example.com.", bitmap:SOA/NS/NSEC/RRSIG}], NXDOMAIN)` succeeds, although `x.a.example.com.` proves `a.example.com.` exists. It also succeeds for `x.child.example.com.` with an NSEC `child.example.com. → example.com.` whose bitmap includes NS and DS, despite the signed child delegation. The probes test interval semantics; a signed fixture should additionally cover the full request path.
- **Fix specification:** Reject NXDOMAIN if either endpoint proves the queried name exists as an empty nonterminal. Enforce zone authority and delegation/DNAME boundaries when deriving closest enclosers and accepting coverage. Bind every denial RRset to the authenticated zone; incomplete or unauthenticated discovery cannot authorize using parent denial below a child. Preserve legitimate apex-only wraparound chains and exact DS-absence-at-delegation handling.
- **Verification:** Add signed end-to-end versions of both examples; neither may be Secure NXDOMAIN. Empty-nonterminal A queries should accept a valid NOERROR/NODATA response. Test a real child NXDOMAIN signed by the child, parent DS NODATA at an unsigned delegation, and root/apex wraparound records.

## RA6X-011 — NSEC wildcard proof does not establish the claimed closest encloser

- **Severity:** High
- **Status:** Confirmed by an isolated semantic probe
- **Location:** `Golang-dnssec-validator/internal/validator/nsec.go`, `VerifyWildcardDenial`, NSEC branch.
- **Problem:** The NSEC branch ignores the authenticated RRSIG Labels value and accepts any interval covering the expanded query name. It can approve synthesis from an ancestor wildcard even when the same NSEC proves a closer existing name, which blocks that wildcard.
- **Evidence:** For `foo.bar.example.com.` and `wildcardLabels=2` (source `*.example.com.`), a record `bar.example.com. → z.bar.example.com.` makes `VerifyWildcardDenial` return `Verified=true`. That record proves `bar.example.com.` exists, so `*.example.com.` cannot synthesize this answer. This error remains after fixing RA6X-009.
- **Fix specification:** Derive the closest encloser/next closer from the authenticated signature and covering NSEC, and require them to agree. Reject proofs crossing delegations, DNAME boundaries, or an existing closer ancestor. Preserve wildcard expansion at the correct encloser and canonical wraparound behavior. Consume only authenticated denial records as required by RA6X-007.
- **Verification:** Combine a real signature over `*.example.com. A` with the example signed NSEC and expand to `foo.bar.example.com.`: reject. Repeat with `*.bar.example.com.` and an appropriate proof: accept. Include a query that is itself an existing empty nonterminal.

## Checkpoint summary

| Severity | Findings |
|---|---|
| Critical | RA6X-007, RA6X-008 |
| High | RA6X-001–RA6X-006, RA6X-009–RA6X-011 |
| Medium | None recorded yet |
| Low | None recorded yet |

Provisional fix order: RA6X-007/008 → RA6X-009 → RA6X-010/011; independently, RA6X-006 → RA6X-002 → RA6X-001/005 → RA6X-004 → RA6X-003. Establish authenticated-data boundaries before adding denial rules, and persistence/publication tracking before cache-dependent rollover phases.
