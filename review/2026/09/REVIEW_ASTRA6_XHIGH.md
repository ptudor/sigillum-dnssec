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

## RA6X-012 — NSEC3 proofs omit delegation boundaries and opt-out security semantics

- **Severity:** High
- **Status:** Confirmed by isolated semantic and signed-response probes
- **Location:** `Golang-dnssec-validator/internal/validator/nsec.go`, `verifyNSEC3NXDOMAIN`, `nsec3Matches`, `nsec3Covers`, `VerifyWildcardDenial`; `validator.go`, `verifyDSAbsence`, `recordValidationVerdict`.
- **Problem:** NSEC3 closest-encloser discovery checks hashes without inspecting the matching record's NS/SOA/DNAME bitmap. It can deny data below a signed child or DNAME. Covering opt-out records are treated as ordinary authenticated absence and produce Secure leaf verdicts, although they can cover existing unsigned delegations. DS absence accepts a covering opt-out interval without the required closest-provable-encloser proof. Unknown flag bits are not rejected.
- **Evidence:** A semantic probe with a self-wrapping NSEC3 for `H(child.example.com.)`, bitmap NS/DS, accepts NXDOMAIN for `x.child.example.com.`. A signed self-wrapping apex NSEC3 with `Flags=1` yields `proof.Verified=true` and a Secure leaf verdict. `verifyDSAbsence` checks only `hashBetween(childHash, ...)` plus the opt-out bit. [RFC 5155 §§8.2–8.9 and 9.2](https://www.rfc-editor.org/rfc/rfc5155#section-8.3) define the missing constraints.
- **Fix specification:** Retain the exact closest-encloser and next-closer records, enforce authority/bitmap boundaries, ignore unknown flag values, and represent opt-out uncertainty separately from successful signature verification. Require a complete closest-provable-encloser proof for opt-out DS absence. A next-closer opt-out proof must not make an ordinary answer Secure. Preserve genuine unsigned delegations as Insecure and secure non-opt-out proofs as Secure; add compatible result metadata rather than renaming existing statuses.
- **Verification:** Convert both examples into complete signed response fixtures; test signed and unsigned delegations, DNAME enclosers, flags 0/1/2/3, incomplete opt-out DS proofs, and wildcard answers whose next-closer cover has opt-out set. Assert both cryptographic diagnostics and final status.

## RA6X-013 — Wildcard and DS-absence paths combine incompatible NSEC3 chains

- **Severity:** High
- **Status:** Confirmed for wildcard proofs by an isolated probe; identical parameter-selection defect in DS absence
- **Location:** `Golang-dnssec-validator/internal/validator/nsec.go`, `VerifyWildcardDenial`, `groupNSEC3ByParams`; `validator.go`, `verifyDSAbsence`.
- **Problem:** Normal NSEC3 denial partitions records by algorithm/iterations/salt, but wildcard and DS-absence validation hash using only the first record's parameters and search every record's interval. A signed interval from a different chain is then interpreted in the wrong hash space, permitting false absence or an insecure-delegation downgrade.
- **Evidence:** The probe supplies two self-wrapping records, each owned by `H(foo.example.com.)` under its own salt (empty and `AA`). Each record alone correctly refuses to deny `foo.example.com.`, but together `VerifyWildcardDenial(..., Labels=2)` returns Verified: it computes the first hash and finds it inside the second chain's interval. Both callers directly set `params := records[0]` and never call `groupNSEC3ByParams`.
- **Fix specification:** Share one parameter-aware proof engine across NXDOMAIN, NODATA, wildcard, and DS absence. Every record used in a proof must have the same authenticated zone, algorithm, iteration count, and decoded salt. Evaluate complete chains independently during transitions; normalize equivalent empty salts. Do not reject a valid complete chain merely because a separate supported chain is incomplete, and never merge their evidence.
- **Verification:** Sign the two individually insufficient records and confirm their union still fails. Repeat for DS absence, different iteration counts and algorithms, and reversed record order. A complete valid chain alongside an incomplete transition chain must work independently of order.

## RA6X-014 — Valid wildcard NODATA, empty-nonterminal denial, and DNAME answers are unsupported

- **Severity:** Medium
- **Status:** Confirmed by code paths
- **Location:** `Golang-dnssec-validator/internal/validator/nsec.go`, `verifyNSECNODATA`, `verifyNSEC3NODATA`; `validator.go`, `verifyActualRecord`; `internal/dns/query.go`, `parseResponse`.
- **Problem:** NODATA requires an exact NSEC/NSEC3 owner match. That excludes valid wildcard NODATA, where the matching record belongs to the wildcard, and NSEC denial for an empty nonterminal that has no own NSEC. DNAME-generated CNAMEs are also rejected for lacking a CNAME RRSIG, even though the DNAME signature is the relevant authentication. Valid signed domains are reported Bogus.
- **Evidence:** Both NODATA helpers only return success inside their exact-owner/hash branches. The NSEC helper has no interval/descendant proof case. The parser and leaf verification have no DNAME handling; CNAME verification unconditionally requires its own signature. [RFC 5155 §8.7](https://www.rfc-editor.org/rfc/rfc5155#section-8.7) specifies the wildcard-hash proof.
- **Fix specification:** Implement explicit wildcard-NODATA and NSEC empty-nonterminal proof branches, with authenticated closest-encloser/type-bitmap constraints. Authenticate DNAME, verify the synthesized CNAME's exact substitution, and follow its target within existing loop/depth limits. Preserve strict rejection of ordinary unsigned CNAMEs, false NXDOMAIN for existing nonterminals, and positive-answer handling. Keep supported query parameters and JSON fields compatible.
- **Verification:** Serve a signed zone with `*.example.com. A`, query absent AAAA at `foo.example.com.`, and require Secure NODATA under NSEC and NSEC3. Query an empty nonterminal under NSEC. Test a signed DNAME answer, a tampered synthesized target, and a DNAME chain that exceeds the DNS name-length limit.

## RA6X-015 — CNAME traversal is detached from the authenticated leaf response and fails open on lookup errors

- **Severity:** High
- **Status:** Confirmed by control flow; end-to-end response-switching fixture still recommended
- **Location:** `Golang-dnssec-validator/internal/validator/validator.go`, `verifyActualRecord`, `checkAndFollowCNAME`, `validateWithCache`; `internal/dns/query.go`, `parseResponse`.
- **Problem:** After verifying one leaf response, the validator makes a second DNS request to decide which CNAME target to follow. It neither authenticates that response nor binds `CNAME[0]` to the queried owner/Answer section. If the second lookup fails, returns no CNAME, or is altered, target validation can be skipped or directed to a different name while the first CNAME's signature keeps the result Secure. Explicit CNAME queries are also made dependent on target-CNAME existence, although the requested CNAME RRset itself is the answer.
- **Evidence:** `checkAndFollowCNAME` takes `queryResult.CNAME[0]` from the merged parser, returns `(nil,nil)` when no server responds/no CNAME appears, and never checks a signature. Its caller ignores `err != nil`. `RecordValidation` retains neither the authenticated target nor a pending-target requirement. A signed alias to a bogus target plus a failed second request can therefore leave `lastStatus == StatusSecure`.
- **Fix specification:** Return authenticated answer/alias data with leaf verification and follow that exact CNAME owner/target without rediscovery. Treat failure to validate a required target as Indeterminate, not successful completion. Ignore unrelated CNAMEs and unauthenticated sections. For `type=CNAME`, complete upon authenticating the requested RRset; if additional traversal is offered, separate it from that query's verdict. Preserve loop/depth guards, sticky insecure ancestry, and original requested type for ordinary alias resolution.
- **Verification:** Serve a valid signed CNAME to a bogus target, then drop or change subsequent replies: final status must never be Secure. Inject an unrelated Additional CNAME; it must not be followed. Test cross-zone and same-zone aliases, explicit CNAME queries, and second-hop timeouts.

## RA6X-016 — Trusted key material loses its zone identity during signature verification

- **Severity:** High
- **Status:** Confirmed by isolated executable probe; exploitation requires key reuse across zones or another same-key signing context
- **Location:** `Golang-dnssec-validator/internal/validator/dnssec.go`, `verifyDNSKEYRRSIGOne`, `VerifyRRsetRRSIGFromResponse`, `VerifyDenialRRSIGFromResponse`, `reconstructDNSKEY`; `internal/dns/types.go`, `DNSKEYRecord`/`RRSIGRecord`.
- **Problem:** DNSKEY owners are discarded, and verification reconstructs trusted keys and DNSKEY RRset owners from the incoming signature's SignerName. Cryptographic success can authenticate a different zone's signature when the two zones reuse a key. DS/denial helpers also do not enforce the expected signing zone. The leaf path's preliminary signer check is insufficient because it can inspect a different signature from the one that succeeds (RA6X-009).
- **Evidence:** The probe creates a key at `other.example.`, computes the DS for the same key at `child.example.`, and passes a DNSKEY signature produced only at `other.example.` to `VerifyDNSKEYRRSIGByKeys`; it succeeds. `verifyDNSKEYRRSIGOne` reconstructs every record at `rrsigRecord.SignerName` and has no expected-zone argument. Denial verification similarly creates a trusted key at each received SignerName.
- **Fix specification:** Carry the authenticated zone/owner with each trusted key set. Require DNSKEY RRset owner and signer to equal the child zone; DS signer to equal the actual parent zone; and denial owner/signer to satisfy that zone's authority rules. Verify original wire records, without rewriting their owner/class to make signatures fit. Preserve legitimate key reuse and key-tag collisions; only cross-zone authentication must stop.
- **Verification:** Reuse a KSK/ZSK across two independently signed zones and replay each zone's DNSKEY, DS, NSEC/NSEC3, and leaf signatures into the other. Reject cross-zone evidence while accepting each original response and legitimate shared-key deployments. Test this after RA6X-007 and RA6X-009.

## RA6X-017 — Unsupported DS algorithms and first-signature rejection produce false Bogus verdicts

- **Severity:** Medium
- **Status:** Confirmed; first-signature denial failure reproduced
- **Location:** `Golang-dnssec-validator/internal/validator/validator.go`, `verifyActualRecord`, `validateZone`; `dnssec.go`, `ValidateChainLink`; `nsec.go`, `VerifyNSECDenialWithRRSIG`, `VerifyNSEC3DenialWithRRSIG`.
- **Problem:** Leaf verification commits to the first covering RRSIG/tag, and denial wrappers reject an expired or unknown-key first signature before the crypto layer can try valid alternatives. Separately, an authenticated DS set containing only unsupported algorithms/digests is classified Bogus instead of having no supported authentication path. These cases break valid rollovers and make diagnostics differ from DNSSEC validators.
- **Evidence:** The isolated probe's denial crypto helper accepts a valid signature after an expired first signature, while `VerifyNSECDenialWithRRSIG` returns `NSEC RRSIG expired`. Leaf candidate keys are selected only for `FindRRSIGForType`'s first tag. No capability classification occurs before `ValidateChainLink`'s `no matching DNSKEY` Bogus result. See [RFC 6840 §5.4](https://www.rfc-editor.org/rfc/rfc6840#section-5.4) and [RFC 4035 §5.2](https://www.rfc-editor.org/rfc/rfc4035#section-5.2).
- **Fix specification:** Try each eligible covering signature as a whole and accept a fully valid candidate; integrate with RA6X-009's metadata binding. Classify authenticated DS records by supported algorithm/digest before matching, following the no-supported-path rule only after parent authentication. Preserve Bogus for an available supported path whose signatures/digests fail; never allow an unknown extra DS to downgrade a broken supported chain.
- **Verification:** Permute expired, unsupported, missing-key, and valid signatures with different tags under A, CNAME, NSEC, and NSEC3. Test only-unsupported DS, mixed supported/unsupported DS with a good supported path, and a broken supported path. All orders must yield the same correct verdict.

## RA6X-018 — Per-server Secure indicators are transport success, and extended mode misses signature failures

- **Severity:** Medium
- **Status:** Confirmed
- **Location:** `Golang-dnssec-validator/internal/validator/validator.go`, `ValidateMultipleServers`, `compareDNSKEYSets`, `queryLeafAllServers`, `leafFingerprint`; `static/app.js`, `showZoneDetails`.
- **Problem:** Every successful NOERROR DNSKEY response is labeled Secure before cryptographic validation, including empty or unsigned responses. Only the first usable server's data is validated. Other servers serving identical data with missing/expired signatures are shown as secure and generate no disagreement. DNSKEY consensus compares only 16-bit tags, and leaf fingerprinting lowercases case-sensitive RDATA such as TXT.
- **Evidence:** `AddressResult{Status: StatusSecure}` is changed only for transport/RCODE errors. `compareDNSKEYSets` uses `map[uint16]bool`; empty DNSKEY responses are skipped in consensus. Leaf fingerprints omit RRSIG and call `strings.ToLower(rr.String())`. UI renders each address's status as a checkmark without another verification gate.
- **Fix specification:** Distinguish queried/reachable from authenticated, then validate each server's applicable DNSKEY/DS/leaf response against the authenticated chain in extended mode. Compare canonical RRsets by complete key material and type-aware RDATA; retain case where DNS semantics require it. Report nonresponders, incomplete data, and signature differences without requiring every server to agree to establish one valid path. Preserve quick-mode latency and existing overall-status policy, documenting how disagreement affects diagnostics.
- **Verification:** Use two servers with identical data but a missing/expired signature on one; the second must be flagged. Test an empty DNSKEY response, same-tag different keys, duplicate records, TXT case changes, TTL-only differences, and equivalent case-insensitive domain-name RDATA.

## RA6X-019 — Recursive infrastructure lookups ignore truncation, owner identity, and some DNS errors

- **Severity:** Medium
- **Status:** Confirmed
- **Location:** `Golang-dnssec-validator/internal/dns/resolver.go`, `exchangeRecursive`, `ResolveNS`, `ResolveAddresses`, `CheckZoneCut`, `DiscoverZoneCuts`; `internal/validator/validator.go`, `validateZone`.
- **Problem:** Infrastructure queries use a separate UDP-only path without TCP retry. Large NS/address answers can be truncated and silently treated as complete or as missing zone cuts. NS discovery accepts any NS owner in Answer, including records reached through aliases. Address lookup returns `(empty,nil)` even after both queries fail. The walk then derives a parent by dropping one label instead of using its actual discovered predecessor, causing misdirected DS requests for delegations whose parent skips labels.
- **Evidence:** `exchangeRecursive` returns immediately after UDP `ExchangeContext`; none of its callers check `Truncated`. `CheckZoneCut` tests only the record's Go type; `ResolveNS` drops the owner. `ResolveAddresses` always ends with `return addresses,nil`. `validateZone` receives `hierarchy` but ignores it and calls `GetParentZone(zone)`.
- **Fix specification:** Share robust DNS transport with TCP fallback and explicit RCODE/error handling, keeping CD enabled for diagnostics. Bind NS records to the requested owner and follow aliases only where appropriate. Carry the actual authenticated parent from the zone walk for DS queries; incomplete discovery must not authorize parent denial below a possible child. Preserve successful partial A/AAAA lookup behavior while surfacing failed families and transport truncation.
- **Verification:** A local recursive fixture must return TC over UDP and a complete TCP answer, unrelated-owner NS/CNAME answers, address SERVFAIL/timeouts, and a delegation `child.branch.example.` directly from `example.`. Check complete server enumeration, correct parent DS destination, and bounded cancellation.

## RA6X-020 — JSON write deadline expires before valid configured validation work finishes

- **Severity:** Medium
- **Status:** Confirmed
- **Location:** `Golang-dnssec-validator/server.go`, `nonSSEWriteTimeout`, `registerRoutes`, `withWriteDeadline`; `handlers.go`, `HandleValidateJSON`.
- **Problem:** JSON validation gets an absolute 30-second socket write deadline at handler entry, while its configurable work timeout may exceed 30 seconds and defaults to exactly 30. Slow validations therefore finish with a result that cannot be delivered, including timeout diagnostics at the default boundary. JSON encoding errors are ignored and the request is counted as HTTP 200.
- **Evidence:** `/api/validate` is wrapped in `withWriteDeadline(30*time.Second, ...)`; the handler creates a separate context using `config.TotalTimeout` and encodes only after `v.Validate` returns. Nothing re-arms the deadline for result writing or handles `Encode` errors.
- **Fix specification:** Bound validation time and response-write time separately: arm a short write deadline when the completed result is ready, or allocate total work time plus a bounded delivery budget. Preserve request cancellation and non-SSE slow-client protection. Log/count failed response writes without exposing partial JSON as successful validation.
- **Verification:** Use a real HTTP server/socket and a deterministic validation delay crossing 30 seconds with `TotalTimeout=60s`; the completed response must arrive. Test default-timeout diagnostics and a client that stops reading after work completes. Avoid a ResponseRecorder-only test, which cannot reproduce socket deadlines.

## RA6X-021 — Arbitrary HTTP methods create unbounded Prometheus time series

- **Severity:** Medium
- **Status:** Confirmed
- **Location:** `Golang-dnssec-validator/internal/metrics/metrics.go`, `promAPIRequests`, `RecordAPIRequest`; `handlers.go`, all method-rejection paths.
- **Problem:** The raw request method is a persistent CounterVec label. An unauthenticated caller can send a new valid HTTP token as the method on each request, receiving 405 while adding a never-evicted metric series. Per-IP rate limiting bounds the rate, not lifetime cardinality, and rotating source IPs accelerates exhaustion.
- **Evidence:** `promAPIRequests` labels are endpoint/method/status; handlers pass `r.Method` even on 405; `WithLabelValues` creates a series for every new method string. No normalization, allowlist, or removal exists.
- **Fix specification:** Map HTTP methods to a fixed known set plus one `OTHER` label before recording metrics, including rejected requests. Keep endpoint/status labels bounded and metric name/label keys unchanged. Preserve the actual method in structured request logs if desired.
- **Verification:** Send thousands of distinct methods to each API route, collect the registry, and assert the number of method label values stays within the documented fixed bound; normal GET/POST/etc. labels and 405 behavior must remain correct.

## RA6X-022 — SSE completion and cached UI results do not represent the finished top-level validation

- **Severity:** Medium
- **Status:** Confirmed
- **Location:** `Golang-dnssec-validator/internal/validator/validator.go`, early Bogus returns in `validateWithCache`, leaf validation/cache updates; `static/app.js`, `addZoneCard`, `completeValidation`, error/complete event handlers.
- **Problem:** Nested CNAME validation emits terminal `complete` events on early Bogus returns without checking depth; the browser closes at that event and misses the actual top-level result. Zone events are emitted before leaf record verification, while the UI stores the early object in click handlers and never reconciles it with the complete payload. Thus final leaf failures/proofs/disagreements can be absent from the visible details even after the final result is known. Shared cached zone objects also overwrite per-name `RecordValidation` during same-zone CNAME traversal.
- **Evidence:** Only the normal end-of-function complete emission has `depth == 0`; both Bogus branches emit unconditionally. `completeValidation` updates badges/raw JSON only, and `seenZones` prevents replacing early cards. `validatedZones[zone].RecordValidation` is overwritten for each alias in that zone, although the field describes an individual queried name.
- **Fix specification:** Emit exactly one terminal event for the top-level request and carry nested failures as CNAME results. Cache zone authentication separately from per-name answer validation. Reconcile cards/tabs from the final payload and expose all leaf denial/wildcard/server-disagreement diagnostics without hiding failures behind a successful data signature. Preserve event names and compatible payload fields; additive identifiers for per-name results are appropriate.
- **Verification:** Record the SSE stream for an alias to a bogus target and assert one complete event containing the original chain and CNAME failure. In a browser, verify expired leaf signatures and wildcard-proof failures appear in zone details after completion. Test two aliases in the same zone whose leaf outcomes differ.

## RA6X-023 — An existing truncated private-key backup is accepted before the live key is overwritten

- **Severity:** High
- **Status:** Confirmed by executable probe
- **Location:** `Golang-tudor-dnssec-signer/internal/signer/rollover.go:416–456`, `BackupKey`; `internal/signer/keys.go:279–350`, `backupExistingKeyFiles`; `internal/fsutil/fsutil.go`, `CopyFile`.
- **Problem:** Backup recovery checks that the public half matches and the private half exists, but does not validate private contents. A crash or failed copy can leave an empty/truncated private file. Retrying rollover then destroys the last usable live private key while claiming that its backup is safe. Subsequent rollover signing fails and cannot reconstruct the old private key required by the current trust chain.
- **Evidence:** Both backup paths use `!FileExists(... + ".private")` as the repair condition. `CopyFile` opens/truncates the destination and copies directly, so an interrupted write produces an existing incomplete file. The isolated probe created a valid backup, truncated its private half, and successfully started KSK rollover; signing then failed with `no PrivateKey field found in file`, and the backup remained empty.
- **Fix specification:** Validate the complete backup pair, expected owner/role/algorithm and cryptographic correspondence before allowing any live-key overwrite. Repair an incomplete backup atomically from a verified live pair, preserving conflicting material for diagnosis. Make backups durable before activation, including file and directory synchronization. Never overwrite a different key on a tag collision. Integrate with RA6X-002 rather than relying on filename existence as transaction recovery.
- **Verification:** Exercise missing, zero-length, truncated, mismatched and unreadable private backups, including interruption during the private copy. Every retry must preserve a usable old pair or abort before live replacement. Verify both direct rollover backup and implicit backup during key generation/import.

## RA6X-024 — Import mutates live keys/output before validating ownership and does not restore prior artifacts on failure

- **Severity:** High
- **Status:** Confirmed
- **Location:** `Golang-tudor-dnssec-signer/main.go:1398–1558`, `runImport`, `loadBindKeyPair`; `internal/signer/keys.go`, `SaveKeyFiles`.
- **Problem:** Import prechecks flags, pair correspondence and matching algorithms but leaves domain ownership validation until signing, after writing both live key slots. Failure writing the second key, signing, state persistence or config persistence leaves a partially applied import. Config-append failure unconditionally removes the signed output, including a file that existed before import. A recovery/migration attempt can therefore replace working keys or delete a served zone despite returning an error.
- **Evidence:** `SaveKeyFiles` runs at lines 1482/1485; `SignZone` validates loaded key ownership later. Signing failure removes only the in-memory zone. A state-save failure returns without restoring keys/output. The config failure path calls `os.Remove(signedPath)` without saving/restoring pre-existing bytes, unlike the corresponding add rollback path.
- **Fix specification:** Before activation, validate both keys' canonical owner, protocol, supported algorithm, role and actual signing capability, and stage the complete signed zone. Commit keys, state, configuration and output as a recoverable transaction; on failure restore the exact prior artifacts and ownership/modes, or retain a clearly identified recoverable staged transaction without publishing it. Never delete pre-existing output as cleanup. Preserve import syntax, supported BIND input forms and unrelated configured zones; coordinate shared transaction machinery with RA6X-002/023.
- **Verification:** Import valid pairs for the wrong domain and assert no live artifact changes. Fault-inject each key write, signing, state save and final config append with pre-existing keys/output present. Restart/retry after each interruption and verify the prior generation remains usable and output is never removed unintentionally.

## RA6X-025 — State merging loses CLI warnings and resurrects removed zones despite the process lock

- **Severity:** High
- **Status:** Confirmed by executable probe
- **Location:** `Golang-tudor-dnssec-signer/internal/state/state.go:189–229`, `ReloadFromDisk`, `rolloverEqual`; `daemon.go`, `signAllZones`; `registrar_cli.go`, `lockedRunPush`, `persistRegistrarUrgentWarning`, `clearStickyWarnings`; `main.go`, `runRemove`.
- **Problem:** The merge treats `LastSigned` and a subset of rollover fields as a version for all zone state. CLI updates to warnings/errors or deletion have neither a newer signing timestamp nor a different rollover, so the daemon ignores them and overwrites the disk on its next save. An urgent registrar-recovery warning can disappear, a cleared warning can reappear, and successful `remove` can be undone in state before the documented SIGHUP. The lock serializes writes but does not resolve these stale-object merges.
- **Evidence:** The only merge cases are a missing in-memory zone, newer disk `LastSigned`, or differing `rolloverEqual` with a non-older timestamp. There is no deletion handling or general mutation revision. A probe saved an urgent warning through a second State object: reload ignored it. Removing the disk zone followed by daemon-style reload/save recreated that zone on disk.
- **Fix specification:** Use an authoritative reload under the process lock before mutation, or explicit persisted revisions plus deletion markers and well-defined conflict resolution. Preserve all CLI mutations, including warning addition/clearance, removal and phase metadata changes that do not sign. Coordinate config/state snapshots so stale pre-SIGHUP configuration cannot recreate removed state. Preserve single-writer behavior, existing state readability and unrelated zones; do not solve this by always replacing newer unsaved signing results with older disk data.
- **Verification:** Interleave daemon cycles with registrar warning add/clear, remove, add and rollover commands. After every subsequent save/restart, the last serialized mutation must persist. Include equal `LastSigned`, changes only to rollover timestamps, and removal before SIGHUP.

## RA6X-026 — The daemon continues signing and overwrites disk state after a failed reload

- **Severity:** High
- **Status:** Confirmed
- **Location:** `Golang-tudor-dnssec-signer/daemon.go`, `signAllZones` (both `ReloadFromDisk` calls); `internal/state/state.go`, `ReloadFromDisk`, `Save`.
- **Problem:** If state becomes unreadable or malformed while the daemon is running, it logs a warning and continues using stale in-memory state. It can then sign with key files changed by a CLI transition and overwrite the unreadable/newer state with its old snapshot. This turns a recoverable read failure into lost rollover or registrar state and potentially publishes an incorrect trust-chain generation.
- **Evidence:** Both reload errors are logged without returning. Signing/rollover processing and final `Save()` still execute. A missing state file is also treated as a successful no-op reload, permitting silent reconstruction from potentially stale memory.
- **Fix specification:** Fail the mutation cycle closed when the authoritative state cannot be loaded/validated after obtaining the process lock. Preserve existing output and disk evidence, expose a persistent operational failure, and retry the read on the next cycle. Define explicit recovery for an intentionally missing state file rather than equating it with an empty/no-change update. Coordinate with RA6X-002/025/036; retain service liveness and unrelated read-only diagnostics.
- **Verification:** After daemon startup, replace state with malformed JSON, deny reads, and simulate an interrupted CLI key transition. Assert no key/zone/state mutation until a valid consistent state is restored, and health reports the blocked signing cycle.

## RA6X-027 — Lowering TTL immediately before rollover discards still-live cache lifetimes

- **Severity:** High
- **Status:** Confirmed by executable probe
- **Location:** `Golang-tudor-dnssec-signer/internal/signer/sign.go:209–222`, `SignZone`; `internal/signer/rollover.go`, `dnskeyTTLFloor`, `zskRetirementFloor`; `internal/state/state.go`, published TTL fields.
- **Problem:** The signer retains maximum published TTLs only while rollover is already active. A normal re-sign with lower TTL replaces the recorded larger TTL immediately, even though resolvers may still hold the previous RRsets for their original lifetimes. Starting rollover next uses the reduced floor and can activate/retire keys before those old caches expire.
- **Evidence:** Both assignments use `zoneState.Rollover == nil || newTTL > recordedTTL`. A probe signed with a seven-day DNSKEY TTL, lowered it to one hour, immediately re-signed, and observed `PublishedDNSKEYTTL == 3600`. The seven-day cache horizon was lost with no elapsed wait. The same reset applies to `PublishedMaxRRSIGTTL`.
- **Fix specification:** Retain publication-generation cache horizons, including larger TTLs preceding a decrease, until their original expiry. Use those horizons for prepublication and retirement and persist them across restart. Include generated denial records when computing relevant signature cache lifetimes. Preserve configured TTLs on wire; the fix must lengthen safety waits, not silently undo the operator's TTL change. Build on publication acknowledgments from RA6X-004.
- **Verification:** Prime a validating resolver with long-lived old DNSKEY/data RRsets, lower TTLs, re-sign and immediately start rollover. Verify continuous validation and retention of old keys until the original cache horizon. Cover restart and repeated TTL increases/decreases before and during rollover.

## RA6X-028 — Equivalent escaped DNS owner names are signed as different RRsets

- **Severity:** High
- **Status:** Confirmed by executable probe
- **Location:** `Golang-tudor-dnssec-signer/internal/signer/sign.go`, RRset grouping in `signRecordsWithKeys` and `verifySignedRecords`, NSEC/NSEC3 owner collection and delegation helpers.
- **Problem:** Owner identity is based on lowercased presentation strings rather than decoded canonical DNS labels. Two spellings of the same wire name can form separate RRsets and denial-chain owners. The signer's self-verification repeats the same grouping mistake, so it reports success for output whose signatures fail after an authoritative server merges the equivalent owners.
- **Evidence:** The probe supplied A records at `www.example.com.` and `\119ww.example.com.`. `SignZone` succeeded and wrote two A-covering signatures. Normalizing both owners to their identical wire name produced a two-record RRset for which neither signature verified. This is a complete output correctness failure, not merely inconsistent display casing.
- **Fix specification:** Introduce one canonical wire-label identity function and use it consistently for RRsets, owner equality, subdomain/delegation checks, empty non-terminals and denial-chain ordering/closure. Keep original presentation where appropriate for output, while signing the complete semantic RRset. Handle escaped dots, decimal escapes and escaped ASCII case; do not merge distinct binary labels or lowercase opaque RDATA.
- **Verification:** Sign equivalent escaped/unescaped owner spellings and verify the served RRsets with an independent implementation or wire-normalized parser. Cover NSEC and NSEC3, wildcard/delegation names, owner case, escaped dots and different binary labels; assert one semantic RRset and valid denial chains.

## RA6X-029 — Zone validation accepts CNAME/data conflicts and self-verifies the invalid zone

- **Severity:** Medium
- **Status:** Confirmed by executable probe
- **Location:** `Golang-tudor-dnssec-signer/internal/signer/sign.go`, `validateZoneRecords`, `ValidateZoneFile`, `SignZone`, `verifySignedRecords`.
- **Problem:** Input validation checks apex SOA/NS and zone membership but omits semantic owner constraints. An owner containing both a CNAME and A record is accepted, signed and atomically replaces the previous output. Authoritative loaders may reject that output, leaving deployment stale, or serve an invalid alias/data combination. Signature correctness alone does not make a zone publishable.
- **Evidence:** A probe with both `www.example.com. A 192.0.2.2` and `www.example.com. CNAME ns.example.com.` returned successful signing and wrote the signed file. There is no CNAME exclusivity check before publication.
- **Fix specification:** Validate canonical owner/type constraints before writing output: CNAME must not coexist with ordinary data, multiple conflicting CNAME targets must be rejected, and apex/delegation/DNAME structural constraints should be audited with explicit accepted exceptions for DNSSEC metadata and glue. Preserve supported RR types and legitimate delegation data. Reuse RA6X-028 canonical identities; do not require a running authoritative server merely to validate input.
- **Verification:** Add invalid CNAME+A, CNAME+MX, multiple-target and apex-CNAME fixtures and assert failure leaves prior output/state intact. Include valid CNAME plus generated DNSSEC metadata and delegation/glue fixtures accepted by an independent authoritative zone checker.

## RA6X-030 — Expanded Ed25519 private-key validation does not verify the seed against its public half

- **Severity:** Medium
- **Status:** Confirmed by executable probe
- **Location:** `Golang-tudor-dnssec-signer/internal/signer/keys.go`, `VerifyKeyPairCorrespondence`; `main.go`, `loadBindKeyPair`; `internal/signer/crypto.go`.
- **Problem:** For the 64-byte Ed25519 form, correspondence validation trusts the embedded public-key suffix instead of deriving it from the private seed. A corrupt seed with an unchanged suffix passes validation but generates invalid signatures. Import/recovery therefore accepts unusable key material before the later signing verification catches it, after live-file mutation in the import path.
- **Evidence:** The probe generated an Ed25519 pair, flipped the first seed byte while leaving the public suffix intact, and observed `VerifyKeyPairCorrespondence` return nil. Signing succeeded at the API level, but the resulting signature failed verification with the advertised public key.
- **Fix specification:** Derive the expanded key from the seed, compare the derived public key and stored suffix, and reject inconsistent expanded keys before persistence. Validate scalar ranges for ECDSA in the same boundary audit. Preserve support for valid 32-byte seed and 64-byte expanded inputs; never silently rewrite a malformed key during import.
- **Verification:** Mutate each half independently and test truncated/oversized forms. Valid seed/expanded forms must still sign and verify; malformed forms must fail before any live key/output changes.

## RA6X-031 — A lost DELETE response can strand the registrar with no DS and bypass emergency recovery

- **Severity:** High
- **Status:** Confirmed by executable transport probe
- **Location:** `Golang-tudor-dnssec-signer/internal/registrar/registrar_dynadot.go:549–588`, `ReplaceDS`; `registrar_cli.go`, emergency warning handling.
- **Problem:** The restore logic runs only after a successful HTTP response to DELETE. A server can apply the deletion and then lose the connection or exceed the caller deadline before returning its response. The client treats that ambiguous outcome as a harmless clear failure, performs no restoration and returns no `ErrRegistrarDSEmpty` sentinel, so callers also omit the sticky emergency warning. The parent can be left with an insecure delegation.
- **Evidence:** A probe transport applied DELETE to a simulated DS store and returned `io.ErrUnexpectedEOF`. `ReplaceDS` returned a plain `clear_dnssec` error, issued only the initial PUT, never restored, and left the store empty. Its detached restore context is constructed only after the early DELETE-error return.
- **Fix specification:** Treat any potentially dispatched DELETE as an uncertain destructive operation. On transport/cancellation/ambiguous server failure, reconcile the registrar's actual state and restore the desired safe set using a bounded detached context; if safety cannot be verified, return an emergency outcome and persist remediation state. Verify postconditions rather than assuming an accepted/empty response means the DS set is already correct. Preserve explicit `registrar clear` semantics and additive rollover publication; never delete an old DS merely to resolve uncertainty.
- **Verification:** Simulate DELETE applied then EOF, timeout/cancellation, non-JSON/error response, and asynchronous acceptance. Confirm restoration or a persistent emergency warning; test restart between deletion and recovery. Distinguish explicit clear from replace and preserve all required old/new DS records.

## RA6X-032 — The signer's live validation can pass invalid signatures and understate a broken DS chain

- **Severity:** Medium
- **Status:** Confirmed
- **Location:** `Golang-tudor-dnssec-signer/internal/validate/validate.go`, `evalRRSIGCover`, `checkRRSIGPresent`, `checkDNSKEYVisible`, `computeOverall`, `bogusWhenDSPresent`; `dnssecstatus/index.html`, `isServfail`.
- **Problem:** The command/dashboard describes signatures as valid using only their time window and key tag; it never verifies their cryptographic bytes or binds them to the returned RRset/owner. DNSKEY visibility also compares only 16-bit tags. A broken served zone can therefore get a full pass. Separately, a known mismatching parent DS with otherwise passing checks becomes `partial`, and a missing one-of-two required signatures can also remain partial despite an authenticated DS chain. The static dashboard infers SERVFAIL from error-message text, including resolver-side failures, rather than the structured verdict.
- **Evidence:** `evalRRSIGCover` returns `valid=true` after `ValidityPeriod` without calling `Verify`; even an empty `Signature` qualifies. `checkDNSKEYVisible` sets found flags from `KeyTag()` only. `computeOverall("fail", "pass", "pass", "pass")` returns partial, and the DS-specific override considers DNSKEY/RRSIG status `fail` but not `DSCheck.MatchesKSK` or missing-signature partial states.
- **Fix specification:** Distinguish presence/freshness observations from cryptographically validated RRsets. Verify SOA and DNSKEY signatures against complete owner-bound keys and RRsets, including supported rollover alternatives; propagate an actually broken trust chain as failure while retaining partial for uncertainty/approaching refresh. Keep existing JSON fields/CLI flags compatible and add explicit evidence fields if needed. Make the static dashboard consume the structured result and preserve resolver-outage uncertainty.
- **Verification:** Serve matching tags and current timestamps with corrupt/empty signatures, wrong owner/full key material, a mismatching parent DS and exactly one missing required signature. None may pass; proven broken chains must fail. Valid dual-signature rollover, refresh warnings and resolver outages must remain correctly distinguished.

## RA6X-033 — Configured zones that fail initialization can be absent from every health/status count

- **Severity:** Medium
- **Status:** Confirmed
- **Location:** `Golang-tudor-dnssec-signer/daemon.go`, `checkAndSignZone`, `checkAndSignZoneSafe`; `health.go`, `healthHandler`, `healthzHandler`; `status.go`, `buildStatusOutput`; `internal/metrics/metrics.go`, `UpdateZoneMetrics`.
- **Problem:** If a configured zone has no state and key recovery/generation fails, the daemon returns before creating an error-bearing zone or recording a failed signing operation. Status, metrics and health enumerate only state, so the failed zone is invisible and health can return 200 with all counted zones healthy. Zero signing/expiry timestamps are also skipped rather than identifying an uninitialized zone.
- **Evidence:** The `RecoverOrGenerateKeys` error branch returns before `SetZone`, `AddError`, `RecordSigningOperation` and `SigningError`. Health checks directory writability and existing state entries; it never compares them to `cfg.Zones`. Its expiration loop ignores zero timestamps.
- **Fix specification:** Track initialization failure for every configured zone, using a retryable placeholder or separate operational status. Reconcile configured/managed counts and make readiness fail for a configured zone that has never produced a valid deployed generation. Preserve error recovery on later cycles and distinguish liveness from readiness; do not expose private key data in status.
- **Verification:** Start with writable directories and a corrupt existing key pair for a configured zone absent from state. Assert the zone appears with its error, failure metrics increment, and readiness is unsuccessful. Repair keys and verify initialization clears the error and restores readiness.

## RA6X-034 — Hook timeouts do not bound descendants holding inherited stderr pipes

- **Severity:** Medium
- **Status:** Confirmed on darwin/arm64 by an isolated hook probe; verify the fix on other supported Unix targets
- **Location:** `Golang-tudor-dnssec-signer/hooks.go`, `executeHook`, `executeBatchHook`, `executeHookSync`; `daemon.go`, hook wait/shutdown handling.
- **Problem:** Hooks use `exec.CommandContext` to kill the direct process after 30 seconds, but do not configure `WaitDelay` or terminate a process group. In asynchronous paths, stderr is copied through a pipe into a capped writer. A shell's descendant can retain that pipe after the shell is killed, keeping `Run` blocked beyond the advertised timeout. Repeated cycles can accumulate stuck hooks and external reload operations, and shutdown tracking can remain occupied.
- **Evidence:** Both asynchronous paths set `command.Stderr = stderrBuf` and call `command.Run()` with no pipe-wait bound or process-tree cleanup. The buffer cap limits memory per hook, not subprocess lifetime. An isolated test invokes the real `executeHook` with argv `sh -c 'sleep 35 & wait'`, waits on its supplied wait group, and measures 35.014 seconds despite the 30-second timeout. The same inherited-pipe mechanism has no upper bound when the child does not exit.
- **Fix specification:** Bound command and pipe-drain lifetime, and define supported-platform process-tree cancellation for timed-out hooks. Preserve useful stderr prefixes, existing hook environment and successful long-but-within-budget hooks. Ensure descendants cannot later deploy a stale generation after a timeout; coordinate deployment ordering with RA6X-004.
- **Verification:** Run a hook whose shell launches a child inheriting stderr and which outlives the shell timeout. Check elapsed execution/shutdown time, child cleanup and subsequent hook ordering on FreeBSD/Linux/macOS; include exec-style and shell-style hooks and a child that ignores the first termination signal.

## RA6X-035 — Missing signed output does not trigger regeneration while state still looks fresh

- **Severity:** Medium
- **Status:** Confirmed
- **Location:** `Golang-tudor-dnssec-signer/internal/signer/sign.go`, `NeedsSign`; `daemon.go`, reload and signing-cycle change detection.
- **Problem:** Change detection relies on unsigned source metadata, forced signing and signature refresh time; it does not verify the published output exists. Deleting/restoring only part of the output directory, or changing `output_dir` on reload, can leave a zone without a signed file until the next signature refresh even though the daemon is running and state reports a recent success.
- **Evidence:** `NeedsSign` receives the source path and checks source/state timestamps and size; there is no stat/read check of `<output_dir>/<domain>.zone.signed`. Reload does not force regeneration solely because the output directory changes.
- **Fix specification:** Treat absent/unreadable/non-regular output and a changed output destination as requiring safe regeneration/deployment. Reconcile directory setup on reload, preserve the prior served generation when the new destination fails, and record output-specific failures in readiness. Avoid re-signing every poll or using output mtime as the sole proof of integrity.
- **Verification:** Sign a zone, remove its output while keeping source/state unchanged, and run a cycle: the output must be restored immediately. Repeat after changing output directory and with an unwritable destination; verify error visibility and preservation of the prior served file.

## RA6X-036 — Syntactically valid malformed state is accepted and later panics or changes rollover interpretation

- **Severity:** Medium
- **Status:** Confirmed
- **Location:** `Golang-tudor-dnssec-signer/internal/state/state.go`, `LoadState`, `ReloadFromDisk`, `SetZone`, `SnapshotZones`; `internal/signer/sign.go`, `loadKeysForSigning`.
- **Problem:** JSON parsing is treated as full state validation. `{"zones":null}` replaces the initialized map with nil, and null zone entries are accepted. Later writes/dereferences panic. Unsupported rollover types/phases and inconsistent identities are also not rejected at load time, allowing fallback signing paths to interpret damaged state as ordinary operation. This is particularly dangerous during recovery or state migration.
- **Evidence:** `LoadState` returns immediately after `json.Unmarshal`; `ReloadFromDisk` dereferences `diskZone.LastSigned` without checking for null entries. `SetZone` assigns into the map. Signing switches on recognized rollover type/phase without an exhaustive validated state boundary.
- **Fix specification:** Validate and normalize the persistence schema before exposing state: initialize an explicitly allowed empty map, reject null zone entries, invalid domains/paths, impossible phase/type combinations and inconsistent key identities. Preserve backward-compatible omitted fields with conservative defaults, while failing closed for ambiguous rollover state. Return actionable errors without overwriting the original file. Align with RA6X-002/025/026.
- **Verification:** Load null maps, null entries, unknown phases/types, missing rollover keys and supported legacy state fixtures through both startup and reload. Invalid state must return a controlled error and preserve output/disk evidence; valid legacy state must remain usable without silently dropping rollover keys.

## RA6X-037 — Signer heartbeat redirects can disclose its API key across origins or over HTTP

- **Severity:** Medium
- **Status:** Confirmed by an isolated local HTTP/TLS probe
- **Location:** `Golang-tudor-dnssec-signer/heartbeat.go:43–66`, `NewHeartbeatClient`, `Send` (111–136); `internal/config/config.go:506–508`.
- **Problem:** Configuration requires HTTPS unless explicitly overridden, but the HTTP client follows redirects without enforcing that restriction. A 307/308 response replays the form body, including the API key, to a different origin or a cleartext destination. The sibling validator's heartbeat client already constrains redirects, so the shared security expectation is implemented inconsistently.
- **Evidence:** The client sets only `Timeout`; `Send` puts `api_key` in a replayable `strings.Reader` POST body. A TLS `httptest` endpoint redirecting with 307 to a second plain HTTP server caused that server to receive the synthetic API key with `AllowInsecure` left false. The test changed only TLS trust roots using the test server's client, retaining Go's default redirect behavior.
- **Fix specification:** Apply an explicit redirect policy before replaying credential-bearing requests: reject cross-origin redirects and HTTPS downgrades, or disable redirects entirely with an actionable error. Preserve legitimate same-origin endpoint normalization if supported, bounded redirect counts, event queue behavior and the explicit initial-HTTP development override. Do not log the key, form body or secret-bearing URLs.
- **Verification:** Test 307 and 308 redirects from a trusted local TLS endpoint to another HTTPS origin and to HTTP; the destination must receive no request containing the key. Test same-origin redirects, loops and the explicit development override separately.

## RA6X-038 — Config add/remove operations can turn valid TOML into a corrupted configuration

- **Severity:** Medium
- **Status:** Confirmed by two isolated config-editing probes
- **Location:** `Golang-tudor-dnssec-signer/internal/config/config.go:618–736`, `AddZoneToConfigFile`, `RemoveZoneFromConfigFile`, table-header helpers.
- **Problem:** Removal recognizes headers by line text without tracking TOML string context. A header-looking line inside a multiline hook string can be mistaken for the actual zone table; removal then deletes the string terminator and unrelated contents. Addition uses Go `%q` escaping for TOML strings, which emits escapes that TOML rejects for otherwise valid Unix filenames. Both operations return success after replacing the configuration without parsing the result.
- **Evidence:** Start with valid TOML consisting of `[hooks]`, `post_sign = '''`, a line `[zones."example.com"]`, `printf hello`, the closing `'''`, then the actual `[zones."example.com"]` table and its path. `RemoveZoneFromConfigFile` returns nil and the resulting file fails with an unterminated multiline literal string. Separately, adding a source path containing a literal BEL byte writes `\a` using `%q`; the TOML decoder rejects that escape. Both behaviors reproduced in temporary files.
- **Fix specification:** Identify zone tables using TOML syntax/context, preserving unrelated tables, multiline strings and comments. Serialize newly added values using TOML-compatible escaping. Before atomic replacement, parse and validate the candidate and assert that its semantic change is limited to the intended zone. Handle supported whitespace, quoted keys and commented headers consistently. Preserve CLI syntax, existing config fields, permissions and the useful comment-preserving behavior; failure must leave the original bytes intact.
- **Verification:** Add/remove zones from configurations with basic/literal multiline hook strings containing apparent headers, commented headers, spaced/dotted table syntax, escaped paths and final tables without trailing newlines. Assert valid TOML before/after and equality of unrelated configuration values. Invalid candidate output must never replace the original.

## RA6X-039 — Registrar diagnostic script signs the wrong bytes for empty request bodies

- **Severity:** Medium
- **Status:** Confirmed with synthetic credentials and a stubbed curl executable
- **Location:** `Golang-tudor-dnssec-signer/scripts/dynadot-probe.sh:137–141`, `call`; reference implementation `internal/registrar/dynadot.go`, request signature construction.
- **Problem:** Bash command substitution strips trailing newlines from the constructed string to sign. GET and DELETE have empty bodies, so required separators disappear and their HMAC differs from the Go adapter. This diagnostic can report authentication failure even with correct credentials, undermining investigation of registrar publication failures. Bodies ending in newlines have the same defect.
- **Evidence:** `string_to_sign=$(printf '%s\n%s\n%s\n%s' "$API_KEY" "$path" "$req_id" "$body")` loses two trailing LF bytes when both request ID and body are empty, and one when an ID is present. A local run of `get` and `del`, with no network request, produced signatures different from an independent HMAC over `api_key + "\n" + path + "\n\n"`.
- **Fix specification:** Construct/sign the exact byte sequence without lossy command substitution, for example using Bash's `printf -v` or a direct pipeline that preserves trailing bytes. Keep the raw request body identical to the signed body, preserve optional request IDs and the existing macOS Bash 3.2 compatibility, and make the redacted diagnostic accurately show separator bytes. Do not change the Go adapter's authentication formula.
- **Verification:** Compare script signatures with the Go adapter or fixed independent vectors for GET, DELETE and PUT, with/without request IDs and with empty/newline-terminated bodies. Use synthetic credentials and a local/stub transport; no registrar mutation is needed.

## RA6X-040 — Startup can race configuration reload before workers obtain a guarded snapshot

- **Severity:** Medium
- **Status:** Confirmed by Go's race detector in an isolated startup/reload probe
- **Location:** `Golang-tudor-dnssec-signer/daemon.go:180`, `Reload`; `daemon.go:287`, `runSigningLoop`; `Run` startup and `main.go`, `runServe` signal handling.
- **Problem:** Reload replaces `d.cfg` under the daemon mutex, but the signing goroutine reads its initial poll interval without that mutex. A SIGHUP during startup can race that read. Other startup references, notably starting `d.heartbeat`, similarly occur outside the snapshot guard. A mutex around writes alone does not make publication safe, and startup/shutdown ordering needs a coherent lifecycle boundary.
- **Evidence:** A temporary test creates a daemon, starts `runSigningLoop` with its wait-group registration, calls `Reload` repeatedly with fresh config copies, then cancels and waits. `go test -race . -run TestAstra6StartupReloadRace -v` reports the read at `daemon.go:287` racing the write at line 180. The ordinary suite passes because it does not exercise this startup interleaving.
- **Fix specification:** Read the initial configuration and worker dependencies through a guarded immutable snapshot, or serialize reload until startup has published a ready lifecycle state. Audit every startup reference to pointers swapped by reload and coordinate heartbeat start/stop and worker registration with cancellation. Preserve hot reload, listener restrictions, poll-interval reset behavior and graceful shutdown; do not hold the daemon lock across network operations.
- **Verification:** Add deterministic startup barriers around worker creation and snapshot acquisition, reload at each barrier, and run under `-race`. Also deliver shutdown before/after those boundaries and assert no worker starts after shutdown completion and no heartbeat/client remains orphaned.

## RA6X-041 — Unusable anchor refreshes can replace working trust anchors and suppress fallback

- **Severity:** Medium
- **Status:** Confirmed from the load/refresh data flow
- **Location:** `Golang-dnssec-validator/internal/dns/anchors.go:107–147`, `finalizeAnchors`; `LoadAnchorsWithFallback` (233–246); `GetActiveAnchors` (250–276); `anchors_store.go:28–39`, `Load`.
- **Problem:** The loader validates expiry and digest structure, but does not require a currently active pinned anchor. A file containing only future-dated anchors, or anchors with malformed/missing `ValidFrom`, counts as a successful nonempty load and prevents URL fallback. An empty anchor set returned by the URL also counts as success. Refresh then overwrites the last usable set and resets its age, turning a recoverable bad mirror update into a validation outage until a later successful reload.
- **Evidence:** File fallback tests only `len(anchors.Anchors) > 0`; active-date filtering occurs later in `GetActiveAnchors`. `AnchorsStore.Load` unconditionally assigns the returned set and `loadedAt`. Thus a correctly pinned tuple with `ValidFrom` in the future passes file loading but yields zero active anchors. This is separate from the authenticity flaw in RA6X-008.
- **Fix specification:** Validate dates and require at least one currently usable authenticated anchor before declaring a source/load successful. Retain future anchors alongside active ones for rollover. Try the configured fallback for an unusable file; if every source fails, retain any still-valid last-known-good set and do not reset successful-refresh metrics. Never continue trusting expired anchors merely to preserve availability. Preserve file-first/offline operation and static pinning unless deliberately redesigned with RA6X-008.
- **Verification:** Refresh a working store with future-only, malformed-date, expired-only and empty source documents; test both file and URL paths. Require fallback or a controlled error without replacing a still-valid set/resetting its timestamp. A mixed active/future set must load and make the future key usable at its activation time.

## RA6X-042 — Signing has no stable-source snapshot boundary

- **Severity:** Medium
- **Status:** Needs investigation — establish whether all deployed zone producers use atomic replacement
- **Location:** `Golang-tudor-dnssec-signer/internal/signer/sign.go:106–121`, `SignZone`, `parseZoneFile`, `NeedsSign`; `daemon.go`, `checkAndSignZone`.
- **Problem:** The signer stats a pathname, then separately opens/parses it without checking that it read one stable version. An in-place truncate/rewrite can expose a syntactically valid prefix containing SOA and NS but missing the rest of the zone. That prefix can be signed, including authenticated denial for omitted names, and replace the complete output. Poll quiescence cannot protect a write that begins after the check; forced/CLI signing bypasses change detection. A non-regular source can also block parsing while the global state lock is held.
- **Evidence:** The only captured metadata is from `os.Stat` before `parseZoneFile`; there is no post-read identity/size/time check or writer coordination before output replacement. Current syntax/semantic verification cannot distinguish a complete small zone from an incomplete but valid prefix. A later poll detecting another change does not prevent temporary publication of missing records.
- **Fix specification:** Define a stable input contract across all signing entry points. Prefer producer-side write/fsync/atomic rename and document/enforce that deployment requirement. Read through one regular-file descriptor, reject unsupported stream/device sources, and detect changes during reading before publishing. If in-place writers must be supported, coordinate snapshots with them; metadata checks alone cannot establish completeness of a paused valid prefix. Preserve valid small zones, explicit force-sign behavior on stable input and the last good output on failed snapshots.
- **Verification:** Use a writer with barriers after truncation, after a valid SOA/NS prefix and during remaining writes. Trigger daemon refresh, forced rollover and CLI signing at each point; no partial generation may publish. Test atomic replacements during reads and a FIFO source without allowing a hung test. Inspect actual deployment scripts to resolve the producer-contract assumption.

## RA6X-043 — CLI signing does not honor the daemon's per-zone/batch hook contract

- **Severity:** Medium
- **Status:** Confirmed
- **Location:** `Golang-tudor-dnssec-signer/main.go:631–636`, `runSign`, `runPostSignHook`; `hooks.go`, `executeHookSync`, `executeBatchHook`; `README.md:297–314`.
- **Problem:** One-shot `sign` invokes the hook once with only `OutputDir`, leaving per-zone variables empty and never supplying batch variables. Single-zone CLI commands also use the per-zone synchronous helper even when coalescing is configured. A reload script written against the documented daemon contract can therefore reload nothing, fail, or act on inherited/stale environment values in CLI/cron operation.
- **Evidence:** `runSign` passes `&HookEnv{OutputDir: cfg.OutputDir}` to `executeHookSync` irrespective of `CoalescePostSign`. The batch helper alone sets `DNSSEC_DOMAINS` and `DNSSEC_BATCH_SIZE`; the synchronous helper sets only the four per-zone variables. The environment test calls the helper directly with a populated `HookEnv`, so it misses the empty caller data.
- **Fix specification:** Share hook invocation semantics between daemon and CLI. Track the zones actually signed successfully; invoke per-zone hooks with their exact source/output paths, or one synchronous batch hook with those domains when coalescing is enabled. Define single-zone batch behavior consistently and prevent inherited opposite-mode variables from misleading scripts. Preserve argv/shell selection, partial-success publication and the existing documented variable names. Propagate deployment failures as specified by RA6X-004.
- **Verification:** Run the actual `sign`, `resign`, add/import and rollover CLI handlers with a hook recording all `DNSSEC_*` variables. Test zero/one/multiple successful zones, mixed failures, both coalescing settings and preexisting environment variables. Assert the correct successful zones and paths are supplied and completion is synchronous.

## RA6X-044 — Ownership failures are reported as successful key/state publication

- **Severity:** Medium
- **Status:** Confirmed error-handling gap; first-run impact depends on the service account/deployment
- **Location:** `Golang-tudor-dnssec-signer/internal/fsutil/fsutil.go:35–89`, `InitOwnershipTarget`, `ChownToTarget`; `WriteFileAtomicOwned` (111–148); CLI directory setup.
- **Problem:** Ownership-aware writes return success even when ownership transfer fails, so root-run CLI commands can replace daemon-readable keys/state with root-owned 0600 files. On a first root-run command with no `data_dir`, owner inference silently does nothing; the comment says the daemon will create the tree later, but the CLI itself creates it first. Starting an unprivileged daemon afterward cannot repair/access root-owned 0700 key directories.
- **Evidence:** `InitOwnershipTarget` returns on every `Stat` error, including missing directory. `ChownToTarget` logs and discards `os.Chown` errors. `WriteFileAtomicOwned` continues to rename after a failed chown of the staged file. This differs from `WriteConfigFileAtomic`, which correctly aborts before replacement if preserving ownership fails.
- **Fix specification:** Treat required owner/mode assignment as part of the staged write's success contract and fail before replacing a readable predecessor when it cannot be applied. Distinguish no configured target from a failed attempt to inspect one. Provide an explicit bootstrap account/ownership procedure when the tree does not exist instead of assuming a later daemon start repairs it. Preserve intentional root-only deployments, existing daemon ownership and config-file ownership separation; never infer an arbitrary non-root account.
- **Verification:** Fault-inject chown failure before replacement and assert the old key/state remains readable and the CLI returns a specific error. On a disposable Unix system, bootstrap as root with a missing tree then run as the documented service user; setup must either establish usable ownership or fail with exact corrective instructions. Cover an existing correctly owned tree and deliberate root-only operation.

## RA6X-045 — Deployment walkthroughs contain commands that prevent a working installation/reload

- **Severity:** Medium
- **Status:** Confirmed artifact/path inconsistencies; service authorization must be validated on the target OS
- **Location:** `Golang-dnssec-validator/QUICKSTART-FREEBSD.md:9–16,66–73,115`; validator `Makefile:43–46`; `Golang-tudor-dnssec-signer/QUICKSTART.md:25–28,54,150–154,209–210`; signer `README.md:125–126`.
- **Problem:** The FreeBSD validator walkthrough builds one path and installs another, which fails on a clean checkout or installs a stale local binary. It also copies an Apache snippet under one basename and includes another. The signer walkthrough pairs an unprivileged service with `systemctl reload nsd` without granting the service the necessary reload authority, and calls the account optional although its service unit requires it. Its advice to change only the algorithm config does not migrate existing keys and can contribute to RA6X-001.
- **Evidence:** `make build-freebsd` emits `build/dnssec-validator-freebsd-amd64`, but installation reads `dnssec-validator`. Copying `apache-dnssec-validator.conf` into the Includes directory retains that basename, while the shown `Include` names `dnssec-validator.conf`. Signer systemd sets `User=dnssec-tudor`; no matching noninteractive reload permission/control-socket setup appears in the steps.
- **Fix specification:** Make walkthrough build/install/include paths agree with shipped artifacts. Define one complete unprivileged setup including account creation, source/output accessibility and narrowly scoped reload authorization appropriate to NSD/systemd. Replace config-only algorithm migration advice with the supported rollover workflow and its publication requirements. Preserve default loopback exposure and avoid broad privilege grants or instructions to regenerate a live KSK.
- **Verification:** Follow each walkthrough in a clean disposable target environment without preexisting artifacts or privilege rules. Confirm the installed binary matches the just-built artifact, Apache config validation succeeds, the service account can sign and reload NSD noninteractively, and a changed serial/signature is actually served. Exercise existing-key algorithm migration.

## RA6X-046 — Current guidance and historical compliance prescriptions conflict with the implementation

- **Severity:** Low
- **Status:** Confirmed documentation/maintenance hazard
- **Location:** `Golang-dnssec-validator/docs/RFC_FIXES.md`, multi-algorithm and denial-proof prescriptions; `docs/RFC_COMPLIANCE.md`, algorithm support/status claims; `Golang-tudor-dnssec-signer/RFC_COMPLIANCE_REVIEW.md:168–183`; signer `CLAUDE.md`, rollover and future-scope sections.
- **Problem:** Documents reachable as technical guidance contain obsolete or incorrect implementation prescriptions without a clear superseded boundary. Examples include requiring all DS algorithms to match, presenting weak denial checks as compliance fixes, and claiming complete production compliance despite unsupported paths. The signer guidance also labels implemented features out of scope. This can cause a future engineer or coding agent to reintroduce previously corrected validation behavior or skip the missing invariants documented here.
- **Evidence:** The validator's current `ValidateChainLink` and its updated tests implement any-valid-path behavior, while the older RFC fix instructions prescribe all-algorithm matching. Signer compliance text states all issues addressed/all authoritative scenarios supported; RA6X-001–004/028–029 demonstrate concrete exceptions. Historical status checklists are not evidence that current call paths enforce their claimed properties.
- **Fix specification:** Mark historical reviews/plans as dated and superseded without rewriting their historical record. Make current technical guidance state tested capabilities, unsupported denial/algorithm cases and operational assumptions, and point to executable regression coverage. Correct normative RFC claims against primary text, especially any-valid-path and authenticated denial. Do not change validation behavior merely to match obsolete prose or discard previous incident evidence.
- **Verification:** Trace every current support/compliance claim to an implementation path and meaningful test. Ensure README/agent guidance directs maintainers to the current contract; explicitly label archived instructions so they cannot reasonably be mistaken for pending fixes.

## RA6X-047 — Generated ED25519 private files are not directly readable by the BIND-format reader

- **Severity:** Low
- **Status:** Needs investigation — incompatibility reproduced; clarify whether external key-file interoperability is an intended contract
- **Location:** `Golang-tudor-dnssec-signer/internal/signer/keys.go:380–391`, `formatPrivateKey`, key generation; `README.md`, key import/recovery documentation.
- **Problem:** Newly generated ED25519 private files use the BIND-style v1.3 header but store Go's 64-byte expanded key. The dependency's BIND-format reader expects the 32-byte seed and rejects the file. Internal signing supports both representations, so this is an external migration/recovery limitation rather than an immediate signing failure. Imported 32-byte keys and generated 64-byte keys also produce different compatibility outcomes.
- **Evidence:** An isolated test generates an ED25519 pair, passes `formatPrivateKey(key, private)` into the installed `miekg/dns` `ReadPrivateKey`, and gets `dns: bad private key`. Serializing `private.Seed()` instead is accepted. The README describes conversion into the tool's own format, so a required round-trip/export guarantee needs confirmation rather than assumption.
- **Fix specification:** If these files are intended for standard-tool recovery, serialize valid ED25519 keys as 32-byte seeds while continuing to read legacy 64-byte files, or provide a documented explicit conversion/export path. Validate seed/public correspondence before conversion (RA6X-030). If the format is intentionally private, document the limitation and safe recovery conversion clearly. Preserve key identity/DS records and never regenerate keys to solve a format mismatch.
- **Verification:** Round-trip newly generated and imported keys through both the internal loader and an independent BIND/ldns-compatible reader, then sign and verify the same RRset. Confirm unchanged DNSKEY/DS bytes and backwards compatibility with existing expanded-key files.

## RA6X-048 — CLI paths inconsistently persist and clear operational errors

- **Severity:** Medium
- **Status:** Confirmed
- **Location:** `Golang-tudor-dnssec-signer/main.go:618–649`, `runSign`; `runResign` (676–691); single-zone rollover signing handlers; `internal/signer/sign.go:77–83,203–227`.
- **Problem:** One-shot ZSK rollover failures are logged but neither added to zone errors nor included in the returned error, so cron can exit successfully while rollover repeatedly fails. Conversely, a successful explicit `resign` does not clear a prior signing error, leaving status/readiness erroneous after repair. A failing single-zone sign returns an error without recording it in persisted zone status. These paths disagree with `SignAll` and daemon error bookkeeping.
- **Evidence:** The `CheckZSKRollover` error branch in `runSign` only calls `slog.Error`; final success depends on `signErr` alone. `SignAll` explicitly adds/clears errors around `SignZone`, whereas `runResign` calls `SignZone` and saves without either operation. `SignZone` itself clears transient warnings, not errors.
- **Fix specification:** Centralize operation-result bookkeeping across daemon and CLI: persist current per-zone signing/rollover failures, return an aggregate failure for cron, and clear only the resolved operation's errors after successful repair. Retain unrelated registrar/deployment errors and continue signing/deploying successful zones. Preserve status JSON fields and command syntax; align hook failures with RA6X-004 rather than conflating signing and deployment.
- **Verification:** Force a rollover backup/write failure after successful one-shot signing and require a nonzero exit plus a persistent zone error. Seed a signing error, repair its cause and run `resign`; status must recover. A new failing `resign` must appear in status while preserving unrelated errors and the last good output.

## RA6X-049 — Atomic-write helpers silently discard the durability result

- **Severity:** Medium
- **Status:** Confirmed
- **Location:** `Golang-tudor-dnssec-signer/internal/fsutil/fsutil.go:141–148,199–230`, `WriteFileAtomicOwned`, `WriteConfigFileAtomic`, `SyncDir`; key backup/activation and state/config callers.
- **Problem:** Helpers advertised as durable report success even if opening/fsyncing the containing directory fails after rename. The failure is logged only at debug level. A caller can advance a rollover or announce a persistent config/state update even though the directory entry is not known to survive a crash. This weakens the recovery guarantees needed by RA6X-002/023 independently of atomic visibility.
- **Evidence:** `SyncDir` returns no error; both error branches only call `slog.Debug`. Both atomic write helpers then return nil. A successful file-content fsync does not by itself establish durability of the subsequent directory rename.
- **Fix specification:** Return and propagate durability outcomes for critical key/state/config commits, distinguishing a pre-rename failure from a visible-but-durability-uncertain commit. Recovery must reconcile the actual visible generation; do not blindly delete/roll back a possibly committed file. Explicitly classify unsupported directory-sync behavior on supported filesystems/platforms instead of treating all I/O errors as harmless. Preserve atomic replacement, file formats and predecessor recovery material.
- **Verification:** Inject directory-open and directory-fsync errors before/after activation. Assert actionable errors and conservative rollover/publication behavior, then restart and reconcile the visible state. Run crash/recovery tests on supported deployment filesystems; distinguish atomicity from persistence across power loss.

## Checkpoint summary

| Severity | Count | Findings |
|---|---:|---|
| Critical | 2 | RA6X-007, RA6X-008 |
| High | 20 | RA6X-001, RA6X-002, RA6X-003, RA6X-004, RA6X-005, RA6X-006, RA6X-009, RA6X-010, RA6X-011, RA6X-012, RA6X-013, RA6X-015, RA6X-016, RA6X-023, RA6X-024, RA6X-025, RA6X-026, RA6X-027, RA6X-028, RA6X-031 |
| Medium | 25 | RA6X-014, RA6X-017, RA6X-018, RA6X-019, RA6X-020, RA6X-021, RA6X-022, RA6X-029, RA6X-030, RA6X-032, RA6X-033, RA6X-034, RA6X-035, RA6X-036, RA6X-037, RA6X-038, RA6X-039, RA6X-040, RA6X-041, RA6X-042, RA6X-043, RA6X-044, RA6X-045, RA6X-048, RA6X-049 |
| Low | 2 | RA6X-046, RA6X-047 |

Provisional fix order: validator RA6X-007/008/016 → RA6X-009/017/041 → RA6X-010–014/015/019 → RA6X-018/022. Signer persistence RA6X-006/026/036/040/044/049 → RA6X-025 → RA6X-002/023/030 → RA6X-038/024/001/005. Signer publication RA6X-028 → RA6X-029; RA6X-042/035/034/043/031 → RA6X-004/027 → RA6X-003. RA6X-032/033/048 follow corrected state/publication semantics. RA6X-020/021/037/039 are independent; RA6X-045/046/047 document and verify the corrected contracts. Supporting-file and test coverage review remains in progress.
