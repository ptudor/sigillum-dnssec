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

## Checkpoint summary

| Severity | Count | Findings |
|---|---:|---|
| Critical | 2 | RA6X-007, RA6X-008 |
| High | 13 | RA6X-001, RA6X-002, RA6X-003, RA6X-004, RA6X-005, RA6X-006, RA6X-009, RA6X-010, RA6X-011, RA6X-012, RA6X-013, RA6X-015, RA6X-016 |
| Medium | 7 | RA6X-014, RA6X-017, RA6X-018, RA6X-019, RA6X-020, RA6X-021, RA6X-022 |
| Low | 0 | None recorded yet |

Provisional fix order: RA6X-007/008/016 → RA6X-009/017 → RA6X-010–014/015/019 → RA6X-018/022. Independently: RA6X-006 → RA6X-002 → RA6X-001/005 → RA6X-004 → RA6X-003. RA6X-020/021 can be fixed independently. The remaining signer/supporting-file review is in progress.
