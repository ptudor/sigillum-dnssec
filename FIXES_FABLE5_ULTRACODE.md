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

