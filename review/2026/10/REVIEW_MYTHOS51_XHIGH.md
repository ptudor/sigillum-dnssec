# Deep code review — Mythos 5.1 XHigh

Review date: 2026-10-07  
Scope: the complete repository at commit `deda2c4` (v1.1.1): both Go modules (`signer/`, `validator/`), their embedded web assets, packaging and service definitions, release tooling, CI workflows, shipped configuration and documentation, and the test suites (read for coverage, not re-reviewed).  
Method: every non-test source file was read in full by the lead reviewer; eight parallel adversarial sub-reviews (signer daemon/CLI, signing and key core, state/config/filesystem, internet validation and registrar, validator engine, validator DNS/RDAP/config, validator HTTP layer, packaging/CI/docs) each read their area line by line and the lead reviewer re-verified every reported item against the code before including it. `go vet ./...`, `go test -race -count=1 ./...` and `govulncheck ./...` (module and call-graph scans) were run in both modules: all clean. Three signer findings were additionally confirmed empirically by running a locally built `sigillum-signer add` against a scratch configuration (symlinked output, NSEC TTL, CDS signing key); one suspected validator issue (Go `ReadTimeout` cancelling long SSE handlers) was disproved by experiment and is not reported.

The five previous rounds (`review/2026/08`, `review/2026/09`) were read first; items their verification tables mark PASS are not re-reported unless this round found the fix incomplete, in which case the finding says so.

The review is analysis only. No source files were changed.

Severity scale: **Critical** = exploitable or data-destroying in normal operation; **High** = likely to produce a DNSSEC outage, a silent safety failure or a stuck automation in realistic deployments; **Medium** = a real correctness, security or robustness defect with a workaround or narrow trigger; **Low** = defects that mask bugs, maintainability traps, docs/code contradictions. "Needs investigation" marks items whose mechanism is confirmed from the code but whose real-world trigger or impact was not measured.

All eight sub-reviews were received. The validator-engine probes cited below were run against a scratch copy of the module (not committed to the module itself); they build only on the existing `harness_test.go` fixture and are preserved verbatim in `REVIEW_MYTHOS51_XHIGH_validator_probes.go.txt` next to this document so each can be dropped into `validator/internal/validator` as a regression test once its finding is fixed. Findings are numbered sequentially in severity order; the summary table at the end lists them by severity and the fix order accounts for dependencies.

## Findings

### RM51X-001 — KSK and algorithm rollovers remove or add the parent DS without waiting for the new DNSKEY RRset to propagate

**Severity:** High

**Location:** `signer/internal/signer/rollover.go:200-239` (`CompleteKSKRollover`), `rollover.go:245-280` (`CheckKSKRollover`), `rollover.go:602-695` (`StartAlgorithmRollover`, the `Action` text at 667), `signer/internal/registrar/registrar.go:60-84` (`IncludesOldDS`), `signer/registrar_cli.go:396-419` (`autoPublishDS` op dispatch, `replace = !registrar.IncludesOldDS(rollover)` at 410), `signer/main.go:1537-1546` (`runRolloverComplete` → `MaybeAutoPublishDS(..., "rollover_complete")`), `signer/main.go:1607-1611` (`runRolloverAlgorithm` → `MaybeAutoPublishDS(..., "rollover_start")`); contrast the ZSK gates at `rollover.go:478-494` and `525-546`; docs `signer/CLAUDE.md:360-376`, `signer/README.md:342-349`.

**Problem:** RFC 6781 §4.1.2 (KSK) and §4.1.4 (algorithm) require that the DS at the parent only changes after the new DNSKEY RRset (and, for an algorithm roll, the new-algorithm signatures) has propagated: every authoritative server serves it and one DNSKEY TTL has elapsed so no resolver still caches the old-only RRset. The ZSK state machine implements exactly this (`PublishedSince(phaseStart)` plus `stampPhasePublication` with the DNSKEY cache horizon). The KSK and algorithm paths do not. `rollover complete` checks only that the new DS is visible at every parent server, moves the record to `ds_propagation_wait`, and in that state `IncludesOldDS` is already false, so the registrar automation immediately calls `ReplaceDS` with the new-only set and the old DS disappears. For an algorithm rollover the new-algorithm DS is pushed additively at `rollover start`, seconds after the new keys were written and before any secondary has transferred the double-signed zone. Nothing consults `zoneState.PublishedSince(rollover.Started)` or `DNSKEYCacheHorizon` on either path, and `TestRDAYBLUEX007_KSKCompletionReplacesWithNewOnly` locks the start→complete→new-only sequence in with zero elapsed time. The documentation tells operators the old DS "may be removed at the registrar as soon as step 2 succeeds" and calls the algorithm sequence "conservative", which it is not.

**Evidence:** `registrar.go:78-79` — `case "ksk": return r.State == statepkg.KSKRolloverStateDSAddWait`; `registrar_cli.go:407-410` — `case "rollover_complete": replace = !registrar.IncludesOldDS(rollover)`; `rollover.go:227-238` — `CompleteKSKRollover` sets `ds_propagation_wait` and saves with no publication or TTL check; `main.go:1542-1543` — the replace runs as soon as `hookOK` (which in immediate mode is true at file write). Failing scenario: `publication = "immediate"` or `"hook"` (hook reloads the primary only), `auto_publish = true`, DNSKEY TTL 86400. `rollover start` at T0; the registry publishes the new DS within minutes; the operator runs `rollover complete` at T0+10m; the probe sees the new DS on every parent server; `ReplaceDS` leaves only the new DS. A secondary that has not yet transferred the T0 generation still serves DNSKEY(old only); every validator that reaches it now sees DS(new) with no matching key → bogus until the transfer. Independently, a resolver whose DS cache expires before its DNSKEY cache re-fetches DS(new only) and validates it against the cached old-only DNSKEY RRset → bogus for up to the remaining DNSKEY TTL. For the algorithm roll, a validator that enforces the signalled-algorithm rule (Unbound `harden-algo-downgrade`) goes bogus while its cached DNSKEY RRset lacks the new algorithm.

**Fix specification:** Introduce one "new DNSKEY RRset propagated" predicate shared by KSK and algorithm rollovers: `zoneState.PublishedSince(rollover.Started)` is true and `now >= max(PublishedAt of that generation + dnskeyTTLFloor(zoneState), zoneState.DNSKEYCacheHorizon)`; persist the computed instant in the existing `PhaseHorizon` field so it survives restarts. (1) `CompleteKSKRollover`/`CompleteAlgorithmRollover` must refuse while the predicate is false, naming the horizon and (in probe mode) the unconfirmed servers; `--force` may bypass the time floor only when it says so. (2) `IncludesOldDS` must keep returning true for `ds_propagation_wait` until the predicate holds, so neither `rollover complete`'s automation nor a later `registrar push` can shrink the parent set early; the daemon's `CheckKSKRollover` performs the new-only replace once the predicate holds (see also the retry finding below). (3) For the algorithm rollover, stop pushing the new-algorithm DS at `rollover start`; push it additively only once the predicate holds (a daemon-driven publisher op or an automatic sub-phase), keeping `algo_ds_add_wait` as the operator-facing state and the printed DS record for manual publication. (4) Correct `signer/CLAUDE.md` and `README.md` to describe the DNSKEY-TTL wait. Keep the registrar interface, CLI command names, config keys and the persisted phase names; older state records without a horizon are treated as "not yet satisfied" and stamped on the next cycle, exactly as the ZSK path does.

**Verification:** Extend `registrar_phase_rdaybluex007_test.go` with a fake prober and an injectable clock: after `StartKSKRollover` and an immediate `CompleteKSKRollover` the fake registrar must still hold old+new; it becomes new-only only after the horizon passes and `PublishedSince(Started)` holds; `rollover complete` without `--force` errors while the generation is pending in probe mode; algorithm `rollover start` pushes the old-DS-only set until the predicate holds. Run `go test -race ./...` in `signer`.

### RM51X-002 — Every parent and authoritative address must answer, so single-stack hosts can never complete a rollover, confirm a probe-mode publication or import

**Severity:** High

**Location:** `signer/internal/validate/parentds.go:148-224` (`discoverNSWith`; the family loop at 193-216 adds every A and AAAA address), `parentds.go:292-362` (`ProbeParentDS`; `if err != nil { return obs, ... }` at 318-321), `parentds.go:370-391` (`ProbePublishedSerial`; `return false, ..., nil` at 377-380); consumers `signer/internal/signer/rollover.go:818-826` (`CheckAlgorithmRollover` logs a probe failure at Debug and returns nil), `rollover.go:484-487` and `536-539` (ZSK phases wait on `PublishedSince`), `signer/daemon.go:1238-1260` (`probePendingPublications`), `signer/main.go:1487-1494` (`runRolloverComplete` refuses without `--force`), `signer/import_cli.go:430-433` (import requires the parent probe unless `--offline`).

**Problem:** RDAYBLUEX-003 made discovery cover every nameserver identity, but the probes then require every *address* of every identity — both families — to answer authoritatively. Every gTLD and ccTLD server has an AAAA record, so on a signer host without IPv6 connectivity (the project's own "colo box" target) every `ProbeParentDS` fails on the first AAAA address with a local dial error, and `ProbePublishedSerial` returns "not yet" forever. Consequences: `rollover complete` always refuses unless `--force` is passed; an algorithm rollover sits in `algo_old_ds_removal_wait` indefinitely with the cause logged only at Debug; with `publication = "probe"`, `PendingPublication` never clears, `PublishedSince` is never true, and the fully automatic ZSK rollover never leaves `pre_publish` while the old ZSK keeps signing past its lifetime; KSK/algorithm `retiring` never completes; `import` without `--offline` always fails. The same happens on an IPv6-only host for A addresses. Nothing in the documentation states a dual-stack requirement, and the health endpoints report the daemon healthy throughout.

**Evidence:** `parentds.go:193-216` collects `net.JoinHostPort(ip, port)` for `dns.TypeA` and `dns.TypeAAAA` with no connectivity policy; `parentds.go:318-321` returns the error of the first unreachable server; `parentds.go:377-380` turns any transport error into "not yet"; `rollover.go:823-826` swallows the error at Debug. `TestRDAYBLUEX003_OneFamilyGluePlusResolvedSecondFamily` asserts both families are probed; no test or document covers local reachability of one family.

**Fix specification:** Keep identity-level coverage as the safety requirement and make address-level failures family-aware: for each nameserver identity at least one of its addresses must answer authoritatively and consistently; an address that fails with a local, non-DNS transport error (`ENETUNREACH`, `EHOSTUNREACH`, `EADDRNOTAVAIL`, i.e. no route for that family) may be skipped only when another address of the same identity answered; timeouts, REFUSED/SERVFAIL, non-authoritative or mismatched answers must still fail the probe. Record skipped addresses in a new optional `ParentDSObservation.Skipped` field and in the `ProbePublishedSerial` details. Alternatively, or in addition, add `validate.address_families = "both" | "ipv4" | "ipv6"` (default `both`) and document it. In every case, log a probe failure that blocks a rollover phase at Warn with rate limiting and surface it as a transient zone warning so `status` shows why the phase is stuck. Preserve the fail-closed behaviour for every non-connectivity error and the existing observation fields.

**Verification:** Hermetic test: a delegation whose single nameserver has one address on the test server and one on an unroutable literal (`[100::1]:port`); assert `ProbeParentDS` succeeds with the skipped address reported and that a timeout (not a route error) still fails. Daemon test in probe mode with the same delegation: publication confirms and a ZSK rollover advances. Confirm the stuck-phase warning appears in `status`. Run `go test -race ./...` in `signer`.

### RM51X-003 — Owner names whose first label starts with `*` but is not a wildcard are signed with a wildcard `Labels` count; validators mark them bogus

**Severity:** High

**Location:** `signer/internal/signer/sign.go:1663-1690` (`createRRSIG` computes `Labels` correctly at 1670-1672), `sign.go:1692-1746` (`signRRSIG`: every branch calls miekg's `rrsig.Sign`, which overwrites `Labels` with `CountLabel(name)` minus one whenever the name merely starts with `*`), `sign.go:1400-1467` (`verifySignedZoneWithModel` never asserts `Labels`), `signer/internal/signer/zonemodel.go:47-62` (`canonicalLabel` emits a bare `*`).

**Problem:** RFC 4592 §2.1.1 makes `*foo.example.com.` and `**.example.com.` ordinary owner names; only a leftmost label that is exactly `*` is a wildcard. miekg/dns `RRSIG.Sign` tests `strings.HasPrefix(name, "*")`, so such names are published with `Labels = CountLabel − 1`, i.e. the signature claims a wildcard expansion. miekg's `Verify` reconstructs the signed name the same way, so the post-sign self-check passes and the zone is written. A real validator sees `Labels` below the owner label count, treats the answer as wildcard-synthesized, demands a no-closer-match NSEC/NSEC3 proof the server never sends for an exact name, and returns bogus for that name (the NSEC/NSEC3 at that owner has the same defect).

**Evidence:** The signing-core sub-review drove the real `SignZone` through a `go test -overlay` fixture: `RRSIG owner=**.example.com. covers=TXT Labels=2 CountLabel=3`, `RRSIG owner=*foo.example.com. covers=TXT Labels=2 CountLabel=3`, self-verification error `<nil>`; the true wildcard `*.example.com.` gets the correct `Labels=2`.

**Fix specification:** (1) In `canonicalLabel`, escape `*` as `\*` whenever the label is not exactly `*`, so the name handed to `Sign` never starts with a bare asterisk (wire-identical; `PackDomainName` resolves the escape); keep equal wire names mapping to equal canonical strings. (2) In `signRRSIG`, capture the intended `Labels` before `Sign` and fail closed if the library changed it. (3) In `verifySignedZoneWithModel`, assert for every RRSIG that `Labels == CountLabel(owner) − (1 if the leftmost canonical label is "*" else 0)`, and add the missing negative check that no RRSIG covers a non-signable RRset. RRSIGs for true wildcards, key files, state schema and config keys are unchanged.

**Verification:** Extend the wildcard/RA6X-028 tests with owners `*foo`, `**`, `*-x` and `a.*` in NSEC and NSEC3 modes; assert `Labels == CountLabel` for the non-wildcards; mutate an RRSIG `Labels` via `mutateBeforeVerify` and assert the verifier rejects it. Cross-check with `unbound-host`/`delv` against NSD serving the output.

### RM51X-004 — Package post-install re-applies ownership and mode to directories inside the service-owned state directory, a symlink privilege escalation on every upgrade

**Severity:** High

**Location:** `packaging/sigillum-signer-postinstall.sh:10-11` (`install -d -o sigillum-signer -g sigillum-signer -m 0700 /var/lib/sigillum-signer/keys` and `... -m 0750 .../signed`), `packaging/sigillum-signer-postinstall.sh:4` and `packaging/sigillum-signer.service:16-17` (the parent `/var/lib/sigillum-signer` is owned by the service account), `packaging/sigillum-signer-postinstall.sh:12-14` (`systemctl daemon-reload` immediately after).

**Problem:** GNU `install -d` on a pre-existing path opens it without `O_NOFOLLOW` and applies `fchown`/`fchmod` through that descriptor. Because the service account owns the parent directory, a compromised daemon (or anyone running as `sigillum-signer`) can replace `keys` with a symlink to any directory; the next `apt upgrade`/`dnf upgrade` runs the post-install as root, chowns the target (for example `/etc/systemd/system`) to the service account and chmods it 0700, and the following `daemon-reload` loads whatever drop-in the attacker placed there (`User=root`). The validator post-install is not affected because everything it touches lives under root-owned directories.

**Evidence:** The packaging sub-review reproduced the primitive with coreutils 9.11: `ln -s target parent/keys; install -d -m 0700 parent/keys` changed `target` to `drwx------` and left the symlink in place; `-o/-g` go through the same code path. Debian 13 and Fedora 43 ship coreutils 9.x.

**Fix specification:** Never apply ownership or mode to an entry that already exists inside a non-root-owned directory. Record `fresh=$([ -d /var/lib/sigillum-signer ] || echo 1)` before line 4 and run lines 10-11 only when `fresh=1`; on upgrades do nothing, since the daemon already creates and tightens both directories itself (`signer/internal/signer/keys.go:956-1001`). Do not replace with `[ -e ] || install -d` (still racy) and do not add a recursive chown. Keep the config-file ownership lines (root-owned directory, safe), `daemon-reload` and account preservation.

**Verification:** In `scripts/package-container-test.sh`, after the first install run `runuser -u sigillum-signer -- sh -c 'mv /var/lib/sigillum-signer/keys /var/lib/sigillum-signer/k; ln -s /etc/systemd/system /var/lib/sigillum-signer/keys'`, reinstall, and assert `stat -c '%U %a' /etc/systemd/system` is still `root 755`.

### RM51X-005 — A child zone inherits the grandparent's stale keys or the parent's unauthenticated keys when the parent is indeterminate: availability failures become Bogus, and zones below an indeterminate parent read Secure

**Severity:** High

**Location:** `validator/internal/validator/validator.go:475-483` (`nextParentDNSKEY` returns `zr.DNSKEY` whenever it is non-empty regardless of status, otherwise the previous keys), `validator.go:1422` (`result.DNSKEY = answerDNSKEYsOwnedBy(diag.DNSKEY, zone)` assigned from the first server's unverified answer before any authentication), the Indeterminate returns that keep it at `validator.go:1510-1512`, `1529-1532`, `1561-1564`, `1646-1649`; the zone loop `validator.go:243-346` stops only on Bogus (322-328) and continues past an Indeterminate zone (334-345); `validateZone`'s DS path `validator.go:1527-1574` returns Bogus at 1566-1574 when the child's DS RRSIG does not verify under the supplied keys; `finalizeNoDSDelegation` `validator.go:2135-2141` treats empty parent keys as the insecure-ancestor case.

**Problem:** One function, two failure modes. (a) Stale keys: a zone that ends Indeterminate with no DNSKEY (every server's DNSKEY query timed out, the typical shape for a large DNSKEY answer on a fragment-dropping path, see RM51X-024) makes `nextParentDNSKEY` hand the *grandparent's* keys to the child. The walk continues, the child's DS is fetched from the reachable parent servers and its RRSIG is verified under the wrong keys, `validateZone` returns Bogus ("DS RRSIG verification failed: no eligible trusted key with tag …"), and because Bogus short-circuits the loop the **overall verdict is Bogus** for a correctly signed zone whose parent merely could not be fetched. (b) Unauthenticated keys: `result.DNSKEY` is filled from the first server's answer for diagnostics before authentication, and when the zone ends Indeterminate for any other reason (DS query failed, no active anchor, budget exhausted) those keys are handed down unchanged. The child's DS RRSIG is then verified under keys nobody authenticated, the child's `ZoneResult.Status` becomes `secure` with a `chain_link`, and the `chain` array and the SSE `zone` events present a per-zone assurance that was never earned; the top-level verdict stays Indeterminate only because `lastStatus` never returns to Secure. The comment on `nextParentDNSKEY` reasons only about laundering into Insecure (which it correctly prevents); it does not consider that keeping keys converts an availability failure into a cryptographic one, nor that `zr.DNSKEY` is not an authenticated set.

**Evidence:** Probe `TestProbe_F1_IndeterminateParentMakesChildBogus` (parent `test.` DNSKEY dropped and not cached, child DS served normally): `zone test. status=indeterminate errors=[failed to query DNSKEY from any nameserver]`, `zone child.test. status=bogus errors=[DS RRSIG verification failed: … no eligible trusted key with tag 60639 …]`, `RESULT=bogus`. Probe `TestProbe_F5_IndeterminateParentKeysAuthenticateChild` (parent DNSKEY served, parent DS dropped): `zone test. status=indeterminate errors=[failed to query DS from parent …]` followed by `zone child.test. status=secure … ds_validation: verified=true`. Both probes are in the sidecar file `REVIEW_MYTHOS51_XHIGH_validator_probes.go.txt` next to this document and use only the existing `harness_test.go` fixture.

**Fix specification:** Separate "served for display" from "authenticated", and stop the authenticated walk at an indeterminate zone. (1) `nextParentDNSKEY` returns `zr.DNSKEY` only when `zr.Status == StatusSecure` (at that point it is the verified RRset assigned at 1662), nil for Insecure, and nil for Indeterminate/Bogus. (2) A zone whose status is Indeterminate terminates the walk exactly as Bogus does, finalising the result as Indeterminate; or, equivalently, thread a `parentIndeterminate` flag into `validateZone` (next to `parentInsecure`) that marks every descendant Indeterminate with an error naming the parent and never performs DS verification against inherited keys. (3) Gate `finalizeNoDSDelegation`'s `len(parentDNSKEY) == 0 → Insecure` branch on `parentInsecure` rather than on empty keys, so the change cannot regress into the laundering the current comment guards against. Keep: Bogus still short-circuits; Insecure stickiness; the cached-zone path (259-285) applies the same rule; `result.DNSKEY` stays in the JSON for diagnostics; JSON/SSE schema unchanged.

**Verification:** Port both probes into `internal/validator` as regression tests: the first must give `RESULT=indeterminate` with `child.test.` Indeterminate and an error naming the parent and no "DS RRSIG verification failed"; the second must not report `child.test.` as `secure` and must produce no `chain_link` below a non-secure parent. Add the inverse: a Bogus or Indeterminate parent with a DS-less child must not read Insecure.

### RM51X-006 — An NXDOMAIN carrying a signed CNAME at the queried name is validated as a denial of the QNAME: dangling CNAMEs and DNAME targets in a correctly signed zone read Bogus

**Severity:** High

**Location:** `validator/internal/validator/validator.go:1104-1109` (`isDenialForType` returns true for any `RcodeNameError` without looking at the Answer section), `validator.go:897-924` (`verifyActualRecord` denial branch), `validator.go:704-720` (`leafCandidateError`, same test), contrast the NOERROR branch which requires `len(qr.CNAME) == 0`.

**Problem:** RFC 1034 §4.3.2 and RFC 2308 §2.1 allow an NXDOMAIN response to carry the CNAME chain in the Answer section, with the RCODE and the NSEC/NSEC3 records referring to the *last* name of the chain. A CNAME whose target does not exist in the same zone (dangling CNAMEs after decommissioning, CDN cut-overs, a DNAME whose target tree lacks the name) is therefore classified as a denial of the queried name; the NXDOMAIN proof is evaluated for the CNAME owner, which exists, fails ("no NSEC record proves www… doesn't exist"), and `recordValidationVerdict` returns Bogus. Unbound and BIND validate the CNAME RRset and the target's NXDOMAIN separately and return a secure chained answer, so this tool reports a SERVFAIL-grade failure for a configuration every resolver accepts.

**Evidence:** Probe `TestProbe_F27_DanglingCNAMEIsBogus`: RCODE NXDOMAIN, Answer `www.child.test. CNAME dead.child.test.` with a valid RRSIG, Authority the child's apex NSEC with RRSIG: `record_validation: verified=false err="no NSEC record proves www.child.test. doesn't exist"`, `RESULT=bogus`; the control query for `dead.child.test.` alone is `secure`.

**Fix specification:** In `isDenialForType` (and so in `leafCandidateError` and `verifyActualRecord`), an NXDOMAIN whose Answer section holds a CNAME owned by the queried name (or a DNAME ancestor plus its synthesised CNAME) is an alias answer, not a denial of the QNAME: authenticate the CNAME/DNAME RRset exactly as the NOERROR alias path does, set `Target`, and let `followAlias` validate the target, where the target's own query returns the authenticated NXDOMAIN. Denial records in the alias hop's Authority section need not be consumed (the hop re-queries the target). An NXDOMAIN with no owner CNAME keeps the current denial path; `qtype == CNAME` remains a positive answer. `leafFingerprint`, disagreement semantics and the schema are unchanged.

**Verification:** The probe must yield `RESULT=secure` with `cname_chains[0].result == secure` and the target's `record_validation.denial_proof.verified == true`. Add the DNAME flavour (DNAME + synthesised CNAME + NXDOMAIN) and an NXDOMAIN with an *unsigned* owner CNAME, which must stay bogus.

### RM51X-007 — CDS and CDNSKEY RRsets are signed only by the ZSK, so parents ignore them (RFC 7344 §4.1)

**Severity:** Medium

**Location:** `signer/internal/signer/sign.go:1321-1358` (`signRecordsWithModel`; only `dns.TypeDNSKEY` selects the KSKs at 1338-1346, every other type uses the ZSKs at 1347-1357), `sign.go:1140-1163` (`stripInputDNSSEC` keeps CDS/CDNSKEY), `sign.go:1176-1255` (`validateZoneRecords` permits them at the apex), `sign.go:1469-1495` (self-verification requires only a ZSK signature for non-DNSKEY types).

**Problem:** RFC 7344 §4.1 requires that the CDS/CDNSKEY RRset "MUST be signed with a key that is represented in both the current DNSKEY and DS RRsets" — that is, by the KSK — unless the parent uses the DNSKEY RRset as its trust anchor. Operators who put CDS/CDNSKEY in the unsigned zone (to drive parent-side DS automation, RFC 8078) get records signed only by the ZSK, which a parent or registry scanner must reject. The RFC 8078 §4 "delete DS" sentinel (`CDS 0 0 0 00`) is likewise emitted with a ZSK signature and is silently ineffective. Nothing warns.

**Evidence:** Empirical run of a locally built `sigillum-signer add` on a zone carrying `@ IN CDS 0 0 0 00` and `@ IN CDNSKEY 0 3 0 AA==`: the output contained `RRSIG CDS 15 2 3600 ... 26467 example.test.` and `RRSIG CDNSKEY ... 26467` where 26467 is the ZSK, while `RRSIG DNSKEY ... 52450` carries the KSK tag.

**Fix specification:** In `signRecordsWithModel`, sign `dns.TypeCDS` and `dns.TypeCDNSKEY` RRsets at the apex with the KSK set (every `signingKSKs` member, like DNSKEY) instead of the ZSKs; extend the self-verification role rule (`verifySignedZoneWithModel`, the `want`/`roleName` block at 1484-1489) so those types require a KSK signature per published algorithm. Do not generate CDS/CDNSKEY automatically (out of scope); reject or warn on CDS/CDNSKEY below the apex. Public API, key file formats and state schema are unchanged.

**Verification:** Unit test signing a zone with apex CDS/CDNSKEY: assert every RRSIG covering those types carries a KSK key tag and verifies under the KSK, and that the post-sign verifier fails a zone where they are ZSK-signed (use `mutateBeforeVerify`). Re-run the empirical `add` above and inspect the RRSIG key tags.

### RM51X-008 — Atomic replacement destroys symlinked output, state and config files, leaving the nameserver on a stale target

**Severity:** Medium

**Location:** `signer/internal/signer/sign.go:2050-2128` (`writeSignedZone`: `os.CreateTemp` + `os.Rename(tempPath, path)` at 2066 and 2113), `sign.go:975-988` (`outputUnusable` uses `os.Stat`, which follows the link and reports the target as usable), `sign.go:489-506` (`StagedZone.Publish` rename), `signer/internal/fsutil/fsutil.go:166-210` (`WriteFileAtomicOwned`, rename at 202), `fsutil.go:220-266` (`WriteConfigFileAtomic`: `os.Stat(path)` at 221 follows the link but `os.Rename` at 258 replaces the link itself), `fsutil.go:327-376` (`CopyFile`).

**Problem:** `rename(2)` replaces the directory entry, so when the destination is a symbolic link the link itself is replaced by the new regular file and the link target is left untouched. An operator who points NSD or BIND at a fixed path and symlinks the signer's output there (or symlinks `/etc/sigillum-signer/config.toml` to a configuration-management tree) loses the link on the first signing or `add`/`remove`: the nameserver keeps loading the old target, every later re-sign goes to the output directory, and the served signatures expire with the daemon reporting healthy. `NeedsSign` cannot detect it because `outputUnusable` only checks that *something* regular exists at the path. The same applies to `state.json` and the key files written through `WriteFileAtomicOwned`.

**Evidence:** Empirical run: with `signed/example.test.zone.signed -> elsewhere/served.zone`, `sigillum-signer add example.test ...` left `signed/example.test.zone.signed` as a 2667-byte regular file and `elsewhere/served.zone` still containing its old content.

**Fix specification:** Resolve the destination before staging: `realPath := filepath.EvalSymlinks(path)` (fall back to `path` only when the final component does not exist), create the temporary file in `filepath.Dir(realPath)` and rename over `realPath`, in `writeSignedZone`, `StagedZone.Publish`, `WriteFileAtomicOwned`, `WriteConfigFileAtomic` and `CopyFile`. Refuse (with a clear error) when the resolved target lies outside the configured directory for key and state files, so a link cannot redirect private material. Alternatively document that symlinked outputs are unsupported and make `outputUnusable` reject a symlink with an actionable message. Keep file modes, ownership handling and the durability semantics unchanged.

**Verification:** Tests for each writer with a symlinked destination: the link survives, the target holds the new bytes, mode/ownership rules still hold; a dangling link and a link outside the directory behave per the chosen policy. Re-run the empirical `add` above.

### RM51X-009 — The parent zone is assumed to be exactly one label up, so zones delegated across an empty non-terminal cannot be validated or rolled

**Severity:** Medium

**Location:** `signer/internal/validate/validate.go:727-736` (`findParentZone` strips one label), `validate.go:322-352` (`CheckDSAtParent`), `validate.go:740-816` (`resolveNS` requires an NS RRset in the answer or authority section), `signer/internal/validate/parentds.go:148-157` (`discoverNSWith` → "no NS records found"), `parentds.go:294` (`ProbeParentDS` uses `findParentZone`).

**Problem:** For `a.b.example.com` delegated directly from `example.com` (so `b.example.com` is an empty non-terminal), the NS query for `b.example.com.` returns NODATA with an SOA, not NS, in the authority section. `discoverNS` fails with "no NS records found", so `ProbeParentDS` errors: `rollover complete` needs `--force`, `CheckAlgorithmRollover` never observes old-DS absence (logged at Debug only), `import` needs `--offline`, and `status --validate`/the dashboard report the DS check as "error" for a correctly delegated zone. Multi-label delegations are common in enterprise and reverse zones, and the limitation is undocumented.

**Evidence:** `validate.go:735` — `return dns.Fqdn(strings.Join(labels[1:], "."))`; `parentds.go:155-157` — `if len(names) == 0 { return nil, fmt.Errorf("no NS records found for %s", zone) }`; `validate.go:771-773` — the same check in `resolveNS`.

**Fix specification:** Replace `findParentZone` with an enclosing-zone search: starting one label up, query NS (or SOA) through the configured resolver and stop at the first name that owns an NS RRset (the real parent, which also holds the DS); keep the one-label result as the first candidate so existing behaviour is unchanged for ordinary zones. Use the found parent in `CheckDSAtParent` and `ProbeParentDS`; bound the walk by the label count and cache the result per validator call. No API or state change.

**Verification:** Hermetic test (reuse the `validate` fixtures) with an ENT between child and parent: `ProbeParentDS` must query the real parent's servers and `CheckDSAtParent` must return "pass" for a matching DS. Existing parent-DS tests unchanged.

### RM51X-010 — The validator reports NSEC3 iteration counts above 100 as Bogus instead of Insecure (RFC 9276 §3.2)

**Severity:** Medium

**Location:** `validator/internal/validator/warnings.go:20-25` (`NSEC3MaxRecommendedIterations = 100`), `validator/internal/validator/nsec.go:416-419`, `465-467`, `841-852`, `1153-1156` (`nsec3IterationsOverCap` refuses the proof), `validator/internal/validator/validator.go:2048-2051` (`verifyDSAbsence` refuses the DS-absence proof), `validator.go:1212-1274` (`recordValidationVerdict`: a refused proof reaches the final `return StatusBogus` at 1273), `validator.go:2135-2184` (`finalizeNoDSDelegation` reaches `StatusBogus` at 2178); contrast the signer, which accepts up to 150 at `signer/internal/config/config.go:677`.

**Problem:** RFC 9276 §3.2 says validating resolvers SHOULD treat NSEC3 records with iteration counts above their limit as *insecure*, and only permits SERVFAIL for very high counts; Unbound and BIND treat counts above 150 as insecure. This validator refuses any proof above 100 and the refusal flows into the verdict machinery as a signature failure, so a NODATA/NXDOMAIN answer or an unsigned delegation under a zone using 101-150 iterations is reported **bogus** (SERVFAIL) while production resolvers return insecure (or, with BIND's 150 cap, even secure). The sibling signer will happily produce such a zone (`nsec3_iterations` up to 150 is accepted), so the two tools in this repository contradict each other. Two further defects in the same check: (b) it runs on the raw candidate slice before any signature is verified (`nsec.go:416-419` precedes `verifyDenialRRsetsFromResponseB` at 439), so one injected, unsigned NSEC3 with `Iterations=65535` in the Authority section of an otherwise valid response forces the refusal, and the CPU it was meant to save is budgeted anyway; (c) in `VerifyNSEC3Denial` the cap is applied across all records, so an over-cap record from a *different* chain (salt-transition leftovers) poisons a valid chain that would have proved the denial.

**Evidence:** `nsec.go:416-419` — `proof.Error = fmt.Sprintf("NSEC3 iterations=%d exceeds RFC 9276 cap ...")` with `Verified` false; `validator.go:1266-1273` — a `RecordValidation` with `RRSIGVerified == false` and an error that is neither "unqueryable" nor "budget" returns `StatusBogus`; `validator.go:2178-2183` — the same for DS absence.

**Fix specification:** Treat an over-cap iteration count as an explicit *insecure* outcome rather than a verification failure: return a proof with a new `OverCap` (or reuse `OptOut`-style) marker and no cryptographic work, map it to `StatusInsecure` in `recordValidationVerdict` and `finalizeNoDSDelegation` with a warning that names the count and the cap, and keep the hashing refusal (the CPU-amplification guard, R-088) exactly as is. Make the cap a single shared constant used by both the warning and the refusal, raise it to 150 to match deployed resolvers, and align the signer's `nsec3_iterations` upper bound (`config.go:677`) with it. Evaluate the cap per chain and only on authenticated records (after `verifyDenialRRsetsFromResponseB`, before any hashing), ignoring over-cap chains the way unknown-flag records are ignored, and never emit the "possible downgrade attack" wording for an iteration-count refusal. JSON fields are additive only.

**Verification:** Harness tests: NXDOMAIN, NODATA and DS-absence responses whose NSEC3 records carry 120 iterations must yield `insecure` with the warning; 600 iterations may remain a refusal; a valid 0-iteration chain plus one unsigned 65535-iteration NSEC3 injected must stay `secure`; two chains, one over the cap and one proving the denial, must be accepted. Cross-check with `unbound-host -v` against a test zone signed by the signer with `nsec3_iterations = 120`.

### RM51X-011 — `add` and `rollover start` publish DS at the registrar as soon as the local file is written

**Severity:** Medium

**Location:** `signer/main.go:1268-1278` (`runAdd`: `hookOK` then `MaybeAutoPublishDS(cfg, state, domain, "add")`), `main.go:1393-1410` (`runRolloverStart`), `main.go:418-478` (`runPostSignHook`; immediate mode returns `served = true` at 461-463 regardless of any nameserver), `signer/internal/signer/sign.go:420-427` (`recordSignedZone` confirms publication at write time in immediate mode), `signer/internal/config/config.go:209-219` (`PublicationMode` auto-selects `immediate` whenever no hook is configured), `signer/registrar_cli.go:398-406`.

**Problem:** RFC 6781 §4.2 (going from insecure to secure) and §4.1.2 require the signed DNSKEY RRset to be served by every authoritative server before the parent publishes a DS. In the default configuration (`publication` unset, no hook → `immediate`), `add` with `auto_publish = true` pushes the DS record the instant the signed file is on disk — before NSD or BIND has reloaded it and long before any secondary has transferred it. With `publication = "hook"` the hook confirms only the primary. Validators that fetch the new DS and then query a server still serving the unsigned (or old) zone return bogus until propagation completes. The RA6X-004 "served" gate was designed for this but in immediate mode it is satisfied by the file write, and no mode waits for secondaries or a TTL. The same `hookOK` short-cut governs the `rollover_start` additive push (harmless for KSK because the old DS stays, but it is the entry point of the algorithm-rollover issue above).

**Evidence:** `main.go:461-463` — `case config.PublicationImmediate: return true, deployErr`; `sign.go:423-424` — `if s.cfg.PublicationMode() == config.PublicationImmediate { zoneState.ConfirmPublication(now, now) }`; `main.go:1274-1275` — `if hookOK { MaybeAutoPublishDS(cfg, state, domain, "add") }`.

**Fix specification:** Gate the `add` DS push on the same propagation predicate proposed for rollovers: require either `publication = "probe"` confirmation that every authoritative server serves the signed generation, or an explicit operator opt-in flag (`--publish-ds-now`) that prints the RFC 6781 caveat; otherwise print the DS and defer the push to the daemon, which publishes once the generation is confirmed served (probe mode) or after `dnskeyTTLFloor` has elapsed since confirmed publication in hook mode. In immediate mode refuse automatic DS publication for a newly added zone and say why. Keep `registrar push` as the manual override. No config key or registrar interface changes beyond the optional flag.

**Verification:** Test `runAdd` with `auto_publish = true` in immediate mode: the fake registrar receives no DS; in probe mode with a fake prober that reports the serial served everywhere: the DS is pushed; with an unconfirmed probe: not pushed and the zone shows a pending warning. Run `go test -race ./...` in `signer`.

### RM51X-012 — A failed `add` discards the zone's removal marker, re-opening stale-configuration re-adoption (RA6X-025 incomplete)

**Severity:** Medium

**Location:** `signer/main.go:1221-1222` (`runAdd`: `state.ClearRemoved(domain)` before `SetZone`), `main.go:1226-1241` (every later failure calls `unwindAdd`), `main.go:607-648` (`unwindAdd` removes the zone and saves, never restoring the marker); contrast `signer/import_cli.go:686` and `722-724` (`beginImportTx` captures `removedAt` and `rollback` calls `RestoreRemoved`); consumer `signer/daemon.go:947-960`.

**Problem:** `remove` records a deletion marker so a daemon still holding the pre-removal configuration does not re-create the zone from it. `add` clears that marker in memory first; if signing, the state save or the config append then fails, `unwindAdd` persists a state that holds neither the zone nor the marker. A daemon that has not yet merged the marker (remove and add within one poll interval, or a restart) sees `zoneState == nil` and no marker, recovers the keys from disk and republishes a zone the operator explicitly removed, from the old path. `RestoreRemoved` exists exactly for this and has a single caller (`import`).

**Evidence:** `main.go:1221` `state.ClearRemoved(domain)`; `main.go:608-611` `state.RemoveZone(domain); persistState(state)`; `grep -rn RestoreRemoved` → only `import_cli.go:723`.

**Fix specification:** In `runAdd`, capture `removedAt, wasRemoved := state.RemovedAt(domain)` before `ClearRemoved`, pass both into `unwindAdd`, and call `state.RestoreRemoved(domain, removedAt)` when `wasRemoved` before `persistState`. Skip the needless `persistState` in the key-generation failure branch (nothing was changed yet). No schema or `Removed` semantics change; `import` unchanged.

**Verification:** Test modelled on `add_rollback_rdaybluex033_test.go`: `MarkRemoved` + save, run `add` with an injected config-append failure, reload the disk state and assert `Removed[domain]` is present with the original timestamp; then run one daemon cycle with a configuration listing the zone and `LoadedAt` before `removedAt` and assert no zone is created.

### RM51X-013 — The config-write preflight checks file append, but the edit needs directory write, so `add`/`import`/`remove` fail late or refuse valid layouts

**Severity:** Medium

**Location:** `signer/main.go:388-394` (`preflightConfigAppend` opens the file `O_APPEND|O_WRONLY`), used at `main.go:1168` (`runAdd`), `main.go:1316` (`runRemove`), `signer/import_cli.go:225`; the actual writer `signer/internal/config/config_edit.go:63` and `:123` → `signer/internal/fsutil/fsutil.go:220-266` (`WriteConfigFileAtomic`: `os.CreateTemp(dir, ...)` at 228, `os.Rename` at 258).

**Problem:** The commit creates a temporary file in the configuration *directory* and renames it over the config, which needs write and search permission on the directory, not write permission on the file. In the hardened layout the package installs (`/etc/sigillum-signer` root:sigillum-signer 0750, `config.toml` root:sigillum-signer 0640) a daemon-user `add` passes the preflight whenever the file happens to be group-writable, generates keys, signs the zone and saves state, then fails at `CreateTemp` with EACCES and unwinds, deleting the freshly minted keys. Conversely a read-only file in a writable directory fails the preflight although the atomic write would succeed. The stated purpose ("fail fast before generating keys or signing") is not met.

**Evidence:** `fsutil.go:228` `tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")` versus `main.go:389` `os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)`.

**Fix specification:** Replace the probe with one that exercises what the commit needs: `os.Stat(path)` must find a regular file (after resolving symlinks per the symlink finding), `os.CreateTemp(filepath.Dir(path), ".config-write-check-*")` must succeed and the probe file is removed; when running as root nothing further. Keep the function name and call sites; the error text should say "config directory not writable". `AddZoneToConfigFile`/`RemoveZoneFromConfigFile` and the config format are unchanged.

**Verification:** Test with a 0555 directory holding a 0666 config: `add` must fail before `RecoverOrGenerateKeysReport` (no key files, no signed output, state unchanged). Inverse test: writable directory, 0444 file → `add` succeeds.

### RM51X-014 — Readiness never reports a failed state save or a skipped cycle; `lastSaveFailed` is write-only

**Severity:** Medium

**Location:** `signer/daemon.go:67-71` (field comment: "it remains the readiness/diagnostic signal that unsaved work exists"), `daemon.go:846-866` (only stores), `daemon.go:710` (`lastSigningRun.Store` before the lock at 716-720), `daemon.go:736-741` (state fault path), `signer/health.go:62-158` and `161-211` (no reference to `lastSaveFailed`; liveness is `signingLoopDead` plus `lastSigningRun` staleness).

**Problem:** A cycle whose `Save` fails for a reason the 10-second directory probe does not reproduce (rename EACCES, ENOSPC after the probe's zero-byte file, a marshal failure) leaves signed output on disk that the authoritative state does not describe and hooks withheld (RDAYBLUEX-006), while `/health` and `/healthz` keep returning healthy. The health probe cache is invalidated only on a "real write failure" classification, and nothing reads the flag. Separately, `lastSigningRun` is stamped before the state lock is acquired, so a cycle skipped on lock contention (10-second timeout) or on a state fault still counts as "ran"; a daemon that skips every cycle (a wedged lock holder, an advisory-lock regression on a network filesystem) reports `signing_loop_alive: true` until signatures expire.

**Evidence:** `grep -rn lastSaveFailed --include=*.go signer | grep -v _test` → stores in `daemon.go` only; `daemon.go:710` precedes `daemon.go:716` `acquireStateLock(snap.cfg.DataDir, 10*time.Second)`.

**Fix specification:** Surface both conditions in the two health handlers as `dependency_errors` entries ("state: the last cycle's save did not commit; signed output may be undeployed", "signing_loop: N consecutive cycles skipped: <reason>") and mark the daemon unhealthy; record the skip reason and a consecutive-skip counter on the daemon; move `lastSigningRun.Store` after the lock and reload succeed (or add `lastCycleCompleted`). Health JSON is additive only (new strings inside the existing array).

**Verification:** Extend `health_probe_rdaybluex035_test.go`: force a `Save` failure (unwritable `SetPath`), run one cycle, assert `/health` returns 503 with the new entry; restore, run a cycle, assert 200. Second test: hold `state.json.lock` from the test, run a cycle, assert the skip is reported and `signing_loop_alive` is false.

### RM51X-015 — `state.json` has no schema marker and drops unknown fields, so an old daemon left running across an upgrade erases what a newer CLI wrote

**Severity:** Medium

**Location:** `signer/internal/state/state.go:329-351` (`LoadState`, `json.Unmarshal` at 341), `state.go:522-541` (`readDiskLocked`, 534), `state.go:930-967` (`Save`, `json.MarshalIndent` at 942); `packaging/sigillum-signer-postinstall.sh:15` and `docs/linux-packages.md:133-136` (upgrades do not restart the daemon).

**Problem:** `encoding/json` silently discards unknown fields. Every release so far added `ZoneState`/`RolloverState` fields (`revision`, `source_digest`, `published_*`, `*_cache_horizon`, `ds_removal_pushed_at`). Because the package deliberately does not restart the service, the normal upgrade sequence is: new binary installed, old daemon still running, operator uses the new CLI. The old daemon's next cycle merges the file (new fields invisible to its struct) and saves it without them; after the eventual restart the new daemon finds them absent. New *phase names* are already fail-closed by `validateRolloverState`, field additions are not.

**Evidence:** Hypothetical but concrete: a v1.1 daemon running, a v1.2 CLI writes `ds_removal_pushed_at` (the RDAYBLUEX-007 "never repeated" guard) via `rollover complete`; the old daemon's cycle rewrites the file without it; after restart the new daemon repeats the registrar DS replacement. The same mechanism re-baselines `source_digest` and degrades `revision`-based merging to content comparison.

**Fix specification:** (a) Add a top-level `"schema": N` integer (absent means 1); `LoadState`/`readDiskLocked` refuse a document whose schema is newer than the binary supports with an actionable error, so an old daemon skips cycles (the existing RA6X-026 fail-closed path) instead of merging over newer data. (b) Make `ZoneState` round-trip unknown fields (custom `UnmarshalJSON`/`MarshalJSON` keeping a `map[string]json.RawMessage` of unrecognised keys, re-emitted on marshal and excluded from the merge classes) so a newer CLI's data survives an older daemon's save even when the schema number is unchanged. (c) State in `docs/linux-packages.md` that the daemon must be restarted after an upgrade before the new CLI is used. Existing key names and the `zones`/`removed` shape must not change; schema-1 files must load exactly as today.

**Verification:** Test: a document with an extra zone field `"future_field": 7` survives `LoadState` → `Save` → raw re-read; `"schema": 99` is rejected by `LoadState` and by `ReloadFromDisk` without touching memory; `TestStateLoad_OldSchemaTolerant` still passes.

### RM51X-016 — A failed registrar replace at KSK `rollover complete` is never retried; the zero-DS emergency is left for the operator to notice

**Severity:** Medium

**Location:** `signer/main.go:1537-1546` (`runRolloverComplete`: `MaybeAutoPublishDS(..., "rollover_complete")`, result discarded, skipped entirely when `hookOK` is false), `signer/internal/signer/rollover.go:245-280` (`CheckKSKRollover` has no publisher call) versus `rollover.go:750-769` and `808-814` (`pushOldDSRemoval` is retried every cycle for algorithm rollovers, idempotent via `DSRemovalPushedAt`), `signer/registrar_cli.go:326-328`, `427-447`.

**Problem:** For a KSK rollover the only registrar replace happens once, synchronously in the CLI. If the hook or probe did not confirm (`hookOK == false`), the registrar is unreachable, or `ReplaceDS` ends in `ErrRegistrarDSEmpty` (the parent left with zero DS, the RA6X-031 emergency), nothing retries: a sticky warning is persisted and the daemon advances `ds_propagation_wait → retiring → complete` regardless. The verification table records RDAYBLUEX-007 as "exactly once with retry on registrar failure" for both workflows, which is only true for the algorithm path.

**Evidence:** `main.go:1542-1546` — `if hookOK { MaybeAutoPublishDS(...) } else { fmt.Printf("DS auto-publish skipped ...") }` with no state recorded; `rollover.go:245-280` contains no `rm.publisher` use.

**Fix specification:** Mirror the algorithm path: once the propagation predicate from the first finding holds, `CheckKSKRollover` calls the publisher with a KSK-specific op (or reuses `OpRolloverOldDSRemoval`) every cycle until success and records success in `DSRemovalPushedAt` (already generic); keep the CLI's attempt as the first try. Do not advance to `retiring` while the sticky zero-DS warning is present unless the operator clears it. No schema change.

**Verification:** Fake registrar failing the first `ReplaceDS`: the daemon retries on the next cycle and pushes exactly once after success; a zero-DS outcome is retried rather than abandoned; the phase does not advance while the URGENT warning stands.

### RM51X-017 — The FreeBSD rc.d script starts the validator without `-config`; a missing file silently yields "listen on every interface with built-in defaults"

**Severity:** Medium

**Location:** `validator/freebsd/sigillum-validator:53-69` (the `daemon` line at 67-68 passes only `${sigillum_validator_command}`), `validator/internal/config/config.go:241-256` (`Load`: no file at any default path → `LoadFromEnv`), `config.go:146` (`ListenAddr: ":8791"`); contrast `packaging/sigillum-validator.service:11-12` (`-check -config` then `-config`); `validator/QUICKSTART-FREEBSD.md:36-37` ("the rc.d script passes nothing else").

**Problem:** `main.go:29-33` documents that an explicit `-config` that cannot be read is fatal and "never quietly downgraded", but the shipped rc.d relies on auto-discovery. If `/usr/local/etc/sigillum-validator/config.toml` is absent (fresh install, rename, typo, different prefix), `Load("")` falls through to `LoadFromEnv()`, which with an empty environment yields `DefaultConfig()`: `listen_addr = ":8791"` on all interfaces, bypassing the Apache front door and its trusted-proxy rate-limit attribution, with default anchor and RDAP settings. The service comes up and reports healthy, so nothing alerts. The deployment notes in the project's own memory record exactly this failure on the production host.

**Evidence:** `freebsd/sigillum-validator:67-68` — `/usr/sbin/daemon -f -p ${pidfile} -u ${sigillum_validator_svcuser} -S -T ${name} ${sigillum_validator_command}`; `config.go:254-255` — `return LoadFromEnv()`.

**Fix specification:** Add `: ${sigillum_validator_config:="/usr/local/etc/sigillum-validator/config.toml"}`, pass `-config "${sigillum_validator_config}"` on the `daemon` line, and add a `start_precmd` that runs `${sigillum_validator_command} -check -config "${sigillum_validator_config}"` as the service user and refuses to start on failure (mirroring the systemd unit). Separately change `DefaultConfig().ListenAddr` to `"127.0.0.1:8791"` so the env/default path is loopback-only like both shipped TOML files; keep key and variable names. Update `QUICKSTART-FREEBSD.md`. Do not change the search order (an explicit unreadable `-config` stays fatal).

**Verification:** With the config renamed, `service sigillum_validator start` must fail with the `-check` error; with it present, `sockstat -46l -p 8791` shows only 127.0.0.1. Go test: `config.DefaultConfig().ListenAddr == "127.0.0.1:8791"` and `LoadFromEnv()` with an empty environment listens on loopback.

### RM51X-018 — Per-IP rate limiting is keyed on the full address, so one IPv6 /64 gets unlimited fresh buckets

**Severity:** Medium

**Location:** `validator/ratelimit.go:59-93` (`Allow`, map keyed by the raw `ip` string), `ratelimit.go:101-121` (`evictLocked`), `ratelimit.go:156-170` (`Middleware`), `ratelimit.go:250-287` (`extractClientIP`).

**Problem:** Every distinct IPv6 address receives a fresh bucket with the full burst (30). A single residential /64 (or a /56 or /48 at a VPS) therefore yields 30 validations per new address for free; the R-091 cap of 50,000 buckets bounds memory but not the bypass, and once the cap is hit `evictLocked` sheds ten percent of *live* buckets, resetting legitimate clients to full burst as collateral. The global validation semaphore then becomes the only brake on outbound DNS amplification, and an attacker can keep it pinned at 100 in-flight validations indefinitely without ever receiving a 429.

**Evidence:** `ratelimit.go:63` `bucket, exists := rl.limiters[ip]` with `ip` straight from `extractClientIP`; no prefix normalisation anywhere; `ratelimit.go:115-120` evicts arbitrary map entries.

**Fix specification:** Canonicalise the key before lookup: `netip.ParseAddr`, `Unmap()`, then `addr.Prefix(64)` for IPv6 (configurable `rate_limit.ipv6_prefix_len`, default 64) and `/32` for IPv4. Keep the token-bucket semantics, the `Retry-After: 1` header, the 429 problem body and the metrics. Trusted-proxy semantics unchanged.

**Verification:** Unit test: 100 requests from `2001:db8::1`…`2001:db8::64` share one bucket and the 31st is rejected; `2001:db8:0:1::1` is a separate bucket; `::ffff:203.0.113.5` and `203.0.113.5` share a bucket. `go test -race .` in `validator`.

### RM51X-019 — Every event and the final result embed the raw wire response of every queried server, repeated across zone and complete events

**Severity:** Medium

**Location:** `validator/internal/validator/validator.go:2208-2229` (`ValidateMultipleServers` stores `result.Response = queryResult` at 2226), `validator.go:1361-1374` (`applyServerResults` copies the full `AddressResult` into `result.Nameservers[i].Addresses[j]`), `validator.go:312-318` and `396-402` (the leaf zone event is emitted twice), `validator.go:453-465` (`complete` repeats the whole chain), `validator/internal/validator/result.go:70-76` (`AddressResult.Response *dns.QueryResult json:"response,omitempty"`), `validator/internal/dns/types.go:130-154` (`QueryResult` with parsed DNSKEY/RRSIG slices and `RawResponse []byte json:"raw_response,omitempty"`), `validator/handlers.go:419`; UI `validator/static/app.js:286`, `330` (`item.dataset.result = JSON.stringify(zoneResult)`, never read).

**Problem:** For each server address the serialised zone result carries the parsed DNSKEY RRset (base64 public keys), every RRSIG (base64 signatures) and the entire raw DNS message base64-encoded. A root DNSKEY answer is roughly 1.5 KB on the wire, so each address contributes several KB of JSON; the root alone has 13 queried addresses, `.com` 26, and extended mode (the default) does this for every zone, re-sends the leaf zone, then sends the whole chain again inside `complete`. A single default validation can push hundreds of KB to the browser that nothing reads: `app.js` renders only `ip`, `status`, `rtt_ns` and `error` per address, and no document mentions `raw_response`. Server-side this is base64 and JSON encoding inside the 10-second delivery budget, and a cheap GET that returns hundreds of KB is an amplification vector. Needs investigation (memory): per-validation memory is bounded only by fan-out, not by response size. Up to 64 addresses × 64 KB TCP answers × every attacker-controlled zone level, times `max_concurrent_validations`, is retained for the lifetime of the validation; measure RSS and the `complete` payload with a mock delegation of 64 addresses returning 60 KB DNSKEY answers over TCP.

**Evidence:** `grep -n "Response = nil" validator/internal/validator/*.go` → nothing; `grep -n "raw_response\|\.response" validator/static/app.js` → nothing.

**Fix specification:** Stop serialising the per-server wire copy by default: keep `Response` for internal verification but mark `QueryResult.RawResponse` as `json:"-"` (undocumented, unused by the UI) and nil out each `AddressResult.Response` after `judgeDNSKEYServers` has consumed it, or replace it with a slim summary (key tags, rcode, truncated flag, RTT). If full detail must remain available to API consumers, document it and gate it behind `?detail=full`. Delete the dead `item.dataset.result` writes. Nothing else in the JSON/SSE schema changes.

**Verification:** Handler test with the harness fixture: the encoded `complete` payload contains no `raw_response` key and grows O(servers × small) rather than O(servers × message size); capture `/api/validate?domain=www.iana.org` before and after and compare sizes; RA6X-018 consensus tests still pass.

### RM51X-020 — The same post-install lines reset the group of `signed/` on every upgrade, revoking the nameserver's access

**Severity:** Medium

**Location:** `packaging/sigillum-signer-postinstall.sh:11`; `docs/linux-packages.md:66-68` and `signer/QUICKSTART.md:31` tell operators to grant the nameserver group access to `signed/`.

**Problem:** The documented setup changes the group (or an ACL) of `/var/lib/sigillum-signer/signed` so NSD/BIND can traverse it. Every package upgrade resets it to `sigillum-signer:sigillum-signer 0750` (a `chmod` on a directory with an ACL also rewrites the mask). The daemon keeps writing 0644 files nobody can read, the next reload fails, and the nameserver serves the pre-upgrade RRSIGs until they expire. The container test never changes the group, so CI cannot see it.

**Evidence:** Same lines as RM51X-004; the daemon itself only tightens the keys directory (`EnsureDirSecure`) and never touches the group of `signed/`.

**Fix specification:** Same change as RM51X-004 (create once, never modify afterwards) and state in `docs/linux-packages.md` that the package creates `signed/` once.

**Verification:** Container test: `chgrp nobody /var/lib/sigillum-signer/signed` after the first install, reinstall, assert `stat -c %G` is still `nobody`.

### RM51X-021 — The shipped Apache include for the validator is rejected by httpd

**Severity:** Medium

**Location:** `validator/freebsd/apache-sigillum-validator.conf:23` (`ProxyTimeout 300` inside `<Location>`); shipped by `.goreleaser.yaml:44`; installed by `validator/QUICKSTART-FREEBSD.md:83-101`.

**Problem:** `ProxyTimeout` is a server/virtual-host directive. `httpd -t` fails with `AH00526: Syntax error ... ProxyTimeout not allowed in <Location> context`, so the QUICKSTART's `apachectl configtest` fails and an operator who reloads without testing leaves Apache unable to restart. `signer/apache.conf.example` passes.

**Evidence:** Reproduced by the packaging sub-review against Apache 2.4.68.

**Fix specification:** Remove line 23 and put the timeout on the SSE worker: `ProxyPass balancer://sigillum-validator/validate timeout=300`. Leave the SetEnv/Header lines. Optionally add an `apachectl -t` check of both example files to CI.

**Verification:** `httpd -t` with a minimal configuration that `Include`s the file reports `Syntax OK`.

### RM51X-022 — Signer documentation prescribes `sudo`/`systemctl` reload hooks that cannot run under the packaged unit

**Severity:** Medium

**Location:** `signer/QUICKSTART.md:36-51`, `75-78` (`post_sign_cmd = ["/usr/bin/sudo", "-n", "/usr/sbin/nsd-control", "reload"]`), `168-183` (hand-written unit); `signer/README.md:131`, `401-402` (`post_sign = "systemctl reload nsd"`); contradicted by `packaging/sigillum-signer.service:18` (`NoNewPrivileges=yes`) and `docs/linux-packages.md:70-72`.

**Problem:** Under `NoNewPrivileges=yes` `sudo` refuses to run and `systemctl reload nsd` as an unprivileged user is denied by polkit. A packaged install following the README/QUICKSTART therefore fails every hook; with a hook configured, publication is confirmed only on hook success, so rollover timers never start, `sign` exits non-zero, and NSD never reloads the refreshed file while the served RRSIGs age toward expiry. The QUICKSTART unit also carries a stale description and no hardening and, if copied to `/etc/systemd/system/`, shadows the packaged unit.

**Evidence:** `grep -n "sudo\|systemctl reload" signer/QUICKSTART.md signer/README.md` versus `packaging/sigillum-signer.service:18`.

**Fix specification:** Rewrite the QUICKSTART around the no-privilege path (membership in the group that may read NSD's control key, `post_sign_cmd = ["/usr/sbin/nsd-control", "reload"]`), state that `sudo`/`systemctl` hooks do not work under the packaged unit, replace the README examples with `nsd-control reload`/`rndc reload`, and replace the QUICKSTART's hand-written unit with "install the package" or a copy of `packaging/sigillum-signer.service`. Do not weaken the unit.

**Verification:** No hook example in the docs uses `sudo` or `systemctl`; `systemd-analyze security sigillum-signer` unchanged.

### RM51X-023 — The hard-coded B-root address is the pre-November-2023 one; every quick-mode validation pays a timeout on it

**Severity:** Medium (Needs investigation: confirm against the current IANA `named.root`)

**Location:** `validator/internal/dns/resolver.go:375-392` (`GetRootServers`, line 379 `"199.9.14.201", // b.root-servers.net`); consumers `validator/internal/validator/validator.go:53-58`, `1296-1298`, `1774`; quick mode takes `queryServers[:2]` at `validator.go:2198-2199`.

**Problem:** B-root renumbered to 170.247.170.2 / 2801:1b8:10::b on 2023-11-27 and the old address was announced for withdrawal. The validator still dials it for the root DNSKEY RRset and for every TLD DS query; in quick mode the two root servers queried are A and B, so every quick validation waits `query_timeout_seconds` on the dead address and reports a failed root server. The list is also IPv4-only (the 13 IPv6 root addresses are never queried), so an IPv6-only host cannot validate anything and the "query every server" consensus is incomplete at the root.

**Evidence:** `resolver.go:379`; `anchors_test.go:265-279` pins only A and M.

**Fix specification:** Replace the list with the current IANA root hints (IPv4 and IPv6), record the `named.root` revision date in a comment, and add a test comparing all entries against a fixture copied from IANA. Optionally prime the list from the trusted recursive resolver (`ResolveNSSet(ctx, ".")`) with the static list as fallback. `GetRootServers()` stays a `[]string`.

**Verification:** `dig +norecurse @170.247.170.2 . DNSKEY` versus `@199.9.14.201`; after the change a quick-mode validation shows no root-server timeout.

### RM51X-024 — Advertising a 4096-byte EDNS buffer defeats the TC→TCP fallback for large answers

**Severity:** Medium

**Location:** `validator/internal/dns/query.go:88` (`msg.SetEdns0(4096, true)`), `validator/internal/dns/resolver.go:72` (`msg.SetEdns0(4096, false)`); the TCP retry at `query.go:65-69` only triggers on TC.

**Problem:** A 4096-byte advertisement invites 1.5-4 KB UDP datagrams that fragment at a 1500-byte MTU; fragment loss and filtering are common (the 2020 DNS flag day settled on 1232 for exactly this). Servers never set TC for answers that fit in 4096, so a lost fragment becomes a `query_timeout_seconds` read timeout and the server is reported as "query failed" (indeterminate, disagreement noise). Large DNSKEY RRsets during KSK rollovers, the situation a DNSSEC troubleshooting tool exists for, are the typical trigger. A UDP timeout is never retried over TCP (`query.go:64-69` retries only when `Truncated` is set), so on such a path every server of a zone with a large DNSKEY answer reads as unreachable while the small DS and A answers succeed, which is precisely the precondition of RM51X-005.

**Evidence:** `query.go:88`, `resolver.go:72`; miekg sizes the receive buffer from the OPT record.

**Fix specification:** Advertise 1232 on both paths and retry once over TCP when the UDP exchange fails with a `net.Error` whose `Timeout()` is true; TC→TCP is already implemented and `Truncated` reporting stays. `QueryResult` schema and `Truncated` reporting unchanged.

**Verification:** Extend the RA6X-019 truncation test to assert the OPT UDP size on the received query is 1232 and that a 1.3 KB answer arrives over TCP; a transport-aware `mockDNS.drop` that drops UDP only while TCP serves the answer must still authenticate the zone.

### RM51X-025 — One client can hold the whole global validation capacity by naming tarpit nameservers

**Severity:** Medium

**Location:** `validator/handlers.go:84-104` (`acquireValidationSlot` is global-only; default `max_concurrent_validations = 100`), `handlers.go:222`, `392` (slot held for the full `TotalTimeout`), `validator/internal/dns/query.go:60-69` (`dns.Client{Timeout}` applies separately to dial, write and read, so one address can cost roughly 3 × `query_timeout_seconds` across UDP read, TCP dial and TCP read), sequential per-address loops at `validator/internal/validator/validator.go:1808-1824`, `615-634`, `569-587`; rate limit 10 req/s per IP (`config.go:161-165`).

**Problem:** A domain whose nameservers answer UDP with TC=1 and then stall TCP (or drop packets) makes every validation of it run for the full 30 seconds. 100 slots / 30 s = 3.3 requests per second to saturate, while one IP may send 10 per second, so a single anonymous client with EventSource keeping `/validate` open can keep the service at 503 for everyone indefinitely without ever hitting the rate limit. RDAYBLUEX-010 and R-086 bounded fan-out and total concurrency but not per-client concurrency, and the per-phase timeout multiplies the per-server cost beyond the documented meaning of `query_timeout_seconds`.

**Evidence:** `handlers.go:85-91` selects on the global semaphore only; miekg's client applies `Timeout` per phase.

**Fix specification:** (a) Add a per-client-IP in-flight cap (for example 4) in `acquireValidationSlot`, keyed by `extractClientIP` with the rate limiter's bounded map and the same 503 plus `Retry-After`; (b) wrap each `exchange` (UDP plus TCP retry) in `context.WithTimeout(ctx, q.timeout)` so a server costs at most one `query_timeout_seconds`; (c) document the relation between `rate_limit.per_sec × total_timeout_seconds` and `max_concurrent_validations`. Result schema, 503 semantics and the global cap are unchanged.

**Verification:** Handler test with a blocking `validateFn`: five concurrent requests from one IP, the fifth gets 503 while another IP still acquires a slot; querier test with a fixture that answers TC then never accepts TCP returns within about `q.timeout`.

### RM51X-026 — `import --keys-dir` rejects about 1 in 256 BIND- and ldns-generated ECDSA keys

**Severity:** Medium

**Location:** `signer/internal/signer/keys.go:836-858` (`verifyECDSACorrespondence`, `if len(privateKey) != size` at 837), `sign.go:1709`, `1722` (`signRRSIG` length checks), `keys.go:864-873` (`ParsePrivateKeyFromFile` returns the raw base64 bytes), `signer/internal/signer/bindkeys.go:101-114`.

**Problem:** BIND 9.16/9.18 (`opensslecdsa_tofile`) and ldns write the private scalar with `BN_bn2bin`, which strips leading zero octets, so a P-256 scalar below 2^248 (probability 1/256; P-384 likewise) is stored as 31 (47) bytes. The signer demands exactly 32/48 bytes and lists the pair as unusable ("invalid ECDSA private key length 31 (want 32)"); when that pair is the KSK the parent's DS names, the whole takeover is blocked.

**Evidence:** The signing-core sub-review reproduced it with a generated P-256 key whose `D.Bytes()` is 31 bytes written in BIND v1.3 format: `ValidateKeyForImport: ... invalid ECDSA private key length 31 (want 32)`. miekg's own `PrivateKeyString` zero-pads, so the repository fixtures never trigger it.

**Fix specification:** Normalise at the parse boundary: when the file's `Algorithm` is 13 or 14, accept `1 <= len <= 32/48` and left-pad with `new(big.Int).SetBytes(b).FillBytes(make([]byte, size))`; keep rejecting longer values, keep the exact-length invariant for the in-memory form and the `[1, n-1]` scalar check. Generated keys and file formats are unchanged.

**Verification:** Loop-generate a P-256 and a P-384 key until `len(D.Bytes()) < size`, write BIND v1.3 text with the minimal-length base64, assert `ParsePrivateKeyFromFile` returns 32/48 bytes and `ValidateKeyForImport` passes; assert 33-byte and zero inputs are still refused.

### RM51X-027 — When the parent's nameserver set cannot be resolved, the DS query falls back to the child's own servers and reports a "possible downgrade attack"

**Severity:** Medium

**Location:** `validator/internal/validator/validator.go:1773-1786` (`parentNS = fallbackServers` whenever `ResolveNSSet(parentZone)` errors, returns nil or yields no addresses); consequences in `finalizeNoDSDelegation` `validator.go:2164-2183`.

**Problem:** The DS RRset exists only in the parent. On a transport error, SERVFAIL or REFUSED from the recursive resolver for the parent's NS set, the DS query is sent to the child's servers. A child-only authoritative answers DS-at-apex with its own NODATA (apex NSEC signed by the child, rejected by the signer-zone check) or an upward referral (no NSEC at all). Both shapes end in `finalizeNoDSDelegation` as Bogus "the parent's proof of DS absence did not verify (possible downgrade attack)" or as Indeterminate with the same wording. A resolver hiccup becomes a security alarm, in the one tool whose purpose is to tell the two apart.

**Evidence:** Probe `TestProbe_F2_ParentNSFailureFallsBackToChildServers` (`test. NS` dropped at the recursive resolver; the child answers `child.test. DS` with NODATA plus its child-signed apex NSEC): `zone child.test. status=bogus errors=[the parent's proof of DS absence did not verify: … RRSIG signer child.test. is not the expected signing zone test.]`, `RESULT=bogus`.

**Fix specification:** Remove the fallback. If the parent is not the root and its nameserver set cannot be resolved (error, nil set or zero addresses), return an error from `queryDSFromParentWithValidation`; `validateZone` already maps that to Indeterminate "failed to query DS from parent" (1529-1532, 1459-1464). Keep the root-server list for `parentZone == "."`. `parentDSResult` and the schema are unchanged.

**Verification:** The probe must give `RESULT=indeterminate` with an error naming the parent NS lookup and no "downgrade attack" text; assert through the mock's question log that no DS query reached a child address.

### RM51X-028 — RRSIG validity windows are compared as absolute times, not with the RFC 4034 §3.1.5 / RFC 1982 serial arithmetic every resolver uses

**Severity:** Medium

**Location:** `validator/internal/validator/dnssec.go:520-525` (`rrsigWireTimeValid`, used by all signature verification), `dnssec.go:213-219` (`VerifyRRSIGValid`), `validator/internal/dns/records.go:72-79` (`RRSIGFromRR` sets the `IsValid`/`IsExpired` display flags the same way).

**Problem:** RFC 4034 §3.1.5 requires Inception/Expiration comparisons to use serial-number arithmetic: the fields cannot refer to dates more than 68 years away, and an expiration more than 2^31 seconds ahead of `now` is *in the past*. Unbound (`check_dates`) and BIND (`isc_serial_lt`) implement this, so a signature with expiration `now + 70 years` is expired for them. This validator converts both fields to `time.Time` and compares linearly, so it reports **Secure** for a signature every production resolver rejects, which is exactly the misconfiguration (an "expires 2099" signing policy) a diagnostic tool must catch. There is also no check that inception precedes expiration in serial order. miekg's `RRSIG.ValidityPeriod` does not implement RFC 1982 either, so it is not a drop-in replacement.

**Evidence:** Probe `TestProbe_F4_SerialArithmetic`: for expiration `now + 70y`, `rrsigWireTimeValid=true`, `RRSIGFromRR IsValid=true IsExpired=false`, and miekg's `ValidityPeriod` also returns true.

**Fix specification:** Implement the RFC 1982 comparison on the uint32 fields: valid iff `int32(now − inception) ≥ −skew` and `int32(expiration − now) ≥ −skew` and `int32(expiration − inception) ≥ 0`, with `now = uint32(time.Now().Unix())` and `skew = ClockSkewTolerance` in seconds. Use it in `rrsigWireTimeValid`, `VerifyRRSIGValid` and the `RRSIGFromRR` display flags so the JSON and the verdict agree. Error text may keep the RFC 3339 rendering.

**Verification:** Unit tests: expiration = now + 2^31 + 1 → invalid (expired); inception = now + 2^31 + 1 → invalid (not yet valid); inception > expiration in serial order → invalid; ordinary windows unchanged; `TestR028_ExpiredSignatureRejected` still passes.

## Low findings

Each entry keeps the same seven elements in compressed form (location, problem with evidence, fix, verification). All were confirmed from the code by the lead reviewer unless marked "Needs investigation".

### RM51X-029 — NSEC/NSEC3 TTL uses SOA MINIMUM alone (RFC 9077 requires the lesser of SOA TTL and MINIMUM)
**Severity:** Low. **Location:** `signer/internal/signer/sign.go:255-256`, `1749-1756` (`getSOAMinimumTTL`), `1835`, `2033`. **Problem/Evidence:** empirical run with `@ 300 IN SOA ... 86400` produced `NSEC ... 86400` and `RRSIG NSEC ... 86400`; negative answers and RFC 8198 synthesis are cached far longer than the zone's negative-caching TTL. **Fix:** compute `denialTTL = min(SOA.Hdr.Ttl, SOA.Minttl)` once in `prepareSignedZone` and use it for NSEC/NSEC3 (NSEC3PARAM stays 0); add a verifier check that every denial record carries it. **Verification:** sign zones with SOA TTL below, above and equal to MINIMUM; assert the denial TTL and RRSIG `OrigTtl`; mutate a TTL via `mutateBeforeVerify` and assert rejection.

### RM51X-030 — A one-slot signal channel and a reload that can block about 50 s drop a SIGTERM
**Severity:** Low. **Location:** `signer/main.go:766-767`, `805-818` (SIGHUP path), `655-666` (`loadStateLocked` waits up to 30 s), `signer/daemon.go:410-415` (heartbeat stop/start, up to 20 s of synchronous POSTs). **Problem:** the signal goroutine is the only consumer; `signal.Notify` drops signals when the channel is full, so `reload` followed by another HUP and a TERM loses the TERM and `wait_for_pids` hangs. The 30 s lock wait also makes a reload during a long cycle fail silently (logged error, old config stays). **Fix:** enlarge the buffer, move heartbeat stop/start out of the signal goroutine, and queue "reload requested" so HUPs coalesce and a reload deferred by a running cycle is applied after it. **Verification:** park a cycle via `beforeSignZone`, send HUP, TERM, HUP; assert `Run` returns within the shutdown budget.

### RM51X-031 — Web handlers read `cfg/state` and the generation non-atomically (RDAYBLUEX-025 incomplete)
**Severity:** Low. **Location:** `signer/web.go:272-291` (`d.current()` then `d.Generation()`), `signer/daemon.go:684-704` (`takeSnapshot` reads both under one lock). **Problem:** a `Reload` between the two calls caches a pre-reload validation result under the post-reload key for up to 30 s. **Fix:** add `currentGen()` returning cfg, state and generation under one `RLock` and use it in the three validating handlers. **Verification:** race-detector test swapping and bumping under `d.mu` while handlers run.

### RM51X-032 — `/health` on the dashboard listener is rate-limited by `health.allow_remote`, not the listener's exposure
**Severity:** Low. **Location:** `signer/web.go:294`, `signer/daemon.go:95-100`, `signer/health.go:22-51`. **Problem:** with `web.allow_remote = true` and `health.allow_remote = false`, `/health` and `/healthz` are reachable on the exposed port with no limiter; cost is per-request status snapshots (probes stay cached). **Fix:** pass the listener's exposure into `RegisterHealthHandlersWithDaemon` or do not register health on the web mux. **Verification:** burst requests to `/health` on a web server built with that split; assert 429 appears.

### RM51X-033 — The hook retry backoff map grows without bound
**Severity:** Low. **Location:** `signer/hook_dispatch.go:75-87`, `250-277` (`settle` inserts on failure, deletes only on success), `164-196`. **Problem:** identities are `(domain, signedAt)`; a failing generation superseded by a newer signing never settles successfully and its entry lives for the process lifetime. **Fix:** in `settle`, drop older entries of the same domain; prune entries whose `until` is older than `hookRetryBackoffMax` on each `dispatch`. **Verification:** dispatch three failing generations for one domain; assert `len(h.backoff) == 1`.

### RM51X-034 — Hook completions that miss the 10-second state lock are dropped; long cycles can turn this into a redeploy loop (Needs investigation)
**Severity:** Low. **Location:** `signer/daemon.go:1153-1161` (`recordHookResult` gives up after 10 s), `712-721` and `803-805` (the cycle holds the lock across network probes). **Problem:** when cycle k+1 starts before the hook from cycle k completes and runs longer than 10 s, the completion is discarded; in hook mode the zone stays pending, is re-dispatched, and `PublishedAt` never advances. **Fix:** hand completions to the signing goroutine through a mutex-protected queue drained right after the cycle's first `ReloadFromDisk`; keep the immediate path as the fast case. **Verification:** park cycle k+1 for more than 10 s while a hook completes; assert the zone is confirmed and not re-dispatched.

### RM51X-035 — The Windows build does not compile, and the Windows lock implementation would deadlock `serve` if it did
**Severity:** Low. **Location:** `signer/internal/fsutil/fsutil.go:82`, `273` (`syscall.Stat_t`), `signer/filelock_windows.go:22-44`, `signer/main.go:728` → `735` → `655-657`, `signer/CLAUDE.md:578-579`. **Problem/Evidence:** `GOOS=windows go build ./...` fails in `fsutil`; if it compiled, `acquireInstanceLock` would hold `winLockMu` for the process lifetime and `loadStateLocked` would block on the same non-reentrant mutex; `release` panics on a second call. **Fix:** either drop Windows explicitly (`//go:build !windows`, delete the `_windows.go` files, fix the docs) or make it real (separate mutexes, idempotent release, a non-Unix ownership shim). **Verification:** `GOOS=windows go build ./...` either fails with a clear constraint message or succeeds with a test proving instance lock then state lock returns.

### RM51X-036 — `status`, `/api/status` and the dashboard omit configured-but-uninitialised zones that `/health` and `sign` report
**Severity:** Low. **Location:** `signer/main.go:1055`, `signer/web.go:317`, `364`; contrast `signer/health.go:64`, `162`, `main.go:948`, `daemon.go:897`. **Fix:** pass `configuredZones(cfg)...` in all three places. **Verification:** config with one zone and empty state: `status` summary shows total 1, errors 1, matching `/health`.

### RM51X-037 — `.env.example` files and a dead env-sourcing wrapper document configuration nothing reads
**Severity:** Low. **Location:** `signer/.env.example:1-9` (`DNSSEC_TUDOR_CONFIG` has no reader; `LOG_OUTPUT`, which is read at `signer/main.go:79`, is missing), `validator/.env.example:2`, `5`, `41`, `51-52` ("copy to .env" although nothing loads one; `LISTEN_ADDR=:8791` all interfaces; deprecated `STATIC_DIR`; "empty = unrestricted" is false, `getEnvCSV` returns the loopback default), `validator/freebsd/sigillum-validator.sh:7-18` (`set -a; . file` wrapper shipped by `.goreleaser.yaml:44` although the rc.d and QUICKSTART say no wrapper is used). **Fix:** delete both example files and the wrapper, drop the `.env` entries from the `.gitignore` files, and list the supported environment variables with exact semantics in `validator/README.md`. **Verification:** the FreeBSD archive contains no `.sh`; `grep -rn DNSSEC_TUDOR_CONFIG .` is empty.

### RM51X-038 — Test-only production paths: an unbounded hook launch branch and vestigial helpers
**Severity:** Low. **Location:** `signer/hooks.go:259-278` (`firePostSignHooks` with `wg != nil` creates a throwaway dispatcher bypassing the process-wide bound; only tests use it), `hooks.go:331-347` (`executeHookSync`, tests only), `signer/main.go:1184-1188` and `576-598` (`keyPairAbsent` result discarded, comment describes a superseded role). **Fix:** remove the `wg` branch and `executeHookSync` (port tests to `newHookDispatcher`/`runHookInvocation`); use or rename `keyPairAbsent`. **Verification:** build, vet, ported tests pass.

### RM51X-039 — Deferred hooks survive `Reload` with stale generation references
**Severity:** Low. **Location:** `signer/daemon.go:72-77`, `782-789`, `347-464` (`Reload` never clears `deferredHooks`). **Problem:** after a failed save and a SIGHUP, the next cycle still launches the old reference; the hook runs and its completion is discarded as superseded. **Fix:** set a flag in `Reload` that the signing goroutine consumes to clear `deferredHooks`. **Verification:** fail save, reload, run a cycle; assert no invocation for the stale `SignedAt`.

### RM51X-040 — Browser-side escapers are text-context only; attribute interpolations rely on server enums
**Severity:** Low (latent). **Location:** `signer/dnssecstatus/index.html:266-270`, `273`, `404`, `513`; `validator/static/app.js:876-881`, `419`, `286`, `330` (dead `dataset.result`), `183-188` (unparsable `complete` does not close the EventSource, so the browser reconnects and is refused). **Fix:** add an `escapeAttr` that also escapes quotes, use it in attribute contexts, coerce numeric fields, delete `dataset.result`, close the stream in the invalid-`complete` branch. **Verification:** render a fixture whose domain contains `"`; assert one element with the literal id.

### RM51X-041 — `setupLogging` closes the active sink before installing its replacement
**Severity:** Low. **Location:** `signer/main.go:266-311` (`closeSyslogWriter()` at 275 and `logFile.Close()` at 293-296 precede `slog.SetDefault` at 311). **Problem:** records emitted during SIGHUP go to a closed writer and vanish. **Fix:** open the new sink, `SetDefault`, then close the previous one. **Verification:** log continuously across `setupLogging()` and assert no "file already closed" errors or sequence gaps.

### RM51X-042 — The dashboard reads one public-key file per zone per page load and per 60-second refresh
**Severity:** Low. **Location:** `signer/web.go:319-330`, `signer/templates/index.html:6`. **Fix:** cache DS text per `(generation, domain, KSK.ID)` or compute lazily in `apiZoneHandler`. **Verification:** benchmark with 3000 zones; count file opens via a seam.

### RM51X-043 — Parent-DS observations are keyed by 16-bit key tag; a tag collision can make `import` choose the wrong KSK
**Severity:** Low. **Location:** `signer/internal/validate/parentds.go:300-312` (`algorithm[k.KeyTag()] = k.Algorithm` overwrites), `336-360`; `signer/internal/signer/bindkeys.go:285-290`, `393-406`. **Problem:** two candidate KSKs with the same tag and different algorithms collapse into one slot, so `PresentOnAll[tag]` can be true for the key whose DS is not at the parent and `DSMissing` stays false. **Fix:** key observations by `(tag, algorithm)` alongside the tag maps; `pickByTag` errors on ambiguity and accepts `tag/alg` or a path. **Verification:** two generated KSKs forced to one tag with different algorithms; the parent serves one DS; assert the right choice and an ambiguity error for `--ksk <tag>`.

### RM51X-044 — RRSIG verification in the internet validator stops at the first key with a matching tag
**Severity:** Low. **Location:** `signer/internal/validate/validate.go:547-556` (`break` on the first tag+algorithm match), `568-572` (marks `broken`). **Problem:** RFC 4035 §5.3.1 requires trying every matching key; a tag collision during a ZSK or algorithm rollover reports "broken"/SERVFAIL for a zone validators accept. **Fix:** try every candidate and set `broken` only if none verifies. **Verification:** extend `validate_verdict_test.go` with two equal-tag keys where only the second verifies.

### RM51X-045 — Import rollback skips a role whose activation failed half-way
**Severity:** Low. **Location:** `signer/import_cli.go:289-302` (`tx.activated` appended only after success), `744-765`; `signer/internal/signer/keytx.go:304-312` (`.private` copied before `.key`). **Problem:** a failure between the two copies leaves a mismatched live pair that rollback does not restore. **Fix:** append the role to `tx.activated` (and set `tx.tags[role]`) before calling `ActivateKeyPair`. **Verification:** add an `activate-mid:ksk` step to the import fault-injection test and assert both halves equal the prior pair.

### RM51X-046 — `dynadot-probe.sh` still echoes both credentials under `bash -x`
**Severity:** Low. **Location:** `signer/scripts/dynadot-probe.sh:42-48` (claim), `52-53`, `68`, `168-170`. **Evidence:** the registrar sub-review ran `bash -x` with stub `curl` and synthetic credentials and saw `+ API_KEY=...`, `+ API_SECRET=...` and the signing string on stderr; `set +x` only runs inside `hmac_b64` and before `curl`. **Fix:** `{ set +x; } 2>/dev/null` at the top of the script. **Verification:** add a `bash -x` case to `TestDynadotProbeScript_SignaturesAndSecretHandling` asserting stderr contains neither credential.

### RM51X-047 — `pushOldDSRemoval` retries a destructive `ReplaceDS` every poll interval with no backoff
**Severity:** Low. **Location:** `signer/internal/signer/rollover.go:808-814`, `signer/registrar_cli.go:427-447`. **Fix:** exponential backoff with a cap persisted in the rollover record; stop after N identical registrar errors while keeping the warning. **Verification:** fake registrar rejecting DELETE; assert attempt spacing grows.

### RM51X-048 — `validate.resolver` is never validated; a bracketed IPv6 literal becomes `[[...]]:53`
**Severity:** Low. **Location:** `signer/internal/validate/validate.go:820-836`; `signer/internal/config/config.go:655-690` validates only the timeout. **Fix:** validate and normalise at load (host, host:port, ip, `[v6]`, `[v6]:port`). **Verification:** table test; keep the empty → `/etc/resolv.conf` → `9.9.9.9:53` chain and document the Quad9 fallback.

### RM51X-049 — Registrar digest strings are lowercased but not whitespace-normalised (Needs investigation)
**Severity:** Low. **Location:** `signer/internal/registrar/registrar_dynadot.go:553`, `signer/internal/registrar/registrar.go:135-137`. **Problem:** any whitespace in the API's digest makes every `push` a destructive replace whose read-back never verifies. **Fix:** check a live GET; strip whitespace in `GetDS` and `dsKey`. **Verification:** unit test with a spaced digest.

### RM51X-050 — Removal-marker reconciliation keys on `LastSigned`, so a re-added zone whose first sign fails is dropped every cycle
**Severity:** Low. **Location:** `signer/internal/state/state.go:628-641`, `signer/daemon.go:952-958`, `847`. **Problem:** the daemon clears the marker in memory, the placeholder has `LastSigned` zero, the pre-save reload deletes it and re-adopts the disk marker; the init error never persists and init is retried every cycle. **Fix:** track the disk's markers in the merge base and apply the three-way rule to markers. **Verification:** disk marker + re-add placeholder with an init error → zone survives the reload, marker gone.

### RM51X-051 — `Duration.UnmarshalText` accepts `Inf`, `NaN` and overflowing values with platform-dependent results
**Severity:** Low. **Location:** `signer/internal/config/config.go:315-345` (`strconv.ParseFloat` then `time.Duration(n * unit)`). **Evidence:** the state/config sub-review probed `"Infd"`/`"1e30d"` → max int64 on arm64 (accepted as a 292-year lifetime), min int64 on amd64. **Fix:** reject NaN/Inf and out-of-range products. **Verification:** table test.

### RM51X-052 — Relative `data_dir`/`output_dir`/zone paths resolve against each process's working directory
**Severity:** Low. **Location:** `signer/internal/config/config.go:722-728`, `706-709`; `signer/daemon.go:314-339`; `signer/main.go:1118` (only zone paths from `add` are made absolute). **Problem:** daemon and CLI can lock and write different trees. **Fix:** resolve relative paths against the config file's directory in `LoadConfig`, or require absolute paths. **Verification:** load a config with relative paths from another cwd.

### RM51X-053 — `health.listen`/`web.listen` are only checked for loopback-ness; `""` with `allow_remote` binds an ephemeral port on all interfaces
**Severity:** Low. **Location:** `signer/internal/config/config.go:737-747`, `754-769`; `signer/daemon.go:193`. **Fix:** require `net.SplitHostPort` to succeed with a non-zero port. **Verification:** `""`, `"127.0.0.1"`, `":0"` rejected naming the field.

### RM51X-054 — `hooks.post_sign` and `hooks.post_sign_cmd` may both be set; the first silently loses and `shell = true` is ignored
**Severity:** Low. **Location:** `signer/internal/config/config.go:296-302`, `signer/hooks.go:140-156`. **Fix:** reject both set, and `shell` without `post_sign`. **Verification:** unit tests for both rejections.

### RM51X-055 — `RemoveZoneFromConfigFile` deletes comments preceding the next table and the file's final newline
**Severity:** Low. **Location:** `signer/internal/config/config_edit.go:95-115`. **Fix:** walk back over blank/comment lines before the next header; preserve a trailing newline. **Verification:** byte-compare expected output with a banner comment before `[hooks]`.

### RM51X-056 — `preserveOwner` silently lets a non-root edit change the config's owner
**Severity:** Low. **Location:** `signer/internal/fsutil/fsutil.go:272-281` (`if geteuid() != 0 { return nil }`). **Problem:** the docstring says the config "never changes hands", but a non-root process in a writable directory renames a file it owns over one owned by someone else. **Fix:** refuse when not root and the destination's uid differs. **Verification:** test via the `geteuid`/`chownFn` seams.

### RM51X-057 — Stale `.<name>.*.tmp` files from a crash are never cleaned up
**Severity:** Low. **Location:** `signer/internal/fsutil/fsutil.go:168`, `228`, `340`; `signer/internal/signer/sign.go:2066`. **Fix:** at daemon startup and in `loadConfigStateLocked`, under the state lock, remove files matching exactly `^\.[^/]+\.[0-9]+\.tmp$` older than an hour in `data_dir`, `keys/`, `output_dir`; log each removal. **Verification:** unit test for matching/non-matching names.

### RM51X-058 — A `state.json` containing top-level `null` loads as an empty state
**Severity:** Low. **Location:** `signer/internal/state/state.go:341-343`, `534-536`. **Fix:** require the first non-whitespace byte to be `{` and give empty files a dedicated message; keep `{"zones": null}`. **Verification:** tests for `null`, empty, `[]`.

### RM51X-059 — Zero `expires`/`rollover_due` in persisted key records trigger a permanent warning or an immediate ZSK rollover
**Severity:** Low. **Location:** `signer/internal/state/state.go:417-425`; `signer/internal/signer/sign.go:2192-2207`; `signer/internal/signer/rollover.go:300`, `329`. **Fix:** reject a zero `Expires`; normalise a zero `RolloverDue` to `Created + 0.75×(Expires−Created)` at load. **Verification:** load a record without `rollover_due` → derived value; zero `expires` → load error.

### RM51X-060 — Metrics: series for zones that never enter state are never deleted; failed inits observe 0 s; histogram comments are wrong
**Severity:** Low. **Location:** `signer/internal/metrics/metrics.go:151-234`, `237-251`, `68`, `120`. **Fix:** include configured domains in the tracked set; skip the histogram for `(0, false)`; widen buckets and fix comments. **Verification:** extend `TestUpdateZoneMetrics_RemovedZoneSeriesDeleted`.

### RM51X-061 — Dead state API: `ReplaceFromDisk` and `State.Validate` have no production callers
**Severity:** Low. **Location:** `signer/internal/state/state.go:353-359`, `494-517`; `grep -rn ReplaceFromDisk --include=*.go signer | grep -v _test` → only the definition. **Fix:** remove, and update the RA6X-025 docstring that still describes the wholesale replace.

### RM51X-062 — `warnIfConfigWorldReadable` ignores write bits unless the config holds secrets
**Severity:** Low. **Location:** `signer/internal/config/config.go:488-505`. **Problem:** a group- or world-writable config without secrets is not flagged although `hooks.post_sign*` runs as the daemon account. **Fix:** always warn when `perm & 0o022 != 0`. **Verification:** extend the existing test with a hook-only 0o666 config.

### RM51X-063 — No test enforces the "every ZoneState field belongs to one merge class" invariant
**Severity:** Low (test gap). **Location:** `signer/internal/state/state.go:764-767`. **Fix:** reflection test perturbing each exported field of `ZoneState`, `KeyState`, `RolloverState` and asserting `zoneContentEqual` and the `copy*` helpers reflect it.

### RM51X-064 — A ZSK rollover blocked by a KSK/algorithm rollover saves state every cycle
**Severity:** Low. **Location:** `signer/internal/signer/rollover.go:312-321` (`AddWarning` dedupes but `Save()` is unconditional). **Fix:** save only when the warning was added. **Verification:** two consecutive checks produce one write.

### RM51X-065 — Removal markers are never pruned
**Severity:** Low. **Location:** `signer/internal/state/state.go:543-554`, `621-646`. **Fix:** drop markers older than the longest configured poll interval times a generous factor once every running daemon has reloaded (or on `remove` of a zone re-added and signed). **Verification:** unit test.

### RM51X-066 — `withWriteDeadline` clears the socket deadline on handler return, so the final buffered flush is unbounded
**Severity:** Low. **Location:** `validator/server.go:166-181` (`defer rc.SetWriteDeadline(time.Time{})` at 172), `validator/handlers.go:476-487`. **Problem:** net/http flushes the remaining buffer after the handler returns; with `WriteTimeout: 0` a stalled client can pin that goroutine forever. **Fix:** on exit reset the deadline to `now + timeout` instead of zero. **Verification:** fake controller recording deadlines; the last one is non-zero.

### RM51X-067 — Graceful shutdown neither cancels in-flight validations nor tells SSE clients; `Start`/`Shutdown` race on `s.server`
**Severity:** Low. **Location:** `validator/server.go:266-296`, `validator/main.go:144-232`, `validator/handlers.go:222`. **Fix:** a process-wide shutdown context wired through `BaseContext`, a final fatal SSE event on shutdown, `s.server` assigned in `NewServer`, second-signal forced exit. **Verification:** integration test with a blocking seam; `Shutdown` returns promptly and the stream sees a fatal event.

### RM51X-068 — The validator CSP (`style-src 'self'`) blocks the inline `style=""` attributes app.js emits for error, warning and disagreement cards
**Severity:** Low (masked UI bug). **Location:** `validator/static/app.js:637`, `648-649`, `658-659`, `731-732` (seven inline style attributes); `validator/health.go:129`. **Fix:** replace with classes and add rules to `style.css`; keep the CSP. **Verification:** load a bogus fixture with DevTools open: no CSP violations, red borders render.

### RM51X-069 — Unauthenticated validator endpoints disclose build and filesystem details
**Severity:** Low. **Location:** `validator/health.go:36-43` (`version`, `build_time`, `uptime`), `validator/handlers.go:505-531` and `validator/internal/dns/types.go:157-163` (`loadedFrom` path in `/api/anchors`); error strings from `validator/internal/rdap/client.go:100-106`, `140-142` and `validator/internal/dns/egress.go:194`, `207` reach the public JSON. **Fix:** drop version/build from the public `/health`, replace `loadedFrom` with a coarse enum, map transport failures to fixed categories in public output. **Verification:** handler tests asserting the fields are absent.

### RM51X-070 — Static asset caching: cacheable 404s and un-versioned assets cached for a day next to a `no-store` index
**Severity:** Low. **Location:** `validator/server.go:111-135`, `validator/static/index.html:10`, `134`. **Fix:** set long cache headers only on 200 and reference assets with a build-derived query string. **Verification:** `GET /nonexistent` carries no `public, max-age`.

### RM51X-071 — Client disconnects are counted as `indeterminate` validations and logged at WARN
**Severity:** Low. **Location:** `validator/handlers.go:226-240`, `300-313`; `validator/internal/validator/validator.go:244-255` (reports "validation timeout" for `context.Canceled`). **Fix:** distinguish cancellation from deadline; skip or label the metric; demote the log. **Verification:** seam returning `context.Canceled`; no `indeterminate` increment.

### RM51X-072 — Dead, injection-prone SSE helpers
**Severity:** Low. **Location:** `validator/sse.go:119-153` (`WriteRawEvent`, `WriteComment`, `WriteID`; no callers; no CR/LF rejection). **Fix:** delete or make them reject CR/LF. **Verification:** build after removal.

### RM51X-073 — 405 responses lack `Allow`; `HEAD` is rejected on GET resources
**Severity:** Low. **Location:** `validator/handlers.go:123-128`, `328-333`, `512-517`. **Fix:** add `Allow`, treat HEAD like GET on `/api/anchors` and `/health`. **Verification:** table test.

### RM51X-074 — IDN input is rejected outright
**Severity:** Low. **Location:** `validator/handlers.go:534-573`. **Fix:** convert with `idna.Lookup.ToASCII` before validation and echo the A-label. **Verification:** U-label input → 200 with the `xn--` form.

### RM51X-075 — Validator lifecycle and logging nits
**Severity:** Low. **Location:** `validator/main.go:213-216` with `validator/internal/heartbeat/heartbeat.go:186-222` (the "stopping" heartbeat is sent after `cancel()` and never awaited), `validator/logging.go:66-73` (log file never reopened; rotation needs a restart), `validator/server.go:267-275` (`ErrorLog` nil, panics bypass slog). **Fix:** return a `stop` that waits, add SIGHUP reopen or document it, set `ErrorLog`. **Verification:** `httptest` records `stopping` before `stop()` returns.

### RM51X-076 — X-Forwarded-For entries carrying `host:port` collapse every client into the loopback bucket (Needs investigation)
**Severity:** Low. **Location:** `validator/ratelimit.go:264-275`. **Fix:** check the production proxy's format; strip a trailing port with `net.SplitHostPort` before parsing. **Verification:** unit test with `203.0.113.5:1234` entries.

### RM51X-077 — Egress trust is keyed by host only, not by the dial target
**Severity:** Low. **Location:** `validator/internal/dns/egress.go:44-52`, `71-85`, `184-191`; `validator/handlers.go:492-493`. **Problem:** with `recursive_resolver = "10.0.0.53:5353"` an NS record pointing at `10.0.0.53` is trusted and port 53 of that host is dialled; with the default `127.0.0.1` an attacker can route "authoritative" queries to the operator's loopback resolver. **Fix:** trust the exact `host:port` dial target. **Verification:** policy from `"127.0.0.1:5353"` refuses `Permit("127.0.0.1")`.

### RM51X-078 — IPv6 "public" classification still admits `::/96`, `2001:30::/28` and `100:0:0:1::/64`
**Severity:** Low. **Location:** `validator/internal/dns/egress.go:111-129`, `157-180`. **Evidence:** the DNS sub-review probed `::7f00:1`, `2001:30::1`, `100:0:0:1::1` → permitted. **Fix:** additionally require IPv6 destinations to lie inside `2000::/3`. **Verification:** add the three to the non-public table.

### RM51X-079 — RDAP URL is built from wire-derived names without escaping
**Severity:** Low. **Location:** `validator/internal/rdap/client.go:127-130` (`fmt.Sprintf("%s/domain/%s", ...)`); names enter from `validator/internal/validator/validator.go:579-585` and `391`. **Problem:** an alias target such as `x?y.evil.example.` passes `dns.IsDomainName` and becomes a query string against the operator's RDAP origin. **Fix:** validate against the LDH grammar and build with `url.PathEscape`; only follow LDH alias targets into non-DNS consumers. **Verification:** `QueryDomain(ctx, "x?y.evil.example")` errors with zero requests.

### RM51X-080 — `recursive_resolver = ""` or `"[::1]"` passes validation and breaks every validation at run time
**Severity:** Low. **Location:** `validator/internal/config/config.go:48`, `158`, `295` (never validated), `validator/handlers.go:492-493`, `validator/internal/dns/resolver.go:22-24`, `validator/internal/dns/query.go:38-47`. **Fix:** parse and normalise in `Validate()`; build the egress policy from the effective resolver. **Verification:** `recursive_resolver = ""` → load error.

### RM51X-081 — The AA bit is recorded but never consulted; referrals are judged as denial candidates (Needs investigation)
**Severity:** Low. **Location:** `validator/internal/dns/query.go:107`; no use in `validator/internal/validator/validator.go`. **Fix:** classify an AA=0 empty answer as "not authoritative (referral/lame)" and exclude it from denial evaluation. **Verification:** loopback fixture answering AA=0 with an NS authority section.

### RM51X-082 — Anchor cache and URL stages are unreachable in production; `Refresh()` resets the age metric; an older cache outranks a newer built-in document
**Severity:** Low. **Location:** `validator/internal/dns/anchors.go:367-391`, `validator/anchors_store.go:66-96`, `validator/main.go:187-202`, `validator/README.md:76-78`. **Fix:** one precedence applied by both `Load` and `Refresh` (prefer the newest `generatedAt`, operator file first); set `loadedAt` only when the set changed or came from the network; correct the README. **Verification:** older cache + newer built-in → built-in adopted.

### RM51X-083 — `DefaultConfigPaths` includes a working-directory-relative `config.toml`
**Severity:** Low. **Location:** `validator/internal/config/config.go:20-24`, `246-260`. **Fix:** drop the relative entry; log the loaded path. **Verification:** `Load("")` from a directory containing `config.toml` falls through to the environment.

### RM51X-084 — `RCodeName` knows only RCODEs 0-5
**Severity:** Low. **Location:** `validator/internal/dns/types.go:211-225`. **Fix:** `dns.RcodeToString` with a `RCODE<n>` fallback.

### RM51X-085 — Post-sign window check uses a second clock reading; very large RSA zones can never pass self-verification
**Severity:** Low. **Location:** `signer/internal/signer/sign.go:350`, `1313`, `1428`, `358-387`. **Problem:** a pass longer than the fixed 10-minute tolerance (roughly 600k RSA RRsets) fails every RRSIG window check and is retried forever. **Fix:** compare the intended window against the pass clock, keep the fresh clock only for currency. **Verification:** window check with a verification clock 15 minutes after the signing clock.

### RM51X-086 — A DNAME at the apex does not occlude names beneath it
**Severity:** Low. **Location:** `signer/internal/signer/zonemodel.go:170-188`, `191-203` (ancestor walks stop before the apex), `signer/internal/signer/sign.go:1238`. **Evidence:** the signing-core sub-review signed `@ DNAME target.` plus `www A` without error; `www` received an NSEC. **Fix:** include the apex in the DNAME-occlusion walk. **Verification:** apex DNAME + child record → validation error.

### RM51X-087 — Remediation hint for a missing old ZSK names a command that refuses ZSK rollovers
**Severity:** Low. **Location:** `signer/internal/signer/sign.go:720`, `signer/main.go:1461`. **Fix:** name the real remedy (restore the tag-named public half) and consider a guarded `rollover complete --force` for ZSK signing-phase rollovers.

### RM51X-088 — Non-IN class records and mixed TTLs within an RRset are accepted and fail or misbehave later
**Severity:** Low. **Location:** `signer/internal/signer/sign.go:1176-1255` (`validateZoneRecords` checks neither), `1678` (RRSIG class hard-coded IN), `1679`, `1684` (RRSIG TTL/OrigTtl from file order). **Evidence:** `ver CH TXT` fails post-sign verification with "dns: bad key"; `www 300 A` + `www 7200 A` emits both TTLs with `OrigTtl` depending on order. **Fix:** reject non-IN records; normalise an RRset's TTLs to the minimum (RFC 2181 §5.2) before signing. **Verification:** table tests.

### RM51X-089 — nfpm `file_info` omits owner/group, so `rpm -V` reports the config file forever
**Severity:** Low. **Location:** `.goreleaser.yaml:77-78`, `122-123`; `packaging/*-preinstall.sh:3`. **Fix:** add `owner: root` and `group: <service>`; keep the post-install chown as a safety net; add `rpm -V` to the container test.

### RM51X-090 — `.gitignore` misses lock/temp files written into `testdata/` and a developer's local `config.toml`
**Severity:** Low. **Location:** `signer/.gitignore:7-9`, `24-25`; `validator/.gitignore`; names from `signer/filelock_unix.go:27`, `63`. **Fix:** add `*.lock`, `testdata/state.json.*`, `/config.toml`, `/validator.local.toml`. **Verification:** `git check-ignore signer/testdata/serve.lock validator/config.toml`.

### RM51X-091 — systemd units: no stop-timeout alignment, no syscall filter, undocumented `ReadWritePaths` need
**Severity:** Low. **Location:** `packaging/sigillum-signer.service:7-28`, `packaging/sigillum-validator.service:7-29`; `signer/daemon.go:244-249`. **Fix:** `TimeoutStopSec=150` for the signer; `SystemCallFilter=@system-service`, `CapabilityBoundingSet=`, `ProtectClock`, `ProtectHostname`, `RestrictNamespaces`, `RestrictRealtime`, `MemoryDenyWriteExecute`, `ProtectProc=invisible`; document the drop-in for an `output_dir` outside the state directory. **Verification:** `systemd-analyze security` and the container test.

### RM51X-092 — `preremove` aborts package removal when `systemctl stop/disable` fails
**Severity:** Low. **Location:** `packaging/sigillum-signer-preremove.sh:4-10`, `packaging/sigillum-validator-preremove.sh:4-10` (`set -e`). **Fix:** `|| true` with a stderr warning; keep the `remove`/`0` gating. **Verification:** mask the unit before `apt remove`; removal succeeds.

### RM51X-093 — `.gitleaks.toml` uses the deprecated singular `[allowlist]` block
**Severity:** Low. **Location:** `.gitleaks.toml:8-13`. **Fix:** rename to `[[allowlists]]`.

### RM51X-094 — Documentation drift: README directory setup contradicts the package model; FreeBSD guides ship Linux paths; the health listener is undocumented in the package guide
**Severity:** Low. **Location:** `signer/README.md:60-69` (`chown -R`, `/bin/false`, 0755 `signed/`), `docs/linux-packages.md:20` (omits `127.0.0.1:8054`), `validator/config.toml.example:2`, `12`, `18` and `validator/QUICKSTART-FREEBSD.md:46-58`, `165-169` (`/var/lib` cache path never created on FreeBSD, stale load order), `signer/sigillum-signer.rc.d:5` (`BEFORE: nsd` runs the first hook before the nameserver is up), `18-19` versus `packaging/sigillum-signer.toml:3-4` (`/var/db` versus `/var/lib`), `63-65` (`daemon -o` log rotation undocumented), `36` versus `validator/freebsd/sigillum-validator:33` (`bin` versus `sbin`). **Fix:** point the README at the package guide, add the 8054 listener, add a FreeBSD cache path and directory to the QUICKSTART and rc.d, fix the load-order text, use `REQUIRE: nsd`, recommend `--log-output syslog`, pick one install directory.

### RM51X-095 — `verify-signatures.sh` does not check manifest completeness; `update-notices.py` mixes cwd- and script-relative paths
**Severity:** Low. **Location:** `scripts/verify-signatures.sh:23-35`, `scripts/update-notices.py:22`, `26-28`, `82`. **Fix:** assert every `*.tar.gz *.deb *.rpm` in `dist/` appears in `checksums.txt`; default `--dist` to the repository root and resolve artifact paths against it.

### RM51X-096 — The denial-proof engine is chosen on unauthenticated records, so one injected unsigned NSEC flips an authenticated NSEC3 denial to Bogus

**Severity:** Low

**Location:** `validator/internal/validator/validator.go:899-923` (`verifyActualRecord`: `if len(nsecCands) > 0 {…} else if len(nsec3Cands) > 0`), `validator.go:705-718` (`leafCandidateError`), `validator.go:2003-2043` (`verifyDSAbsence`), `validator.go:1152-1172` (`verifyWildcard` switch). **Problem/Evidence:** NSEC wins whenever any NSEC record parsed from Answer/Authority exists, before any signature is checked. Probe `TestProbe_F9_InjectedNSECDivertsNSEC3Proof`: a clean NSEC3 NXDOMAIN is `secure`; the same response plus one unsigned `junk.child.test. NSEC` is `bogus` ("NSEC RRset at junk.child.test. has no RRSIG"). In extended mode another clean server can still win the candidate selection; in quick mode or behind a single on-path injector the false alarm is deterministic. Same family as the pre-authentication cap check in RM51X-010. **Fix:** authenticate both record types first (both calls are budgeted), then run the engine on whichever authenticated set is non-empty, trying NSEC3 when the NSEC set authenticates to nothing; keep the `rejected` diagnostics. **Verification:** the probe returns `secure` in both runs; add the DS-absence and wildcard variants.

### RM51X-097 — Label counting ignores escaped dots; an alias target such as `a\.b.example.` is treated as a wildcard expansion and reads Bogus

**Severity:** Low

**Location:** `validator/internal/validator/chain.go:86-97` (`GetZoneLabels` uses `strings.Count`), consumers `dnssec.go:697-715` (`DetectWildcardSynthesis`) and `nsec.go:1096` (`VerifyWildcardDenial`); `nsec.go:1208-1218` (`lastNLabels`), `1005-1016` (`splitLabels`/`commonSuffixLabels`), `650` (`closestEncloser` label split), `chain.go:10-61` (`SplitIntoZoneHierarchy`/`GetParentZone`); `validator.go:990` follows `c.Target` unfiltered (unlike `discoverAliasTarget` at 582). **Problem/Evidence:** top-level input is filtered by `isValidDomain`, but CNAME/DNAME targets come from DNS data. RRSIG `Labels` is a wire-label count (miekg `CountLabel` is escape-aware, so the signature verifies) while `GetZoneLabels` counts dots: probe `TestProbe_F11_EscapedDotTargetReadsAsWildcard` prints `RRSIG labels=3; GetZoneLabels=4; dns.CountLabel=3`, the alias hop reports `wildcard=true src="*.b.child.test."` lacking a proof, `RESULT=bogus`. The same string splits feed closest-encloser and next-closer computation, so NSEC/NSEC3 reasoning on such names is wrong too. **Fix:** replace every presentation-string split or count used for DNSSEC reasoning with `dns.CountLabel`/`dns.SplitDomainName` (`GetZoneLabels`, `lastNLabels`, `nextCloserName`, `splitLabels`/`commonSuffixLabels`, `closestEncloser`, `SplitIntoZoneHierarchy`, `GetParentZone`, `DetectWildcardSynthesis`); `compareCanonicalNames`/`toWireFormat` are already escape-aware. **Verification:** the probe returns `secure`; unit tests `GetZoneLabels("a\\.b.example.") == 3` and `lastNLabels("a\\.b.example.", 1) == "example."`; an NSEC3 NXDOMAIN proof for a qname containing an escaped dot.

### RM51X-098 — NSEC3 hashing is not charged to the verification budget; distinct-salt chains multiply closest-encloser hashing

**Severity:** Low

**Location:** `validator/internal/validator/nsec.go:476-496` (`VerifyNSEC3Denial` loops every chain), `648-674` (`closestEncloser`: one hash per ancestor label, each `iterations + 1` SHA-1 rounds), `857-877` (`computeNSEC3Hash`); also `VerifyWildcardDenial` 1171-1194 and `verifyDSAbsence` `validator.go:2070-2110`; `budget.go` is never consulted on these paths. **Problem/Evidence:** a hostile but genuinely signed zone can place about 300 NSEC3 RRsets with distinct salts in one TCP response (each verifies; the budget of 2000 covers it), each becoming its own chain; for a 100-label qname at 100 iterations that is about 3.7 M SHA-1 computations per response. Probe `TestProbe_F7_NSEC3ChainCPU` measured 0.31 s per response on this machine; `leafCandidateError` repeats it for every server (up to 64) and nothing checks `ctx` between chains, so one request can burn roughly 20 s of CPU and keeps burning past its deadline until the current response finishes. Bounded, but it is the only cryptographic work outside the budget. **Fix:** charge the budget per NSEC3 hash computation (for example one unit per `ceil((iterations+1)/50)` rounds) through the existing `charge`, cap the number of chains considered per response (for example 4, the rest listed in `Ignored`), and check `ctx` between chains; document the new unit next to `DefaultVerificationBudget`. **Verification:** the probe with a budgeted call returns `ErrVerificationBudgetExhausted` (Indeterminate) instead of running to completion; a cancelled context stops the loop.

### RM51X-099 — Slice aliasing between cached `ZoneResult`s and their chain copies can corrupt leaf warnings (Needs investigation)

**Severity:** Low

**Location:** `validator/internal/validator/validator.go:261` and `309` (`result.Chain = append(result.Chain, *cachedResult)` / `*zoneResult`: struct copies sharing the `Warnings` backing array), `357` (`leafZone := &result.Chain[len-1]`), `365` and `384` (`leafZone.Warnings = append(leafZone.Warnings, …)`); warnings are added one at a time at `result.go:226`, so capacities grow 1, 2, 4, 8. **Problem:** whenever `cap(Warnings) > len` (a zone with 3, or 5 to 7, warnings), the leaf append writes into the cached zone's backing array; a later alias hop in the same zone copies the cached struct again and appends, overwriting the first copy's element, so the top-level `chain[i].warnings` in the JSON and the `complete` event shows the alias hop's message. The same hazard applies to `Errors` and `Disagreements` if they are ever appended on a copy. The agent's probe used a three-element batch append, which allocates capacity 3 and therefore did not trigger the overlap; the mechanism follows from Go slice semantics and the one-at-a-time appends in production. **Fix:** clone slices when copying a zone result into `result.Chain` (or `append(slices.Clone(leafZone.Warnings), msg)` at the two append sites). No schema change. **Verification:** harness test: a zone that accumulates three warnings one at a time, `www` CNAME to `a` in the same zone, both producing a leaf warning (for example opt-out); assert the top-level zone's warning text is intact.

## Summary by severity

| ID | Severity | Area | Title |
| --- | --- | --- | --- |
| RM51X-001 | High | signer rollover/registrar | DS changed at the parent without a DNSKEY-propagation gate (KSK and algorithm) |
| RM51X-002 | High | signer validate | Every address of every nameserver must answer; single-stack hosts cannot roll, confirm or import |
| RM51X-003 | High | signer signing | Non-wildcard owners starting with `*` get a wildcard `Labels` count |
| RM51X-004 | High | packaging | Post-install `install -d` on service-owned entries is a symlink privilege escalation |
| RM51X-005 | High | validator engine | Indeterminate parent hands stale or unauthenticated keys to its children (Bogus / false Secure) |
| RM51X-006 | High | validator engine | NXDOMAIN with a signed owner CNAME validated as a denial of the QNAME |
| RM51X-007 | Medium | signer signing | CDS/CDNSKEY signed by the ZSK only |
| RM51X-008 | Medium | signer fsutil/signing | Symlinked output/state/config replaced by regular files |
| RM51X-009 | Medium | signer validate | Parent zone assumed one label up |
| RM51X-010 | Medium | validator engine | NSEC3 iterations above 100 reported bogus instead of insecure; cap checked before authentication |
| RM51X-011 | Medium | signer CLI | `add`/`rollover start` publish DS at file-write time |
| RM51X-012 | Medium | signer CLI | Failed `add` discards the removal marker |
| RM51X-013 | Medium | signer CLI | Config-write preflight checks the wrong capability |
| RM51X-014 | Medium | signer daemon | Failed saves and skipped cycles never reach readiness |
| RM51X-015 | Medium | signer state | No state schema marker; old daemon drops newer fields after upgrade |
| RM51X-016 | Medium | signer rollover | KSK `rollover complete` registrar replace never retried |
| RM51X-017 | Medium | validator packaging | FreeBSD rc.d starts without `-config`; defaults bind all interfaces |
| RM51X-018 | Medium | validator HTTP | Rate limiting keyed on full IPv6 address |
| RM51X-019 | Medium | validator engine/HTTP | Raw per-server responses repeated in every event |
| RM51X-020 | Medium | packaging | Upgrade resets the group of `signed/` |
| RM51X-021 | Medium | validator packaging | Shipped Apache include rejected by httpd |
| RM51X-022 | Medium | signer docs | Documented `sudo`/`systemctl` hooks cannot run under the packaged unit |
| RM51X-023 | Medium | validator DNS | Stale B-root address; IPv4-only root list |
| RM51X-024 | Medium | validator DNS | 4096-byte EDNS buffer and no UDP-timeout→TCP retry |
| RM51X-025 | Medium | validator HTTP | One client can hold the whole validation capacity |
| RM51X-026 | Medium | signer import | BIND/ldns ECDSA keys with short scalars rejected |
| RM51X-027 | Medium | validator engine | DS query falls back to the child's servers; reports a downgrade attack |
| RM51X-028 | Medium | validator engine | RRSIG validity compared as absolute time, not RFC 1982 serial arithmetic |
| RM51X-029 … RM51X-099 | Low | all | See the Low findings section (71 items) |

Totals: 99 findings — 6 High, 22 Medium, 71 Low, 0 Critical.

## Suggested fix order

1. **RM51X-004, RM51X-020** (packaging post-install) — one change fixes both; ship before the next package release since every upgrade re-exposes it.
2. **RM51X-003** (wildcard `Labels`) — pure signer-core change with a verifier assertion; no dependencies; fixes bogus names for affected zones.
3. **RM51X-005** together with **RM51X-027** (validator walk: authenticated keys only, stop at indeterminate, no child fallback for DS) — both change what `validateZone` receives and both are verdict-correctness defects; land them as one change with the four probes ported as tests. Then **RM51X-006** (NXDOMAIN alias answers) and **RM51X-028** (serial arithmetic), which are independent of each other and of step 3's walk change.
4. **RM51X-002** (address-family probing) first, then **RM51X-009** (enclosing-zone discovery): both change `parentds.go`/`validate.go` and are prerequisites for any rollover gating to work on real hosts.
5. **RM51X-001** (DNSKEY-propagation predicate) then **RM51X-016** (KSK retry) and **RM51X-011** (`add` DS timing): all three consume the same predicate; implement it once in `rollover.go` and reuse it. Update the docs in the same change (RM51X-022 can be folded in).
6. **RM51X-007**, **RM51X-029**, **RM51X-086**, **RM51X-088** (signing-core correctness: CDS signing key, denial TTL, apex DNAME, class/TTL validation) — independent, small, each with a verifier check.
7. **RM51X-008** then **RM51X-013** and **RM51X-056** (filesystem writers: symlink resolution, directory-write preflight, owner preservation) — the preflight should test the resolved target directory, so do the symlink change first.
8. **RM51X-015** (state schema) before **RM51X-012**, **RM51X-050**, **RM51X-058**, **RM51X-059** (state merge and validation fixes), so the field round-trip and schema gate land before the merge semantics change.
9. **RM51X-014**, **RM51X-030**, **RM51X-034**, **RM51X-039**, **RM51X-033** (daemon lifecycle and hook dispatch) — share the signing goroutine ownership model; design the completion queue (RM51X-034) together with the readiness signals (RM51X-014).
10. **RM51X-026** (ECDSA scalar normalisation) and **RM51X-043**, **RM51X-045** (import/tag keying) — independent import fixes.
11. Validator denial path: **RM51X-097** (escape-aware label counting) first, because the closest-encloser code it touches is shared, then **RM51X-010** and **RM51X-096** as one "authenticate first, then choose the engine and apply the cap per chain" refactor, then **RM51X-098** (budgeted hashing, chain cap) on top of it.
12. Validator deployment and transport: **RM51X-017** and **RM51X-021** (deployment blockers, any time), **RM51X-023**, **RM51X-024** (root list, EDNS 1232 and the UDP-timeout→TCP retry that removes the common trigger of RM51X-005), then **RM51X-025** and **RM51X-018** (both touch slot/rate accounting; implement the per-client cap on top of the canonical key), then **RM51X-019**, **RM51X-099**, **RM51X-077** to **RM51X-082**, and the remaining Low items.
13. Documentation and hygiene items (**RM51X-037**, **RM51X-094**, **RM51X-089** to **RM51X-093**, **RM51X-095**) can land at any time but should be re-checked after steps 1 to 5 change the operator workflow.
