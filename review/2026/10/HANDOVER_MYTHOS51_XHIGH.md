# Handover — fixes for the Mythos 5.1 XHigh review

Date: 2026-10-07  
Review: `REVIEW_MYTHOS51_XHIGH.md` (99 findings: 6 High, 22 Medium, 71 Low).  
Scope of this pass: the six High findings. Every fix is committed on `main`
with tests; `go vet ./...` and `go test -race -count=1 ./...` are green in
both modules at the final commit.

## Done

| Finding | Commit | What changed | Tests |
| --- | --- | --- | --- |
| RM51X-004 (+RM51X-020) post-install symlink escalation / `signed/` group reset | `8e3bc9f` | `packaging/sigillum-signer-postinstall.sh`, `packaging/sigillum-validator-postinstall.sh`: state directories created on first install only, never modified afterwards; `docs/linux-packages.md` updated | `scripts/package-container-test.sh` plants a symlink and re-groups the directories before the reinstall and asserts neither is followed or reset. **Not executed in this session** (needs Linux + Docker/podman; see the memory note about gummi). Run `scripts/test-packages.sh` after a `make snapshot`. |
| RM51X-005 indeterminate parent hands down stale/unauthenticated keys | `9a50aad` | `validator/internal/validator/validator.go`: `nextParentDNSKEY` hands keys down only from a Secure zone; the walk tracks the nearest indeterminate ancestor and `validateZone` marks descendants indeterminate naming it; `finalizeNoDSDelegation` fails closed without parent keys | `walk_indeterminate_rm51x005_test.go` (5 fixture tests), updated `verification_fixes_test.go`, `chain_enforce_test.go` |
| RM51X-006 NXDOMAIN with alias at the queried name read as a denial | `c212a95` | `isDenialForType` takes the queried name; an NXDOMAIN whose Answer holds a CNAME owned by it takes the alias path; `discoverAliasTarget` consults NXDOMAIN answers | `nxdomain_alias_rm51x006_test.go` (CNAME, DNAME, unsigned alias stays bogus, stray CNAME at another owner) |
| RM51X-003 `*foo`/`**` signed with a wildcard `Labels` count | `e7a982d` | `signer/internal/signer/zonemodel.go` `canonicalLabel` escapes `*` in any label other than the wildcard label; `sign.go` `rrsigLabels` helper, post-`Sign` assertion, verifier check | `wildcard_labels_rm51x003_test.go`; `independentVerify` test helper now normalises the RRSIG owner the way a resolver unpacks it |
| RM51X-002 every address of every nameserver had to answer | `c68430c` | `signer/internal/validate/parentds.go`: per-identity coverage, `isLocalRouteError` (ENETUNREACH/EHOSTUNREACH/EADDRNOTAVAIL/EAFNOSUPPORT), `ParentDSObservation.Skipped`, publication details name skipped addresses; `validate.go` `directExchange` seam; `rollover.go` blocked-phase warning (`rollover is waiting: …`) at Warn; README note | `parentds_rm51x002_test.go` |
| RM51X-001 (+RM51X-016) parent DS changed before the new DNSKEY RRset propagated | `cf7b275` | `state.go`: `RolloverState.NewKeysPropagatedBy`, new `ds_add_pushed_at`, `NeedsOperator` for `algo_ds_add_wait`; `rollover.go`: `stampNewKeyPropagation`/`newKeysPropagated`, `pushOldDSRemoval` gated and returning `settled`, `advanceAlgorithmDSAdd`, `OpRolloverNewDSAdd`, KSK completion waits for the registrar update; `registrar.go` `IncludesOldDS` reads the horizon; `main.go`: `rollover complete` accepts both add-wait states, `rollover algorithm` no longer pushes DS; CLAUDE.md/README rollover sections and DS table | `rollover_ds_propagation_rm51x001_test.go`; rewritten `registrar_phase_rdaybluex007_test.go`, `dsset_rdaybluex007_test.go` |

Behaviour notes the next engineer should know:

- **RM51X-001 semantics.** `rollover complete` still succeeds as soon as the new DS is at every parent server (it starts the DS-TTL wait for retiring the old KSK, which is independent of DNSKEY propagation). What is gated is the parent set shrinking to new-only (and, for an algorithm rollover, the new DS appearing at all). `IncludesOldDS` is now time-dependent; a state record written by an older version in `ds_propagation_wait`/`retiring` has no horizon and is treated as "not propagated" until the next cycle stamps one, so an upgrade mid-rollover keeps old+new at the registrar until then. A KSK rollover record now persists after retiring until the horizon passes, even for zones without registrar automation (at most one DNSKEY TTL plus cache horizons), which blocks an automatic ZSK rollover for that long. The daemon never asks the publisher whether a zone has automation before the horizon; `settled` is learned from `PublishDS` returning `published == false`.
- **RM51X-003 output spelling.** RRSIG (and NSEC) owners for names such as `*foo.example.com.` are written as `\*foo.example.com.` in the signed file. NSD, BIND and miekg parse it to the same wire name; a tool that compares presentation strings would see a difference.
- **RM51X-002 classifier.** Only local route errors are skipped; `ECONNREFUSED` deliberately is not (a listening problem on the server side). `probeIdentities` fails an identity on any non-route failure of any of its addresses, even if another address answered.
- **RM51X-005 output.** Descendants of an indeterminate zone carry the error `ancestor zone X could not be authenticated; no authenticated chain of trust reaches this zone` and per-server status `indeterminate`; served DNSKEYs stay in the JSON as diagnostics.
- The review's validator probes (`REVIEW_MYTHOS51_XHIGH_validator_probes.go.txt`) for F1, F5 (RM51X-005) and F27 (RM51X-006) are now real tests; the remaining probes (F2 → RM51X-027, F4 → RM51X-028, F9 → RM51X-096, F11 → RM51X-097, F7 → RM51X-098) still reproduce their findings and can be ported the same way.

## Not done

Everything from RM51X-007 onward. The review's "Suggested fix order" still applies; with steps 1–4 complete the next steps are:

5. **RM51X-007, RM51X-029, RM51X-086, RM51X-088** — signing-core correctness: CDS/CDNSKEY signed by the KSK, NSEC/NSEC3 TTL = min(SOA TTL, MINIMUM), apex DNAME occlusion, class/TTL validation. Independent, small, each with a verifier check.
6. **RM51X-008 → RM51X-013, RM51X-056** — filesystem writers (symlink resolution first, then the directory-write preflight and owner preservation).
7. **RM51X-015** (state schema marker) before **RM51X-012, RM51X-050, RM51X-058, RM51X-059**.
8. **RM51X-014, RM51X-030, RM51X-034, RM51X-039, RM51X-033** — daemon lifecycle and hook dispatch.
9. **RM51X-026, RM51X-043, RM51X-045** — import fixes.
10. Validator: **RM51X-027** (no DS fallback to the child's servers) and **RM51X-028** (RFC 1982 serial arithmetic) are small and verdict-affecting and worth doing next; then **RM51X-097** before **RM51X-010/RM51X-096** (authenticate-first denial path), then **RM51X-098**, then deployment/transport items **RM51X-017, RM51X-021, RM51X-023, RM51X-024**, then **RM51X-025, RM51X-018, RM51X-019** and the rest.
11. Documentation and hygiene items at any time; **RM51X-022** (sudo hooks in the docs) is partly obsolete now that CLAUDE.md/README describe automation, but the QUICKSTART still prescribes `sudo`.

Housekeeping:

- The review document itself was not annotated with fix status; this file is the status record.
- `CHANGELOG.md` has an `Unreleased` section for the six fixes; `docs/release-notes/` has no entry yet.
- Attribution: commits `d0b225d` and `2705f39` (the review itself) carry a `Co-Authored-By` trailer; the fix commits do not. The repo mirrors to a public GitHub remote, so no trailers from here on.
