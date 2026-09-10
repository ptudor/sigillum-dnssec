# Fix verification — Daybreak Blue XHigh

Verification date: 2026-09-10

Review baseline: `3a43241`

Verified source revision: `2a87fdf`

## Result

All 35 findings pass after verification. Every entry in `FIXES_DAYBREAK_BLUE_XHIGH.md` was marked `FIXED`; there were no `SKIPPED` findings. The audit found four incomplete edge cases in the recorded fixes and one pre-existing lifecycle race disclosed by the fix log. Those defects were corrected before the final verdicts below.

The verification compared each finding's problem, fix specification, verification cases, and "preserve"/"must not change" requirements against the implementation. It also traced the surrounding state, reload, publication, network, file, and cache paths and reviewed the new tests for whether they exercise the stated failure mode rather than only the implementation's happy path.

## Per-finding verdicts

| Finding | Verdict | Verification |
| --- | --- | --- |
| RDAYBLUEX-001 | **PASS** | Parent DS candidates are selected only after positive data or denial authenticates. Ordered bad-first/good-later, all-invalid, denial, quick-mode, budget, and diagnostic cases are covered without changing the result schema or making disagreement determine the verdict. |
| RDAYBLUEX-002 | **PASS** | Leaf candidates now classify and authenticate positive RRsets, CNAME, DNAME plus synthesized CNAME, and denial paths. Empty or invalid paths cannot win; alias discovery continues across servers and cancellation stops new queries. Later detailed output and disagreement behavior remain intact. |
| RDAYBLUEX-003 | **PASS** | Delegation discovery retains canonical nameserver identities, validates questions and response status, retries truncation over TCP, handles glue by owner and bailiwick, resolves missing families, and fails when any nameserver lacks an address. Direct DS/SOA probes require authoritative, question-matched, owner-correct answers. Resolver and custom-port behavior is preserved. |
| RDAYBLUEX-004 | **PASS** | Reload compares the canonical, symlink-resolved `data_dir` identity and rejects a move before publishing any new snapshot. Equivalent spellings remain accepted; failed comparisons and unresolved paths fail closed while startup locking, configuration, and state formats remain unchanged. |
| RDAYBLUEX-005 | **PASS** | Hook work carries daemon generation, domain/output identity, signed timestamp, and publication token. Completion mutates state only while all identities still match; stale success and failure are discarded across reload, removal/re-addition, output changes, and newer signing. CLI hook behavior and the hook environment remain unchanged. |
| RDAYBLUEX-006 | **PASS** | Daemon hooks are queued until the merged state is visibly committed. Pre-commit save/reload failures launch nothing and retain the newer in-memory generation; post-rename durability warnings may deploy. Confirmation applies only matched publication fields and no longer replaces newer memory from an old disk snapshot. |
| RDAYBLUEX-007 | **PASS** | DS construction is explicitly phase-based. KSK and algorithm workflows publish both records only during overlap and replace with the new-only set at the safe transition, exactly once with retry on registrar failure. Existing commands, persisted rollover states, and manual operation remain compatible. |
| RDAYBLUEX-008 | **PASS** | Old-DS absence is keyed by key tag plus algorithm across every digest type, so an unexpected digest cannot be mistaken for removal. The observation API and conservative every-parent-server gate are unchanged. |
| RDAYBLUEX-009 | **PASS** | SSE methods propagate `FlushError` when available, cancel the handler, and release the validation slot. Ordinary `http.Flusher` writers retain best-effort behavior and the event schema is unchanged. |
| RDAYBLUEX-010 | **PASS** | Nameserver identities, resolved addresses, and total queries are bounded and deduplicated; validation uses a fixed worker pool and stops queued work on cancellation. Truncation is disclosed as incomplete evidence and cannot produce Secure. Normal-sized results and public output fields remain compatible. |
| RDAYBLUEX-011 | **PASS** | Anchor loading follows operator file, last-known-good cache, embedded pins, then URL; cache writes are validated, atomic, private, and never replace a good set with bad data. Offline first start and restart-after-fetch are covered. Cache paths cannot alias the operator file through textual paths, directory symlinks, or hard links. Operator precedence and configured sources remain intact. |
| RDAYBLUEX-012 | **PASS** | Every typed environment value is parsed fail-closed; malformed integers, overflows, and unsupported booleans are returned together with variable names and without echoing values. Empty variables still use defaults and accepted spellings/config fields are unchanged. |
| RDAYBLUEX-013 | **PASS** | Publication authority follows the configured immediate, hook, or probe mode even when a hook exists. Immediate and probe mode cannot be promoted by hook success; hook mode retains its former confirmation behavior. CLI ordering, state schema, and hook contract are preserved. |
| RDAYBLUEX-014 | **PASS** | Registrar endpoints require HTTPS except the documented loopback development case, never follow redirects, and apply response bounds. Validation happens before credentials or requests are used; provider request shapes and credentials remain unchanged. |
| RDAYBLUEX-015 | **PASS** | Signature timing validation prevents serial-time wrap and enforces operational bounds. Self-verification checks every RRSIG's actual inception, expiration, span, and current validity before replacement, and state records the earliest expiration actually published. Existing keys and configuration field names are unchanged. |
| RDAYBLUEX-016 | **PASS** | Change detection hashes a consistent source snapshot and compares content even when size and mtime match. Verification found that legacy states could record a digest before publishing those bytes; they now require one successful signing pass before the digest is stored, so the recorded identity always describes the served output. Metadata remains an optimization and read failures preserve the last-known-good output. |
| RDAYBLUEX-017 | **PASS** | Source reads enforce byte and record-count limits while reading, detect growth and inconsistent snapshots, and keep the previous signed output/state on failure. A failure for one zone does not stop other zones. Ordinary zone parsing and publication semantics remain unchanged. |
| RDAYBLUEX-018 | **PASS** | A daemon-owned dispatcher supplies a process-wide concurrency bound, per-generation single flight, supersession of queued stale work, retry backoff, reload purge, and bounded shutdown. Coalescing, hook arguments/environment, current-generation retries, and synchronous CLI execution are preserved. |
| RDAYBLUEX-019 | **PASS** | State merging uses a common base and field revisions so same-generation daemon and CLI changes merge without whole-object overwrite. Diagnostics, publication fields, and rollover transitions survive both operation orders and save-failure recovery; on-disk compatibility is retained. |
| RDAYBLUEX-020 | **PASS** | RDAP base URLs require HTTPS and public destinations. Redirects are refused and every dial is checked after resolution, closing rebinding and alternate-address paths. Response parsing, timeouts, and public result fields remain compatible. |
| RDAYBLUEX-021 | **PASS** | Configuration enforces a usable refresh window relative to polling and minimum granularity. The daemon also wakes at the exact earliest refresh threshold and processes zones by expiration urgency, including reload and poll changes, without hot-looping. Manual signing and existing configuration keys remain unchanged. |
| RDAYBLUEX-022 | **PASS** | The public-only DNS policy rejects deprecated site-local IPv6 space along with other non-public categories and repeats the decision at dial time. Tests cover IPv4, IPv6, mapped/transition forms, and allowed Quad9 examples. Explicit policy-off behavior is unchanged. |
| RDAYBLUEX-023 | **PASS** | Positive integer settings use checked integer-to-duration conversion before multiplication. Boundary and overflow values fail configuration/startup with the field identified; valid settings and units retain their prior meaning. |
| RDAYBLUEX-024 | **PASS** | `parent_ds_ttl` is range-checked before narrowing, corrupt persisted values are rejected, and legacy/fallback values use a nonzero checked effective TTL for retirement gates. Default behavior, TOML keys, and the state schema remain compatible. |
| RDAYBLUEX-025 | **PASS** | Aggregate and per-zone cache entries and in-flight work are scoped to the daemon generation. Old work cannot fill a new generation, reload invalidates immediately, and per-zone entries remain bounded. Endpoint schemas and freshness behavior within one generation are unchanged. |
| RDAYBLUEX-026 | **PASS** | A cold per-zone timeout returns 503 with `Retry-After` and never emits `200 null`; the background computation may still populate the cache. Unknown zones, successful JSON, stale-while-refresh behavior, and single flight remain unchanged. |
| RDAYBLUEX-027 | **PASS** | Both handlers share one trimmed, case-insensitive mode parser and reject unknown values with 400 before acquiring a validation slot or starting work. Empty still defaults to extended; quick/extended behavior, metrics labels, and schemas are preserved. |
| RDAYBLUEX-028 | **PASS** | RDAP DS key tag, algorithm, digest type, and digest text are range/format validated before narrowing or comparison. Malformed records cannot match, while valid supported records and result fields retain their behavior. |
| RDAYBLUEX-029 | **PASS** | Managed-zone validation enforces label and wire-length limits, ASCII/A-label grammar, separators, hyphen rules, and root exclusion before CLI/config mutation. Verification found mixed-case NSEC3 signing still failed; NSEC3 and NSEC3PARAM owners now use the canonical apex, and a full mixed-case signing regression test passes. Filename, state, and canonical collision behavior remain unchanged. |
| RDAYBLUEX-030 | **PASS** | Negative per-zone KSK/ZSK lifetimes are rejected with zone/key context; omitted or zero values still inherit and positive overrides remain valid. The loader used by reload and config edits applies the rule without changing the schema. |
| RDAYBLUEX-031 | **PASS** | `resign` and `import` return a nonzero error after deployment-hook failure while retaining the successfully signed/imported state and output for retry. Operations without a hook still succeed and existing hook inputs remain unchanged. |
| RDAYBLUEX-032 | **PASS** | Startup validates all required fields for each enabled integration, including endpoint transport rules, before daemon work begins. Disabled integrations remain inert and existing configuration keys/provider behavior are preserved. |
| RDAYBLUEX-033 | **PASS** | Safety decisions use error-aware stat operations and atomic no-clobber claims. Backup allocation handles ordinary files, symlinks, concurrent claims, permission/I/O errors, and hard-link fallback; rollback removes only a generation it minted and can identify. Existing artifacts are never overwritten or removed by an ambiguous check. |
| RDAYBLUEX-034 | **PASS** | Registrar, RDAP, and anchor HTTP readers consume at most limit plus one byte and reject any response exceeding the advertised limit, including exact boundary cases. Error dispatch and normal response formats remain unchanged. |
| RDAYBLUEX-035 | **PASS** | Health probes are single-flighted and cached for a bounded TTL, with reload/write-failure invalidation and rate-limited remote mode. Verification found invalidation during a failing in-flight probe gave detached waiters a false nil result; the completed result is now stored on the shared entry even after detachment, while new requests re-probe. Health schemas and readiness meaning are unchanged. |

## Corrections made during verification

- `b987179` canonicalizes NSEC3 owner suffixes for mixed-case managed zones (RDAYBLUEX-029).
- `cab65c0` serializes pre-start heartbeat reload publication with daemon startup. This closes the pre-existing race disclosed in the fix log and prevents shutdown from stopping a different client than the one `Run` started.
- `ac5f1dc` preserves an in-flight health probe's failure for every existing waiter across cache invalidation (RDAYBLUEX-035).
- `3f98812` rejects cache/operator anchor aliases through existing parents and hard links (RDAYBLUEX-011). It also brings public-resolver test fixtures into repository policy.
- `f9a7d00` requires successful output publication before a legacy source digest becomes authoritative (RDAYBLUEX-016).
- `2a87fdf` updates an older change-detection fixture to model the now-required digest metadata; this was the only regression found by the final full suite after the production correction.

## Tests and remaining limitation

- `go vet ./...` passed in both Go modules.
- `go mod verify` passed in both Go modules.
- `go test -race -count=1 ./...` passed in both Go modules at the verified revision.
- Focused race-enabled tests for the newly corrected mixed-case signing, startup/reload ordering, health invalidation, anchor aliases, and legacy digest publication passed repeatedly.
- `gofmt -l` over both modules and `git diff --check` were clean.

The package install/reinstall/removal exercise mentioned as not run in the fix log could not run here: its script requires Docker on a Linux amd64 host, while this verifier is Darwin arm64 and Docker is absent. The package/service/config changes and test script were inspected, and the anchor behavior is exercised through unit and process-level tests. CI retains the Linux package job. This is a verification-environment limitation, not a `SKIPPED` finding.
