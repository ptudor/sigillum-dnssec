# Deep Code Review — GPT-5.6 SOL MAX

Date: 2026-07-11
Scope: entire tracked repository, including both Go modules, tests, embedded web assets, examples, packaging, and operational documentation
Mode: analysis only; no source changes

## Review method

The review traces the signer and validator from configuration and process startup through DNS I/O, trust establishment, signing/rollover state transitions, persistence, HTTP/SSE exposure, and shutdown. Existing review ledgers and regression tests are treated as historical evidence, not proof that a current path is correct. Validation performed during the review includes `go test -race -count=1 ./...` and `go vet ./...` in both modules; both currently pass when the network-listener tests are run outside the restricted sandbox. Additional targeted checks are recorded in the applicable findings.

## Findings

### R-001 — Removing one zone can delete every following commented TOML table

**Severity:** High

**Location:** `Golang-tudor-dnssec-signer/config.go:591-641`, especially `RemoveZoneFromConfigFile`; `Golang-tudor-dnssec-signer/config.go:673-677`, `isTOMLTableHeader`; `Golang-tudor-dnssec-signer/config_remove_test.go:88-145`

**Problem:** `dnssec-tudor remove` finds the end of a zone table with a line-based predicate that does not recognize a valid TOML table header followed by an inline comment. If the next table is written as `[zones."next.example"] # comment`, removal does not stop there. It deletes that table and every subsequent line until it encounters a header whose final non-space character is `]`, or through EOF. This can silently erase unrelated zones and global/registrar configuration, including credentials, while the command reports success.

**Evidence:** `RemoveZoneFromConfigFile` removes `lines[removeStart:end]`; `end` advances until `isTOMLTableHeader` returns true. That predicate is only `HasPrefix("[") && HasSuffix("]")`. A trailing `#` comment makes the suffix test false even though TOML accepts the header. The existing header-variant test covers a comment on the table being removed, then deliberately follows it with an uncommented sibling header; it does not cover a commented *following* header, which is the destructive boundary case.

**Fix specification:** Replace the boundary detector with parsing that understands TOML table headers and comments, preferably an AST/token-preserving TOML edit. If a line-oriented implementation is retained, it must strip only a syntactically valid inline comment outside quoted strings and recognize both normal and array table headers, quoted/dotted keys, surrounding whitespace, and comments. It must remove only the exact requested zone table, preserve all other bytes as far as practical, retain the existing file mode and owner, and fail without rewriting if the structure cannot be identified unambiguously. Do not change the CLI syntax, config schema, `errZoneNotInConfig` contract, or the rule that keys are not deleted.

**Verification:** Add a table-driven regression test where the target is followed by (a) `[zones."next"] # comment`, (b) `[[some.array]] # comment`, and (c) a quoted header containing `#`. Parse the result with `go-toml`, assert only the target is absent, and byte-check that all following tables/comments/secrets survive. Also test that ambiguous or malformed TOML causes an error and leaves the original file byte-identical.

### R-002 — Zone removal transfers ownership of the root-owned secrets file to the daemon account

**Severity:** High

**Location:** `Golang-tudor-dnssec-signer/main.go:338-380`, `loadConfigAndState` / `loadConfigStateLocked`; `Golang-tudor-dnssec-signer/config.go:596-640`, `RemoveZoneFromConfigFile`; `Golang-tudor-dnssec-signer/ownership.go:25-63`, `InitOwnershipTarget`; `Golang-tudor-dnssec-signer/ownership.go:104-147`, `writeFileAtomicOwned`; documented trust boundary in `Golang-tudor-dnssec-signer/CLAUDE.md:84-85`

**Problem:** When root invokes a mutating CLI command and `data_dir` belongs to the unprivileged daemon user, global ownership state is initialized to that user. Zone removal rewrites `/etc/.../config.toml` through the same helper used for daemon data and chowns the replacement to the daemon account. The documented deployment expects a root-owned, group-readable configuration because it contains registrar API keys and shell-hook commands. After one removal, a compromised daemon can edit those commands/credentials; a later root-run invocation or service restart can turn that write access into command execution or persistent DNS control.

**Evidence:** `InitOwnershipTarget(cfg.DataDir)` records the data directory UID/GID. `RemoveZoneFromConfigFile` calls `writeFileAtomicOwned(configPath, ...)`; that helper chowns both the temporary file and final path to the recorded data-directory owner. It never stats and restores the destination configuration's original UID/GID. The source comment says “ownership preserved,” but only the mode from `os.Stat` is preserved.

**Fix specification:** Split configuration replacement from data/key ownership handling. The config writer must capture the existing file's UID, GID, mode, and relevant platform metadata before replacement and apply them to the temporary file before rename; any ownership-preservation failure must abort before replacing the original. It must never infer configuration ownership from `data_dir`. Continue to make state/key/output writes usable by the daemon account. Preserve the config path, schema, mode restrictions, atomic-replacement semantics, and public CLI behavior.

**Verification:** On Unix, create a config owned by one test UID/GID (or use an injected stat/chown seam when tests are not privileged) and a data directory owned by another, initialize ownership as the root path would, remove a zone, then assert the config's UID/GID and mode are unchanged while the requested table alone is removed. Include a forced `chown` failure and verify the original config remains byte-identical. Run the test under `go test -race` as well because the ownership target is process-global.

### R-003 — A configuration path change is detected but the signer reads and republishes the old zone

**Severity:** High

**Location:** `Golang-tudor-dnssec-signer/daemon.go:430-477`, `checkAndSignZone`; `Golang-tudor-dnssec-signer/sign.go:90-116`, `SignZone`; `Golang-tudor-dnssec-signer/state.go:174-214`, `ReloadFromDisk`

**Problem:** After an operator edits a managed zone's `path` and reloads the daemon, change detection uses the new path from `Config`, but the actual signing operation uses the stale path stored in `state.json`. The daemon can therefore notice that file B changed, log that it is signing B, then parse file A and publish A again. This is a correctness and stale-data risk for DNS content migration and can keep records that the operator believed were removed.

**Evidence:** `checkAndSignZone` passes `zoneCfg.Path` to `NeedsSign`, but then calls `snap.signer.SignZone(domain)` without passing it. `SignZone` stats and parses `zoneState.Path`. Existing zones get their `Path` only when first initialized; neither daemon reload nor `ReloadFromDisk` reconciles it with `cfg.Zones[domain].Path`.

**Fix specification:** Make the active configuration the authoritative source path for every sign. Either pass the resolved `ZoneConfig`/path into `SignZone` or reconcile the state's path under its lock before signing. Update the persisted `ZoneState.Path` only in a transaction that cannot claim a successful migration if parsing/signing the new path fails. A failed new path must not overwrite the last known-good signed output or change source mtime/size bookkeeping. Keep the existing `state.json` field for backward compatibility, do not change signed-zone naming, and do not silently fall back to the old path after the config explicitly selects a new one.

**Verification:** Start with state/config pointing at file A, then reload a config pointing at distinguishable file B without recreating state. Assert `NeedsSign` triggers, the signed output contains B and not A, and saved state records B. Add failure cases for missing/malformed B and assert the previous signed output and state provenance remain intact.

### R-004 — Automatic ZSK rollover leaves live keys rotated when state persistence fails

**Severity:** High

**Location:** `Golang-tudor-dnssec-signer/rollover.go:190-233`, `startZSKRollover`; `Golang-tudor-dnssec-signer/keys.go`, `GenerateZSKWithAlgorithm` / key-file replacement; contrast `Golang-tudor-dnssec-signer/rollover.go:476-551`, algorithm-rollover save rollback; `Golang-tudor-dnssec-signer/daemon.go:390-400`

**Problem:** Starting an automatic ZSK rollover replaces the live ZSK files and mutates in-memory rollover state, then returns `state.Save()` directly. If that save fails, the live key files remain new while durable state still describes the old ZSK with no rollover. The daemon's later pre-save merge can re-adopt the old on-disk state. A subsequent sign can then publish/sign with an untracked key set and drop the old DNSKEY before cached signatures/keys have expired, causing validating resolvers to return bogus/SERVFAIL.

**Evidence:** `startZSKRollover` backs up the old key, calls `GenerateZSKWithAlgorithm` (which writes the live `domain.zsk.private` and `.key` files), sets `zoneState.Rollover`, and immediately returns `rm.state.Save()` with no rollback branch. The KSK and algorithm rollover paths contain explicit state/key restoration for an equivalent save failure, showing that this failure mode is recognized elsewhere. No test injects a ZSK-start save failure.

**Fix specification:** Make ZSK rollover start transactional across key files and state. On any persistence failure, restore the prior in-memory ZSK/rollover/`ForceResign` values and atomically restore both old live key files from the validated backup. If restoration fails, return an error that includes both failures, emit an unmistakable critical diagnostic, and prevent automatic signing from proceeding until manual recovery. Prefer staging the new key pair under unique names and committing only after durable state is ready. Preserve key formats/names, backup retention, state schema compatibility, algorithm selection, and rollover timing semantics.

**Verification:** Inject a `State.Save` failure after new-key generation and assert: the function fails, live private/public bytes equal the originals, state has no rollover and still references the old key, and a subsequent sign uses the old key. Add failures for restoring either half of the pair and assert the daemon enters/fails into the explicit non-signing recovery path. Run with the race detector.

### R-005 — Algorithm rollover can commit only the new KSK when ZSK generation fails

**Severity:** High

**Location:** `Golang-tudor-dnssec-signer/rollover.go:452-552`, `StartAlgorithmRollover`; `Golang-tudor-dnssec-signer/keys.go`, `GenerateKSKWithAlgorithm`, `GenerateZSKWithAlgorithm`, and `saveKeyFiles`

**Problem:** Algorithm rollover generates and installs the new KSK first, then generates the new ZSK. If the second generation/write fails, the function returns immediately without restoring the already-replaced KSK. Durable state still points to the old keys and has no rollover record, while the live KSK file is from the target algorithm. The next sign can omit the parent-DS-matched old KSK and break the chain of trust. A failure between writing the private and public half of either generated pair can also expose a mixed or partial live pair.

**Evidence:** After both old pairs are backed up, lines 497-500 install the new KSK. Lines 501-504 return on any ZSK generation error. Rollback is implemented only for the later `state.Save` failure at lines 528-551. `saveKeyFiles` writes/replaces the live pair as part of each generation, so the first operation is externally visible before the second succeeds.

**Fix specification:** Stage both target-algorithm key pairs without altering live names, validate private/public correspondence and key tags, then commit the complete set plus rollover state as one recoverable transaction. On every failure after the first backup—including either generation, either pair write, state mutation/save, or rename—restore both original live pairs and the original in-memory state. Never leave one key type on the new algorithm and one on the old outside a persisted algorithm-rollover phase. Preserve current CLI/API, key encodings, backup filenames, and backward-compatible state fields.

**Verification:** Add deterministic fault injection at: new KSK private/public write, new ZSK generation, new ZSK private/public write, each commit rename, and state save. For every failure, assert both live pairs and durable/in-memory state are exactly pre-operation. Add a successful-path test proving both new pairs and the persisted rollover appear together and that signing publishes both old and new algorithms as before.

### R-006 — The ZSK rollover TTL guard can be shorter than the DNSKEY TTL actually published

**Severity:** High

**Location:** `Golang-tudor-dnssec-signer/sign.go:139-148`, DNSKEY TTL selection; `Golang-tudor-dnssec-signer/rollover.go:247-280`, `dnskeyTTLFloor` and `handleZSKRolloverState`

**Problem:** When `dnskey_ttl = 0`, signing uses the zone's SOA TTL for the DNSKEY RRset, but rollover timing substitutes a hard-coded 24-hour floor. A zone with an SOA TTL greater than 24 hours can advance to the new signing key or retire the old key while resolvers still cache the prior DNSKEY RRset. That violates the rollover's cache-safety invariant and can produce intermittent bogus answers/SERVFAIL for the difference between the actual TTL and 24 hours.

**Evidence:** `SignZone` assigns `dnskeyTTL = getSOATTL(records)` when the configured value is zero. `dnskeyTTLFloor` cannot see the records or the TTL that was published and returns exactly `24*time.Hour` for the same configuration. The phase-gating tests set a nonzero one-second/one-hour `DNSKEYTtl`; none exercises SOA-derived DNSKEY TTLs.

**Fix specification:** Gate each rollover phase using the TTL of the DNSKEY RRset actually first published in that phase, not an unrelated fallback. Persist the observed TTL (or the calculated not-before transition instant) with the rollover so restarts and later config/SOA edits cannot shorten a previously established wait. For old state lacking this field, choose a safe migration behavior that cannot advance earlier than the maximum relevant configured/observed TTL. Do not change the externally published DNSKEY TTL, existing duration config meanings, or state decoding for old files.

**Verification:** Sign a zone with `dnskey_ttl = 0` and SOA TTL 172800, start rollover, advance a fake clock by 25 hours, and assert the phase does not advance; it may advance only after the recorded 48-hour TTL plus existing phase constraints. Test restart round-trip, SOA TTL increases/decreases mid-phase, explicit nonzero DNSKEY TTL, and old-schema state.

### R-007 — ZSK retirement ignores the lifetime of signatures made by the retiring key

**Severity:** High

**Location:** `Golang-tudor-dnssec-signer/sign.go`, `SignZone` and RRset signing; `Golang-tudor-dnssec-signer/rollover.go:331-376`, `handleZSKRolloverState`

**Problem:** The retirement wait is based only on the DNSKEY TTL. Data RRSIGs inherit the covered RRset's TTL, so an old-ZSK signature can remain cached substantially longer than the DNSKEY RRset containing that key. Removing the old ZSK after only the DNSKEY TTL makes that cached signature unverifiable after a resolver refreshes DNSKEY, producing an avoidable bogus/SERVFAIL interval.

**Evidence:** `SignZone` emits data signatures with the covered RRset's TTL. The rollover state machine advances from double-signing to completion using `dnskeyTTLFloor(cfg)` and never records or consults the largest TTL of an RRset signed by the retiring ZSK. For example, a one-hour DNSKEY TTL and seven-day A TTL allow the old DNSKEY to disappear approximately six days before an old cached A+RRSIG necessarily expires. RFC 7583's ZSK rollover timing uses the maximum of the key-set TTL and signature/data TTL, not the key-set TTL alone.

**Fix specification:** When a phase first publishes signatures from a key set, record a not-before transition derived from the maximum TTL of every RRset whose signature can outlive that phase, plus any propagation allowance already required by the strategy. Persist that deadline so a restart or later TTL decrease cannot shorten it. Account for TTL increases before the retiring key is removed. Preserve the existing rollover strategy, CLI/API, record TTLs, and backward decoding of state; old state without the new timing datum must take a conservative path.

**Verification:** With an injected clock, roll a zone whose DNSKEY TTL is one hour and whose longest signed RRset TTL is seven days. Assert that completion is impossible after one hour and possible only after the recorded safe deadline. Cover restarts, a mid-phase TTL increase/decrease, zones whose DNSKEY TTL is the maximum, and old-schema state.

### R-008 — KSK and algorithm rollovers retire the old trust path before cached parent DS RRsets expire

**Severity:** High

**Location:** `Golang-tudor-dnssec-signer/main.go:1098-1152`, rollover-completion handling; `Golang-tudor-dnssec-signer/rollover.go:96-133`, `CompleteKSKRollover`; `Golang-tudor-dnssec-signer/rollover.go:555-587`, algorithm-rollover completion

**Problem:** Seeing the new DS at the parent once is treated as permission to remove the old KSK immediately. Resolvers that cached the preceding, old-DS-only RRset can still have that DS for its full parent TTL. Once the child publishes only the new KSK, those resolvers have no key matching their cached DS and validation fails. The same unsafe transition exists in ordinary KSK and full algorithm rollover.

**Evidence:** The daemon calls the parent check and, on the first successful observation, immediately invokes the completion function, which restores/removes key files and clears rollover state. The next sign omits the old KSK. Neither state type stores when the new parent DS was first observed nor the TTL/expiration of the old parent DS RRset. Automatic DS replacement occurs only after that child-side removal. RFC 7583's double-KSK procedure retains the old key until the prior DS has had time to expire from validating caches.

**Fix specification:** Add a persisted post-DS-publication dwell phase. Record the first continuously confirmed observation of the expected new DS and a conservative deadline based on the authoritative parent DS TTL plus propagation margin; reset the observation if the expected DS disappears. Continue publishing both KSKs and their DNSKEY signatures until the deadline, then remove the old KSK. Apply the same invariant to algorithm rollover and to automatic/manual registrar modes. Preserve `--force` as the explicitly unsafe operator override and preserve existing command/API shapes and old-state decoding.

**Verification:** Simulate a parent changing from old-only DS to new-only DS with a 48-hour TTL. Assert that one successful poll and repeated restarts cannot complete before the deadline, disappearance of the new DS resets/blocks completion, and completion after the deadline leaves a valid new-only chain. Include KSK and algorithm rollovers, automatic registrar replacement, zero/missing TTL handling, and the explicit force path.

### R-009 — Import accepts different KSK and ZSK algorithms and can publish an incompletely signed zone

**Severity:** High

**Location:** `Golang-tudor-dnssec-signer/main.go:1415-1420`, `runImport`; `Golang-tudor-dnssec-signer/sign.go:713-770`, DNSKEY/data signing; `Golang-tudor-dnssec-signer/sign.go:785-868`, `verifySignedZone`

**Problem:** Import merely warns when the KSK and ZSK use different algorithms. The resulting DNSKEY RRset signals both algorithms, while the DNSKEY RRset is signed only with the KSK algorithm and ordinary RRsets only with the ZSK algorithm. That is an algorithm-incomplete zone and standards-conforming validators may reject it. The post-sign verifier checks only that an RRset has some valid signature, so it certifies this invalid output.

**Evidence:** `runImport` prints a warning but continues. The signing code assigns DNSKEY signatures to the KSK set and data signatures to the ZSK set rather than producing every required algorithm over every authoritative RRset. `verifySignedZone` succeeds after finding one verifying RRSIG and never compares the algorithms advertised by zone-signing DNSKEYs with the set of RRSIG algorithms on each RRset. RFC 6840 section 5.11 requires a signed zone to sign every RRset with every algorithm present in its DNSKEY RRset.

**Fix specification:** Reject mismatched-algorithm KSK/ZSK imports before changing any live file unless full multi-algorithm signing is deliberately implemented. Independently strengthen the output verifier to derive the active zone-signing algorithms from DNSKEY and require a valid, in-time signature from each over every authoritative RRset, including DNSKEY. Do not reject separate KSK/ZSK keys of the same algorithm, change supported algorithms, alter public command syntax, or weaken validation during a legitimate algorithm-rollover phase where both algorithms must be emitted.

**Verification:** Import a valid KSK of one supported algorithm and ZSK of another and assert a nonzero result with byte-identical key/config/state/signed-output files. Add synthetic verifier tests showing that one-of-two algorithms fails, both succeeds, an invalid/expired signature for either fails, and a normal same-algorithm split and deliberate algorithm rollover continue to pass.

### R-010 — A failed zone removal reconstructs only part of the deleted configuration

**Severity:** High

**Location:** `Golang-tudor-dnssec-signer/main.go:942-970`, `runRemove`; `Golang-tudor-dnssec-signer/config.go`, `RemoveZoneFromConfigFile` and `AddZoneToConfigFile`

**Problem:** If durable state saving fails after the zone table has been removed, rollback re-adds only the domain and zone path. Per-zone algorithm, lifetimes, serial policy, registrar settings, explicit booleans, ordering, and comments are lost. The command reports failure but has silently changed future signing/rollover behavior, including settings that protect key lifetime and parent DS publication.

**Evidence:** `runRemove` saves only the parsed `ZoneState` and calls `AddZoneToConfigFile(configPath, domain, zonePath)` on rollback. That helper creates a minimal table from its arguments; it has no copy of the bytes or parsed `ZoneConfig` that `RemoveZoneFromConfigFile` deleted. The rollback return value cannot restore arbitrary keys/comments because they were discarded before the state save was attempted.

**Fix specification:** Treat config and state removal as a recoverable transaction. Retain an exact snapshot of the original config (including comments/order/permissions) until state persistence commits, and atomically restore it on every later error; report a compound error if restoration itself fails. Prefer staging both new files and committing with a recoverable journal/generation marker so a crash between renames is also resolvable. Do not alter the TOML schema, existing option meanings, unrelated zone formatting, or the successful remove behavior.

**Verification:** Create a zone table containing every optional field, inline comments, neighboring tables, and unusual ordering; inject state-save and each rename/fsync failure. Assert command failure and byte-for-byte original config/state restoration after both normal return and simulated restart recovery. Also assert successful removal changes only the intended zone and state entry.

### R-011 — A failed re-add deletes a pre-existing signed zone that may still be served

**Severity:** High

**Location:** `Golang-tudor-dnssec-signer/main.go:435-462`, `runAdd` rollback closure; `Golang-tudor-dnssec-signer/main.go`, `runAdd`

**Problem:** `add` supports reusing an existing key pair after a zone has previously been managed, but its rollback always removes the configured signed-output path. A failure during recovery, signing, state persistence, or config update therefore deletes the last known-good signed zone left by the previous management period. A nameserver or deployment process reading that path can immediately lose the zone even though the add failed.

**Evidence:** The rollback closure unconditionally calls `os.Remove(signedPath)` when unwinding. It never records whether the output existed before the command or saves its bytes/metadata. Earlier control flow intentionally detects and reuses existing keys, so a pre-existing signed output is an expected state rather than an exceptional one.

**Fix specification:** Snapshot or durably stage every pre-existing artifact that `add` may replace. On failure, restore the exact previous signed output and metadata; remove the path only if this invocation created it and there was no predecessor. Make rollback idempotent and report restoration failures. Preserve the existing re-add/key-reuse behavior, path layout, permissions, CLI, and successful output content.

**Verification:** Seed old keys and a distinctive signed zone, then inject failures before signing, after output replacement, during state save, and during config update. Each failure must leave all original bytes and modes intact. Also test a truly new zone, for which failed add leaves no new output, and a successful re-add, which replaces the output as it does today.

### R-012 — Key import is not transactional and can leave live key slots partially replaced

**Severity:** High

**Location:** `Golang-tudor-dnssec-signer/main.go:1429-1492`, `runImport`; `Golang-tudor-dnssec-signer/keys.go`, `saveKeyFiles`

**Problem:** Import installs the converted KSK, then the converted ZSK, then signs and updates state/config. Any error after the first installation can leave some or all imported keys live while durable metadata and the parent DS still describe the old set. Later cleanup removes output/state but does not restore the prior key files. This can turn a failed administrative command into a chain-of-trust outage.

**Evidence:** The two `saveKeyFiles` calls are sequential and externally visible. Each may move an existing pair to backup names before replacing it. Subsequent error paths return or remove newly written state/output/config entries but do not restore both original live key pairs. A second-pair write failure is enough to leave the first imported pair installed without a corresponding successful import.

**Fix specification:** Parse and validate both source pairs—including private/public correspondence, roles, algorithms, and tags—before touching live paths. Stage both pairs plus signed output/state/config, then commit them as one recoverable transaction; on every failure restore all old artifacts exactly and retain no partial imported generation. Coordinate this with the generic pair-atomicity fix in R-013. Preserve accepted input encodings, live/backup naming, file permissions, CLI/API, and successful import semantics.

**Verification:** Use fault injection at every pair write/rename, sign, state save, config write, directory sync, and rollback operation. From both empty and already-managed starting states, assert either the complete new generation is committed or every old artifact is byte-identical. Include mismatched public/private input, duplicate tags, mixed algorithms, and crash-recovery tests.

### R-013 — Private/public key pairs are replaced non-atomically

**Severity:** Medium

**Location:** `Golang-tudor-dnssec-signer/keys.go:225-260`, `saveKeyFiles`; `Golang-tudor-dnssec-signer/keys.go:347-354`, `moveKeyPair`

**Problem:** The private and public halves of a live key are separate files committed in sequence. If the public write/rename fails after the private half succeeds, the live slot contains a mixed or incomplete pair. The backup rollback path itself ignores a rename failure. Callers commonly return the original error without restoring the pair, so an ordinary I/O failure can make the daemon unable to load/sign with keys that were valid before the operation.

**Evidence:** `saveKeyFiles` moves the old pair, writes/replaces the private file, and only then writes/replaces the public file. There is no generation manifest or atomic directory switch that readers can use to select a complete pair. `moveKeyPair` attempts to undo the first rename if its second rename fails but discards the rollback error, so the reported result does not describe the potentially split state.

**Fix specification:** Stage both halves, fsync and validate their correspondence, then expose a complete generation atomically (for example through a generation directory plus atomic manifest/pointer) or implement rigorous pair rollback under the existing layout. Readers must never select half of one generation and half of another. Propagate compound rollback errors and provide restart recovery for interrupted commits. Preserve key file formats, permission requirements, public key-loading APIs, and compatibility with existing on-disk pairs/backups.

**Verification:** Inject failures before/after each write, chmod/chown, fsync, and rename and terminate between every commit step. Concurrent and restarted readers must see either the complete old pair or complete new pair, never a mixture. Verify rollback-error reporting and migration/reading of existing layouts.

### R-014 — First-time root administration can create a data tree the service account cannot use

**Severity:** Medium

**Location:** `Golang-tudor-dnssec-signer/ownership.go:39-45`, ownership inference; `Golang-tudor-dnssec-signer/main.go:367-369`, `runAdd`; first-time `add`/`import` directory and file creation

**Problem:** When the configured data directory does not yet exist and an operator runs the documented administrative command as root, ownership inference silently returns no service owner. The command then creates the directory, keys, state, and output as root. The daemon is normally configured to drop to a dedicated user and subsequently cannot update those artifacts, so a successful setup becomes a startup or first-sign failure.

**Evidence:** Ownership inference treats a missing path as a successful no-owner result. `runAdd` then creates the directory using the current effective identity, and downstream writers preserve that identity because no inferred UID/GID is available. Existing-directory tests cover inferred ownership; the missing-directory/root bootstrap case is not exercised.

**Fix specification:** Make privileged bootstrap ownership explicit and deterministic. Accept/configure the intended daemon account or fail before creating artifacts with a precise remediation message; do not guess an account from unrelated system state. Apply ownership to the directory and all staged files before commit. Keep non-root operation and existing correctly owned directories working, and do not weaken mode checks or make secrets group/world-readable.

**Verification:** In an isolated privilege-capable test, start with no data directory and run add/import as root for a configured service UID/GID; assert every directory/key/state/output has the intended owner and the dropped-privilege daemon can sign. Test missing owner configuration fails without creating anything, non-root setup retains its identity, and an existing tree keeps its established ownership.

### R-015 — Concurrent removal can be undone by a daemon holding an older configuration snapshot

**Severity:** Medium

**Location:** `Golang-tudor-dnssec-signer/state.go`, `ReloadFromDisk` and `Save`; `Golang-tudor-dnssec-signer/main.go`, `runRemove`; daemon signing/reload loop

**Problem:** The merge used before saving durable state adds/updates entries read from disk but never treats absence as deletion. A daemon cycle that began with the old configuration can acquire the lock after `remove`, merge the now-deleted on-disk state into its in-memory map, and save its stale zone entry back. Even after SIGHUP excludes the zone from signing, the resurrected state can make status misleading and block a later add as already managed.

**Evidence:** `ReloadFromDisk` iterates disk entries and assigns them but does not delete in-memory entries missing from disk. `runRemove` removes config/state under the shared lock, but a daemon already holding a copied config/state can continue after the lock is released. The operator message requiring SIGHUP does not create a deletion marker or generation check that distinguishes intentional deletion from an older writer.

**Fix specification:** Introduce deletion-aware concurrency control: config authority plus state reconciliation, tombstones/generation numbers, or a compare-and-swap transaction that rejects an older writer. A removed zone must remain removed across a concurrent in-flight cycle and restart, while CLI additions made during daemon operation must still merge safely. Preserve state schema compatibility through optional fields/migration and preserve the existing external lock protocol for old installations.

**Verification:** Pause a daemon after it snapshots the zone, complete `remove` in another process, then resume the save. Assert the zone stays absent from config and state across reload/restart and can be added again. Also test concurrent add, update of an unrelated zone, repeated remove, and old-state migration.

### R-016 — Shutdown holds the daemon mutex while waiting for handlers that need the same mutex

**Severity:** Medium

**Location:** `Golang-tudor-dnssec-signer/daemon.go:139-156`, `Daemon.Shutdown`; `Golang-tudor-dnssec-signer/daemon.go`, `current` and HTTP handler/watcher access

**Problem:** `Shutdown` holds the daemon's write mutex across the blocking `http.Server.Shutdown` call. An in-flight handler that has not yet called `current()` needs the corresponding read lock before it can return, while `Shutdown` waits for that handler. The two operations wait until the shutdown context expires; under the wrong handler timing this makes every graceful stop degrade into a forced timeout and can skip orderly completion work.

**Evidence:** `Shutdown` acquires `d.mu`, reads the server, and invokes its blocking shutdown without unlocking. Request paths and watcher/status paths call `d.current()` under `RLock`. `http.Server.Shutdown` waits for active handlers rather than canceling them synchronously, creating the lock/wait cycle.

**Fix specification:** Under the mutex, snapshot the server pointer and update only the minimal lifecycle state; release the mutex before calling any blocking shutdown/wait operation. Make concurrent/repeated shutdown idempotent and protect server replacement with explicit lifecycle state rather than a long-held lock. Do not change endpoints, shutdown timeout configuration, or the guarantee that a normal shutdown drains active requests.

**Verification:** Add a handler seam that pauses immediately before `current()`, begin shutdown, then release the handler and assert both complete well before the context deadline. Run with the race detector and cover no-server, repeated/concurrent shutdown, a genuinely slow handler that times out, and watcher activity during shutdown.

### R-017 — Successful signing and rollover erase unrelated persistent warnings

**Severity:** Medium

**Location:** `Golang-tudor-dnssec-signer/sign.go:183-200`, `SignZone`; `Golang-tudor-dnssec-signer/rollover.go:120-125`, `369-373`, and `575-580`; `Golang-tudor-dnssec-signer/registrar_cli.go:17-27`, `recordRegistrarWarning`; `Golang-tudor-dnssec-signer/state.go:406-419`

**Problem:** Warnings have no category or ownership, and several unrelated success paths call `ClearWarnings()`. A normal sign or rollover completion can therefore erase an urgent persisted warning that a registrar replacement left the parent with zero DS records. The dashboard/health state becomes healthy-looking while the external outage remains. Conversely, a later successful registrar reconciliation has no targeted way to clear only the resolved registrar warning.

**Evidence:** `recordRegistrarWarning` deliberately persists `URGENT: registrar left zone with ZERO DS...`. `SignZone` clears the entire slice after writing any valid signed file, and every rollover completion also clears it wholesale. `ClearWarnings` is simply `z.Warnings = nil`; it cannot distinguish rollover-due notices from registrar, ownership, or other future warnings.

**Fix specification:** Give warnings stable source/code identity internally and remove only warnings whose condition the current operation actually resolved. Keep the public `warnings` string array and old-state decoding compatible; unknown legacy strings must remain until explicitly resolved, not disappear on sign. A registrar warning may clear only after a successful read-back confirms the expected nonempty DS set. Signing may refresh only signer-owned expiry/rollover notices, and rollover completion may clear only its own action notice.

**Verification:** Persist an urgent zero-DS warning, run a successful sign and each rollover completion, and assert the warning survives state round-trip and remains visible in status/health. Then make registrar push/read-back confirm the intended DS set and assert only that warning clears. Cover duplicate suppression and legacy string-only state.

### R-018 — Per-zone web validation bypasses the dashboard's cache and work bound

**Severity:** Medium

**Location:** `Golang-tudor-dnssec-signer/web.go:15-95`, shared validation cache; `Golang-tudor-dnssec-signer/web.go:299-318`, `apiValidateZoneHandler`

**Problem:** The aggregate dashboard and `/api/validate` use a single-flight cache, but `/api/validate/{domain}` constructs a fresh validator and performs live DNS queries for every request. There is no request-level concurrency limit, per-zone cache, or cancellation propagation. When the unauthenticated dashboard is exposed through a reverse proxy, repeated requests can consume sockets, resolver capacity, goroutines, and the server's request budget despite the protection on the neighboring endpoint.

**Evidence:** `apiValidateZoneHandler` calls `v.ValidateZone(domain)` directly. The only bounding logic (`validationCache.get`) is used by `cachedValidateAll`; the per-zone handler never enters it. `http.Server.WriteTimeout` bounds response writes, not already-started DNS work, and the validation API itself has no context parameter to cancel on disconnect.

**Fix specification:** Route both validation endpoints through one bounded scheduler with a global concurrency cap, key-based single flight, short result TTL, and request cancellation. A cold request at capacity should return a deterministic 429/503 with `Retry-After`; stale-result behavior must be explicit. Preserve endpoint paths and JSON schemas and do not serialize routine signing behind dashboard validation. Keep loopback defaults and allow legitimate parallel validation up to the configured limit.

**Verification:** Issue many simultaneous requests for the same and different zones against a blocking fake resolver. Assert one computation per key, a fixed global maximum, bounded goroutine count, prompt cancellation after client disconnect, and 429/503 at capacity. Verify cache expiry, stale/cold responses, and parity of aggregate/per-zone results.

### R-019 — Zone registration appends directly to the live config and can leave it truncated

**Severity:** Medium

**Location:** `Golang-tudor-dnssec-signer/config.go:572-589`, `AddZoneToConfigFile`; `Golang-tudor-dnssec-signer/main.go`, successful `runAdd` and `runImport` commit order

**Problem:** Adding/importing a zone writes TOML directly with `O_APPEND` and neither fsyncs nor checks the deferred close. A short I/O failure or crash can leave a partial table/header/path in the only config file. State and signed output are committed first, so the command can leave an un-loadable config plus a managed state entry, or report success before the append is durable. This is the write-side counterpart to the removal transaction problems in R-001/R-010.

**Evidence:** `AddZoneToConfigFile` opens the live file and executes one `WriteString`, then returns without `Sync`; `defer f.Close()` discards close errors. It does not use `writeFileAtomicOwned`, which stages, fsyncs, renames, and syncs the parent directory. Both add and import persist state before calling this helper.

**Fix specification:** Construct the complete new config from an exact snapshot, validate it with the strict TOML decoder, and commit through an atomic/durable writer that preserves bytes for unrelated tables/comments plus original mode/owner. Coordinate config, state, keys, and signed output using the transaction/recovery mechanism required by R-010 through R-013 so a crash resolves to a complete old or new generation. Preserve TOML schema, successful formatting conventions, and public CLI behavior.

**Verification:** Inject short writes, file sync/close failure, rename failure, directory-sync failure, and process termination at every commit boundary. On restart, assert either the byte-identical old config/state/artifacts or a fully parseable new set containing exactly one zone. Exercise secrets-bearing 0640 config, comments, inline table comments, concurrent daemon access, add, and import.

### R-020 — Signed-zone rename is not made durable before state can record success

**Severity:** Medium

**Location:** `Golang-tudor-dnssec-signer/sign.go:1370-1425`, `writeSignedZone`; `Golang-tudor-dnssec-signer/ownership.go:104-160`, durable atomic-write helper

**Problem:** The signed file is fsynced and renamed, but its parent directory is not fsynced. A power loss can therefore lose or roll back the directory entry even after state is saved with a new serial, source metadata, and signature expiration. On restart `NeedsSign` can trust that state and decline to recreate the missing/old output until another trigger, leaving the authoritative deployment without the generation state claims is live.

**Evidence:** `writeSignedZone` returns immediately after `os.Rename`. The repository's `writeFileAtomicOwned` explicitly calls `syncDir` after rename for this durability reason, but signed-zone publication does not. The signing state mutation follows the write and is later durably saved by CLI/daemon paths.

**Fix specification:** Make signed-output publication use the same file-and-directory durability contract as state/config while retaining its unique-temp concurrency behavior and 0644 mode. A directory-sync failure must be surfaced/recorded so state is not silently treated as durably published; recovery must safely re-sign or reconcile the output on restart. Preserve output path/content, prior-output-on-signing-error behavior, and cross-platform support.

**Verification:** Add filesystem seams for file sync, rename, and directory sync plus a crash-recovery test at each boundary. After simulated restart, state and output must agree on the published serial/generation, and a missing or older output must force regeneration. Re-run concurrent atomic-writer tests and assert mode/content remain unchanged.

### R-021 — Rollover metrics retain stale active types after a type transition

**Severity:** Low

**Location:** `Golang-tudor-dnssec-signer/metrics.go:148-193`, `UpdateZoneMetrics`

**Problem:** When a zone has a rollover, the collector sets only its current `{domain,type}` series to 1. It resets all types only when there is no rollover. If state changes directly from one rollover type to another between scrapes/restarts/tests, the old type remains 1 indefinitely, producing contradictory alerts and dashboards.

**Evidence:** The non-nil branch calls `WithLabelValues(domain, zone.Rollover.Type).Set(1)` only. The three known labels are zeroed solely in the `else` branch. Prometheus gauge vectors retain earlier label values across scrapes.

**Fix specification:** On every state-to-metrics refresh, zero all supported rollover-type labels for each current domain before setting the one current type. Handle unknown future types without leaving known types stale, and preserve metric names/labels and deletion behavior for removed domains.

**Verification:** Scrape after `ksk -> algorithm -> zsk -> nil` transitions without an intervening nil state and assert exactly one type is 1 at each step, then all zero. Include an unknown type and removed domain.

### R-022 — Key generation knowingly accepts a colliding key tag after ten retries

**Severity:** Low

**Location:** `Golang-tudor-dnssec-signer/keys.go:72-104`, key-generation collision loop

**Problem:** The collision guard documents that equal 16-bit tags can overwrite backup identity and cause registrar upsert to replace the old DS, but after ten collisions it logs a warning and proceeds with exactly that unsafe key. Random occurrence is extraordinarily unlikely, yet a generator failure, deterministic entropy problem, or test/future implementation can turn the guard into silent integrity loss instead of a fail-closed error.

**Evidence:** On `attempt >= maxTagAttempts`, lines 93-96 warn and `break`; `saveKeyFiles` then installs the colliding key and returned `KeyState.ID` is the already-used tag. Downstream backup filenames and rollover state use that tag as identity.

**Fix specification:** Return a hard error after the bounded retries and leave every live/backup key and state entry unchanged. The error should name the domain/role/attempt count without secret material. Preserve the retry bound, random-generation algorithm, normal key formats, and public API except for failing this impossible-to-represent state.

**Verification:** Inject a generator that returns a used tag for every attempt and assert a nonzero error with no filesystem/state changes. Then return a unique tag on the last allowed attempt and assert success; cover collisions with both live roles and backup files.

### R-023 — Hook stderr capture is unbounded and can exhaust daemon memory

**Severity:** Low

**Location:** `Golang-tudor-dnssec-signer/hooks.go:46-109`, `executeHook`; `Golang-tudor-dnssec-signer/hooks.go:111-175`, `executeBatchHook`

**Problem:** Asynchronous post-sign hooks capture all stderr in a `bytes.Buffer` for up to 30 seconds. A broken command that writes continuously can allocate until the daemon is killed, taking signing and monitoring down. The timeout bounds wall time but not output rate or memory, and multiple non-coalesced zone hooks can amplify the allocation.

**Evidence:** Both functions assign an unconstrained `bytes.Buffer` to `command.Stderr`. There is no `io.LimitReader` equivalent, ring buffer, shared hook concurrency cap, or truncation marker. Per-zone hooks may run concurrently for every zone signed in a cycle.

**Fix specification:** Capture a bounded tail/prefix (with an explicit truncation marker) or stream to a bounded logger, and cap concurrent hook processes independently of the signing loop. Continue draining the child pipe so a full pipe cannot deadlock it. Preserve the 30-second timeout, hook environment/API, stdout behavior, asynchronous daemon semantics, and synchronous CLI behavior.

**Verification:** Run hooks that emit output far beyond the cap, block, fail, and run across many zones. Assert bounded process RSS/goroutines, timeout and shutdown completion, a useful truncated diagnostic, no child deadlock, and unchanged success metrics for normal hooks.

### R-024 — Trust-anchor input is not authenticated and can create an attacker-controlled root of trust

**Severity:** Critical

**Location:** `Golang-dnssec-validator/internal/dns/anchors.go:12-145`, anchor loaders; `Golang-dnssec-validator/internal/validator/dnssec.go:630-668`, `VerifyRootTrustAnchor`; `Golang-dnssec-validator/config.go:407-411`

**Problem:** The validator treats arbitrary local/remote JSON as root trust material. The only swap check is that *one* entry has key tag 20326 or 38696; that entry's digest need not be the real IANA digest, and arbitrary additional anchors are trusted. The HTTP client also follows redirects by default, including HTTPS-to-HTTP and cross-origin redirects, so validating only the configured URL's prefix does not protect the final fetch. An attacker who controls the file/fetch and DNS path can add their own anchor, serve a matching forged root key/chain, and make arbitrary data report `secure`.

**Evidence:** `hasKnownRootTag` checks only an integer. A JSON array containing a dummy tag-20326 record plus an attacker anchor passes, regardless of zone, digest syntax/length, source, `GeneratedAt`, or signature. `LoadAnchorsFromURL` uses an `http.Client` with no `CheckRedirect`. `VerifyRootTrustAnchor` correctly trusts any loaded digest that matches a served root DNSKEY, which turns the unauthenticated loader directly into the security boundary rather than mitigating it.

**Fix specification:** Bootstrap from authenticated IANA material: ship/pin the exact accepted root DS/public-key set and implement a standards-based update path (for example authenticated IANA `root-anchors.xml`/signature processing and RFC 5011 hold-down), treating custom JSON only as a cache derived from verified input. Validate zone `.`, algorithms, digest types/length/hex, validity intervals, duplicates, and exact authorized keys before replacement. Reject scheme downgrade and unapproved origin redirects. Commit updates atomically and retain last-known-good anchors on failure. Preserve the public `RootAnchors`/`/api/anchors` JSON shape and offline startup using an authenticated cache.

**Verification:** Demonstrate the pre-fix exploit with dummy-known-tag-plus-malicious-anchor JSON and a forged root DNSKEY/RRSIG chain, then assert it is rejected. Add HTTPS-to-HTTP, cross-origin, tampered signature/XML/JSON, malformed digest/date/zone, unauthorized extra anchor, valid current+successor set, RFC 5011 timing, offline last-known-good, and atomic-update failure tests.

### R-025 — A nonempty local anchor file permanently prevents remote refresh and can miss the 2026 root rollover

**Severity:** High

**Location:** `Golang-dnssec-validator/internal/dns/anchors.go:131-145`, `LoadAnchorsWithFallback`; `Golang-dnssec-validator/anchors_store.go:27-69`; `Golang-dnssec-validator/main.go:86-136`, refresh loop; `Golang-dnssec-validator/health.go:45-64`

**Problem:** The 24-hour “refresh” always returns any nonempty local file before consulting the URL. Its content age and `GeneratedAt` are ignored, while `loadedAt` is reset on each reread, so health/metrics can call a years-old file fresh. A file containing only KSK-2017 tag 20326 will therefore never acquire successor tag 38696 and will reject the root when the successor takes over. IANA currently schedules that rollover for 2026-10-11, making this an imminent whole-service failure mode.

**Evidence:** `LoadAnchorsWithFallback` immediately returns on successful file load. No code writes a verified remote result back, merges anchor sets, or compares `GeneratedAt`; `Age()` measures process load time only and health checks only `len(anchors)>0`. The project's operational docs describe the path as a cache, but code treats it as an immutable primary. See the current [IANA root-anchor files](https://www.iana.org/dnssec/files) and [ICANN rollover schedule](https://www.icann.org/resources/press-material/release-2026-05-20-en).

**Fix specification:** After implementing R-024 authentication, refresh from the authoritative source on schedule and atomically update the local last-known-good cache; use the file only when the network refresh is unavailable or not yet due. Track source `GeneratedAt`, active key tags, last successful authenticated refresh, and next rollover/expiry, and degrade readiness before no usable active anchor remains. Preserve offline validation with a still-valid cached set and never discard a good set because a refresh is invalid/unreachable.

**Verification:** Start with a valid stale file containing only 20326 and a remote authenticated set adding 38696; assert refresh installs/persists both and survives restart. Advance a fake clock through prepublication, activation, and old-key retirement. Cover network failure, malformed/older remote data, read-only cache, concurrent readers, health/metrics staleness, and rollback to last-known-good.

### R-026 — A wildcard answer without an authenticated denial proof still returns `secure`

**Severity:** High

**Location:** `Golang-dnssec-validator/internal/validator/validator.go:301-329`, leaf-verdict integration; `Golang-dnssec-validator/internal/validator/validator.go:722-797`, `verifyWildcard` and `recordValidationVerdict`

**Problem:** A valid RRSIG whose Labels field indicates wildcard synthesis is insufficient: the validator must also authenticate that no closer/exact name existed. The code detects a missing/invalid NSEC/NSEC3 proof and records an error, but `recordValidationVerdict` returns `secure` immediately whenever the data RRSIG verified. An attacker able to replay a wildcard-signed RRset without its denial proof can therefore obtain a false secure verdict.

**Evidence:** `verifyWildcard` sets `Wildcard=true` and `Error` when the proof is absent or its RRSIG fails, while leaving `RRSIGVerified=true`. `recordValidationVerdict` begins `if rv == nil || rv.RRSIGVerified { return StatusSecure }`; its comment explicitly says incomplete wildcard proof stays secure. The call site adds only a warning. RFC 4035 section 5.3.4 requires the additional wildcard nonexistence validation before the answer is authenticated.

**Fix specification:** A wildcard-synthesized positive answer may be `secure` only when both its answer RRset and the required NSEC/NSEC3 proof verify for the correct zone/name. Missing, expired, forged, or logically incomplete proof is `bogus`; an inability to fetch a complete response due solely to transport/timeout may be `indeterminate`. Preserve status enum and JSON fields, including detailed wildcard proof data, and do not require a closest-encloser NSEC3 exact match beyond RFC 5155 section 8.8's next-closer coverage rule.

**Verification:** Update the existing test that enshrines secure-with-warning. Add valid signed wildcard data with no proof, forged/expired proof, wrong zone/parameters, valid NSEC proof, valid NSEC3 next-closer proof, and non-wildcard positive answers. Assert only the two fully verified wildcard cases remain secure.

### R-027 — Leaf cryptographic verification is not bound to the queried owner or DNS section

**Severity:** High

**Location:** `Golang-dnssec-validator/internal/dns/query.go:95-208`, `parseResponse`; `Golang-dnssec-validator/internal/validator/dnssec.go:393-455`, `VerifyRRsetRRSIGFromResponse`; `Golang-dnssec-validator/internal/validator/validator.go:539-685`, `verifyActualRecord`

**Problem:** Parsed records from Answer, Authority, and Additional are merged and most record models lose owner/section. The leaf verifier then accepts the first cryptographically valid RRset of the requested type/key tag anywhere in the message; it never requires that RRset to be the queried name (or the correctly derived wildcard owner). A forged target answer accompanied by a replayed valid A/CNAME RRset and RRSIG for another owner in the same zone can be labeled secure.

**Evidence:** `parseResponse` appends all three sections. `FindRRSIGForType` filters only type. `VerifyRRsetRRSIGFromResponse` groups every section by owner, iterates every matching signature, and returns on any success without a requested-owner argument. The caller checks only `SignerName` against the zone, which an unrelated authentic RRset in that zone satisfies. CNAME selection likewise uses the first merged CNAME.

**Fix specification:** Preserve owner and section internally and make every verifier accept an explicit query context. Positive leaf data/CNAME must come from the Answer section and cover the normalized QNAME, except that a wildcard signature must bind to the RFC-derived wildcard owner and pass R-026. DNSKEY must be the zone apex, DS the exact child owner in the parent response, and denial records only those relevant to the authenticated proof. Do not break existing public JSON; additive owner/section fields may be internal or optional.

**Verification:** Craft wire responses containing an unsigned/forged target A plus a valid signed `other.example.` A in Additional/Authority and assert bogus; repeat for CNAME and same key tag. Cover mixed owners, sections, case, wildcard synthesis, legitimate answer RRSIGs, DS/DNSKEY owner binding, and replayed unrelated signed records.

### R-028 — Cryptographic helpers can validate a different, expired RRSIG than the one whose time was checked

**Severity:** High

**Location:** `Golang-dnssec-validator/internal/validator/dnssec.go:393-539`, RRset/denial verification helpers; `Golang-dnssec-validator/internal/validator/nsec.go:35-103` and `215-290`; `Golang-dnssec-validator/internal/validator/validator.go:1104-1275`, DS and DS-absence verification

**Problem:** `dns.RRSIG.Verify` verifies bytes, not inception/expiration. Both raw-response helpers omit time checks. Several callers pre-check only the first parsed signature, then the helper is free to succeed with another same-type/tag signature; DS-absence calls the denial helper without any time check at all. Expired authenticated denial can downgrade a currently secure delegation to `insecure`, and expired/replayed data or DS signatures can contribute to false secure chain/leaf results.

**Evidence:** `VerifyDenialRRSIGFromResponse` accepts a candidate immediately after `sig.Verify`; `VerifyRRsetRRSIGFromResponse` does the same. NSEC/NSEC3 wrappers call `findRRSIGForType` once for time/key diagnostics but then verify all raw candidates independently. `verifyDSAbsence` directly calls the denial helper. A valid-time but bad first signature plus an expired cryptographically valid second signature passes the helper.

**Fix specification:** Evaluate each signature as one indivisible candidate: correct owner/section/type, signer zone, algorithm and exact DNSKEY identity (not tag alone), validity with the configured skew policy, then crypto over the associated RRset. Accept only if the *same* candidate passes all checks; aggregate candidate errors without switching metadata. Apply this shared primitive consistently to leaf, DNSKEY, DS, NSEC, and NSEC3 paths while preserving accepted rollover multi-signature behavior and public result schemas.

**Verification:** For every RRset class, test expired-only, not-yet-valid-only, valid-bad-plus-expired-good, expired-bad-plus-valid-good, same-tag different-key, wrong owner/signer, and one fully valid among multiple signatures. Specifically assert expired DS-absence proof cannot produce `insecure`. Run with a fake clock across skew and serial-time wrap cases.

### R-029 — Equivalent DNS names can be managed as independent zones with conflicting keys

**Severity:** High

**Location:** `Golang-tudor-dnssec-signer/config.go:336-467`, config validation; `Golang-tudor-dnssec-signer/config.go:679-697`, `ValidateDomainName`; `Golang-tudor-dnssec-signer/main.go`, `runAdd`/`runImport` exact-key checks; state/key/output path construction throughout the signer

**Problem:** DNS names are case-insensitive and an optional trailing root dot does not change identity, but configuration/state maps and filesystem names use the operator's spelling verbatim. `example.com`, `Example.COM`, and `example.com.` can therefore be added as separate managed zones, generating independent KSK/DS sets for one DNS zone. Automatic registrar publication can oscillate the parent between those sets; case-insensitive filesystems can also make the nominally separate key paths collide.

**Evidence:** `ValidateDomainName` accepts upper case and trailing dots but returns no canonical identity. Config validation iterates map keys without checking normalized duplicates, and add/import reject only exact `cfg.Zones[domain]`/`state.GetZone(domain)` matches. `GetZone*`, key filenames, backup names, signed outputs, metrics labels, and registrar operations retain the raw key string, while DNS wire operations call `dns.Fqdn`/case-insensitive routines.

**Fix specification:** Define one canonical management identity (lowercase, no trailing root dot is compatible with existing filenames) and apply it at every CLI/config/state/API boundary. Reject a config containing duplicate canonical identities before any signing or registrar action. Provide a safe migration/diagnostic for a single legacy mixed-case/dotted entry that reuses its existing keys and never silently merges, deletes, renames, or regenerates competing key sets. Preserve DNS owner semantics, public command shapes, and ability to sign mixed-case owner names within a zone.

**Verification:** Attempt every case/trailing-dot pair in one config and through sequential add/import commands; assert rejection before filesystem/state/registrar changes. Test legacy single-entry loading and migration on case-sensitive and case-insensitive filesystems, state reload, rollover backups, metrics, API lookup, and registrar push all resolve to one identity and retain the existing DS-matched KSK.

### R-030 — Unauthenticated zone-cut discovery can turn a parent referral into a false secure NODATA answer

**Severity:** High

**Location:** `Golang-dnssec-validator/internal/dns/resolver.go:172-245`, `CheckZoneCut`/`DiscoverZoneCuts`; `Golang-dnssec-validator/internal/dns/query.go:65-75`, authoritative flag capture; `Golang-dnssec-validator/internal/validator/validator.go:178-189` and `539-603`; `Golang-dnssec-validator/internal/validator/nsec.go:172-208`, NSEC NODATA logic

**Problem:** The security-critical zone hierarchy is inferred from an unvalidated recursive resolver. If it omits a child cut, leaf validation asks the signed parent for data at the delegation. A parent referral is not an authoritative leaf answer, but the validator ignores the captured AA flag and merges the authority NSEC. For a query at the delegation name, the signed parent-side NSEC (NS set, SOA clear, queried type absent) is accepted as NODATA, yielding `secure` even though the child may publish different data.

**Evidence:** `CheckZoneCut` trusts whether the recursive response places NS in Answer; a NOERROR response without it means “not a zone.” `verifyActualRecord` then treats any NOERROR empty Answer plus NSEC/NSEC3 as denial. `verifyNSECNODATA` requires only owner equality and absence of QTYPE/CNAME; it does not reject the delegation pattern `NS && !SOA`. `QueryResult.Authoritative` is stored but never read anywhere. A signed NSEC referral is cryptographically valid under the parent key, so crypto alone does not correct the authority-boundary error.

**Fix specification:** Derive cuts from authenticated referrals while walking from the root (or independently confirm recursive hints against the currently authenticated parent); recursive resolution may accelerate address discovery but must not decide authority. Require an authoritative final answer from the correct zone, distinguish referrals from NODATA, and reject an NS-without-SOA denial as generic leaf NODATA. Apply equivalent correct-zone/delegation checks to NSEC3 and CNAME discovery. Preserve configurable recursive resolvers as hints, API/result shapes, and direct authoritative querying.

**Verification:** Use a fake recursive resolver that hides a real child cut, then have the parent return a correctly signed NSEC/NSEC3 referral while the child has an A record. Assert the validator follows the referral and validates the child, never secure-NODATA at the parent. Cover secure/insecure delegations, apex NODATA (`NS+SOA`, valid), non-authoritative responses, CNAME targets, glue failures, and honest discovery.

### R-031 — Supported query types collapse to `UNKNOWN` in denial bitmaps

**Severity:** Medium

**Location:** `Golang-dnssec-validator/internal/dns/types.go:174-195`, `TypeName`; `Golang-dnssec-validator/internal/dns/query.go:163-193`, NSEC/NSEC3 parsing; `Golang-dnssec-validator/internal/validator/validator.go:75-93`, `SupportedQueryType`; `Golang-dnssec-validator/internal/validator/nsec.go`, NODATA checks

**Problem:** PTR, SRV, NAPTR, and SPF are accepted query types but absent from the local type-name map. They—and every other unlisted bitmap type—become the same string `UNKNOWN`. A legitimate NODATA proof for SRV can be rejected merely because the owner has an unrelated SSHFP/other unlisted type, and diagnostics cannot identify which type was present. This creates false bogus results for a public API feature.

**Evidence:** `SupportedQueryType` accepts numeric types 12, 33, 35, and 99. `TypeName` omits all four and returns `UNKNOWN`; the parser stores only these strings. NODATA comparison asks whether the query's `UNKNOWN` occurs in the bitmap, so any different unlisted type is indistinguishable from the queried one.

**Fix specification:** Use miekg/dns's complete type registry and a unique `TYPE<decimal>` fallback for unknown numeric types. Prefer retaining numeric bitmap values internally so display naming cannot affect validation. Preserve existing JSON type names for already-known types and accepted query-type/API behavior.

**Verification:** Exhaustively round-trip every supported type through NSEC and NSEC3 parsing. For each of PTR/SRV/NAPTR/SPF, prove NODATA succeeds with unrelated SSHFP/unknown types present and fails when the queried bit is present. Test unknown TYPE#### values remain distinct and existing A/AAAA/MX behavior is unchanged.

### R-032 — Chain validation incorrectly requires every DS algorithm to work

**Severity:** Medium

**Location:** `Golang-dnssec-validator/internal/validator/dnssec.go:182-245`, `ValidateChainLink`; corresponding multi-algorithm tests/comments

**Problem:** A delegation with one valid algorithm path and one stale, unsupported, or temporarily incomplete rollover path is declared bogus. Validators are supposed to accept any single valid supported path; requiring every DS algorithm makes legitimate algorithm rollovers and heterogeneous validator capabilities fail.

**Evidence:** DS records are grouped by algorithm and the function returns an error as soon as any group has no matching DNSKEY. Its comment attributes the opposite rule to RFC 6840. RFC 6840 section 5.11 says validators should accept any single valid path and should not insist all DS/DNSKEY algorithms work; completeness is an optional diagnostic for servers.

**Fix specification:** Separate validation security from completeness diagnostics. Determine locally supported algorithm/digest paths, accept the chain when any supported DS exactly matches a DNSKEY and the later DNSKEY RRSIG verification succeeds, and optionally warn about other broken signaled paths. Treat an authenticated DS set with no locally supported path according to RFC 4035 unsupported-algorithm semantics rather than automatically bogus; treat supported paths that all cryptographically fail as bogus. Preserve result/status APIs and full-match diagnostic visibility.

**Verification:** Update tests that enshrine all-algorithm failure. Cover one valid plus one stale path, valid supported plus unknown algorithm, unsupported-only DS, multiple digests for one key, all supported paths invalid, and two valid rollover paths. Assert the selected authenticated-key set still limits DNSKEY RRSIG verification correctly.

### R-033 — A signed child below an insecure ancestor is mislabeled bogus when an unauthenticated DS exists

**Severity:** Medium

**Location:** `Golang-dnssec-validator/internal/validator/validator.go:191-299`, parent-state threading; `nextParentDNSKEY`; `Golang-dnssec-validator/internal/validator/validator.go:909-1012`, non-root validation

**Problem:** Once an ancestor is proven insecure, descendants cannot regain a chain to the configured root (absent a separate local trust anchor). The code represents that state only by clearing `parentDNSKEY`. If a lower parent response contains a DS, the child path then demands a verified DS RRSIG with the now-nil keys and returns bogus. That DS is unauthenticated under the root and must not change the overall insecure state by itself.

**Evidence:** `nextParentDNSKEY` returns nil for `StatusInsecure`. The no-DS branch has a special nil-parent path returning insecure, which existing tests cover. The DS-present branch has no equivalent: `queryDSFromParentWithValidation` cannot set `RRSIGVerified` with no keys, and lines 982-989 classify it bogus. The no-DNSKEY/DS-present branch similarly returns bogus before considering ancestor state.

**Fix specification:** Thread an explicit parent security state separately from key material. Below an insecure ancestor, keep the overall result insecure and treat descendant DNSKEY/DS/self-signature observations as diagnostics only unless an explicitly configured local trust anchor starts a new validation island. Preserve fail-closed behavior below secure or indeterminate ancestors and existing status/API enums.

**Verification:** Build chains with secure root -> insecure delegation -> child having DS+DNSKEY, DS without DNSKEY, DNSKEY without DS, and deeper descendants; all remain insecure, with useful diagnostics. Confirm the same combinations immediately below a secure parent remain secure/bogus/indeterminate as appropriate, and an optional future local-anchor path is isolated.

### R-034 — CNAME loops and depth exhaustion silently terminate as secure

**Severity:** Medium

**Location:** `Golang-dnssec-validator/internal/validator/validator.go:120-132`, validation recursion; `Golang-dnssec-validator/internal/validator/validator.go:333-356`, depth gate; `checkAndFollowCNAME`

**Problem:** CNAME traversal has only a depth counter. At depth 10 it simply stops looking and returns the security status accumulated so far, normally `secure`; there is no visited-name set or error. A two-name loop repeats until the cutoff and is then reported secure, and a valid chain longer than the policy limit is presented as fully validated although its terminal target was never checked.

**Evidence:** The sole guard is `if depth < maxCNAMEDepth`; the `else` path records nothing. `validatedZones` caches zone results, not visited CNAME owner/target names, so it cannot detect loops within or across zones. `checkAndFollowCNAME` always recursively validates the target without a name-level cycle check.

**Fix specification:** Carry a canonical-name visited set and explicit traversal path. A repeated owner/target is a CNAME-loop failure (bogus DNS data); exceeding a configurable safety depth without a loop is indeterminate/policy-limited unless the full target was otherwise proven. Include a clear result error/path, stop emitting misleading complete events, and preserve the current default limit and JSON compatibility through optional fields.

**Verification:** Test A->B->A, self-CNAME, mixed-case cycles, loops across zones, exactly-limit and limit+1 acyclic chains, and a normal chain. Assert no loop/depth-exceeded result is secure and event/cached-zone behavior terminates with bounded queries.

### R-035 — Multi-server mode selects unverified input-order responses and compares only key tags

**Severity:** Medium

**Location:** `Golang-dnssec-validator/internal/validator/validator.go:473-537`, leaf querying; `Golang-dnssec-validator/internal/validator/validator.go:859-904`, DNSKEY selection; `Golang-dnssec-validator/internal/validator/validator.go:1057-1101`, parent DS query; `Golang-dnssec-validator/internal/validator/validator.go:1316-1410`, `ValidateMultipleServers`/`compareDNSKEYSets`

**Problem:** Extended mode gathers several DNSKEY responses but marks every transport-level NOERROR response `secure`, selects the first by input address order before cryptographic validation, and treats disagreements as warnings. Empty responses are excluded from comparison, and equal key-tag sets are called equal even if flags, algorithms, or public keys differ. DS queries stop at the first NOERROR/NXDOMAIN server, while leaf queries are sequential and likewise verify the first usable answer. A broken first server can make a valid zone bogus/indeterminate despite later valid servers, and per-server JSON can show green for unverified data.

**Evidence:** `AddressResult.Status` initializes to `StatusSecure` before any DNSSEC check. Selection at lines 881-887 takes the first such response, including an empty DNSKEY set. `compareDNSKEYSets` maps only `KeyTag`; 16-bit collisions are expected. The reference loop ignores any response with zero keys. Parent DS returns inside its first-success loop, and leaf fingerprints do not determine which response is cryptographically selected.

**Fix specification:** Cryptographically validate each server's context-bound response before assigning its security status. In extended mode, accept any fully valid path while reporting every timeout, empty/referral, bogus, and byte-level RRset disagreement; choose deterministically from valid responses, not address order. Fingerprint complete canonical owner/RDATA (TTL-insensitive where appropriate), including key flags/protocol/algorithm/public key and denial context. Query parent DS authorities consistently. Preserve quick-mode latency goals, endpoint schemas, and the distinction between server inconsistency and overall DNSSEC validity.

**Verification:** Test first-empty/later-valid, first-bogus/later-valid, all-bogus, timeout, same-tag-different-key, same keys different order/TTL, RRSIG rollover, inconsistent DS/NXDOMAIN, and leaf disagreements. Assert per-server status reflects crypto, overall choice is deterministic, and extended mode actually accounts for every reachable server.

### R-036 — One-record NSEC and NSEC3 chains never cover any absent name

**Severity:** Medium

**Location:** `Golang-dnssec-validator/internal/validator/nsec.go:481-515`, `canonicallyBetween` and `hashBetween`; all NSEC/NSEC3 denial and wildcard callers

**Problem:** In a denial chain containing one owner, the record's next owner equals itself and the interval wraps across the entire namespace except that owner. Both interval helpers treat `start == end` as an empty normal interval, so legitimate minimal signed zones cannot prove NXDOMAIN, wildcard nonexistence, opt-out coverage, or similar denials.

**Evidence:** Wrap handling is entered only for `start > end`. Equality falls through to `name > start && name < end`, which is impossible; the hash helper is identical. Existing interval tests cover normal/wrap/equal-endpoint queries but no equal start/end chain.

**Fix specification:** Implement the DNSSEC cyclic interval rule explicitly: when start equals end, every value except the owner/start is covered. Keep endpoints exclusive and preserve canonical DNS label ordering/base32hex ordering for all other cases. Ensure exact-owner matches continue through the separate existence/type-bitmap path.

**Verification:** Add one-owner NSEC and NSEC3 zones proving several absent names on both sides of the owner, with the exact owner excluded. Run those records through NXDOMAIN, NODATA where applicable, wildcard, and DS-absence callers, plus existing multi-record/wrap tests.

### R-037 — NSEC3 proof logic combines records with incompatible hash parameters

**Severity:** Medium — Needs investigation

**Location:** `Golang-dnssec-validator/internal/validator/nsec.go:293-413`, `VerifyNSEC3Denial` and helpers; `Golang-dnssec-validator/internal/validator/nsec.go:625-660`, wildcard proof; `Golang-dnssec-validator/internal/validator/validator.go:1209-1271`, DS absence

**Problem:** Hashes are computed using the first record's algorithm/iterations/salt, but matching/coverage searches consider every NSEC3 record in the response. During an NSEC3 salt/parameter transition—or with replayed signed records—records from distinct chains can be combined into a logical proof that no single chain establishes. RFC 5155 permits treating mixed-parameter responses as bogus; it does not permit comparing a hash from one parameter space with ranges from another.

**Evidence:** `params := records[0]` supplies salt/iterations, while `nsec3Matches`, `nsec3Covers`, and direct loops never compare each record's tuple to `params`. `VerifyDenialRRSIGFromResponse` can authenticate all involved records because both chains may be legitimately signed, so cryptographic verification does not enforce logical parameter consistency. The same pattern appears in wildcard and delegation proofs.

**Fix specification:** Partition records by complete `(zone, hash algorithm, iterations, salt)` tuple and require every component of a proof to come from one supported, internally consistent chain. Reject malformed mixed data or independently test each chain without cross-combination. Enforce correct owner-zone suffix and hash length. Preserve valid transition responses when one complete chain proves the answer. Investigation should construct simultaneous signed old/new-salt responses and enumerate whether current helpers can false-accept NXDOMAIN, NODATA, wildcard, or DS absence.

**Verification:** Create two individually incomplete, differently salted signed chains whose union satisfies the current searches; assert the union cannot verify. Then test two complete chains (either may verify), mixed algorithms/iterations/salts/zones, ordering changes, replayed records, and single consistent chains across every caller.

### R-038 — Wildcard NODATA responses are unsupported and reported bogus

**Severity:** Medium

**Location:** `Golang-dnssec-validator/internal/validator/nsec.go:172-208`, `verifyNSECNODATA`; `Golang-dnssec-validator/internal/validator/nsec.go:380-413`, `verifyNSEC3NODATA`; leaf denial dispatch in `verifyActualRecord`

**Problem:** When a wildcard exists but lacks the requested type, the authenticated NODATA proof is about the wildcard owner plus the closest-encloser/no-closer-match proof. The implementation only accepts an NSEC/NSEC3 whose owner/hash exactly matches QNAME, so standards-compliant wildcard NODATA responses fail and make a valid zone look bogus.

**Evidence:** Both NODATA helpers compare only QNAME (or `H(QNAME)`) and never search for the generated `*.<closest-encloser>` owner or validate its accompanying closest-encloser proof. RFC 5155 section 8.7 explicitly requires closest-encloser proof plus a matching wildcard NSEC3 with QTYPE and CNAME absent; no test covers this response class.

**Fix specification:** Distinguish exact-name, empty-nonterminal, and wildcard NODATA. For wildcard NODATA, validate the complete closest-encloser/no-closer-match proof and the authenticated wildcard NSEC/NSEC3 bitmap with QTYPE and CNAME absent, using one consistent chain per R-037. Do not weaken ordinary exact-name NODATA or confuse this with positive wildcard answers in R-026. Preserve result JSON while explaining which proof form succeeded.

**Verification:** Add RFC-style NSEC and NSEC3 wildcard NODATA fixtures for present/absent QTYPE, CNAME set, missing/forged closest-encloser component, wrong wildcard owner, mixed parameters, and valid exact-name/empty-nonterminal NODATA. Only complete valid forms may remain secure.

### R-039 — Zero currently active anchors is treated as a bogus root instead of unavailable trust

**Severity:** Medium

**Location:** `Golang-dnssec-validator/internal/dns/anchors.go:148-175`, `GetActiveAnchors`; `Golang-dnssec-validator/internal/validator/validator.go:162-172` and `944-955`; `Golang-dnssec-validator/handlers.go:203-213`, `322-329`; `Golang-dnssec-validator/health.go:45-64`

**Problem:** Availability checks look only at the unfiltered anchor slice. If every entry is future-dated, expired, or has an invalid validity timestamp, requests proceed with zero active anchors and label the real root DNSKEY `bogus`. This is local trust configuration/update failure, not evidence that the root zone is bogus, and readiness incorrectly remains healthy.

**Evidence:** `Validate` and both handlers check `len(anchors.Anchors)`, while root validation later calls `GetActiveAnchors` and passes the possibly empty result to `VerifyRootTrustAnchor`; its no-match error is converted to `StatusBogus`. Health also reports any nonempty raw slice “available.”

**Fix specification:** Validate and snapshot the active anchor set before DNS work. With none active, return service-unavailable/indeterminate with a trust-anchor diagnostic and fail readiness; expose invalid/future/expired counts and dates without secrets. Coordinate with R-024/R-025 so an authenticated successor becomes active at the correct time and last-known-good handling cannot silently extend an expired anchor. Preserve status/API enums and future-anchor preloading.

**Verification:** Test future-only, expired-only, malformed-date-only, current+future, current+expired, clock skew, and transition instants. Assert health/readiness, JSON/SSE status, and metrics distinguish unavailable local trust from a cryptographically bogus root.

### R-040 — RRSIG signer-name comparison is case-sensitive

**Severity:** Medium

**Location:** `Golang-dnssec-validator/internal/validator/validator.go:713-720`, `leafSignerMatchesZone`; A/CNAME leaf verification callers

**Problem:** DNS names are case-insensitive, but a legitimate RRSIG whose Signer Name uses different letter case from the discovered zone is rejected. This creates a false bogus leaf verdict even though cryptographic canonicalization accepts the signature.

**Evidence:** The helper uses Go string equality against `zone` and `dns.Fqdn(zone)`; neither lowercases nor uses DNS name equality. The parser preserves the response's presentation case. Other parts of the code already canonicalize DNS names, so this isolated exact comparison is inconsistent.

**Fix specification:** Compare canonical FQDNs with a DNS-aware case-insensitive routine (for example `dns.EqualDomainName`) after validating syntax. Apply the same rule to all signer/owner/parent-zone bindings introduced by R-027/R-028, without allowing subdomains or merely suffix-matching names. Preserve original presentation strings in JSON.

**Verification:** Verify A and CNAME signatures with lower/upper/mixed-case signer and zone spellings, missing trailing dots, an actually different zone, and a deceptive suffix (`notexample.com`). Valid case variants pass; non-equal names fail.

### R-041 — Startup writability probing truncates and deletes a pre-existing file

**Severity:** Medium

**Location:** `Golang-tudor-dnssec-signer/daemon.go:249-258`, `Daemon.checkDirWritable`; startup validation for data/output/keys directories

**Problem:** The daemon tests writability by creating the fixed path `.startup_check` with truncation semantics and then deleting it. If an operator, deployment tool, or another process already owns a file at that name, every daemon startup destroys it. Close/remove errors are also ignored, so the probe can report success while leaving an artifact or after an unsuccessful flush.

**Evidence:** `os.Create(filepath.Join(dir, ".startup_check"))` is equivalent to create-or-truncate; there is no existence check or `O_EXCL`. The function unconditionally calls `os.Remove(testFile)`. The health checker already demonstrates the safe pattern with `os.CreateTemp` and a unique name.

**Fix specification:** Use a unique same-directory temporary file created exclusively, close it with error checking, then remove only that exact file and surface cleanup failure appropriately. Never open, truncate, chmod, chown, or remove a pre-existing path. Preserve the directories checked and startup's fail-fast writability guarantee.

**Verification:** Place distinctive `.startup_check` files in every checked directory, start validation, and assert their bytes/mode/owner survive. Inject create/write/close/remove failures and concurrent probes; verify unique artifacts, accurate errors, and no leftovers after success.

### R-042 — Rollover backup and restore copies are neither atomic nor durable

**Severity:** Medium

**Location:** `Golang-tudor-dnssec-signer/hooks.go:208-237`, `copyFile`; `Golang-tudor-dnssec-signer/rollover.go:382-440`, `backupKey`/`restoreKeyFromBackup`; `Golang-tudor-dnssec-signer/keys.go`, backup-copy callers

**Problem:** Key backup/restore opens the destination with `O_TRUNC`, streams bytes directly, and does not fsync the file or directory. An I/O error or crash can leave a truncated backup or live key half. A rollover can then durably record the new generation even though the only recovery copy of the old private key was never durable; restore can also produce a mixed live pair by replacing private and public files separately.

**Evidence:** `copyFile` writes the final destination in place, explicitly closes but never syncs it or its directory. `backupKey` performs public and private copies sequentially; `restoreKeyFromBackup` performs private then public sequentially. These paths are the rollback foundation for the state-save failures in R-004/R-005, so a partial copy defeats those higher-level recovery attempts.

**Fix specification:** Stage, validate, fsync, and commit a complete public/private backup generation atomically, with a manifest/pointer or recoverable pair transaction coordinated with R-013. Restore must likewise expose either the complete old or complete new live pair, never truncate a live half in place. Preserve current key encodings, modes/ownership, tag-suffixed backup naming compatibility, and idempotent identical-backup behavior.

**Verification:** Fault every read/write/close/sync/rename and kill the process between pair steps. After restart, assert a complete validated backup and live pair from one generation remain; no zero-length/mixed halves are selectable. Cover initial backup, completing a half-written legacy backup, identical/different collision handling, rollback, and non-root/root ownership.

### R-043 — Non-zone and invalid-protocol DNSKEYs can authenticate signatures

**Severity:** High

**Location:** `Golang-dnssec-validator/internal/dns/query.go:113-135`, DNSKEY parsing; `Golang-dnssec-validator/internal/validator/dnssec.go:102-129`, key lookup; `CollectDSMatchedKeys`, `CollectAnchorMatchedKeys`, and all signature-verification key selection

**Problem:** The validator records the Zone Key flag and Protocol field but never enforces them before using a DNSKEY. A DS can match a key with Zone Key clear or Protocol other than 3, and that key can then verify DNSKEY/data/denial signatures and produce `secure`. RFC 4034 explicitly forbids using a non-zone key to verify RRSIGs and requires a non-3 Protocol key to be treated invalid.

**Evidence:** Parsing computes `IsKSK`/`IsZSK`, but `FindDNSKEYByKeyTag` and DS/anchor collection fall back to/accept any record without `Flags&256` or `Protocol` checks. `reconstructDNSKEY` passes the invalid values to the crypto library; a successful mathematical signature is treated as sufficient. `IsRevoked` is likewise never consulted for root trust-anchor lifecycle (to be addressed with R-024).

**Fix specification:** Centralize DNSKEY eligibility: Protocol must be 3, Zone Key flag must be set for signature verification, algorithm must be locally usable, and RFC 5011 revoke state must be honored for trust anchors. SEP must remain only a hint—do not require it for a DS-authenticated zone key. Keep invalid keys visible in diagnostics/JSON but exclude them from authenticated/signing candidates and explain the rejection. Preserve public record schemas.

**Verification:** Construct cryptographically correct chains using Protocol 2, flags 0/1/128, valid 256/257 keys, reserved ignored bits, and revoked anchors. Invalid keys must never yield secure; valid ZSK-referenced DS and KSK conventions must continue to work. Test every leaf/DS/DNSKEY/denial key-selection path.

### R-044 — Key-tag collisions cause valid signatures and DS links to be rejected by slice order

**Severity:** Medium

**Location:** `Golang-dnssec-validator/internal/validator/dnssec.go:102-129`, `Find*ByKeyTag`; `ValidateChainLink`; `verifyDNSKEYRRSIGOne`; `VerifyDenialRRSIGFromResponse`; leaf and DS RRSIG verification callers

**Problem:** A DNSSEC key tag is only a 16-bit hint, but most paths return the first key with a tag and never try another colliding key. If that first key has the wrong algorithm/material/role, a later key that really verifies the DS or signature is ignored, producing a false bogus result. This contradicts the code's own correct digest treatment and RFC 6840 collision guidance.

**Evidence:** `FindKSKByKeyTag`, `FindZSKByKeyTag`, and `FindDNSKEYByKeyTag` return on their first match. `ValidateChainLink` does not continue to another same-tag KSK after a digest mismatch; `verifyDNSKEYRRSIGOne` selects the first authenticated key with the tag; denial and leaf paths do the same. Response ordering therefore changes the verdict.

**Fix specification:** Treat key tag as a candidate filter, additionally match RRSIG algorithm, enforce R-043 eligibility, and try every candidate cryptographically until one succeeds. DS matching must test every same-tag/algorithm DNSKEY digest. Keep deterministic diagnostics for all failures and never collapse keys into a map keyed only by tag (including R-035 comparisons). Preserve successful first-match performance as a fast path and public APIs where possible.

**Verification:** Generate/construct two distinct DNSKEYs with one tag, put the valid candidate before and after the invalid one, and exercise DS link, DNSKEY RRSIG, DS RRSIG, leaf, and denial validation. Both orders must give the same result; wrong algorithm, no valid candidate, and two valid candidates must be diagnosed correctly.

### R-045 — NSEC ordering compares presentation strings rather than canonical wire names

**Severity:** Medium — Needs investigation

**Location:** `Golang-dnssec-validator/internal/validator/nsec.go:472-500`, `canonicalizeName`/`canonicallyBetween`; `splitLabels`/`compareCanonical`; all NSEC range proofs

**Problem:** RFC 4034 canonical order compares unescaped, lowercased label octets from right to left. The validator lowercases presentation strings and splits on literal dots, so escaped octets (including escaped dots) sort and split incorrectly. A signed NSEC interval can consequently be rejected or, more seriously, accepted for a QNAME that is not canonically inside it, creating a false authenticated denial.

**Evidence:** `splitLabels` uses `strings.Split` and `compareCanonical` uses Go string `<`; neither decodes `\\DDD`/single-character escapes. The sibling signer already implements `canonicalLabelBytes`/`canonicalLess` specifically because presentation comparison mis-orders these names and has tests for escaped octets. Validator tests cover only ordinary ASCII labels.

**Fix specification:** Parse names with a DNS-aware label parser and compare canonical wire octets exactly as RFC 4034 section 6.1 specifies, including escaped dot/octet, case folding, root, and prefix ordering. Exact-owner equality must use the same canonical representation. Do not change NSEC3 base32hex ordering. Investigation should construct signed intervals around escaped labels and identify current false-positive as well as false-negative cases.

**Verification:** Port the signer's escaped-label vectors and add full signed NSEC NXDOMAIN/NODATA/wildcard proofs using `\\000`, `\\046`, `\\065`, high octets, case variants, and prefix names. Compare results against miekg/wire-order reference and a known validating resolver.

### R-046 — Slow SSE clients can hold validation capacity forever

**Severity:** Medium

**Location:** `Golang-dnssec-validator/server.go:30`, `82-85`, and `248-258`; `Golang-dnssec-validator/sse.go:45-98`; `Golang-dnssec-validator/handlers.go:148-195` and event callback

**Problem:** SSE is excluded from every write deadline because streams are long-lived. Event writes and flushes run synchronously inside validation callbacks while the global validation semaphore is held. If a client stops reading and the socket buffer fills, the handler blocks in write/flush; the validation context's timer cannot interrupt a blocked `ResponseWriter`, so enough slow clients permanently exhaust all validation slots.

**Evidence:** Server `WriteTimeout` is zero and `/validate` is not wrapped by `withWriteDeadline`. `SSEWriter` calls `fmt.Fprintf` then `Flush` with no response-controller deadline. `cancelOnWriteError` can cancel only after a write returns an error, and `defer releaseValidationSlot` cannot run while the callback is blocked.

**Fix specification:** Apply a sliding per-event write/flush deadline via `http.ResponseController` (reset for each event/keepalive), close/cancel the stream on deadline, and ensure semaphore/gauge release. Retain long-lived SSE by avoiding one absolute whole-stream deadline. Bound queued events if validation and writing are decoupled, preserve event order/JSON/path, and handle writers that do not support deadlines conservatively.

**Verification:** Use a real TCP client that stops reading after headers and a deadline-aware blocking writer; fill buffers and assert the handler, validation context, semaphore, and gauges clear within the configured bound. Cover normal long streams, slow-but-progressing readers, disconnects, proxy flushing, unsupported deadline writers, and shutdown.

### R-047 — Enabled heartbeat configuration can leak credentials or silently disable monitoring

**Severity:** Medium

**Location:** `Golang-dnssec-validator/config.go:319-413`, `Config.Validate`; `Golang-dnssec-validator/internal/heartbeat/heartbeat.go:42-67` and `69-116`

**Problem:** When heartbeat is enabled, configuration validates only the interval. An HTTP URL sends the API key in cleartext form data (and a default redirect policy can downgrade a configured HTTPS POST via 307/308). Missing API key or app does not fail startup; `NewClient` silently returns a disabled client, so an operator can believe monitoring is active while no heartbeat is sent.

**Evidence:** `Config.Validate` has an HTTPS check for root anchors but none for heartbeat URL/redirects or required credentials. `NewClient` returns `{enabled:false}` for missing key/app without error. `Send` places `api_key` in the POST body and uses an `http.Client` with default redirect behavior.

**Fix specification:** If enabled, require nonempty API key/app, parse and require HTTPS, and reject scheme-downgrade/unapproved-origin redirects; fail configuration/startup with a clear non-secret error. If loopback HTTP is needed for testing, require an explicit narrowly scoped opt-in added backward-compatibly. Preserve disabled-by-default behavior, form schema, endpoint defaults, and never log the key.

**Verification:** Test enabled with missing fields, malformed URL, HTTP, HTTPS->HTTP 307/308, cross-origin redirect, valid HTTPS, disabled incomplete config, and explicit loopback override if added. Capture requests to assert the API key never reaches an insecure/unapproved destination or logs.

### R-048 — The exact base-path URL breaks relative UI assets and API calls

**Severity:** Low

**Location:** `Golang-dnssec-validator/server.go:57-136`, `Server.registerRoutes`; `Golang-dnssec-validator/static/index.html:10`, `108-109`, and `117`; `Golang-dnssec-validator/static/app.js:74-111`

**Problem:** When `base_path` is `/dnssec`, the server renders the UI directly at the exact URL `/dnssec` without redirecting to `/dnssec/`. Browser-relative URLs then resolve against the parent: `style.css`, `app.js`, `validate`, and `api/...` become root paths instead of `/dnssec/...`. The backend's duplicate root routes mask this during direct access, but a reverse proxy that exposes only the configured prefix serves a page with no assets and nonworking validation.

**Evidence:** The exact `basePath` handler rewrites only the request passed to `staticHandler`; it leaves the address-bar URL unchanged. Every UI resource and request is relative rather than root- or base-prefixed. Because both `basePath` and `basePath+"/"` are explicitly registered, `http.ServeMux` cannot supply its usual trailing-slash redirect.

**Fix specification:** Redirect the exact configured base path to `basePath + "/"` with a permanent method-preserving redirect before serving content, retaining the query string. Continue serving the UI and APIs under the slash form and preserve the existing root aliases and empty-base-path behavior. Do not hard-code `/dnssec` into assets or JavaScript.

**Verification:** With empty and `/dnssec` base paths, test exact/slash URLs, query preservation, HEAD, and proxy requests that expose only `/dnssec/`. In a browser or URL-resolution test, assert all stylesheet, script, SSE, and API URLs remain under the prefix and that direct root deployments remain unchanged.

### R-049 — The web UI cannot request the record types supported by the API

**Severity:** Low

**Location:** `Golang-dnssec-validator/static/index.html:23-35`; `Golang-dnssec-validator/static/app.js:25-111`; `Golang-dnssec-validator/handlers.go:114-120` and `303-309`, query-type parsing

**Problem:** The JSON and SSE APIs support twelve record types, but the only shipped user interface always omits `type`, so it can validate only the default A record. Operators cannot inspect AAAA, MX, TXT, NS, SOA, SRV, CAA, PTR, NAPTR, CNAME, or SPF through the UI, and copied result links cannot reproduce a non-A API validation.

**Evidence:** The form has domain and mode controls only. `startValidation` builds `validate?domain=...&mode=...`; `init` and `updateURL` likewise read/write only domain and mode. Both handlers explicitly accept and validate a `type` parameter and default it to A when absent.

**Fix specification:** Add an accessible record-type selector populated from the same supported set, defaulting to A; pass it through SSE requests, history/copy links, reload initialization, example actions, and displayed query state. Keep the API's current parameter name, accepted values, response schema, and absent-parameter A default. Invalid URL values must not silently select a different non-A type.

**Verification:** Exercise every supported type from the form, reload/copy each URL, switch modes, and submit examples. Assert the outgoing SSE query and returned `record_type` agree, A-only links remain backward compatible, and unsupported URL types receive a visible validation error or a documented A fallback.

### R-050 — `static_dir` is a documented but entirely inert configuration surface

**Severity:** Low

**Location:** `Golang-dnssec-validator/config.go:64-65`, `149`, and `260-261`; `Golang-dnssec-validator/server.go:15-16` and `91-107`; `Golang-dnssec-validator/.env.example:41`; `Golang-dnssec-validator/CLAUDE.md:589`

**Problem:** Configuration and deployment documentation promise a selectable web-UI directory, but the server always serves the embedded filesystem and never reads `Config.StaticDir`. An operator can point `STATIC_DIR` or `static_dir` at updated/emergency assets, receive no error or warning, and continue serving the compiled copy.

**Evidence:** Repository-wide references to `StaticDir` are limited to its field, default, and environment assignment. `registerRoutes` unconditionally calls `fs.Sub(staticFiles, "static")`; no file operation consumes the configured value.

**Fix specification:** Formally deprecate the no-op while preserving current single-binary behavior: remove it from active examples/default documentation, retain legacy TOML/environment decoding for a compatibility period, and emit a clear startup warning when a nonempty legacy value is supplied. Keep embedded assets as the only source during that period and do not unexpectedly begin trusting a working-directory path. If external overrides are desired later, introduce them as an explicit new opt-in with startup validation and documented filesystem trust semantics.

**Verification:** Start with no setting and with TOML/environment legacy values pointing to valid, missing, and malicious-looking paths. Embedded assets must remain identical; configured legacy use must be observable in logs but not fail an otherwise compatible startup. Strict TOML decoding must continue accepting the legacy key until its announced removal.

### R-051 — The RDAP registrable-domain test is wrong for public suffixes longer than one label

**Severity:** Low

**Location:** `Golang-dnssec-validator/internal/validator/chain.go:140-170`, `IsRegistrableDomain`/`GetRegistrableDomain`; `Golang-dnssec-validator/internal/validator/validator.go:1004-1010`, RDAP invocation

**Problem:** RDAP cross-checking assumes every registrable domain has exactly two labels. It therefore skips real registrants such as `example.co.uk` and can query public suffixes such as `co.uk` as though they were registrants. The DNSSEC verdict is not derived from RDAP, but diagnostic absence or mismatch warnings become inconsistent by TLD and can mislead an operator investigating DS publication.

**Evidence:** `IsRegistrableDomain` returns `GetZoneLabels(zone) == 2`, and its comment acknowledges that `co.uk` is unsupported. `GetRegistrableDomain` independently takes the last two labels. `validateZone` gates the only RDAP lookup with this predicate.

**Fix specification:** Determine the effective registrable domain with an up-to-date public-suffix implementation, including IDNA normalization, and run the RDAP check only when the validated zone itself equals that registrable domain. Treat unknown/private suffix policy explicitly and keep RDAP advisory: it must not change secure/insecure/bogus status or chain validation APIs.

**Verification:** Table-test `example.com`, subdomains, `example.co.uk`, `co.uk`, `example.com.au`, IDNs, private suffixes, root, and single-label names. Use a fake RDAP client to assert exactly which normalized name is queried and confirm RDAP failures/mismatches remain warnings only.

### R-052 — Heartbeat activity states are advertised but never wired to validation lifecycle

**Severity:** Low

**Location:** `Golang-dnssec-validator/main.go:52-74` and `140-158`; `Golang-dnssec-validator/internal/heartbeat/heartbeat.go:141-178`, `Client.StartBackground`; `Golang-dnssec-validator/handlers.go`, all validation handlers; `Golang-dnssec-validator/ANYSTATUS.md:57-73`

**Problem:** Documentation claims `running`, `validate:start`, and `validate:complete` actions describe live request activity, but request handlers have no heartbeat client and never send any of them. The background loop changes `lastAction` only through its own `starting`/`idle` sends, so it remains idle even during long or concurrent validations. Cancellation also provides no completion signal, allowing process exit before the synchronous `stopping` request finishes.

**Evidence:** `hbClient` is local to `main` and is not injected into `Server` or `Handlers`; repository-wide send calls occur only inside the heartbeat package. The ticker tests for a `validate:` prefix that no caller can set. The returned function only cancels a context; `main` calls it and proceeds without joining the goroutine.

**Fix specification:** Inject a narrow activity observer into handlers, maintain a concurrency-safe active-validation count, and emit start/complete transitions without blocking or failing validation. Periodic status must be `running` while the count is nonzero and `idle` otherwise. Give background shutdown a bounded join/result so `stopping` is attempted before exit. Preserve existing action strings/form fields, disabled behavior, request latency, and secret handling; coalesce or bound asynchronous sends under load.

**Verification:** With a fake heartbeat transport and clock, run overlapping JSON/SSE validations, failures, cancellations, rate-limit rejections, idle ticks, and shutdown. Assert balanced activity, running until the last request finishes, no goroutine growth, validation independence from heartbeat errors, and bounded completion of the final stopping send.

### R-053 — Rate-limiter shutdown panics when called more than once

**Severity:** Low

**Location:** `Golang-dnssec-validator/ratelimit.go:24`, `114-139`, `RateLimiter.Stop`; `Golang-dnssec-validator/server.go:264-278`, `Server.Shutdown`

**Problem:** `Stop` closes an unguarded channel. A repeated or concurrent `Server.Shutdown`—a normal idempotency expectation for lifecycle APIs—panics with `close of closed channel` instead of safely returning the underlying server result.

**Evidence:** `RateLimiter.Stop` consists only of `close(rl.stopCh)` and has no `sync.Once`, state flag, or recoverable result. `Server.Shutdown` invokes it every time. `http.Server.Shutdown` itself supports repeated calls, making the wrapper unexpectedly less robust.

**Fix specification:** Make `RateLimiter.Stop` concurrency-safe and idempotent, preferably with `sync.Once`, and optionally join the cleanup loop with a done channel so shutdown does not leak work. Preserve its no-argument API and the limiter's rate/bucket behavior; do not hold the bucket mutex while waiting.

**Verification:** Call `Stop` and `Server.Shutdown` sequentially and concurrently from many goroutines, before and after server start and cleanup ticks, under `go test -race`. Assert no panic, race, deadlock, or lingering cleanup goroutine and stable repeated shutdown errors.

### R-054 — Invalid metrics allowlists fail open outside the normal configuration loader

**Severity:** Low — Needs investigation

**Location:** `Golang-dnssec-validator/config.go:391-400`, `Config.Validate`; `Golang-dnssec-validator/server.go:70-81`, metrics route construction; direct `NewServer` callers

**Problem:** The normal loader rejects a malformed metrics CIDR, but `NewServer` independently reparses the list and deliberately exposes `/metrics` without any restriction if parsing fails. Any future construction/reload path that misses `Config.Validate`, or a partial-validation regression, turns a defensive error into a fail-open disclosure of service internals.

**Evidence:** On `parseCIDRs` error, route construction logs `metrics access unrestricted` and leaves the unwrapped Prometheus handler installed. An explicit empty list is already the intentional unrestricted state, so invalid and deliberate-unrestricted configurations currently collapse to the same runtime policy. Investigation should enumerate all production construction/reload paths and determine whether direct construction can become externally reachable.

**Fix specification:** Fail closed at route construction even if upstream validation was bypassed: install a denied/unavailable metrics handler or retain a previously validated allowlist, while logging a non-sensitive configuration error. Preserve valid CIDR behavior, the public `/metrics` path/schema, and the documented meaning of an explicitly empty list; do not silently substitute default CIDRs for an operator's invalid restriction.

**Verification:** Construct servers both through `LoadConfig` and directly with valid, empty, mixed, and invalid lists. Invalid lists must never return metrics from any source IP; valid/empty semantics must remain unchanged. Add a regression test for any reload path found during investigation.

### R-055 — The root-anchor age metric is almost always zero or a stale sample

**Severity:** Low

**Location:** `Golang-dnssec-validator/anchors_store.go:10-67`, `AnchorsStore.Load`/`Age`; `Golang-dnssec-validator/main.go:38-50` and `86-136`; `Golang-dnssec-validator/metrics.go:66-71` and `146-149`

**Problem:** `dnssec_validator_root_anchors_age_seconds` is described as the current age of loaded anchors, but it is updated only after retry success and on the 24-hour refresh tick. A successful startup leaves the default zero; a successful refresh resets `loadedAt` and immediately records approximately zero; then the gauge remains frozen for another day. Alerts therefore cannot distinguish fresh, aging, or never-loaded state.

**Evidence:** The initial-success branch never calls `SetRootAnchorsAge`. `Load` sets `loadedAt = time.Now()`, and each later metric update samples `Age()` immediately after `Load`; Prometheus scrapes only the last stored value rather than invoking `Age`. On failed refresh the one sampled age is also frozen until the next daily tick.

**Fix specification:** Calculate age at scrape time from a concurrency-safe loaded timestamp (using an injected clock for tests), or update it at a suitably frequent cadence. Represent never-loaded state explicitly with a separate availability metric and/or NaN rather than zero, and do not reset age after a failed refresh. Coordinate with R-024/R-025/R-039 to expose authenticated document/source age separately from process load age. Preserve the existing metric name and units for load age.

**Verification:** With a fake clock, cover never loaded, successful startup, time advance between scrapes, successful refresh, failed refresh, retry success, and concurrent load/scrape. Assert monotonic increase between successful loads, exact reset only on success, and unambiguous unavailable state.

### R-056 — Request-ID entropy failure produces repeatable zero or partial identifiers

**Severity:** Low

**Location:** `Golang-dnssec-validator/logging.go:12-20`, `GenerateRequestID`; request logging and validation handlers that use the ID

**Problem:** If `crypto/rand.Read` fails, the stated timestamp fallback is not implemented; the function hex-encodes the same zero-filled or partially filled buffer. Repeated failures can assign identical IDs to unrelated requests, defeating log correlation precisely when the host has an entropy/runtime fault.

**Evidence:** The error branch returns `fmt.Sprintf("%x", b)` and reads no clock or counter. A failure before writing bytes returns sixteen zero hex characters; a partial write preserves predictable zeros. The caller has no collision detection.

**Fix specification:** Add a deterministic process-local fallback combining an atomic monotonic counter with time and/or a per-process seed, formatted to the same non-secret fixed-length identifier contract. Keep the cryptographic random fast path, never include client data or credentials, and make the entropy source injectable for tests. Log a rate-limited warning without exposing generated material.

**Verification:** Inject full failure, partial-write failure, repeated failure, and concurrent generation; assert uniqueness, stable valid formatting, race freedom, bounded warning volume, and unchanged successful-random output length.

### R-057 — Release binaries are built with a Go toolchain affected by GO-2026-5856

**Severity:** Low — Needs investigation

**Location:** `Golang-dnssec-validator/go.mod:3`; `Golang-tudor-dnssec-signer/go.mod:3`; both Makefiles/release build environments; reviewed binaries `/tmp/dnssec-validator-review` and `/tmp/dnssec-tudor-review`

**Problem:** Both review builds use Go 1.26.4. Binary-mode `govulncheck` reports reachable `crypto/tls` symbols affected by GO-2026-5856, an Encrypted Client Hello PSK identity privacy leak fixed in Go 1.26.5. The applications do not visibly configure ECH, so practical exposure is not confirmed; future transport configuration or deployment wrappers could activate it.

**Evidence:** `go version -m` reports `go1.26.4` for both binaries. `govulncheck -mode=binary` reports GO-2026-5856 and reachable `tls.Conn.Handshake`, `HandshakeContext`, `Read`, `Write`, and `tls.Dialer.DialContext` symbols for each. The module `go` directives set language floors, not a patched release toolchain, and no repository build file pins a minimum patch version. Investigation should inspect production binary metadata and any ECH-enabled `tls.Config` supplied outside this tree.

**Fix specification:** Build and release both artifacts with Go 1.26.5 or a later supported patched version, pin/enforce that minimum in CI/release tooling, and rebuild from the same dependency locks. Do not disable TLS or ECH as a substitute. Keep module language-version compatibility unless a source requirement independently changes it.

**Verification:** Check production and rebuilt artifacts with `go version -m`; rerun binary-mode `govulncheck` using a compatible current scanner/database and require GO-2026-5856 to be absent. Add a release gate and, if ECH is configured anywhere, an integration handshake test covering rejected/resumed ECH paths.

### R-058 — Deployment and conformance documentation materially disagrees with the running code

**Severity:** Low

**Location:** `Golang-dnssec-validator/QUICKSTART-FREEBSD.md:29-45`; `Golang-dnssec-validator/ANYSTATUS.md:20-73`; `Golang-dnssec-validator/docs/RFC_COMPLIANCE.md:13-149`; `Golang-dnssec-validator/CLAUDE.md:863-881`; `Golang-dnssec-validator/config.go:230-285` and `425-447`

**Problem:** Operator instructions use unrecognized environment names, monitoring docs promise unwired events, and the RFC matrix asserts behaviors contradicted by current validation paths. Following these sources can silently retain timeout/heartbeat defaults and can lead engineers or auditors to rely on nonexistent trust-anchor freshness and DNSSEC guarantees.

**Evidence:** The FreeBSD quickstart sets `QUERY_TIMEOUT=5s` and `TOTAL_TIMEOUT=30s`, while code reads integer `QUERY_TIMEOUT_SECONDS`/`TOTAL_TIMEOUT_SECONDS`. AnyStatus uses `HEARTBEAT_INTERVAL=5m` rather than `HEARTBEAT_INTERVAL_MINUTES` and claims the R-052 request events. The compliance matrix calls protocol-field handling, signature verification, chain walking, and trust-anchor rollover compliant despite R-024 through R-044, and incorrectly says RFC 6840 requires every algorithm. `CLAUDE.md` says stale local anchors fall back to the URL and fetched anchors are cached, but R-025 shows neither behavior exists.

**Fix specification:** After the corresponding code findings are resolved, update all deployment examples to the exact accepted keys/value grammar and rewrite the conformance matrix from executable behavior, with each claim linked to a test and RFC section. Until then, mark affected guarantees as partial/noncompliant rather than aspirational. Preserve current runtime variable names and compatibility; documentation edits must not paper over unresolved findings.

**Verification:** Add a docs/config check that extracts environment variables from maintained examples and rejects names absent from the loader, then execute the quickstart configuration and assert parsed non-default values. Mechanically map every compliance row and documented heartbeat/anchor behavior to a passing test or explicit open finding, and review RFC 6840 wording against the implementation.

### R-059 — Security-critical orchestration is not integration-testable and remains uncovered

**Severity:** Low

**Location:** `Golang-dnssec-validator/internal/validator/validator.go`, `Validator.Validate`/`validateWithCache`/`validateZone`/multi-server/CNAME paths; `Golang-dnssec-validator/internal/dns/query.go` and `resolver.go`; `Golang-dnssec-validator/internal/heartbeat/heartbeat.go`; signer filesystem/state/config transaction paths; both test suites

**Problem:** Unit tests exercise many helpers, but the network, clock, filesystem, and orchestration layers are tightly coupled to concrete implementations. The actual path that combines DNS responses into a security verdict—and the crash/error interleavings that protect signer keys and state—cannot be tested deterministically. This allowed multiple high-severity cross-layer defects in this review to coexist with green tests.

**Evidence:** Current coverage is 51.5% for the validator and 61.6% for the signer. In the validator profile, `Validate`, `validateWithCache`, `validateZone`, all DNS query/resolver methods, multi-server validation, CNAME following, and the entire heartbeat package are 0%; signer `ValidateZone` is 28%, its web mutation handlers are 0%, and transaction paths lack systematic sync/rename/crash fault injection. Both `go test -race -count=1 ./...` runs pass because these paths are not driven end to end.

**Fix specification:** Introduce narrow internal interfaces for DNS exchange/resolution, wall clock, anchor/RDAP/heartbeat transports, and key/config/state filesystem operations, with production adapters retaining existing behavior. Build deterministic signed-response fixtures and a fault-injecting same-filesystem store. Do not change CLI flags, HTTP/JSON/SSE contracts, on-disk schemas, algorithms, or verdict semantics merely to increase a percentage; tests must target every fix and adversarial boundary identified here.

**Verification:** Add hermetic integration suites for secure/insecure/bogus/indeterminate chains, wildcard and denial variants, collisions, multiple servers, CNAME loops, time transitions, cancellation/slow clients, anchor rollover, and every file-operation failure/crash point. Run them under race detection and verify each listed orchestration function executes; use mutation/fault tests to prove assertions fail when the guarded behavior is removed.

### R-060 — Invalid registrar DS digest configuration silently changes to SHA-256

**Severity:** Low

**Location:** `Golang-tudor-dnssec-signer/config.go:38-51`, `RegistrarConfig.DigestType`; `Golang-tudor-dnssec-signer/config.go:337-468`, `Config.Validate`; `Golang-tudor-dnssec-signer/registrar.go:63-72`; `Golang-tudor-dnssec-signer/registrar_test.go:54-73`

**Problem:** Any registrar `digest_type` other than 4 silently becomes 2, including typos and unsupported values. An operator can request the wrong digest, pass startup validation, and have a different DS representation automatically published to the parent. SHA-256 is valid, so this is not inherently insecure, but silent mutation of trust-publication configuration makes intent and change control unverifiable.

**Evidence:** `DigestType` switches only on 4 and defaults everything else to 2. `Config.Validate` never checks `DigestTypeVal`, and the existing test explicitly requires unknown value 1 to default. The selected value feeds DS computation and registrar publication.

**Fix specification:** Accept 0 as the backward-compatible unset/default value and explicitly accept 2 and 4; reject every other configured integer during startup/reload before any signing or registrar call. Keep the default SHA-256 behavior, TOML field name, DS JSON/schema, supported digest set, and already valid configurations unchanged. Errors must identify the field/value without secrets.

**Verification:** Test absent/zero, 2, 4, negative, 1, 3, 255, and overflow/parse cases in TOML and reload. Valid values must generate/publish the requested digest; invalid values must fail before key, state, output, hook, or registrar mutation.

## Summary by severity

| Severity | Count | Finding IDs |
|---|---:|---|
| Critical | 1 | R-024 |
| High | 19 | R-001–R-012, R-025–R-030, R-043 |
| Medium | 24 | R-013–R-020, R-031–R-042, R-044–R-047 |
| Low | 16 | R-021–R-023, R-048–R-060 |
| **Total** | **60** | **R-001–R-060** |

### Complete finding ledger

| ID | Severity | Short description | Prerequisites / coordination |
|---|---|---|---|
| R-024 | Critical | Unauthenticated trust-anchor input | Start R-059 harness work immediately; foundation for R-025, R-039, R-055 |
| R-001 | High | Commented TOML boundary deletes later tables | R-029 canonical identity; reuse R-019 config transaction |
| R-002 | High | Removal chowns root secrets config to daemon | Coordinate ownership model with R-014 and config writer R-019 |
| R-003 | High | Path reload signs old source file | Coordinate output/state commit with R-019/R-020 |
| R-004 | High | ZSK rotation survives state-save failure | Requires R-013 and R-042 pair/backup transaction |
| R-005 | High | Algorithm rollover commits only KSK | Requires R-013 and R-042 pair/backup transaction |
| R-006 | High | Rollover guard shorter than published DNSKEY TTL | Establish shared rollover timing model first |
| R-007 | High | Retiring ZSK signatures outlive key | Requires R-006 TTL model |
| R-008 | High | KSK trust path retired before cached DS | Requires timing model from R-006/R-007 |
| R-009 | High | Import accepts mismatched/incomplete key set | Requires R-013 atomic pairs; coordinate R-043 eligibility rules |
| R-010 | High | Removal rollback reconstructs partial config | Requires R-001 and R-019 |
| R-011 | High | Failed re-add deletes prior signed output | Requires R-019/R-020 transaction primitives |
| R-012 | High | Import partially replaces live keys | Requires R-013 and R-042 |
| R-025 | High | Local anchors prevent authenticated refresh/rollover | Requires R-024 authenticated source pipeline |
| R-026 | High | Wildcard without denial proof reports secure | Requires R-027/R-028, R-036/R-037, R-043–R-045 |
| R-027 | High | Leaf verification not bound to owner/section | Build on R-043/R-044 key-candidate rules |
| R-028 | High | Time check and crypto can accept different signatures | Build on R-043/R-044 key-candidate rules |
| R-029 | High | Equivalent zone names create conflicting identities | Foundation for every signer config/state mutation |
| R-030 | High | Unauthenticated cut/referral yields false secure NODATA | Requires R-027/R-028 and R-043/R-044 |
| R-043 | High | Invalid DNSKEY flags/protocol authenticate signatures | Core verifier primitive; implement with R-044 |
| R-013 | Medium | Key pair replacement is non-atomic | Foundation for R-004/R-005/R-009/R-012/R-042 |
| R-014 | Medium | Root initialization creates unusable service tree | Coordinate with R-002 ownership separation |
| R-015 | Medium | Stale daemon state resurrects removed zone | Requires R-010/R-019 and R-029 identity model |
| R-016 | Medium | Shutdown mutex deadlock | Coordinate lifecycle tests with R-053 |
| R-017 | Medium | Success erases unrelated warnings | Apply after rollover/state transactions stabilize |
| R-018 | Medium | Per-zone validation bypasses work bound/cache | Coordinate capacity accounting with R-046 |
| R-019 | Medium | Config append is non-atomic/non-durable | Config transaction foundation for R-001/R-002/R-010/R-011/R-015 |
| R-020 | Medium | Signed-zone rename lacks directory durability | Output/state transaction foundation for R-003/R-011 |
| R-031 | Medium | Supported types become UNKNOWN in denial maps | Complete before exposing all types through R-049 |
| R-032 | Medium | Validator requires every DS algorithm | Requires candidate model R-043/R-044 |
| R-033 | Medium | Insecure-ancestor child is mislabeled bogus | Requires authenticated cut/absence work R-030 |
| R-034 | Medium | CNAME exhaustion silently ends secure | Use R-059 resolver/orchestration seams |
| R-035 | Medium | Multi-server response selection is input-order/tag-only | Requires R-027 and R-043/R-044 |
| R-036 | Medium | Single-record denial ring covers nothing | Coordinate canonical ordering R-045 |
| R-037 | Medium | Mixed NSEC3 parameters are combined | Complete before wildcard/denial consumers R-026/R-038 |
| R-038 | Medium | Wildcard NODATA falsely reports bogus | Requires R-026 and R-037 |
| R-039 | Medium | No active anchor is reported as bogus/healthy | Requires R-024/R-025 |
| R-040 | Medium | Signer-name comparison is case-sensitive | Apply consistently with R-027 owner binding |
| R-041 | Medium | Startup probe destroys fixed-name file | Independent filesystem safety fix |
| R-042 | Medium | Backup/restore is non-atomic/non-durable | Build on R-013 pair transaction |
| R-044 | Medium | Key-tag collision handling is slice-order dependent | Core verifier primitive; implement with R-043 |
| R-045 | Medium | NSEC order uses presentation strings | Denial primitive for R-026/R-036 |
| R-046 | Medium | Slow SSE clients exhaust validation capacity | Coordinate with R-018 and shutdown tests |
| R-047 | Medium | Heartbeat can leak credentials or silently disable | Secure transport/config prerequisite for R-052 |
| R-021 | Low | Rollover metrics keep stale active types | Apply after R-006–R-008/R-017 state semantics |
| R-022 | Low | Key generation accepts tag collision after retries | Coordinate collision policy with R-044, pair work R-013 |
| R-023 | Low | Hook stderr buffer is unbounded | Independent availability fix |
| R-048 | Low | Exact base path breaks relative UI URLs | Independent; verify with deployed proxy shape |
| R-049 | Low | UI cannot select supported record types | Apply after R-031/R-038 semantics are correct |
| R-050 | Low | `static_dir` configuration is inert | Independent compatibility/deprecation work |
| R-051 | Low | RDAP registrable-domain heuristic is incorrect | Independent advisory-diagnostic fix |
| R-052 | Low | Heartbeat activity lifecycle is unwired | Requires secure configuration/transport R-047 |
| R-053 | Low | Repeated rate-limiter shutdown panics | Coordinate with R-016 lifecycle repair |
| R-054 | Low | Invalid metrics allowlist fails open | Independent defense-in-depth fix |
| R-055 | Low | Anchor-age metric is frozen/misleading | Requires R-024/R-025/R-039 lifecycle semantics |
| R-056 | Low | Failed entropy yields duplicate request IDs | Independent observability fix |
| R-057 | Low | Release toolchain has GO-2026-5856 | Independent immediate release-hygiene fix |
| R-058 | Low | Deployment/conformance docs contradict code | Last, after all behavior fixes they describe |
| R-059 | Low | Critical orchestration lacks deterministic tests | Cross-cutting prerequisite/parallel work for all fixes |
| R-060 | Low | Invalid DS digest silently defaults to SHA-256 | Complete before registrar/rollover publication changes |

## Suggested dependency-aware fix order

1. **Contain release risk and establish the safety harness.** Rebuild with a patched Go toolchain (R-057) immediately. In parallel, implement the internal transport/clock/filesystem seams and adversarial fixtures from R-059; this work must not delay emergency containment of R-024, but every following fix should land with a regression test through those seams.

2. **Rebuild the validator's root of trust and cryptographic candidate model.** Fix anchor authenticity first (R-024). Then centralize DNSKEY eligibility and collision-safe candidate iteration (R-043, R-044), bind verification to the exact owner/section/signature/time tuple (R-027, R-028), and make signer-name comparison canonical (R-040). Build authenticated refresh/last-known-good handling on that foundation (R-025), then correct empty-active-anchor status and observability (R-039, R-055).

3. **Correct authenticated authority and denial semantics.** Implement canonical NSEC ordering and ring behavior (R-045, R-036), isolate NSEC3 parameter sets (R-037), and complete supported-type mapping (R-031). Use those primitives to fix wildcard proofs and wildcard NODATA (R-026, R-038). Then repair authenticated zone-cut/DS-absence handling (R-030, R-033), any-valid-algorithm behavior (R-032), CNAME termination (R-034), and multi-server selection/comparison (R-035). Run the full secure/insecure/bogus/indeterminate matrix before exposing extra UI types.

4. **Create signer identity and persistence primitives before touching workflows.** Canonicalize each zone to one identity (R-029). Separate configuration ownership from daemon data ownership (R-002, R-014), implement durable transactional config replacement (R-019), atomic validated key-pair generations (R-013), atomic/durable backup restoration (R-042), and durable signed-output publication (R-020). Fix the destructive table boundary (R-001) using the new config transaction rather than another bespoke writer.

5. **Rebuild signer command and reload transactions on those primitives.** Fix automatic/algorithm rollover rollback (R-004, R-005), import validation and atomicity (R-009, R-012), removal/re-add rollback (R-010, R-011), stale-daemon resurrection (R-015), and source-path migration (R-003). Repair the startup probe independently in the same filesystem tranche (R-041). Each operation must leave either the complete old generation or complete new generation across injected failure and restart.

6. **Correct rollover timing and publication policy.** Derive one TTL/dwell model from actually published DNSKEY/RRset data (R-006), retain retiring signing keys through their signatures and caches (R-007), and only then extend KSK/algorithm trust-path dwell through parent DS caches (R-008). Reject invalid registrar digest configuration before publication (R-060), stop deliberately accepting generated tag collisions (R-022), preserve independent warnings (R-017), and align metrics after final state transitions are stable (R-021).

7. **Close service availability and boundary gaps.** Add bounded SSE write progress and capacity release (R-046) and apply equivalent work accounting/caching to per-zone validation (R-018). Bound hook output (R-023). Validate heartbeat credentials/HTTPS/redirects first (R-047), then wire lifecycle activity and joined shutdown (R-052). Remove the signer shutdown lock inversion and make validator limiter shutdown idempotent (R-016, R-053). Fail metrics closed on invalid policy (R-054) and make request-ID fallback unique (R-056).

8. **Finish diagnostics, UI, compatibility, and documentation.** Redirect the exact base path (R-048), expose record types only after backend denial semantics are fixed (R-049), deprecate the inert static directory safely (R-050), and correct public-suffix-aware RDAP diagnostics (R-051). Finally update and mechanically validate every deployment/conformance document against the now-tested implementation (R-058).

After each phase, run both module suites with race detection, the targeted fault/crash and signed-packet fixtures, `go vet`, binary vulnerability scanning, and the packaging/static checks. Do not close a finding based only on a helper-unit test: verify its stated cross-module condition and preserve the public/on-disk contracts listed in that finding.
