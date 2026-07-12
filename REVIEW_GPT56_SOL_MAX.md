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

<!-- Additional findings and the required final summary/fix order are appended in later review-only checkpoints. -->
