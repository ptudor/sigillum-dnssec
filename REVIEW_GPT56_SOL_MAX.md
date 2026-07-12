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

<!-- Additional findings and the required final summary/fix order are appended in later review-only checkpoints. -->
