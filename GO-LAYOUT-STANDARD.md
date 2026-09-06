# Go daemon layout standard

How to decompose a flat `package main` Go daemon into `internal/` packages, to
the standard set by **`signer`** (2026-07: it went from a
flat 63-file `package main` to 13 root files + 8 `internal/` packages — see that
project's `CLAUDE.md` "Code Organization" section for the target shape).

This applies to any daemon under `~/Git/daemons/` (mail, dns, rdap, …). The
signer is the worked example; this file is the reusable recipe.

## The prompt

Paste this at a fresh session on the daemon you want to reorganize:

> Decompose this daemon's flat `package main` into `internal/` packages,
> following the standard in `daemons/dnssec/signer` (its
> CLAUDE.md "Code Organization" section is the reference). Rules:
>
> 1. **Green baseline first.** `go build ./... && go vet ./... && go test ./...`
>    must pass before touching anything, so a pre-existing failure is never
>    blamed on the refactor.
> 2. **Map the seams before cutting.** List every top-level type/func; for each
>    candidate package find inbound (used-by) and outbound (depends-on) edges and
>    draw the DAG. The result must be a strict DAG with root `package main` on
>    top: `internal/` packages never import root, and there are no cycles.
> 3. **Extract leaf-first, one package per commit.** Start at the bottom leaf
>    (config, or a shared fs/util leaf if one emerges). Keep build+vet+test green
>    after each package and commit each separately — never leave the tree broken
>    between commits.
> 4. **Qualify with `gofmt -r`, never sed/perl.** It is AST-aware:
>    `gofmt -r 'Config -> config.Config'` rewrites the bare identifier but never
>    the selector in `x.Config`/`time.Config`, and never double-qualifies. One
>    trap: it *does* rewrite composite-literal field keys, so a struct field
>    named like a moved type gets wrongly qualified — revert those (`{pkg.Field:`
>    back to `{Field:`).
> 5. **Alias colliding package names.** If a package name (`state`, `signer`)
>    matches a common local variable, import it aliased (`statepkg`, `signerpkg`)
>    in the root package rather than renaming the variables. (Same convention the
>    sibling `dnssec-validator` uses for its `dns` package: `dnspkg`.)
> 6. **Route tests by what they touch.** White-box tests (using unexported
>    internals) move into the owning package; black-box/integration tests stay at
>    root using the exported, qualified API. Export an internal only when it's a
>    coherent, legitimately-public operation the CLI genuinely needs — not a deep
>    helper for one test.
> 7. **Two recurring gotchas:** (a) a **shared test fixture** used by both root
>    tests and a package's white-box tests can't live in either (test import
>    cycle) — put it in a tiny importable `internal/<name>test` package that only
>    test files import; (b) **grab-bag tests** straddling two packages' internals
>    must be *split by concern*, one part per owning package — never moved whole.
> 8. **CLI glue** entangled with root globals (config-path flag, ldflags build
>    version, file locks) is usually cleaner left at root calling the extracted
>    package's exported API — but move the *pure domain* functions into the
>    package, and propagate the build version via a package var set in `main()`.
> 9. **Finish green:** full build+vet+test pass, `gofmt` clean, build the real
>    binary and exercise it end-to-end (not just tests), update the project
>    CLAUDE.md "Code Organization" to match what you built, then push to `main`
>    (solo repo — commit straight to `main`, no feature branch).

## Notes from the dnssec-signer run (what actually bites)

- The hardest package is the big domain core (there, `signer`): many CLI
  functions reach into its internals, and one shared test fixture (`testConfig`)
  spanned the boundary → it became `internal/dnssectest`.
- **Metrics had to come out first** — the signing core emits metrics and so
  can't import the root package; metrics became a leaf that both import.
- Filelock, the ldflags build version, and config-path loading are the classic
  "keep the CLI glue at root" cases.
- Expect a few coherent internals to need exporting for the CLI (key import,
  recover-or-generate, DS diff, load-key-by-id) — that's fine; deep helpers are
  not.
- Final signer shape: `internal/{config,state,fsutil,metrics,signer,registrar,`
  `validate,dnssectest}` with a strict leaf-first DAG
  (`fsutil → config → state → metrics/signer → registrar → validate → root`).

## Caveat for the mail stack

`daemons/mail/` is multi-repo and multi-binary (`mail-database`, `imap-database`,
`mail-api`, `mail-llm-worker`, `mail-mcp`) with a load-bearing
`replace => ../Golang-tudor-mail-database` sibling layout and a shared schema.
The dependency DAG there already spans module boundaries, so "leaf-first" means
the schema/store package before the readers — the rules above still hold, but the
module split already does some of the work `internal/` did for the signer.
