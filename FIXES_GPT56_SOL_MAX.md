# Fix log — REVIEW_GPT56_SOL_MAX.md

Worked in the suggested dependency-aware fix order (REVIEW_GPT56_SOL_MAX.md §"Suggested dependency-aware fix order").
Each entry: finding ID, what changed, files touched, verification result. SKIPPED entries record why the spec was ambiguous or conflicted with actual code behavior.

Baseline before any changes: both modules build, `go vet ./...` clean, `go test ./...` green (signer 16.0s; validator all packages ok). Toolchain installed: go1.26.4.

---

## Phase 1 — Contain release risk and establish the safety harness

### R-057 — Release toolchain has GO-2026-5856 — FIXED
- **Change:** Added a `toolchain go1.26.5` directive to both modules' `go.mod`. The `go` language-version directive is unchanged (validator `go 1.21.0`, signer `go 1.23.0`); the new directive pins/enforces the minimum patched release toolchain (Go 1.26.5 fixes GO-2026-5856, an Encrypted Client Hello PSK identity leak). `GOTOOLCHAIN=auto` (the environment default) now selects 1.26.5 automatically for build/test/release.
- **Files:** `Golang-dnssec-validator/go.mod`, `Golang-tudor-dnssec-signer/go.mod`
- **Verification:** Rebuilt both binaries; `go version -m` reports `go1.26.5` for each (was `go1.26.4`). Ran `govulncheck -mode=binary` on both rebuilt binaries → "No vulnerabilities found. Your code is affected by 0 vulnerabilities." GO-2026-5856 is absent from both. Both modules still `go build ./...` clean under the pinned toolchain.

