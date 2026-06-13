# Implementation plan: aur-scan

## Goal

Build a standalone Rust CLI that statically scans an AUR package directory
before `makepkg` executes it. The scanner reports packaging-specific risks and
returns a non-zero status when policy says the build must stop.

The scanner treats every input as hostile. It never sources a PKGBUILD, invokes
`makepkg`, follows symlinks, or executes package-controlled commands.

## Paru integration contract

Use paru's `PreBuildCommand`, not `FileManager`, as the enforcement point:

```ini
[bin]
PreBuildCommand = /usr/bin/aur-scan scan .
```

Ship an idempotent per-user installer that builds the release binary, installs
it to `$HOME/.local/bin`, and safely adds or updates this command in paru's
existing `[bin]` section. Use an absolute path so shell `PATH` configuration is
irrelevant, preserve unrelated settings, back up changed configs, and reject
symlinked config files.

Paru runs this command once per package with the package directory as its
current directory. Any non-zero result blocks the build. `FileManager` receives
a temporary multi-package review tree and is suitable only for interactive
review, not the primary enforcement contract.

Exit statuses:

- `0`: scan completed and policy permits the build
- `1`: findings meet the configured blocking threshold
- `2`: invalid arguments or scanner/configuration failure

Default policy blocks `HIGH` and `CRITICAL`. `--strict` blocks `MEDIUM` and
above. `--fail-on` sets an explicit threshold.

## Architecture

Implement a standalone Rust binary:

- `clap` for the CLI
- `tree-sitter` and `tree-sitter-bash` for error-tolerant Bash syntax parsing
- `regex` for behavioral text rules
- `aho-corasick` for literal IOC matching
- `serde` and TOML for external rules and IOC data
- `sha2` and `similar` for approved snapshots and diffs
- `minisign-verify` for authenticated IOC updates

Modules:

```text
src/
  main.rs       CLI and exit-status contract
  model.rs      severities, confidence, findings, reports
  input.rs      bounded, symlink-safe file discovery and reading
  bash.rs       AST extraction and phase-aware command analysis
  rules.rs      built-in and external rules
  scanner.rs    scan orchestration and policy
  baseline.rs   explicit approval snapshots and changed-line diffing
  update.rs     signed IOC update workflow
  output.rs     human and JSON reports with terminal-safe snippets
```

## Input and metadata

Scan only regular files directly in the package directory:

- `PKGBUILD`
- `.SRCINFO`
- `*.install`
- `*.hook`

Reject symlinks for these names. Apply limits for file count, individual file
size, total bytes, and line length. Parse `.SRCINFO` as inert text. If it is
missing, statically extract literal `pkgbase`/`pkgname` assignments from the
PKGBUILD AST; never evaluate shell expressions.

## Analysis model

Each finding records:

- stable rule ID
- severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- confidence (`HEURISTIC`, `STRUCTURAL`, `EXACT`)
- file, one-based line and column
- terminal-safe matched snippet
- description and remediation-oriented rationale
- enclosing PKGBUILD function or install-scriptlet phase when known
- whether the matching line is new relative to an approved baseline

Use the Bash AST to identify functions, commands, pipelines, redirects, command
substitutions, and assignments. Literal and regex rules add evidence but do not
pretend to parse Bash structure.

## Rules

Ship versioned built-in rules plus an optional external TOML rule file.
Bundle package-name indicators from an Arch-hosted list with the referring
mailing-list URL, source update time, normalized content hash, and retrieval
date recorded beside the generated data.

Exact known-risk indicators:

- known malicious package names and publisher strings
- maintained dependency, publisher, path, and package-name indicators
- known persistence and artifact paths

Structural and behavioral rules:

- network output piped to a shell or evaluator
- decoded/decrypted content piped to a shell
- package-manager dependency installation in `.install` scriptlets: `CRITICAL`
- package-manager installation in `package()`: `HIGH`
- package-manager installation in `prepare()` or `build()`: contextual warning
- network clients in install scriptlets or `package()`
- persistence paths, credential-adjacent paths, `setcap`, `chattr +i`
- suspicious source hosts, raw IPs, URL shorteners, and paste services
- missing checksum declarations, missing upstream/source references, and
  unusually short PKGBUILDs
- JavaScript package-manager dependencies as review context, plus install,
  add, and clean-install command variants weighted by execution phase
- `SKIP` checksums, elevated only for non-VCS sources
- obfuscation primitives and long encoded/hex blobs
- parse errors, because incomplete parsing weakens structural coverage

Avoid declaring all build-time package-manager use malicious. Dependency
restoration in `build()` is common; phase and command details determine
severity.

## Approved baselines

Store complete approved copies under the XDG cache directory, keyed by a
filesystem-safe package base plus a hash of its canonical package identity.
Include a manifest with schema version, approval time, package names, and file
hashes.

Commands:

- `aur-scan approve <dir>` explicitly records the current metadata
- `aur-scan diff <dir>` displays changes from the approved snapshot
- `aur-scan scan <dir>` annotates findings on added/changed lines

Scanning never updates approval state. Missing baselines are informational, not
automatic approval.

## IOC updates

Bundle a dated offline IOC file. `update-iocs` downloads data and a detached
Minisign signature, verifies them against a configured public key, validates
the TOML schema and rule patterns, then atomically replaces the user IOC file.
No scan performs network access.

The updater accepts explicit URLs and public key configuration so deployments
can choose and pin their own trusted feed. HTTPS is required unless an explicit
development override is supplied.

## Output

Human output goes to stderr and is quiet on clean packages except for a
one-line summary. Findings are sorted by severity and source location.

`--format json` emits a stable machine-readable report to stdout. Strip control
characters from snippets to prevent terminal escape injection.

## Testing and release criteria

Fixtures cover:

- clean PKGBUILDs
- every exact IOC
- multiline and nested pipe-to-shell commands
- comments and quoted strings that must not become structural findings
- package-manager calls in each phase and install scriptlets
- suspicious sources and checksum combinations
- malformed Bash and variable indirection
- split packages, arrays, hostile filenames, symlinks, and oversized files
- baseline approval, diffing, and changed-line annotation
- signed-update success and invalid-signature rejection
- Paru-style invocation and all exit statuses

Release gates:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```

Document installation, configuration, limitations, rule authoring, baseline
workflow, and the security boundary. In particular, this scanner reviews
packaging metadata; it cannot prove downloaded source archives or the produced
package payload are safe.
