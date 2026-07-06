# aur-scan

`aur-scan` statically scans AUR packaging metadata before a package is built.
It understands Bash syntax well enough to distinguish commands in `build()`,
`package()`, and install scriptlets, and combines that structure with exact
known-risk indicators and packaging-specific heuristics.

It does not execute or source a PKGBUILD.

## Install

For a per-user installation, run:

```sh
./install.sh
```

This builds with Cargo, installs the binary at
`$HOME/.local/bin/aur-scan`, and atomically configures
`$XDG_CONFIG_HOME/paru/paru.conf` (normally
`$HOME/.config/paru/paru.conf`). It uses the absolute binary path, so
`$HOME/.local/bin` does not need to be in Paru's `PATH`.

To make medium findings block too:

```sh
./install.sh --strict
```

Existing Paru settings are preserved. When a config change is needed, the
previous file is copied to `paru.conf.bak`. Re-running the installer is safe.
Use `./install.sh --help` for custom binary and config locations.

The binary is writable by your user. This is appropriate for normal per-user
Paru use, but a user-level scanner is not a security boundary against other
processes already running as your account. For centrally managed machines,
install it in a root-owned system path instead.

## Paru

Configure the enforcement command in `~/.config/paru/paru.conf`:

```ini
[bin]
PreBuildCommand = '/home/you/.local/bin/aur-scan' scan .
```

Paru runs `PreBuildCommand` once per package from the directory containing its
PKGBUILD. `aur-scan` returns:

- `0` when policy permits the build
- `1` when findings meet the blocking threshold
- `2` when scanning cannot complete

Paru treats either nonzero status as a build failure. By default `HIGH` and
`CRITICAL` findings block. To block `MEDIUM` findings too:

```ini
PreBuildCommand = '/home/you/.local/bin/aur-scan' scan --strict .
```

Do not use paru's `FileManager` as the enforcement point. It receives a
temporary review tree that may contain several packages, and every nonzero
status aborts rather than distinguishing warnings.

## Usage

```sh
# Human report; suitable for paru
aur-scan scan /path/to/package

# Machine-readable report
aur-scan scan --format json /path/to/package

# Explicit threshold
aur-scan scan --fail-on low /path/to/package

# Record reviewed metadata
aur-scan approve /path/to/package

# Review later changes
aur-scan diff /path/to/package
```

Approval is explicit and never happens as a side effect of scanning. Approval
refuses `HIGH` or `CRITICAL` findings unless `--force` is supplied. Approval
records the findings present at that moment: on later scans they are labeled
`ACCEPTED` and no longer count toward the blocking threshold, so a reviewed
package builds again. Findings on lines added since approval are marked `NEW`
and always block as usual, even when an identical finding was accepted before.

The cache defaults to `$XDG_CACHE_HOME/aur-scan/baselines`. Override it with
`--cache-dir` or `AUR_SCAN_CACHE_DIR`.

## Rules and IOCs

The binary includes behavioral rules, exact known-risk indicators, and a
1,619-package snapshot referenced by an Arch Linux `aur-general` post. The
bundled list is normalized from the Arch HedgeDoc as updated on June 13, 2026,
with SHA-256
`f46cec3c2e2dd0092de8ed36917ce8ab726fe205d608400ce1b5fa7dc9b6ba70`.
See [`data/package_list.txt`](data/package_list.txt) for both source URLs.
Package lists age quickly; this records provenance rather than claiming
completeness.

Supply a full replacement TOML rules file with:

```sh
aur-scan scan --rules /path/to/iocs.toml .
```

See [`data/iocs.toml`](data/iocs.toml) for the schema. Rule IDs must contain
only uppercase ASCII letters, digits, and underscores. Regexes are validated
before scanning.

`update-iocs` installs a feed only after Minisign verification:

```sh
aur-scan update-iocs \
  --url https://security.example/iocs.toml \
  --signature-url https://security.example/iocs.toml.minisig \
  --public-key 'RW...'
```

The default destination is `$XDG_CONFIG_HOME/aur-scan/iocs.toml`. Once present,
that verified file automatically replaces the bundled IOC rules. Set
`AUR_SCAN_RULES` or pass `--rules` to select another file. Scans never access
the network.

## What It Detects

- configured known-risk package names, dependencies, publishers, and artifacts
- network or decoded content piped into shells, including inside `sh -c`
  payloads and pacman hook `Exec =` command lines (phase `alpm-hook`)
- package-manager installs, weighted by PKGBUILD phase
- network clients in install scriptlets, hooks, and `package()`
- persistence and credential-adjacent paths
- suspicious source hosts and skipped checksums
- missing checksum arrays, absent upstream/source references, and unusually
  short PKGBUILDs
- Bun declared as a dependency, reported as low-severity review context
- `npm install`, `npm ci`, `npm i`, `bun install`, `bun add`, and `bun i`,
  weighted by execution phase
- obfuscation primitives, encoded blobs, capabilities, and immutable files
- malformed Bash that weakens structural analysis

Human findings include severity, confidence, rule ID, source location, phase,
snippet, and rationale. Snippets are length-limited and stripped of control
characters before terminal output. Human reports also end with one concise
`OK:` line naming major check groups that produced no findings. Declared
`*sums` checksum values, including multi-line arrays, are excluded from
long-hex obfuscation detection. Heuristic text rules skip comments; exact IOC
indicators still match anywhere, including comments.
Human reports include a blank line before and after the result so Paru output
remains readable.

## Security Boundary

This tool scans `PKGBUILD`, `.SRCINFO`, `*.install`, and `*.hook` regular files
at the top level of a package directory. It rejects symlinks and applies input
size limits.

It cannot prove that downloaded archives, VCS repositories, compiler inputs,
or the final package payload are safe. Static analysis also cannot completely
resolve shell indirection. Run AUR builds as an unprivileged user in an
isolated clean chroot, retain normal source checks, and manually review
findings and diffs.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```

The integration suite exercises Paru-style invocation, exit statuses, phase
classification, install scriptlets, baselines, signed updates, malformed
syntax, and hostile symlinks. A frozen snapshot of the 50 most-voted AUR
packages under [`tests/corpus/`](tests/corpus/README.md) asserts that popular,
widely reviewed packages produce no blocking findings and stay within a
documented budget of medium findings, so rule changes cannot silently regress
precision.
