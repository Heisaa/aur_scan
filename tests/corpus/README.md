# False-positive corpus

Packaging metadata of the 50 most-voted AUR package bases, used by
`tests/corpus.rs` to keep the scanner's false-positive rate on ordinary,
widely reviewed packages near zero. A blocking finding here is presumed to be
a rule-precision bug until a human review concludes otherwise.

Provenance:

- Selection: top 50 package bases by `NumVotes` from
  `https://aur.archlinux.org/packages-meta-v1.json.gz`, excluding any name on
  `data/package_list.txt`.
- Files: `PKGBUILD`, `.SRCINFO`, and any `install =` scriptlets, fetched from
  `https://aur.archlinux.org/cgit/aur.git/plain/<file>?h=<pkgbase>`.
- Retrieved: 2026-07-06.

The snapshot is deliberately frozen; do not update files in place to make a
test pass. To accept a legitimate HIGH/CRITICAL detection on one package, add
its rule ID to an `allowed-findings.txt` file in that package's directory. To
refresh the whole corpus, re-run the selection above, review the resulting
findings, and update `MEDIUM_BUDGET` in `tests/corpus.rs` alongside this
provenance note.
