use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use aur_scan::{
    model::Severity,
    scanner::{self, ScanOptions},
};
use tempfile::TempDir;

/// Ceiling on MEDIUM findings across the whole corpus. The July 2026 snapshot
/// produces 5, all non-VCS `SKIP` checksum entries that genuinely deserve
/// review. Raise this only after inspecting the new findings and confirming
/// they are correct detections rather than precision regressions.
const MEDIUM_BUDGET: usize = 6;

#[test]
fn popular_packages_stay_below_false_positive_budget() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let cache = TempDir::new().expect("create scan cache");
    let mut directories: Vec<PathBuf> = fs::read_dir(&corpus)
        .expect("read corpus directory")
        .map(|entry| entry.expect("read corpus entry").path())
        .filter(|path| path.is_dir())
        .collect();
    directories.sort();
    assert!(
        directories.len() >= 40,
        "corpus unexpectedly small: {} packages",
        directories.len()
    );

    let mut unexpected = Vec::new();
    let mut medium_total = 0;
    for directory in &directories {
        let allowed = allowed_rules(directory);
        let report = scanner::scan(&ScanOptions {
            package_dir: directory,
            cache_root: cache.path(),
            external_rules: None,
        })
        .unwrap_or_else(|error| panic!("scan failed for {}: {error:#}", directory.display()));
        for finding in &report.findings {
            if finding.severity == Severity::Medium {
                medium_total += 1;
            }
            if finding.severity >= Severity::High && !allowed.contains(&finding.rule_id) {
                unexpected.push(format!(
                    "{}: {} {} at {}:{} > {}",
                    directory.file_name().unwrap_or_default().to_string_lossy(),
                    finding.severity,
                    finding.rule_id,
                    finding.file.display(),
                    finding.line,
                    finding.snippet,
                ));
            }
        }
    }

    assert!(
        unexpected.is_empty(),
        "blocking findings on popular packages; fix the rule or, if the \
         detection is legitimate, record the rule ID in that package's \
         allowed-findings.txt:\n{}",
        unexpected.join("\n")
    );
    assert!(
        medium_total <= MEDIUM_BUDGET,
        "MEDIUM findings across corpus grew to {medium_total} (budget \
         {MEDIUM_BUDGET}); inspect them for precision regressions before \
         raising the budget"
    );
}

/// Rule IDs reviewed and accepted as legitimate detections for one corpus
/// package, listed one per line in `allowed-findings.txt` beside its
/// PKGBUILD. `#` starts a comment.
fn allowed_rules(directory: &Path) -> HashSet<String> {
    let Ok(text) = fs::read_to_string(directory.join("allowed-findings.txt")) else {
        return HashSet::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect()
}
