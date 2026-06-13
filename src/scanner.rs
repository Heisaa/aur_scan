use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use anyhow::Result;
use regex::Regex;

use crate::{
    baseline, bash,
    input::{self, FileKind, SourceFile},
    model::{Finding, ScanReport},
    rules::{self, RuleSet},
};

#[derive(Debug)]
pub struct ScanOptions<'a> {
    pub package_dir: &'a Path,
    pub cache_root: &'a Path,
    pub external_rules: Option<&'a Path>,
}

#[derive(Debug)]
pub struct PackageInput {
    pub directory: PathBuf,
    pub files: Vec<SourceFile>,
    pub package_base: String,
    pub package_names: Vec<String>,
}

pub fn load_package(package_dir: &Path) -> Result<PackageInput> {
    let directory = package_dir.canonicalize()?;
    let files = input::discover(&directory)?;
    let (package_base, package_names) = package_metadata(&files);
    let package_base = package_base
        .or_else(|| package_names.first().cloned())
        .unwrap_or_else(|| {
            directory
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown-package")
                .to_owned()
        });
    Ok(PackageInput {
        directory,
        files,
        package_base,
        package_names,
    })
}

pub fn scan(options: &ScanOptions<'_>) -> Result<ScanReport> {
    let package = load_package(options.package_dir)?;
    let rules = match options.external_rules {
        Some(path) => rules::load_rules(path)?,
        None => rules::bundled_rules()?,
    };
    scan_loaded(&package, options.cache_root, &rules)
}

fn scan_loaded(package: &PackageInput, cache_root: &Path, rules: &RuleSet) -> Result<ScanReport> {
    let comparison = baseline::compare(cache_root, &package.package_base, &package.files)?;
    let mut findings = Vec::new();

    for file in &package.files {
        findings.extend(rules::scan_text(file, rules)?);
        if file.kind.is_script() {
            findings.extend(rules::scan_bash(file, &bash::analyze(file)?));
        }
    }
    if let Some(metadata_file) = package
        .files
        .iter()
        .find(|file| file.kind == FileKind::Srcinfo)
        .or_else(|| {
            package
                .files
                .iter()
                .find(|file| file.kind == FileKind::Pkgbuild)
        })
    {
        findings.extend(rules::known_package_findings(
            &package.package_names,
            rules,
            metadata_file,
        ));
    }

    annotate_changes(&mut findings, &comparison.changed_lines);
    deduplicate(&mut findings);
    findings.sort_by(Finding::sort_cmp);
    let checks_passed = passed_checks(&findings);

    Ok(ScanReport {
        schema_version: 1,
        package_dir: package.directory.clone(),
        package_base: Some(package.package_base.clone()),
        package_names: package.package_names.clone(),
        files_scanned: package.files.len(),
        baseline_present: comparison.present,
        checks_passed,
        findings,
    })
}

fn passed_checks(findings: &[Finding]) -> Vec<String> {
    let groups: [(&[&str], &str); 5] = [
        (
            &[
                "KNOWN_RISK_PACKAGE",
                "IOC_ATOMIC_LOCKFILE",
                "IOC_JS_DIGEST",
                "IOC_ATTACKER_PUBLISHER",
                "IOC_EBPF_PIN",
                "IOC_MONERO_GUI",
            ],
            "known-risk indicators clear",
        ),
        (
            &[
                "PIPE_TO_SHELL",
                "DECODE_TO_SHELL",
                "NETWORK_SUBSTITUTION_EXEC",
            ],
            "no remote/decode-to-shell execution",
        ),
        (
            &["PACKAGE_MANAGER_INSTALL", "NETWORK_IN_INSTALL_PHASE"],
            "no package-manager or network installs",
        ),
        (
            &[
                "MISSING_CHECKSUMS",
                "SKIPPED_CHECKSUM",
                "MISSING_UPSTREAM_URL",
                "NO_SOURCE_REFERENCE",
            ],
            "source integrity metadata present",
        ),
        (&["BASH_PARSE_ERROR"], "Bash syntax parsed cleanly"),
    ];

    groups
        .into_iter()
        .filter(|(ids, _)| {
            !findings
                .iter()
                .any(|finding| ids.contains(&finding.rule_id.as_str()))
        })
        .map(|(_, label)| label.to_owned())
        .collect()
}

fn annotate_changes(
    findings: &mut [Finding],
    changed_lines: &std::collections::HashMap<PathBuf, HashSet<usize>>,
) {
    for finding in findings {
        finding.new_since_approval = changed_lines
            .get(&finding.file)
            .is_some_and(|lines| lines.contains(&finding.line));
    }
}

fn deduplicate(findings: &mut Vec<Finding>) {
    let mut seen = HashSet::new();
    findings.retain(|finding| {
        seen.insert((
            finding.rule_id.clone(),
            finding.file.clone(),
            finding.line,
            finding.column,
        ))
    });
}

fn package_metadata(files: &[SourceFile]) -> (Option<String>, Vec<String>) {
    if let Some(srcinfo) = files.iter().find(|file| file.kind == FileKind::Srcinfo) {
        let mut package_base = None;
        let mut names = Vec::new();
        for line in srcinfo.text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key.trim() {
                "pkgbase" => package_base = Some(value.trim().to_owned()),
                "pkgname" => names.push(value.trim().to_owned()),
                _ => {}
            }
        }
        if package_base.is_some() || !names.is_empty() {
            names.sort();
            names.dedup();
            return (package_base, names);
        }
    }

    let Some(pkgbuild) = files.iter().find(|file| file.kind == FileKind::Pkgbuild) else {
        return (None, Vec::new());
    };
    let scalar = Regex::new(
        r#"(?m)^\s*(pkgbase|pkgname)\s*=\s*(['"]?)([A-Za-z0-9@._+:-]+)['"]?\s*(?:#.*)?$"#,
    )
    .expect("metadata regex must compile");
    let array = Regex::new(r"(?ms)^\s*pkgname\s*=\s*\((?P<body>[^)]*)\)")
        .expect("metadata regex must compile");
    let word =
        Regex::new(r#"['"]?([A-Za-z0-9@._+:-]+)['"]?"#).expect("metadata regex must compile");
    let mut package_base = None;
    let mut names = Vec::new();
    for captures in scalar.captures_iter(&pkgbuild.text) {
        match captures.get(1).map(|value| value.as_str()) {
            Some("pkgbase") => {
                package_base = captures.get(3).map(|value| value.as_str().to_owned())
            }
            Some("pkgname") => {
                if let Some(name) = captures.get(3) {
                    names.push(name.as_str().to_owned());
                }
            }
            _ => {}
        }
    }
    if let Some(captures) = array.captures(&pkgbuild.text)
        && let Some(body) = captures.name("body")
    {
        names.extend(
            word.captures_iter(body.as_str())
                .filter_map(|item| item.get(1).map(|name| name.as_str().to_owned())),
        );
    }
    names.sort();
    names.dedup();
    (package_base, names)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::input::{FileKind, SourceFile};

    use super::package_metadata;

    #[test]
    fn reads_literal_split_package_names() {
        let files = vec![SourceFile {
            name: PathBuf::from("PKGBUILD"),
            text: "pkgbase=demo\npkgname=('demo' 'demo-cli')\n".to_owned(),
            kind: FileKind::Pkgbuild,
        }];
        assert_eq!(
            package_metadata(&files),
            (
                Some("demo".to_owned()),
                vec!["demo".to_owned(), "demo-cli".to_owned()]
            )
        );
    }
}
