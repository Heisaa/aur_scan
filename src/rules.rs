use std::{collections::HashSet, ops::Range, path::Path, sync::LazyLock};

use aho_corasick::AhoCorasick;
use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    bash::BashAnalysis,
    input::{FileKind, SourceFile},
    model::{Confidence, Finding, Severity, safe_snippet},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSet {
    pub schema_version: u32,
    pub generated_at: String,
    #[serde(default)]
    pub source_url: Option<String>,
    #[serde(default)]
    pub source_revision: Option<String>,
    #[serde(default)]
    pub known_packages: Vec<String>,
    #[serde(default)]
    pub literal_rules: Vec<LiteralRule>,
    #[serde(default)]
    pub regex_rules: Vec<RegexRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiteralRule {
    pub id: String,
    pub severity: Severity,
    pub needle: String,
    pub description: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegexRule {
    pub id: String,
    pub severity: Severity,
    pub pattern: String,
    pub description: String,
    pub rationale: String,
}

pub fn bundled_rules() -> Result<RuleSet> {
    let mut rules = parse_rules(include_str!("../data/iocs.toml"))?;
    rules.known_packages = include_str!("../data/package_list.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect();
    Ok(rules)
}

#[cfg(test)]
fn bundled_package_count() -> Result<usize> {
    Ok(bundled_rules()?.known_packages.len())
}

pub fn load_rules(path: &Path) -> Result<RuleSet> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read rule file {}", path.display()))?;
    parse_rules(&text).with_context(|| format!("invalid rule file {}", path.display()))
}

pub fn parse_rules(text: &str) -> Result<RuleSet> {
    let rules: RuleSet = toml::from_str(text).context("cannot parse IOC TOML")?;
    validate_rules(&rules)?;
    Ok(rules)
}

pub fn validate_rules(rules: &RuleSet) -> Result<()> {
    if rules.schema_version != 1 {
        bail!("unsupported IOC schema version {}", rules.schema_version);
    }
    if rules.generated_at.trim().is_empty() {
        bail!("IOC generated_at must not be empty");
    }
    let mut ids = HashSet::new();
    for rule in &rules.literal_rules {
        if rule.needle.is_empty() {
            bail!("literal rule {} has an empty needle", rule.id);
        }
        validate_id(&rule.id, &mut ids)?;
    }
    for rule in &rules.regex_rules {
        validate_id(&rule.id, &mut ids)?;
        Regex::new(&rule.pattern).with_context(|| format!("invalid regex in rule {}", rule.id))?;
    }
    Ok(())
}

fn validate_id(id: &str, ids: &mut HashSet<String>) -> Result<()> {
    if id.is_empty()
        || !id
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
    {
        bail!("invalid rule ID {id:?}; use uppercase ASCII, digits, and underscores");
    }
    if !ids.insert(id.to_owned()) {
        bail!("duplicate rule ID {id}");
    }
    Ok(())
}

pub fn scan_text(
    file: &SourceFile,
    rules: &RuleSet,
    comment_ranges: &[Range<usize>],
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let checksum_ranges = checksum_ranges(&file.text);

    if !rules.literal_rules.is_empty() {
        let matcher = AhoCorasick::new(rules.literal_rules.iter().map(|rule| &rule.needle))
            .context("cannot compile literal IOC matcher")?;
        for matched in matcher.find_iter(&file.text) {
            let rule = &rules.literal_rules[matched.pattern().as_usize()];
            findings.push(text_finding(
                file,
                matched.start(),
                &rule.id,
                rule.severity,
                Confidence::Exact,
                &rule.description,
                &rule.rationale,
            ));
        }
    }

    for rule in &rules.regex_rules {
        let pattern = Regex::new(&rule.pattern)
            .with_context(|| format!("cannot compile rule {}", rule.id))?;
        for matched in pattern.find_iter(&file.text) {
            if within(comment_ranges, matched.start()) {
                continue;
            }
            if rule.id == "OBFUSCATED_LONG_HEX" && within(&checksum_ranges, matched.start()) {
                continue;
            }
            findings.push(text_finding(
                file,
                matched.start(),
                &rule.id,
                rule.severity,
                Confidence::Heuristic,
                &rule.description,
                &rule.rationale,
            ));
        }
    }

    findings.extend(scan_builtin_text(file, comment_ranges));
    Ok(findings)
}

fn within(ranges: &[Range<usize>], byte_offset: usize) -> bool {
    ranges.iter().any(|range| range.contains(&byte_offset))
}

/// Byte spans of `*sums=` assignments, including multi-line arrays, so
/// declared checksum values are not reported as obfuscated blobs.
fn checksum_ranges(text: &str) -> Vec<Range<usize>> {
    static CHECKSUM_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?im)^\s*(?:b2|md5|sha(?:1|224|256|384|512))sums?(?:_[A-Za-z0-9_]+)?\s*\+?=\s*(?:\([^)]*\)|[^\n]*)",
        )
        .expect("checksum assignment regex must compile")
    });
    CHECKSUM_ASSIGNMENT
        .find_iter(text)
        .map(|matched| matched.range())
        .collect()
}

fn scan_builtin_text(file: &SourceFile, comment_ranges: &[Range<usize>]) -> Vec<Finding> {
    let rules = [
        (
            "PERSISTENCE_PATH",
            Severity::High,
            r"(?i)(?:/etc/systemd|\.config/systemd/user|/etc/ld\.so\.preload|\.bashrc|\.profile|crontab)",
            "Persistence-related path or command",
            "Packaging code modifying persistence locations requires careful review.",
        ),
        (
            "CREDENTIAL_PATH",
            Severity::High,
            r"(?i)(?:/|~|\$HOME)(?:\.ssh|/\.ssh|/\.npmrc|/\.git-credentials|/\.config/(?:discord|vault)|/\.docker)",
            "Credential-adjacent path",
            "Packaging code should not read user credentials or application secrets.",
        ),
        (
            "OBFUSCATION_PRIMITIVE",
            Severity::Medium,
            r"(?i)(?:base64\s+(?:-[^\s]*d|--decode)|xxd\s+-r|openssl\s+(?:enc|aes)|eval\s+[^#\n]*\\x[0-9a-f]{2})",
            "Obfuscation or decoding primitive",
            "Decoding and evaluating hidden data can conceal package behavior.",
        ),
        (
            "SUSPICIOUS_SOURCE_HOST",
            Severity::High,
            r"(?i)https?://(?:\d{1,3}(?:\.\d{1,3}){3}|(?:www\.)?(?:pastebin\.com|transfer\.sh|temp\.sh|0x0\.st|bit\.ly|tinyurl\.com))",
            "Suspicious source host",
            "Raw IPs, paste services, and shorteners obscure source provenance.",
        ),
    ];
    let mut findings = Vec::new();
    for (id, severity, pattern, description, rationale) in rules {
        let regex = Regex::new(pattern).expect("built-in regex must compile");
        for matched in regex.find_iter(&file.text) {
            if within(comment_ranges, matched.start()) {
                continue;
            }
            if id == "PERSISTENCE_PATH" && is_packaged_unit_path(&file.text, &matched) {
                continue;
            }
            findings.push(text_finding(
                file,
                matched.start(),
                id,
                severity,
                Confidence::Heuristic,
                description,
                rationale,
            ));
        }
    }

    if file.kind == FileKind::Pkgbuild {
        findings.extend(scan_pkgbuild_metadata(file));

        let skip = Regex::new(r#"(?m)^\s*(?:b2|md5|sha(?:1|224|256|384|512))sums(?:_[A-Za-z0-9_]+)?\s*=\s*\([^)]*['"]SKIP['"]"#)
            .expect("built-in regex must compile");
        let has_vcs = Regex::new(r"(?i)(?:git|hg|svn|bzr)\+").expect("built-in regex must compile");
        for matched in skip.find_iter(&file.text) {
            let severity = if has_vcs.is_match(&file.text) {
                Severity::Low
            } else {
                Severity::Medium
            };
            findings.push(text_finding(
                file,
                matched.start(),
                "SKIPPED_CHECKSUM",
                severity,
                Confidence::Heuristic,
                "Source integrity check is skipped",
                "SKIP removes source-content verification; it is expected mainly for VCS sources.",
            ));
        }
    }
    findings
}

/// Systemd unit paths under `$pkgdir` are package payload that pacman tracks
/// and reviewers see in the file list, not modification of the live system's
/// persistence locations. Other persistence paths (ld.so.preload, dotfiles,
/// crontab) stay suspicious even as payload.
fn is_packaged_unit_path(text: &str, matched: &regex::Match<'_>) -> bool {
    let lowered = matched.as_str().to_ascii_lowercase();
    if !lowered.starts_with("/etc/systemd") && !lowered.starts_with(".config/systemd") {
        return false;
    }
    let prefix = text[..matched.start()].trim_end_matches(['"', '\'', '/']);
    prefix.ends_with("$pkgdir") || prefix.ends_with("${pkgdir}")
}

fn scan_pkgbuild_metadata(file: &SourceFile) -> Vec<Finding> {
    let mut findings = Vec::new();
    let source = Regex::new(r"(?ims)^\s*source(?:_[A-Za-z0-9_]+)?\s*=\s*(?:\([^)]*\)|[^\n]*)")
        .expect("source regex must compile");
    let remote_url =
        Regex::new(r"(?i)(?:https?|git|hg|svn|bzr)\+?://").expect("remote URL regex must compile");
    let checksum =
        Regex::new(r"(?m)^\s*(?:b2|md5|sha(?:1|224|256|384|512))sums(?:_[A-Za-z0-9_]+)?\s*=")
            .expect("checksum declaration regex must compile");
    let upstream_url =
        Regex::new(r"(?m)^\s*url\s*=").expect("upstream URL declaration regex must compile");
    let dependency_array = Regex::new(
        r"(?ims)^\s*(?:depends|makedepends|checkdepends|optdepends)(?:_[A-Za-z0-9_]+)?\s*=\s*\([^)]*\)",
    )
    .expect("dependency array regex must compile");
    let bun_token = Regex::new(r#"(?i)(?:^|[\s'"])bun(?:[<>=:].*)?(?:[\s'"]|$)"#)
        .expect("Bun token regex must compile");

    let source_match = source.find(&file.text);
    if let Some(source_match) = source_match
        && !checksum.is_match(&file.text)
    {
        findings.push(text_finding(
            file,
            source_match.start(),
            "MISSING_CHECKSUMS",
            Severity::Medium,
            Confidence::Structural,
            "Sources are declared without a checksum array",
            "Remote source content should normally be authenticated with checksums or explicit SKIP entries for justified VCS sources.",
        ));
    }

    if let Some(source_match) = source_match
        && remote_url.is_match(source_match.as_str())
        && !upstream_url.is_match(&file.text)
    {
        findings.push(text_finding(
            file,
            source_match.start(),
            "MISSING_UPSTREAM_URL",
            Severity::Low,
            Confidence::Heuristic,
            "Remote sources are present but no upstream url is declared",
            "An upstream project URL gives reviewers an independent reference for validating source provenance.",
        ));
    }

    if source_match.is_none() && !upstream_url.is_match(&file.text) {
        findings.push(Finding {
            rule_id: "NO_SOURCE_REFERENCE".to_owned(),
            severity: Severity::Medium,
            confidence: Confidence::Heuristic,
            file: file.name.clone(),
            line: 1,
            column: 1,
            snippet: "no source= or url= declaration".to_owned(),
            description: "PKGBUILD has no source or upstream reference".to_owned(),
            rationale: "Without source or upstream metadata, reviewers cannot tie the package to an independently identifiable project."
                .to_owned(),
            phase: None,
            new_since_approval: false,
            accepted: false,
        });
    }

    if let Some(dependency) = dependency_array
        .find_iter(&file.text)
        .find(|dependency| bun_token.is_match(dependency.as_str()))
    {
        findings.push(text_finding(
            file,
            dependency.start(),
            "BUN_DEPENDENCY",
            Severity::Low,
            Confidence::Structural,
            "Bun is declared as a package dependency",
            "Bun can be legitimate, but its presence is relevant when reviewing JavaScript dependency installation and lifecycle scripts.",
        ));
    }

    let substantive_lines = file
        .text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .count();
    if substantive_lines <= 8 {
        findings.push(Finding {
            rule_id: "VERY_SHORT_PKGBUILD".to_owned(),
            severity: Severity::Low,
            confidence: Confidence::Heuristic,
            file: file.name.clone(),
            line: 1,
            column: 1,
            snippet: format!("{substantive_lines} substantive lines"),
            description: "PKGBUILD is unusually short".to_owned(),
            rationale: "Very short packaging metadata can be valid, but leaves little context for provenance and behavior review."
                .to_owned(),
            phase: None,
            new_since_approval: false,
            accepted: false,
        });
    }

    findings
}

pub fn scan_bash(file: &SourceFile, analysis: &BashAnalysis) -> Vec<Finding> {
    let mut findings = Vec::new();
    let shell_pipeline = Regex::new(
        r"(?is)(?:curl|wget)\b[^|]*(?:\|\s*(?:[A-Za-z0-9_./-]+\s+)*)(?:sh|bash|zsh|dash|eval)\b",
    )
    .expect("built-in regex must compile");
    let decoded_pipeline = Regex::new(
        r"(?is)(?:base64\s+(?:-[^\s|]*d|--decode)|xxd\s+-r|openssl\s+(?:enc|aes)|gzip\s+-d)\b[^|]*\|\s*(?:sh|bash|zsh|dash|eval)\b",
    )
    .expect("built-in regex must compile");

    for pipeline in &analysis.pipelines {
        if shell_pipeline.is_match(&pipeline.text) {
            findings.push(command_finding(
                file,
                pipeline,
                "PIPE_TO_SHELL",
                Severity::Critical,
                "Network content is piped to a shell",
                "Remote content executes without an inspectable, integrity-checked intermediate file.",
            ));
        }
        if decoded_pipeline.is_match(&pipeline.text) {
            findings.push(command_finding(
                file,
                pipeline,
                "DECODE_TO_SHELL",
                Severity::Critical,
                "Decoded content is piped to a shell",
                "Decoding immediately before execution is a strong concealment signal.",
            ));
        }
    }

    let package_managers =
        Regex::new(r"(?i)^(?:npm|bun|pnpm|yarn|pipx?|cargo|go)$").expect("regex must compile");
    let install_word = Regex::new(r"(?i)\b(?:install|add|get|ci|i)\b").expect("regex must compile");
    let npm_bun_install = Regex::new(
        r"(?i)(?:^|[\s;&|])(?:(?:command|sudo)\s+|env(?:\s+\w+=\S+)*\s+)?(?:npm|bun)\s+(?:install|add|ci|i)\b",
    )
    .expect("npm/Bun install regex must compile");
    let network_clients =
        Regex::new(r"(?i)^(?:curl|wget|aria2c|ftp|nc|ncat)$").expect("regex must compile");
    let network_eval = Regex::new(
        r#"(?is)^(?:eval|sh|bash|zsh|dash)\b.*(?:\$\(\s*(?:curl|wget)\b|<\(\s*(?:curl|wget)\b)"#,
    )
    .expect("regex must compile");

    for command in &analysis.commands {
        let name = command
            .command_name
            .as_deref()
            .unwrap_or_default()
            .rsplit('/')
            .next()
            .unwrap_or_default();
        let phase = command.phase.as_deref().unwrap_or_default();
        if network_eval.is_match(&command.text) {
            findings.push(command_finding(
                file,
                command,
                "NETWORK_SUBSTITUTION_EXEC",
                Severity::Critical,
                "Network output is executed through shell substitution",
                "Remote content executes directly through a command or process substitution.",
            ));
        }
        if (package_managers.is_match(name) && install_word.is_match(&command.text))
            || npm_bun_install.is_match(&command.text)
        {
            let severity = if file.kind == FileKind::Install
                || phase == "install-scriptlet"
                || phase == "alpm-hook"
            {
                Severity::Critical
            } else if phase == "package" || phase.starts_with("package_") || phase == "prepare" {
                Severity::High
            } else {
                Severity::Medium
            };
            findings.push(command_finding(
                file,
                command,
                "PACKAGE_MANAGER_INSTALL",
                severity,
                "Package manager installs dependencies during packaging",
                "Dependency installation can execute third-party lifecycle scripts and bypass declared Arch dependencies.",
            ));
        }
        if network_clients.is_match(name)
            && (file.kind == FileKind::Install
                || phase == "alpm-hook"
                || phase == "package"
                || phase.starts_with("package_"))
        {
            findings.push(command_finding(
                file,
                command,
                "NETWORK_IN_INSTALL_PHASE",
                Severity::High,
                "Network client runs in an install-sensitive phase",
                "Install scriptlets, pacman hooks, and package() should operate on already verified local inputs.",
            ));
        }
        if name == "setcap" || (name == "chattr" && command.text.contains("+i")) {
            findings.push(command_finding(
                file,
                command,
                "PRIVILEGE_OR_IMMUTABILITY",
                Severity::High,
                "Command changes capabilities or file immutability",
                "Capability and immutable-bit changes can create privileged or persistent artifacts.",
            ));
        }
    }

    for error in &analysis.parse_errors {
        findings.push(Finding {
            rule_id: "BASH_PARSE_ERROR".to_owned(),
            severity: Severity::Medium,
            confidence: Confidence::Structural,
            file: file.name.clone(),
            line: error.line,
            column: error.column,
            snippet: error.snippet.clone(),
            description: "Bash syntax could not be fully parsed".to_owned(),
            rationale:
                "Structural checks may be incomplete around malformed or unsupported syntax."
                    .to_owned(),
            phase: None,
            new_since_approval: false,
            accepted: false,
        });
    }
    findings
}

pub fn known_package_findings(
    package_names: &[String],
    rules: &RuleSet,
    file: &SourceFile,
) -> Vec<Finding> {
    let known: HashSet<_> = rules.known_packages.iter().collect();
    package_names
        .iter()
        .filter(|name| known.contains(name))
        .map(|name| Finding {
            rule_id: "KNOWN_RISK_PACKAGE".to_owned(),
            severity: Severity::Critical,
            confidence: Confidence::Exact,
            file: file.name.clone(),
            line: 1,
            column: 1,
            snippet: safe_snippet(name),
            description: "Package appears in the configured known-risk list".to_owned(),
            rationale: "Do not build until the package's history and current maintainer state are verified."
                .to_owned(),
            phase: None,
            new_since_approval: false,
            accepted: false,
        })
        .collect()
}

fn text_finding(
    file: &SourceFile,
    byte_offset: usize,
    id: &str,
    severity: Severity,
    confidence: Confidence,
    description: &str,
    rationale: &str,
) -> Finding {
    let prefix = &file.text[..byte_offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let line_start = prefix.rfind('\n').map_or(0, |index| index + 1);
    let column = file.text[line_start..byte_offset].chars().count() + 1;
    let snippet = file
        .text
        .lines()
        .nth(line - 1)
        .map(safe_snippet)
        .unwrap_or_default();
    Finding {
        rule_id: id.to_owned(),
        severity,
        confidence,
        file: file.name.clone(),
        line,
        column,
        snippet,
        description: description.to_owned(),
        rationale: rationale.to_owned(),
        phase: None,
        new_since_approval: false,
        accepted: false,
    }
}

fn command_finding(
    file: &SourceFile,
    command: &crate::bash::Command,
    id: &str,
    severity: Severity,
    description: &str,
    rationale: &str,
) -> Finding {
    Finding {
        rule_id: id.to_owned(),
        severity,
        confidence: Confidence::Structural,
        file: file.name.clone(),
        line: command.location.line,
        column: command.location.column,
        snippet: command.location.snippet.clone(),
        description: description.to_owned(),
        rationale: rationale.to_owned(),
        phase: command.phase.clone(),
        new_since_approval: false,
        accepted: false,
    }
}

#[cfg(test)]
mod bundled_data_tests {
    #[test]
    fn arch_package_snapshot_has_expected_count() {
        assert_eq!(super::bundled_package_count().unwrap(), 1_619);
    }
}
