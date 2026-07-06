use std::{cmp::Ordering, fmt, path::PathBuf, str::FromStr};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", format!("{self:?}").to_uppercase())
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" | "med" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" | "crit" => Ok(Self::Critical),
            _ => Err(format!("unknown severity: {value}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Confidence {
    Heuristic,
    Structural,
    Exact,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", format!("{self:?}").to_uppercase())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub description: String,
    pub rationale: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    pub new_since_approval: bool,
    #[serde(default)]
    pub accepted: bool,
}

impl Finding {
    pub fn sort_cmp(&self, other: &Self) -> Ordering {
        other
            .severity
            .cmp(&self.severity)
            .then_with(|| self.file.cmp(&other.file))
            .then_with(|| self.line.cmp(&other.line))
            .then_with(|| self.column.cmp(&other.column))
            .then_with(|| self.rule_id.cmp(&other.rule_id))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub package_dir: PathBuf,
    pub package_base: Option<String>,
    pub package_names: Vec<String>,
    pub files_scanned: usize,
    pub baseline_present: bool,
    #[serde(default)]
    pub checks_passed: Vec<String>,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    pub fn worst_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|finding| finding.severity).max()
    }

    pub fn blocks(&self, threshold: Severity) -> bool {
        self.findings
            .iter()
            .any(|finding| !finding.accepted && finding.severity >= threshold)
    }
}

#[derive(Debug, Clone)]
pub struct Location {
    pub line: usize,
    pub column: usize,
    pub snippet: String,
}

pub fn safe_snippet(value: &str) -> String {
    const MAX_CHARS: usize = 240;
    let mut output = String::new();
    for ch in value.trim().chars().take(MAX_CHARS) {
        if ch == '\t' {
            output.push(' ');
        } else if !ch.is_control() {
            output.push(ch);
        }
    }
    if value.trim().chars().count() > MAX_CHARS {
        output.push_str("...");
    }
    output
}
