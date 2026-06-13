use std::io::{self, Write};

use anyhow::{Context, Result};

use crate::model::ScanReport;

pub fn write_human(report: &ScanReport, mut writer: impl Write) -> Result<()> {
    writeln!(writer).context("cannot write report spacing")?;
    writeln!(
        writer,
        "aur-scan: {}",
        report.package_base.as_deref().unwrap_or("unknown")
    )
    .context("cannot write report")?;

    if report.findings.is_empty() {
        writeln!(
            writer,
            "Result: CLEAN ({} {})",
            report.files_scanned,
            plural(report.files_scanned, "file", "files")
        )
        .context("cannot write report")?;
        writeln!(writer).context("cannot write report spacing")?;
        write_passed_checks(report, &mut writer)?;
        writeln!(writer).context("cannot write report spacing")?;
        return Ok(());
    }

    let worst = report
        .worst_severity()
        .map_or_else(|| "NONE".to_owned(), |severity| severity.to_string());
    writeln!(
        writer,
        "Result: {worst} ({} {}){}",
        report.findings.len(),
        plural(report.findings.len(), "finding", "findings"),
        if report.baseline_present {
            " - approved baseline available"
        } else {
            ""
        }
    )
    .context("cannot write report")?;
    writeln!(writer).context("cannot write report spacing")?;

    for (index, finding) in report.findings.iter().enumerate() {
        let changed = if finding.new_since_approval {
            " [NEW]"
        } else {
            ""
        };
        writeln!(
            writer,
            "{}. {} {}{}",
            index + 1,
            finding.severity,
            finding.rule_id,
            changed
        )
        .context("cannot write report")?;
        writeln!(
            writer,
            "   Location: {}:{}:{}",
            finding.file.display(),
            finding.line,
            finding.column
        )
        .context("cannot write report")?;
        writeln!(writer, "   Confidence: {}", finding.confidence).context("cannot write report")?;
        if let Some(phase) = &finding.phase {
            writeln!(writer, "   Context: {phase}").context("cannot write report")?;
        }
        writeln!(writer, "   {}", finding.description).context("cannot write report")?;
        if !finding.snippet.is_empty() {
            writeln!(writer, "   > {}", finding.snippet).context("cannot write report")?;
        }
        if finding.severity >= crate::model::Severity::High {
            writeln!(writer, "   Why: {}", finding.rationale).context("cannot write report")?;
        }
        writeln!(writer).context("cannot write report spacing")?;
    }
    write_passed_checks(report, &mut writer)?;
    writeln!(writer).context("cannot write report spacing")?;
    Ok(())
}

fn write_passed_checks(report: &ScanReport, writer: &mut impl Write) -> Result<()> {
    if !report.checks_passed.is_empty() {
        let concise = report.checks_passed.iter().take(4).map(String::as_str);
        writeln!(writer, "Checks passed:").context("cannot write passed checks")?;
        for check in concise {
            writeln!(writer, "  - {check}").context("cannot write passed checks")?;
        }
    }
    Ok(())
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

pub fn write_json(report: &ScanReport, mut writer: impl Write) -> Result<()> {
    serde_json::to_writer_pretty(&mut writer, report).context("cannot serialize JSON report")?;
    writeln!(writer).context("cannot write JSON report")?;
    Ok(())
}

pub fn stderr() -> io::Stderr {
    io::stderr()
}
