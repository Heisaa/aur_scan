use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Result, bail};
use aur_scan::{
    baseline,
    model::Severity,
    output,
    scanner::{self, ScanOptions},
    update::{self, UpdateOptions},
};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[arg(long, global = true, env = "AUR_SCAN_CACHE_DIR")]
    cache_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan packaging metadata without executing it
    Scan {
        #[arg(default_value = ".")]
        package_dir: PathBuf,

        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,

        #[arg(long, env = "AUR_SCAN_RULES")]
        rules: Option<PathBuf>,

        /// Block MEDIUM and higher findings
        #[arg(long, env = "AUR_SCAN_STRICT")]
        strict: bool,

        /// Set the minimum blocking severity
        #[arg(long, value_enum)]
        fail_on: Option<Severity>,
    },

    /// Explicitly record the current packaging metadata as approved
    Approve {
        #[arg(default_value = ".")]
        package_dir: PathBuf,

        /// Approve even when HIGH or CRITICAL findings exist
        #[arg(long)]
        force: bool,

        #[arg(long, env = "AUR_SCAN_RULES")]
        rules: Option<PathBuf>,
    },

    /// Show changes from the approved packaging metadata
    Diff {
        #[arg(default_value = ".")]
        package_dir: PathBuf,
    },

    /// Download and verify a signed IOC rules file
    UpdateIocs {
        #[arg(long)]
        url: String,

        #[arg(long)]
        signature_url: String,

        /// Minisign public key text or base64 key
        #[arg(long, env = "AUR_SCAN_MINISIGN_KEY")]
        public_key: String,

        #[arg(long)]
        destination: Option<PathBuf>,

        /// Permit HTTP or file:// URLs for local development only
        #[arg(long)]
        allow_insecure_http: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("aur-scan: error: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    let cache_root = match cli.cache_dir {
        Some(path) => path,
        None => baseline::default_cache_root()?,
    };
    match cli.command {
        Command::Scan {
            package_dir,
            format,
            rules,
            strict,
            fail_on,
        } => {
            let rules = effective_rules_path(rules)?;
            let threshold = fail_on.unwrap_or(if strict {
                Severity::Medium
            } else {
                Severity::High
            });
            let report = scanner::scan(&ScanOptions {
                package_dir: &package_dir,
                cache_root: &cache_root,
                external_rules: rules.as_deref(),
            })?;
            match format {
                OutputFormat::Human => output::write_human(&report, output::stderr().lock())?,
                OutputFormat::Json => output::write_json(&report, std::io::stdout().lock())?,
            }
            Ok(if report.blocks(threshold) {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        Command::Approve {
            package_dir,
            force,
            rules,
        } => {
            let rules = effective_rules_path(rules)?;
            let report = scanner::scan(&ScanOptions {
                package_dir: &package_dir,
                cache_root: &cache_root,
                external_rules: rules.as_deref(),
            })?;
            if report.blocks(Severity::High) && !force {
                output::write_human(&report, output::stderr().lock())?;
                bail!("refusing to approve HIGH/CRITICAL findings without --force");
            }
            let package = scanner::load_package(&package_dir)?;
            let destination = baseline::approve(
                &cache_root,
                &package.package_base,
                &package.package_names,
                &package.files,
            )?;
            eprintln!(
                "aur-scan: approved {} at {}",
                package.package_base,
                destination.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Diff { package_dir } => {
            let package = scanner::load_package(&package_dir)?;
            match baseline::unified_diff(&cache_root, &package.package_base, &package.files)? {
                None => bail!(
                    "no approved baseline for {}; run `aur-scan approve {}`",
                    package.package_base,
                    display_path(&package_dir)
                ),
                Some(diff) if diff.is_empty() => {
                    println!("aur-scan: no changes from approved baseline");
                }
                Some(diff) => print!("{diff}"),
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::UpdateIocs {
            url,
            signature_url,
            public_key,
            destination,
            allow_insecure_http,
        } => {
            let destination = destination.map_or_else(update::default_ioc_path, Ok)?;
            update::update(&UpdateOptions {
                url: &url,
                signature_url: &signature_url,
                public_key: &public_key,
                destination: &destination,
                allow_insecure_http,
            })?;
            eprintln!(
                "aur-scan: installed verified IOCs at {}",
                destination.display()
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn display_path(path: &Path) -> String {
    path.to_str().unwrap_or(".").to_owned()
}

fn effective_rules_path(explicit: Option<PathBuf>) -> Result<Option<PathBuf>> {
    if explicit.is_some() {
        return Ok(explicit);
    }
    let default = update::default_ioc_path()?;
    Ok(default.exists().then_some(default))
}
