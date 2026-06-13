use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_FILES: usize = 128;
pub const MAX_LINE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct SourceFile {
    pub name: PathBuf,
    pub text: String,
    pub kind: FileKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Pkgbuild,
    Srcinfo,
    Install,
    Hook,
}

impl FileKind {
    pub fn is_script(self) -> bool {
        matches!(self, Self::Pkgbuild | Self::Install)
    }
}

pub fn discover(package_dir: &Path) -> Result<Vec<SourceFile>> {
    let metadata = fs::symlink_metadata(package_dir)
        .with_context(|| format!("cannot inspect {}", package_dir.display()))?;
    if !metadata.is_dir() {
        bail!("package path is not a directory: {}", package_dir.display());
    }

    let mut candidates = Vec::new();
    for entry in fs::read_dir(package_dir)
        .with_context(|| format!("cannot read package directory {}", package_dir.display()))?
    {
        let entry = entry.context("cannot read package directory entry")?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let kind = match name_str {
            "PKGBUILD" => Some(FileKind::Pkgbuild),
            ".SRCINFO" => Some(FileKind::Srcinfo),
            value if value.ends_with(".install") => Some(FileKind::Install),
            value if value.ends_with(".hook") => Some(FileKind::Hook),
            _ => None,
        };
        if let Some(kind) = kind {
            candidates.push((name, entry.path(), kind));
        }
    }
    candidates.sort_by(|a, b| a.0.cmp(&b.0));

    if candidates.len() > MAX_FILES {
        bail!(
            "too many scannable files: {} exceeds limit {MAX_FILES}",
            candidates.len()
        );
    }
    if !candidates
        .iter()
        .any(|(_, _, kind)| *kind == FileKind::Pkgbuild)
    {
        bail!("PKGBUILD is missing from {}", package_dir.display());
    }

    let mut total = 0_u64;
    let mut files = Vec::with_capacity(candidates.len());
    for (name, path, kind) in candidates {
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("cannot inspect {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("refusing to scan symlink: {}", path.display());
        }
        if !metadata.is_file() {
            bail!("scannable path is not a regular file: {}", path.display());
        }
        if metadata.len() > MAX_FILE_BYTES {
            bail!(
                "{} is too large: {} bytes exceeds limit {MAX_FILE_BYTES}",
                path.display(),
                metadata.len()
            );
        }
        total = total
            .checked_add(metadata.len())
            .context("input byte count overflow")?;
        if total > MAX_TOTAL_BYTES {
            bail!("scannable files exceed total byte limit {MAX_TOTAL_BYTES}");
        }

        let bytes = fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
        let text = String::from_utf8(bytes)
            .with_context(|| format!("{} is not valid UTF-8", path.display()))?;
        if let Some((index, _)) = text
            .split('\n')
            .enumerate()
            .find(|(_, line)| line.len() > MAX_LINE_BYTES)
        {
            bail!(
                "{}:{} exceeds line length limit {MAX_LINE_BYTES}",
                path.display(),
                index + 1
            );
        }
        files.push(SourceFile {
            name: PathBuf::from(name),
            text,
            kind,
        });
    }
    Ok(files)
}
