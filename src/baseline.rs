use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use similar::{ChangeTag, TextDiff};
use tempfile::TempDir;

use crate::input::SourceFile;

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    schema_version: u32,
    approved_at_unix: u64,
    package_base: String,
    package_names: Vec<String>,
    files: Vec<FileRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileRecord {
    name: String,
    sha256: String,
}

#[derive(Debug, Default)]
pub struct BaselineComparison {
    pub present: bool,
    pub changed_lines: HashMap<PathBuf, HashSet<usize>>,
}

pub fn default_cache_root() -> Result<PathBuf> {
    dirs::cache_dir()
        .map(|path| path.join("aur-scan").join("baselines"))
        .context("cannot determine user cache directory; pass --cache-dir")
}

pub fn approve(
    cache_root: &Path,
    package_base: &str,
    package_names: &[String],
    files: &[SourceFile],
) -> Result<PathBuf> {
    fs::create_dir_all(cache_root)
        .with_context(|| format!("cannot create cache directory {}", cache_root.display()))?;
    let destination = baseline_dir(cache_root, package_base);
    let parent = destination
        .parent()
        .context("baseline destination has no parent")?;
    let staging = TempDir::new_in(parent).context("cannot create baseline staging directory")?;
    let files_dir = staging.path().join("files");
    fs::create_dir(&files_dir).context("cannot create baseline files directory")?;

    let mut records = Vec::new();
    for file in files {
        let name = file
            .name
            .to_str()
            .context("cannot approve a non-UTF-8 filename")?;
        fs::write(files_dir.join(name), &file.text)
            .with_context(|| format!("cannot write baseline file {name}"))?;
        records.push(FileRecord {
            name: name.to_owned(),
            sha256: sha256(file.text.as_bytes()),
        });
    }
    let manifest = Manifest {
        schema_version: 1,
        approved_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_secs(),
        package_base: package_base.to_owned(),
        package_names: package_names.to_vec(),
        files: records,
    };
    fs::write(
        staging.path().join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).context("cannot serialize baseline manifest")?,
    )
    .context("cannot write baseline manifest")?;

    if destination.exists() {
        let backup = parent.join(format!(".{}.old", baseline_key(package_base)));
        if backup.exists() {
            fs::remove_dir_all(&backup).context("cannot remove stale baseline backup")?;
        }
        fs::rename(&destination, &backup).context("cannot stage previous baseline")?;
        match fs::rename(staging.path(), &destination) {
            Ok(()) => {
                fs::remove_dir_all(backup).context("cannot remove previous baseline")?;
            }
            Err(error) => {
                let _ = fs::rename(&backup, &destination);
                return Err(error).context("cannot install approved baseline");
            }
        }
    } else {
        fs::rename(staging.path(), &destination).context("cannot install approved baseline")?;
    }
    Ok(destination)
}

pub fn compare(
    cache_root: &Path,
    package_base: &str,
    files: &[SourceFile],
) -> Result<BaselineComparison> {
    let directory = baseline_dir(cache_root, package_base);
    if !directory.exists() {
        return Ok(BaselineComparison::default());
    }
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(directory.join("manifest.json")).context("cannot read baseline manifest")?,
    )
    .context("cannot parse baseline manifest")?;
    if manifest.schema_version != 1 || manifest.package_base != package_base {
        bail!("baseline manifest does not match package {package_base}");
    }

    let mut changed_lines = HashMap::new();
    for file in files {
        let previous_path = directory.join("files").join(&file.name);
        let previous = match fs::read_to_string(&previous_path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                changed_lines.insert(
                    file.name.clone(),
                    (1..=file.text.lines().count().max(1)).collect(),
                );
                continue;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("cannot read {}", previous_path.display()));
            }
        };
        let additions = added_line_numbers(&previous, &file.text);
        if !additions.is_empty() {
            changed_lines.insert(file.name.clone(), additions);
        }
    }
    Ok(BaselineComparison {
        present: true,
        changed_lines,
    })
}

pub fn unified_diff(
    cache_root: &Path,
    package_base: &str,
    files: &[SourceFile],
) -> Result<Option<String>> {
    let directory = baseline_dir(cache_root, package_base);
    if !directory.exists() {
        return Ok(None);
    }
    let mut output = String::new();
    for file in files {
        let previous_path = directory.join("files").join(&file.name);
        let previous = fs::read_to_string(&previous_path).unwrap_or_default();
        if previous == file.text {
            continue;
        }
        let old_name = format!("approved/{}", file.name.display());
        let new_name = format!("current/{}", file.name.display());
        output.push_str(
            &TextDiff::from_lines(&previous, &file.text)
                .unified_diff()
                .context_radius(3)
                .header(&old_name, &new_name)
                .to_string(),
        );
    }
    Ok(Some(output))
}

fn added_line_numbers(old: &str, new: &str) -> HashSet<usize> {
    let diff = TextDiff::from_lines(old, new);
    let mut line = 1_usize;
    let mut additions = HashSet::new();
    for change in diff.iter_all_changes() {
        match change.tag() {
            ChangeTag::Equal => line += 1,
            ChangeTag::Delete => {}
            ChangeTag::Insert => {
                additions.insert(line);
                line += 1;
            }
        }
    }
    additions
}

fn baseline_dir(cache_root: &Path, package_base: &str) -> PathBuf {
    cache_root.join(baseline_key(package_base))
}

fn baseline_key(package_base: &str) -> String {
    let safe: String = package_base
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .take(80)
        .collect();
    let digest = sha256(package_base.as_bytes());
    format!("{safe}-{}", &digest[..12])
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::added_line_numbers;

    #[test]
    fn tracks_inserted_new_lines() {
        let additions = added_line_numbers("one\ntwo\n", "one\nnew\ntwo\n");
        assert!(additions.contains(&2));
        assert_eq!(additions.len(), 1);
    }
}
