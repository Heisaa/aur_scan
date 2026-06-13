#!/usr/bin/env bash
set -euo pipefail

repo=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT

fake_binary=$root/aur-scan
cat >"$fake_binary" <<'EOF'
#!/bin/sh
test "$1" = "--version" && printf 'aur-scan test\n'
EOF
chmod 0755 "$fake_binary"

run_installer() {
    HOME=$root/home XDG_CONFIG_HOME=$root/config \
        "$repo/install.sh" --binary "$fake_binary" "$@"
}

mkdir -p "$root/home"
run_installer

installed=$root/home/.local/bin/aur-scan
config=$root/config/paru/paru.conf
test -x "$installed"
grep -Fq "[bin]" "$config"
grep -Fq "PreBuildCommand = '$installed' scan ." "$config"

before=$(sha256sum "$config")
run_installer
after=$(sha256sum "$config")
test "$before" = "$after"

cat >"$config" <<'EOF'
[options]
BottomUp

[bin]
Sudo = doas
PreBuildCommand = old-command

[custom]
Value = preserved
EOF
run_installer --strict

grep -Fq "BottomUp" "$config"
grep -Fq "Sudo = doas" "$config"
grep -Fq "Value = preserved" "$config"
grep -Fq "PreBuildCommand = '$installed' scan --strict ." "$config"
test "$(grep -c '^[[:space:]]*PreBuildCommand[[:space:]]*=' "$config")" -eq 1
test -f "$config.bak"

spaced=$root/home/dir\ with\ spaces
custom_config=$root/custom/paru.conf
run_installer --bin-dir "$spaced" --config "$custom_config"
grep -Fq "PreBuildCommand = '$spaced/aur-scan' scan ." "$custom_config"
"$spaced/aur-scan" --version >/dev/null

symlink_config=$root/symlink.conf
ln -s "$config" "$symlink_config"
if run_installer --config "$symlink_config" >/dev/null 2>&1; then
    echo "installer accepted a symlinked config" >&2
    exit 1
fi

backup_attack=$root/backup-attack/paru.conf
mkdir -p "$(dirname "$backup_attack")"
printf '[bin]\nPreBuildCommand = old\n' >"$backup_attack"
ln -s "$root/should-not-be-written" "$backup_attack.bak"
if run_installer --strict --config "$backup_attack" >/dev/null 2>&1; then
    echo "installer accepted a symlinked backup" >&2
    exit 1
fi
test ! -e "$root/should-not-be-written"

printf 'installer tests passed\n'
