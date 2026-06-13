#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ./install.sh [options]

Build aur-scan, install it for the current user, and configure paru.

Options:
  --strict              Make paru block MEDIUM findings as well
  --bin-dir DIR         Install directory (default: $HOME/.local/bin)
  --config FILE         Paru config (default: $XDG_CONFIG_HOME/paru/paru.conf)
  --binary FILE         Install an already-built binary instead of running Cargo
  -h, --help            Show this help
EOF
}

die() {
    printf 'aur-scan installer: error: %s\n' "$*" >&2
    exit 1
}

strict=0
bin_dir=${HOME:+$HOME/.local/bin}
config_home=${XDG_CONFIG_HOME:-${HOME:+$HOME/.config}}
config_file=${config_home:+$config_home/paru/paru.conf}
source_binary=

while (($#)); do
    case $1 in
        --strict)
            strict=1
            shift
            ;;
        --bin-dir)
            (($# >= 2)) || die "--bin-dir requires a directory"
            bin_dir=$2
            shift 2
            ;;
        --config)
            (($# >= 2)) || die "--config requires a file"
            config_file=$2
            shift 2
            ;;
        --binary)
            (($# >= 2)) || die "--binary requires a file"
            source_binary=$2
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

[[ -n ${HOME:-} ]] || die "HOME is not set"
[[ -n $bin_dir ]] || die "install directory is empty"
[[ -n $config_file ]] || die "paru config path is empty"
[[ $bin_dir != *$'\n'* && $bin_dir != *$'\r'* ]] || die "install directory contains a newline"
[[ $config_file != *$'\n'* && $config_file != *$'\r'* ]] || die "config path contains a newline"

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
destination=$bin_dir/aur-scan

if [[ -z $source_binary ]]; then
    command -v cargo >/dev/null 2>&1 || die "Cargo is required to build aur-scan"
    printf 'Building aur-scan in release mode...\n'
    cargo build --release --locked --manifest-path "$script_dir/Cargo.toml"
    source_binary=$script_dir/target/release/aur-scan
fi

[[ -f $source_binary && -x $source_binary ]] ||
    die "binary does not exist or is not executable: $source_binary"

install -d -m 0755 -- "$bin_dir"
install -m 0755 -- "$source_binary" "$destination"

shell_quote() {
    local value=$1
    printf "'%s'" "${value//\'/\'\\\'\'}"
}

command_value="$(shell_quote "$destination") scan"
if ((strict)); then
    command_value+=" --strict"
fi
command_value+=" ."
config_line="PreBuildCommand = $command_value"

config_dir=$(dirname -- "$config_file")
install -d -m 0700 -- "$config_dir"
temporary=$(mktemp -- "$config_dir/.paru.conf.XXXXXX")
trap 'rm -f -- "$temporary" "$temporary.new"' EXIT

if [[ -L $config_file || (-e $config_file && ! -f $config_file) ]]; then
    die "refusing to replace non-regular config: $config_file"
fi

if [[ -f $config_file ]]; then
    [[ -r $config_file && -w $config_file ]] || die "paru config is not readable and writable: $config_file"
    cp -p -- "$config_file" "$temporary"
else
    : >"$temporary"
    chmod 0600 "$temporary"
fi

awk -v configured_line="$config_line" '
    function is_section(line) {
        return line ~ /^[[:space:]]*\[[^]]+\][[:space:]]*(#.*)?$/
    }
    function is_bin_section(line) {
        return line ~ /^[[:space:]]*\[bin\][[:space:]]*(#.*)?$/
    }
    function emit_command() {
        if (!command_written) {
            print configured_line
            command_written = 1
        }
    }
    BEGIN {
        in_bin = 0
        saw_bin = 0
        command_written = 0
    }
    {
        if (is_section($0)) {
            if (in_bin) {
                emit_command()
            }
            in_bin = is_bin_section($0)
            if (in_bin) {
                saw_bin = 1
            }
            print
            next
        }
        if (in_bin && $0 ~ /^[[:space:]]*PreBuildCommand[[:space:]]*=/) {
            if (!command_written) {
                print configured_line
                command_written = 1
            } else {
                print "# aur-scan installer disabled duplicate: " $0
            }
            next
        }
        print
    }
    END {
        if (in_bin) {
            emit_command()
        } else if (!saw_bin) {
            if (NR > 0) {
                print ""
            }
            print "[bin]"
            emit_command()
        }
    }
' "$temporary" >"$temporary.new"
mv -- "$temporary.new" "$temporary"
chmod 0600 "$temporary"

if [[ -f $config_file ]] && cmp -s -- "$temporary" "$config_file"; then
    rm -f -- "$temporary"
else
    if [[ -f $config_file ]]; then
        backup=$config_file.bak
        if [[ -L $backup || (-e $backup && ! -f $backup) ]]; then
            die "refusing to replace non-regular backup: $backup"
        fi
        cp -p -- "$config_file" "$backup"
        printf 'Backed up existing paru config to %s\n' "$backup"
    fi
    mv -- "$temporary" "$config_file"
fi
trap - EXIT

"$destination" --version >/dev/null

printf 'Installed aur-scan to %s\n' "$destination"
printf 'Configured paru in %s\n' "$config_file"
printf 'Paru will run: %s\n' "$command_value"
