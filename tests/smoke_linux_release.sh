#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'Wardr Linux release smoke failed. %s\n' "$*" >&2
    exit 1
}

[[ $# -eq 3 ]] || fail "Usage: bash tests/smoke_linux_release.sh {arm64|x64} BASELINE TARGET"
arch=$1
baseline=$2
target=$3
case "$arch" in
    arm64) machine=aarch64 ;;
    x64) machine=x86_64 ;;
    *) fail "Use arm64 or x64." ;;
esac
[[ $(uname -s) = Linux && $(uname -m) = "$machine" ]] || fail "Use a Linux $arch runner."
[[ $(id -u) -ne 0 ]] || fail "Run as a regular user without sudo."

tests_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
umask 077
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
trap 'exit 1' HUP INT TERM
assets=$scratch/assets

python -I "$tests_dir/fetch_live_release.py" --platform linux --arch "$arch" \
    --output "$assets" "$baseline" "$target"

isolate_installation() {
    local location=$scratch/$1
    export HOME="$location/home"
    export XDG_DATA_HOME="$location/data"
    export XDG_CONFIG_HOME="$location/config"
    export XDG_CACHE_HOME="$location/cache"
    export XDG_STATE_HOME="$location/state"
    export XDG_RUNTIME_DIR="$location/runtime"
    export TMPDIR="$location/tmp"
    mkdir -p -- "$HOME" "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" \
        "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR" "$TMPDIR"
}

assert_version() {
    local version=$1
    "$XDG_DATA_HOME/wardr/venv/bin/python" -I - "$version" <<'PY'
import sys
from wardr.updater import current_version, installation_problem

expected = sys.argv[1]
actual = current_version()
problem = installation_problem()
if actual != expected or problem is not None:
    raise SystemExit(f"Expected update-eligible Wardr {expected}, found {actual}. {problem or ''}")
print(f"Verified update-eligible Wardr {expected} in the installed environment.")
PY
}

install_wardr() {
    local version=$1
    sh "$assets/wardr-$version-linux-$arch.run"
    local launcher=$HOME/.local/bin/wardr
    [[ -L "$launcher" && -x "$launcher" && $(readlink -- "$launcher") = "$XDG_DATA_HOME/wardr/venv/bin/wardr" ]] \
        || fail "The native installer did not create the expected command shortcut."
    [[ -s "$XDG_DATA_HOME/applications/com.getwardr.Wardr.desktop" ]] \
        || fail "The native installer did not create the expected desktop entry."
    assert_version "$version"
}

isolate_installation "fresh target"
install_wardr "$target"
result=$("$HOME/.local/bin/wardr" --state-dir "$XDG_STATE_HOME/wardr" update --check)
[[ "$result" = "Your Wardr installation is up to date." ]] \
    || fail "Fresh Wardr $target did not report current after checking the signed live feed. $result"
printf 'Fresh Wardr %s launched and reported current against the signed live feed.\n' "$target"

isolate_installation "upgrade baseline"
install_wardr "$baseline"
installed_python=$XDG_DATA_HOME/wardr/venv/bin/python
"$installed_python" -I "$tests_dir/smoke_update.py" --installed-python "$installed_python" \
    --live-target "$target" "$assets/wardr-$baseline-py3-none-any.whl"
assert_version "$target"
printf 'Verified native Linux %s installation and live in-place update from Wardr %s to %s.\n' \
    "$arch" "$baseline" "$target"
