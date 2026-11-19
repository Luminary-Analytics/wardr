#!/bin/bash
set -euo pipefail

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

if [[ $# != 3 ]]; then
    fail "Usage: bash tests/smoke_macos_release.sh {arm64|x64} BASELINE TARGET"
fi
arch=$1
baseline=$2
target=$3
case "$arch" in
    arm64) machine=arm64 ;;
    x64) machine=x86_64 ;;
    *) fail "Use arm64 or x64 for the macOS architecture." ;;
esac
version_pattern='^(0|[1-9][0-9]{0,8})(\.(0|[1-9][0-9]{0,8})){2}$'
[[ "$baseline" =~ $version_pattern && "$target" =~ $version_pattern && "$baseline" != "$target" ]] ||
    fail "Use two distinct stable Wardr release versions."
[[ "$(uname -s)" == Darwin && "$(uname -m)" == "$machine" ]] ||
    fail "This smoke test requires native macOS $machine."
[[ "$(/usr/sbin/sysctl -in sysctl.proc_translated)" != 1 ]] ||
    fail "Run the smoke test in a native shell outside Rosetta."
/usr/sbin/spctl --status 2>&1 | grep -qx 'assessments enabled' ||
    fail "Gatekeeper assessments must be enabled for the macOS verification."

repo=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
scratch_base=${TMPDIR:-/tmp}
umask 077
work=$(mktemp -d "${scratch_base%/}/wardr-macos-release.XXXXXXXX")
mount_point="$work/volume"
assets="$work/assets"
mounted=false

cleanup() {
    local status=$?
    trap - EXIT
    if [[ "$mounted" == true ]]; then
        if ! /usr/bin/hdiutil detach -quiet "$mount_point" &&
           ! /usr/bin/hdiutil detach -quiet -force "$mount_point"; then
            printf 'Could not detach the disposable Wardr image mounted at %s.\n' "$mount_point" >&2
            exit 1
        fi
    fi
    rm -rf -- "$work"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$mount_point" "$assets"

team=9M6C299C9U
requirement='anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "'"$team"'"'

verify_signature() {
    local artifact=$1 signature
    signature=$(/usr/bin/codesign --display --verbose=4 "$artifact" 2>&1)
    printf '%s\n' "$signature" | grep -Fx "TeamIdentifier=$team" >/dev/null ||
        fail "Unexpected Developer ID team on $artifact."
    printf '%s\n' "$signature" | grep -E '^Timestamp=' >/dev/null ||
        fail "Missing secure code signing timestamp on $artifact."
    if [[ "$artifact" == *.app ]]; then
        printf '%s\n' "$signature" | grep -E '^CodeDirectory .*flags=0x[0-9a-f]+\([^)]*runtime' >/dev/null ||
            fail "Missing hardened runtime on $artifact."
    fi
    /usr/bin/xcrun stapler validate "$artifact"
}

require_notarized() {
    local assessment
    if ! assessment=$(/usr/sbin/spctl --assess -vv "$@" 2>&1); then
        fail "$assessment"
    fi
    printf '%s\n' "$assessment" | grep -qx 'source=Notarized Developer ID' ||
        fail "Gatekeeper did not attribute the artifact to Notarized Developer ID. $assessment"
}

prepare_installation() {
    local version=$1 runtime=$2 image app payload launcher bundled_wheel
    image="$assets/wardr-$version-macos-$arch.dmg"
    /usr/bin/codesign --verify --strict -R="$requirement" "$image"
    verify_signature "$image"
    /usr/bin/hdiutil verify -quiet "$image"
    require_notarized --type open --context context:primary-signature "$image"
    /usr/bin/hdiutil attach "$image" -quiet -readonly -nobrowse -mountpoint "$mount_point"
    mounted=true

    app="$mount_point/Wardr.app"
    /usr/bin/codesign --verify --deep --strict -R="$requirement" "$app"
    verify_signature "$app"
    require_notarized --type execute "$app"
    launcher="$app/Contents/MacOS/Wardr"
    payload="$app/Contents/Resources/payload"
    [[ "$(/usr/bin/lipo -archs "$launcher")" == "$machine" ]] ||
        fail "Wardr $version launcher is not native $machine."
    [[ "$(/usr/bin/lipo -archs "$payload/python/bin/python3")" == "$machine" ]] ||
        fail "Wardr $version bundled Python is not native $machine."

    bundled_wheel="$payload/wheelhouse/wardr-$version-py3-none-any.whl"
    if [[ "$version" == "$baseline" ]]; then
        cmp -s "$bundled_wheel" "$baseline_wheel" ||
            fail "The baseline installer does not contain the published signed Wardr wheel."
    fi
    "$launcher" --prepare-only "$runtime"
    /usr/bin/hdiutil detach -quiet "$mount_point"
    mounted=false
    printf 'Verified Wardr %s %s disk image and app with Apple team %s, stapling and Gatekeeper.\n' \
        "$version" "$arch" "$team"
    shasum -a 256 "$image"
}

check_fresh_dashboard() {
    local interpreter=$1
    "$interpreter" -I - "$repo/tests/smoke_update.py" "$work" "$target" <<'PY'
from pathlib import Path
import runpy
import subprocess
import sys

helper, root, expected = sys.argv[1:]
root = Path(root)
smoke = runpy.run_path(helper)
smoke["require_live_installation"](Path(sys.executable), expected)
log = root / "target-dashboard.log"
state = root / "fresh target state"
with log.open("wb") as output:
    dashboard = subprocess.Popen(
        [sys.executable, "-I", "-m", "wardr", "--state-dir", str(state), "serve", "--port", "0", "--no-browser"],
        stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
    )
    try:
        port, token = smoke["launch_link"](log, 1, dashboard)
        code, page = smoke["request"](port, token, "/")
        if code != 200 or b'id="updates-button"' not in page:
            raise RuntimeError("The installed Wardr dashboard did not expose its Updates control.")
        code, _ = smoke["request"](port, token, "/api/update/check", {})
        if code != 202:
            raise RuntimeError("The installed Wardr dashboard did not accept the update check.")
        status = smoke["await_update_state"](port, token, "current")
        if status["current_version"] != expected:
            raise RuntimeError("The fresh dashboard did not report the expected installed version.")
    finally:
        smoke["stop_dashboard"](dashboard, root)
print(f"Fresh Wardr {expected} served its dashboard and its signed production update check reported current.")
PY
}

python -I "$repo/tests/fetch_live_release.py" --platform macos --arch "$arch" --output "$assets" "$baseline" "$target"
baseline_wheel="$assets/wardr-$baseline-py3-none-any.whl"
target_runtime="$work/fresh target runtime"
baseline_runtime="$work/upgrade baseline runtime"

prepare_installation "$target" "$target_runtime"
check_fresh_dashboard "$target_runtime/venv/bin/python3"
prepare_installation "$baseline" "$baseline_runtime"
interpreter="$baseline_runtime/venv/bin/python3"
"$interpreter" -I "$repo/tests/smoke_update.py" --installed-python "$interpreter" --live-target "$target" "$baseline_wheel"
printf 'Verified native macOS %s install and live in-place update from Wardr %s to %s.\n' "$arch" "$baseline" "$target"
