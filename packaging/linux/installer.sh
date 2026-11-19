#!/bin/sh
set -eu

usage() {
    printf '%s\n' "Install Wardr Community for the current Linux user." \
        "Usage: sh $0 [--no-desktop]" \
        "Use --no-desktop to skip the desktop menu entry."
}

fail() {
    printf 'Wardr installation failed. %s\n' "$1" >&2
    exit 1
}

case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    --no-desktop) desktop=--no-desktop; shift ;;
    *) desktop= ;;
esac
[ "$#" -eq 0 ] || fail "Use --help to see the available options."
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = @ARCH@ ] || fail "Download the installer for your Linux architecture."
[ "$(id -u)" -ne 0 ] || fail "Run this installer as your regular user without sudo."
case "${HOME:-}" in
    /*) ;;
    *) fail "Set HOME to your absolute home directory." ;;
esac
case "${XDG_DATA_HOME:-}" in
    /*) data_home=$XDG_DATA_HOME ;;
    *) data_home=$HOME/.local/share ;;
esac

umask 077
mkdir -p -- "$data_home"
work=$(mktemp -d "$data_home/.wardr-installer.XXXXXXXXXX")
trap 'rm -rf -- "$work"' 0
trap 'exit 1' HUP INT TERM

tail -n +@ARCHIVE_LINE@ < "$0" > "$work/payload.tar.gz"
printf '%s  payload.tar.gz\n' '@SHA256@' | (cd "$work" && sha256sum -c >/dev/null) \
    || fail "The archive checksum did not match. Download the installer again."
tar -xzf "$work/payload.tar.gz" -C "$work"

install_root=$data_home/wardr
"$work/python/bin/python3" -I "$work/install.py" --install-dir "$install_root"
"$install_root/venv/bin/python" -I "$work/desktop.py" ${desktop:+"$desktop"}
exit 0
