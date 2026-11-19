#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "Usage: sh packaging/macos/build.sh PAYLOAD VERSION OUTPUT_DIR" >&2
    exit 2
fi

payload=$(cd "$1" && pwd)
version=$2
mkdir -p "$3"
output=$(cd "$3" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
case "$(uname -m)" in
    arm64) arch=arm64 ;;
    x86_64) arch=x64 ;;
    *) echo "Unsupported macOS architecture." >&2; exit 1 ;;
esac
test -f "$payload/wheelhouse/wardr-$version-py3-none-any.whl"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
volume="$stage/volume"
app="$volume/Wardr.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
/usr/bin/ditto "$payload" "$app/Contents/Resources/payload"
/usr/bin/swiftc -O -swift-version 5 -target "$(uname -m)-apple-macos13.0" \
    "$here/Launcher.swift" -o "$app/Contents/MacOS/Wardr"
/usr/bin/plutil -create xml1 "$app/Contents/Info.plist"
plist="$app/Contents/Info.plist"
/usr/bin/plutil -insert CFBundleIdentifier -string com.luminaryanalytics.wardr "$plist"
/usr/bin/plutil -insert CFBundleExecutable -string Wardr "$plist"
/usr/bin/plutil -insert CFBundleName -string Wardr "$plist"
/usr/bin/plutil -insert CFBundleDisplayName -string Wardr "$plist"
/usr/bin/plutil -insert CFBundlePackageType -string APPL "$plist"
/usr/bin/plutil -insert CFBundleShortVersionString -string "$version" "$plist"
/usr/bin/plutil -insert CFBundleVersion -string "$version" "$plist"
/usr/bin/plutil -insert LSMinimumSystemVersion -string 13.0 "$plist"
marks="$stage/Wardr.iconset"
mkdir -p "$marks"
mark="$here/../../wardr/static/wardr-mark.png"
for size in 16 32 128 256 512; do
    /usr/bin/sips -z "$size" "$size" "$mark" --out "$marks/icon_${size}x${size}.png" >/dev/null
    doubled=$((size * 2))
    /usr/bin/sips -z "$doubled" "$doubled" "$mark" --out "$marks/icon_${size}x${size}@2x.png" >/dev/null
done
/usr/bin/iconutil -c icns "$marks" -o "$app/Contents/Resources/Wardr.icns"
/usr/bin/plutil -insert CFBundleIconFile -string Wardr "$plist"
ln -s /Applications "$volume/Applications"
/usr/bin/codesign --force --sign - "$app"
/usr/bin/hdiutil create -quiet -volname Wardr -srcfolder "$volume" -format UDZO \
    "$output/wardr-$version-macos-$arch.dmg"
