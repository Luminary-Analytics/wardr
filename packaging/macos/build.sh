#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "Usage: sh packaging/macos/build.sh PAYLOAD VERSION OUTPUT_DIR" >&2
    exit 2
fi

identity=${WARDR_MACOS_SIGNING_IDENTITY:--}
notary_profile=${WARDR_MACOS_NOTARY_PROFILE:-}
timestamp=--timestamp
if [ "$identity" = - ]; then
    timestamp=--timestamp=none
    if [ -n "$notary_profile" ]; then
        echo "Set WARDR_MACOS_SIGNING_IDENTITY to a Developer ID Application identity for notarization." >&2
        exit 2
    fi
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
image_name="wardr-$version-macos-$arch.dmg"
if [ -e "$output/$image_name" ]; then
    echo "Choose an output directory without $image_name." >&2
    exit 1
fi
stage=$(mktemp -d "$output/.wardr-macos.XXXXXXXXXX")
trap 'rm -rf "$stage"' EXIT
trap 'exit 1' HUP INT TERM
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
/usr/bin/python3 -I "$here/sign_payload.py" "$app/Contents/Resources/payload" \
    "$identity" "$here/Python.entitlements"
/usr/bin/codesign --force --sign "$identity" "$timestamp" --options runtime "$app"
/usr/bin/codesign --verify --deep --strict "$app"
if [ "$identity" != - ]; then
    developer_id='anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
    /usr/bin/codesign --verify --strict -R="$developer_id" "$app"
fi

ln -s /Applications "$volume/Applications"
image="$stage/$image_name"
/usr/bin/hdiutil create -quiet -volname Wardr -srcfolder "$volume" -format UDZO "$image"
/usr/bin/codesign --sign "$identity" "$timestamp" --identifier com.luminaryanalytics.wardr.disk-image "$image"
/usr/bin/codesign --verify --strict "$image"
if [ "$identity" != - ]; then
    /usr/bin/codesign --verify --strict -R="$developer_id" "$image"
fi

if [ -n "$notary_profile" ]; then
    result="$stage/notary.plist"
    /usr/bin/xcrun notarytool submit "$image" --keychain-profile "$notary_profile" \
        --no-wait --no-progress --output-format plist > "$result"
    submission=$(/usr/bin/plutil -extract id raw -o - "$result")
    echo "Submitted disk image for notarization as $submission."
    /usr/bin/xcrun notarytool wait "$submission" --keychain-profile "$notary_profile" \
        --timeout 30m --no-progress --output-format plist > "$result"
    status=$(/usr/bin/plutil -extract status raw -o - "$result")
    if [ "$status" != Accepted ]; then
        echo "Notarization returned $status for submission $submission." >&2
        /usr/bin/xcrun notarytool log "$submission" --keychain-profile "$notary_profile" >&2 || true
        exit 1
    fi
    /usr/bin/xcrun stapler staple "$image"
    /usr/bin/xcrun stapler validate "$image"
    /usr/sbin/spctl --assess --type open --context context:primary-signature "$image"
    echo "Apple accepted notarization submission $submission. Review its notary log before publishing."
elif [ "$identity" != - ]; then
    echo "Developer ID signing completed. Set WARDR_MACOS_NOTARY_PROFILE to notarize the disk image."
else
    echo "Built an ad-hoc signed test image."
fi

/usr/bin/codesign --verify --strict "$image"
/usr/bin/hdiutil verify -quiet "$image"
mv "$image" "$output/$image_name"
