# Wardr macOS disk images

Build on the Mac architecture you plan to distribute. Use Xcode command-line
tools, Rust (`cargo`), a staged Wardr payload, a **Developer ID Application**
identity with its private key available to `codesign`, and a Keychain profile
for your Apple notary team.
Check identities with `security find-identity -v -p codesigning`. Prepare the
profile interactively with `xcrun notarytool store-credentials wardr-notary`.
Keep the credentials in Keychain. [Apple Developer ID](https://developer.apple.com/developer-id/) ·
[Apple notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)

```sh
WARDR_MACOS_SIGNING_IDENTITY='Developer ID Application: Your Team (TEAMID)' \
WARDR_MACOS_NOTARY_PROFILE=wardr-notary \
  sh packaging/macos/build.sh /path/to/payload 0.2.1 /path/to/release-output
```

Use a fresh output directory for the release. The builder signs and verifies
Mach-O files in the standalone Python runtime and dependency wheels before
signing the app bundle and disk image. It updates the dependency wheels’
RECORD hashes and preserves the published Wardr wheel byte-for-byte.
Developer ID signing uses secure timestamps. The interpreter has the
Disable Library Validation entitlement to load PyCA and CFFI modules from
the installed virtual environment. The app launcher uses Hardened Runtime
with its default library validation. [Apple code signing](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac) ·
[Library validation entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.disable-library-validation)

With the profile set, the builder waits for Apple to accept the submission,
staples and validates the ticket, and runs Gatekeeper’s disk image assessment
before moving the DMG into the output directory. Review the notary log using
the submission ID and test the downloaded image with Finder on a separate
Mac before publishing. Compute final download checksums after stapling.
[Apple distribution guide](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution)

For local tests and CI, leave both variables unset to build an ad-hoc signed
image. Setting only `WARDR_MACOS_SIGNING_IDENTITY` produces a Developer ID
signed image for local validation. Use both variables for notarized downloads.

```sh
dmg=/path/to/release-output/wardr-0.2.1-macos-arm64.dmg
team=YOURTEAMID
requirement="anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"$team\""
codesign --verify --strict -R="$requirement" "$dmg"
xcrun stapler validate "$dmg"
spctl --assess --type open --context context:primary-signature -vv "$dmg"
hdiutil verify -quiet "$dmg"
```

Use the expected Team ID from your Apple Developer account for this check.
[Apple code-signing requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements/)
