# Native Wardr installers

Each installer contains the signed Wardr Community release and a private
Python runtime and dependency wheelhouse. It can install without a network
connection, a system Python installation, or administrator access. Launch
Wardr from the Start menu on Windows, Applications on macOS, or the
applications menu on Linux. Wardr opens its local dashboard in your browser.

| Platform | Installer | Where setup keeps the runtime |
| --- | --- | --- |
| Windows 10 and newer, x64 | `.exe` | `%LOCALAPPDATA%\Programs\Wardr` |
| macOS 13 and newer, Apple Silicon or Intel | `.dmg` containing Wardr.app | `~/Library/Application Support/Wardr Runtime` |
| Linux with glibc, x64 or ARM64 | `.run` | `${XDG_DATA_HOME:-$HOME/.local/share}/wardr` |

Windows and Linux desktop launchers open a console alongside the dashboard.
Use Ctrl+C in that console to stop Wardr. On macOS, choose **Quit Wardr** in the
app menu. Standard Linux shell tools are required. [Windows installer](windows/README.md) · [Linux installer](linux/README.md)

## Updates and data

Native installs use the same **Updates → Check for updates → Update Wardr →
Restart Wardr** flow as the wheel. The installer and updater write to the
private runtime directory. They never open Wardr's data directory. Native
launchers use the same per-user state location as an existing wheel install.
If you previously selected a custom state directory, continue to pass
`--state-dir` when launching the installed interpreter with `-I -m wardr`.
Keep only one Wardr dashboard running for a given state directory.

The update test checks that a restart keeps the listening port, monitoring
interval, software assessment, cached advisory catalog, saved event, and
exported report. It also checks that the restarted dashboard issues a fresh
access token and uses the new package.

## Build and distribute

Run the **Wardr native installers** GitHub Actions workflow for a Community
version already published on getwardr.com. It verifies the release signature
against the repository's pinned public key, checks the wheel hash, and
packages pinned runtime downloads from Astral. Each job runs the produced
installer and exercises a test-signed upgrade in the installed copy. The
temporary update wheel and signing key stay in the test job.

The workflow uploads preview installers as GitHub Actions artifacts. For a
public release, use the Windows signing guide to sign and verify Setup on
Windows. Follow the Mac signing guide to sign the app and its bundled runtime
before submitting and stapling each disk image. Keep publisher keys out of
the repository and retain the existing Wardr release key for application
updates. [Windows signing](windows/README.md#authenticode-release-signing) · [Mac signing and notarization](macos/README.md)

On a native macOS build host with command-line developer tools installed,
run the commands below. The Intel build also needs Rust and Homebrew's
`openssl@3` to compile PyCA cryptography with static OpenSSL. [PyCA build instructions](https://cryptography.io/en/latest/installation/#building-cryptography-on-macos)

```sh
python -m pip install cryptography==50.0.2
python packaging/build_payload.py --version 0.2.1 --output dist/native-payload
sh packaging/macos/build.sh dist/native-payload 0.2.1 dist
```

Open the disk image and drag Wardr to Applications. The application provisions
its private runtime on first launch.
