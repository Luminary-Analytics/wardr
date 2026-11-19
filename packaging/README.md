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

## Sign and publish a release

Push the reviewed software commit containing the new `pyproject.toml` version
to the public repository's `main` branch. Wait for the required builds and
tests to pass, then run this from the Wardr software checkout.

```sh
python3.11 packaging/release.py --version X.Y.Z --site ../Wardr-Site --signing-repo ../resonant-client --signing-key ~/.config/wardr-release/community-ed25519.pem
```

Use `--plan` for a read-only preview. The runner keeps release artifacts and
progress in `dist/release/X.Y.Z`.

The runner seals the wheel and source archive and verifies the in-place
upgrade from the current signed wheel to the candidate, including the state
saved across restart. It stages the request and sealed wheel on the existing
private signing repository's `main` branch and a release tag. Windows,
macOS, and Linux CI build and test the installers. Windows CI signs Setup,
and macOS CI signs, notarizes, and staples the disk images. The Wardr release
key stays local. Platform signing credentials stay in the protected private
release environment.

The runner uploads and verifies the artifacts on a GitHub draft, stages and
validates the site with the signed release and installer catalogs, promotes
the draft, and pushes the site to Render. After verifying the deployed site
and downloads, it verifies fresh native installs and live in-place upgrades
on Windows x64, macOS ARM64 and Intel, and Linux ARM64 and x64. The baseline
comes from the signed prior feed in the release checkpoint. Each upgrade
checks that settings and saved data survive the dashboard restart.

The runner waits for GitHub run metadata to settle and then waits for all five
jobs. Use the recorded Actions run to confirm the upgrade on each platform.
The release guide explains when to wait, resume, or retry.
[Verify all five live checks](../docs/DEVELOPMENT.md#verify-all-five-live-checks) · [Resume or retry a release](../docs/DEVELOPMENT.md#resume-or-retry-a-release)

## Build preview installers

Run the **Wardr native installers** GitHub Actions workflow for a Community
version already published on getwardr.com. It verifies the release signature
against the repository's pinned public key, checks the wheel hash, and
packages pinned runtime downloads from Astral. Each job runs the produced
installer and exercises a test-signed upgrade in the installed copy. The
temporary update wheel and signing key stay in the test job.

The workflow uploads preview installers as GitHub Actions artifacts. The
platform guides describe Windows Authenticode verification and macOS signing
and notarization. [Windows signing](windows/README.md#authenticode-release-signing) · [Mac signing and notarization](macos/README.md)

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
