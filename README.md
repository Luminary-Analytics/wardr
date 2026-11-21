# Wardr Community

Wardr helps you harden a desktop or server you manage. The goal is to show
what a machine exposes, explain the evidence behind each finding, and make it
clear how to fix and verify security gaps. Community is free under the
[MIT License](LICENSE).

The installed application checks host settings, inventories local network
bindings, correlates selected security events, and matches supplied software
inventories to published advisories. It combines those findings into a
remediation plan. [Wardr homepage and demo](https://getwardr.com/)

## Project documentation

- [Architecture](docs/ARCHITECTURE.md) covers software components, evidence
  and repair flows, data storage, trust boundaries, and coverage.
- [Development and operations](docs/DEVELOPMENT.md) covers running from
  source, troubleshooting, native checks, builds, and the release workflow.
- [Security policy](SECURITY.md) covers vulnerability reporting and release
  verification.
- [Signing handoff](docs/HANDOFF_SIGNING_MOVE.md) records the decision to sign
  Wardr's installers in this repository and the work left to do.
- [Company site repository](https://github.com/Luminary-Analytics/wardr-site)
  contains the public site and its download publishing workflow.

## Install

Download the native installer for Windows, macOS, or Linux. These installers
include the runtime and can install offline. [Download Wardr](https://getwardr.com/#release) ·
[Native installer guide](packaging/README.md)

To install from the wheel, use Python 3.11 or later and run these commands
from your downloads folder. [Set up pipx](https://pipx.pypa.io/stable/)

```console
pipx install ./wardr-0.3.1-py3-none-any.whl
wardr
```

To upgrade from v0.2.0, close Wardr, download the v0.3.1 wheel, and run
`pipx install --force ./wardr-0.3.1-py3-none-any.whl` once. Launch Wardr again
as the account whose security settings you want to check.

## Dashboard

Wardr prints a private loopback launch link. It scans on startup and hourly
while the dashboard service runs. Select **Run scan** for an immediate refresh.

- **Checklist** shows the risk, evidence, and next step for each check,
  including OS hardening, local credential permissions (`~/.ssh`, `~/.aws`,
  `~/.kube`, `~/.gnupg`, `~/.docker`), and local AI/MCP security hygiene.
  Supported permission repairs on macOS and Linux show a dry-run diff preview,
  save an atomic rollback snapshot, and verify automatically after applying.
  Any failed finding also offers **Report to Wardr**, which strips hostnames,
  usernames, home paths, IPs, emails, and secrets locally before previewing
  the redacted report for optional submission or offline JSON export.
- **Defense** brings together a prioritized plan, local TCP listeners and UDP
  bindings, attack-surface warnings for exposed databases and local AI
  endpoints, persistent baseline-drift and Ed25519-signed Rapid-Defense Feed
  hunting rules, and software version matches.
- **Software** supports one-click **Auto-scan installed software** (fast,
  incremental CycloneDX discovery for Python, Homebrew, Debian/Ubuntu, and
  Alpine matched against verified Rapid-Defense Feed advisories) as well as
  manual CycloneDX JSON + OSV JSON uploads. CISA catalog membership increases
  priority for an existing version match.
  [CycloneDX](https://cyclonedx.org/specification/overview/) · [OSV schema](https://ossf.github.io/osv-schema/)
- **Events** shows the monitor's available sources, persistent host baseline
  drift, and up to 2,000 retained local observations. Hunting alerts link to
  specific events, support declarative signed feed rules, and offer one-click
  redacted **Report to Wardr** escalation.
- **Reports** and **Defense** export HTML and JSON. Exports can contain the
  machine name, software versions, bindings, and event details.

## Update Wardr

Starting with v0.2.1, open **Updates** in the dashboard and choose **Check for
updates**. When a signed release is available, select **Update Wardr** to verify
and install it, then choose **Restart Wardr**. Use the new dashboard window or
the launch link printed in your terminal.

In-place updates require Wardr installed in a pipx or Python virtual
environment, with pip available in that environment or uv on `PATH`.
Download the wheel and use your package manager for releases that change
dependencies or when in-place updates are unavailable.

```console
wardr update --check
wardr update
```

The CLI checks explicitly and installs only when you run `wardr update`.
Restart any open Wardr process after a CLI update. On Windows, invoke the
environment's Python with `-m wardr update` to keep the Wardr launcher free
for replacement. [Update troubleshooting](docs/DEVELOPMENT.md#operate-and-troubleshoot)

## Offline mode

Start a dashboard session with public advisory downloads and Wardr release
checks disabled.

```console
wardr serve --offline
```

Local checks, software assessments from files, event monitoring, and report
exports work offline. Cached advisories remain available. For optional model
review, install and start [Ollama](https://ollama.com/download) locally. While
online, prepare Wardr's pinned Qwen2.5 1.5B model, which downloads about 986 MB.

```console
wardr model pull
wardr model status
wardr serve --offline
```

In **Defense → Plan**, select **Review with local AI**. Wardr passes anonymous
plan item numbers, categories, and priorities to the loopback model and presents
validated groups of existing tasks. It keeps the evidence, recommendations,
inventory, and raw event content out of the model request. For a fully offline
runtime configuration, disable Ollama's cloud features in Ollama.
[Ollama offline configuration](https://docs.ollama.com/faq#how-do-i-disable-ollamas-cloud-features)

## Servers

```console
wardr scan
wardr exposure
wardr surface
wardr inventory
wardr fim --init && wardr fim
wardr assess --auto
wardr assess --sbom inventory.json --advisories advisories.json
wardr fix --preview aws-credentials-permissions
wardr feed --import-bundle defense-v1.json --signature defense-v1.json.sig
wardr report-issue --finding ssh-directory-permissions --zero-day --out redacted.json
wardr plan --format html > wardr-plan.html
wardr watch
wardr service-template --platform systemd
wardr service-template --platform systemd --fleet
wardr fleet server --host 127.0.0.1 --port 8443
wardr fleet enroll --server https://fleet.example.com --token wf_enroll_... --tags prod,linux
wardr fleet agent --interval 60
wardr threat-network --host 127.0.0.1 --port 8787
wardr serve --no-browser --offline
```

## Teams & Fleet Management

Small core security teams can self-host **Wardr Fleet** with zero extra
dependencies (`wardr fleet server`) to monitor and harden servers and user
computers from one web console:

- **RBAC for core teams**: `admin`, `responder`, and `viewer` roles backed by
  PBKDF2-SHA256 operator credentials, session tokens, and an immutable SQLite
  audit log.
- **Short-lived enrollment tokens**: Mint bounded, revocable tokens with
  default host roles (`server` / `workstation`) and tags; each host receives a
  unique hashed device token (`0600` locally) that can be revoked in one click.
- **Cross-host correlation & zero-RCE bulk fixes**: Automatically correlates
  shared posture failures, exposed databases/AI ports, FIM tampering, and
  zero-day baseline-drift alerts across the fleet. Operators can queue strictly
  allowlisted actions (`scan`, `exposure`, `inventory`, `fim_check`,
  `apply_fix`, `undo_fix`) across hosts or tag groups—never arbitrary remote
  scripts—and export executive HTML/JSON compliance reports.

`wardr watch` emits new events as JSON Lines on stdout and coverage updates on
stderr. Use an existing service supervisor for continuous collection. The
dashboard always binds to IPv4 loopback. Keep its launch link private.

On Windows, launch a headless dashboard through the installed environment's
Python interpreter with `-m wardr serve --no-browser` so future updates can
replace the Wardr launcher.

`wardr advisories --refresh` downloads the public CISA catalog. The dashboard
offers a manual refresh when online or an opt-in six-hour schedule via
`wardr serve --auto-advisories`. Wardr sends no local inventory or event data in
that request. [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

## Coverage

| Platform | Checks | Event sources |
| --- | --- | --- |
| macOS | Firewall, FileVault, Gatekeeper, System Integrity Protection, updates, SSH permissions | New TCP listeners and launch item changes |
| Windows | Firewall profiles, Defender, BitLocker, SMBv1, UAC, Secure Boot, Remote Desktop authentication, cached updates | New TCP listeners and selected System, Security, and Defender events |
| Linux | Firewall, ASLR, kernel link protections, AppArmor or SELinux, OpenSSH policy and permissions, cached APT or DNF advisories | New TCP listeners and selected SSH journal events |

OS permissions and available sources determine how much Wardr can verify.
The tools cover local evidence and published vulnerabilities. Wardr's
emerging-threat work focuses on detecting suspicious activity early.

Scans, retained events, the advisory cache, and computed software matches are
stored in the current user's Wardr data directory. The software matcher keeps
its result rather than the uploaded inventory or advisory files. Use
`wardr --state-dir <path> <command>` for a different local directory.

## Build and verify

Use a development virtual environment for local builds and tests.

```console
python -m pip install -e .
uv build
python -m unittest discover -s tests -v
```

The Blender scene, procedural render, and editable TripoSR mesh are in
`design/`. The installed app ships the rendered PNG.
[TripoSR project](https://github.com/VAST-AI-Research/TripoSR)

Wardr Community releases starting with v0.2.1 have Ed25519-signed manifests.
To verify a download manually, use the matching version's manifest and
detached signature, and a trusted public key obtained independently. Wardr
verifies downloads offline using PyCA cryptography without an OpenSSL
command. [Release downloads](https://getwardr.com/#release)

```console
wardr verify-release --manifest release.json --signature release.json.sig --public-key trusted.pem wardr-0.3.1-py3-none-any.whl
```

See the [security policy](SECURITY.md) for private vulnerability reporting and
release provenance.
