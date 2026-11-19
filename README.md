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
- [Company site repository](https://github.com/Luminary-Analytics/wardr-site)
  contains the public site and its download publishing workflow.

## Install

Install Python 3.11 or later and [pipx](https://pipx.pypa.io/stable/). Download
the wheel from [Wardr releases](https://github.com/Luminary-Analytics/wardr/releases)
and run the following commands from your downloads folder.

```console
pipx install ./wardr-0.2.0-py3-none-any.whl
wardr
```

To upgrade from a downloaded wheel, run `pipx install --force ./wardr-0.2.0-py3-none-any.whl`
with the new filename. To install from a source checkout, use `pipx install .`.
Wardr has no third-party Python runtime dependencies. Run it as the account
whose security settings you want to check.

## Dashboard

Wardr prints a private loopback launch link. It scans on startup and hourly
while the dashboard service runs. Select **Run scan** for an immediate refresh.

- **Checklist** shows the risk, evidence, and next step for each check.
  Supported SSH permission changes on macOS and Linux require confirmation
  and are checked again after they run.
- **Defense** brings together a prioritized plan, local TCP listeners and UDP
  bindings, recent telemetry correlations, and software version matches.
  Socket bindings show local interface scope. Reachability depends on your
  host firewall and network configuration.
- **Software** accepts a CycloneDX JSON inventory and an OSV JSON advisory
  export. Wardr matches supported package identities and version ranges.
  Unassessed ranges and packages without supplied records appear as gaps.
  CISA catalog membership increases priority for an existing version match.
  [CycloneDX](https://cyclonedx.org/specification/overview/) · [OSV schema](https://ossf.github.io/osv-schema/)
- **Events** shows the monitor's available sources and recent activity. Hunting
  alerts link to specific events and offer steps for investigating. Treat
  correlated events as investigation leads.
- **Reports** and **Defense** export HTML and JSON. Exports can contain the
  machine name, software versions, bindings, and event details.

## Offline mode

Start a session with public advisory downloads disabled.

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
wardr assess --sbom inventory.json --advisories advisories.json
wardr plan --format html > wardr-plan.html
wardr watch
wardr serve --no-browser --offline
```

`wardr watch` emits new events as JSON Lines on stdout and coverage updates on
stderr. Use an existing service supervisor for continuous collection. The
dashboard always binds to IPv4 loopback. Keep its launch link private.

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

```console
uv build
python -m unittest discover -s tests -v
```

The Blender scene, procedural render, and editable TripoSR mesh are in
`design/`. The installed app ships the rendered PNG.
[TripoSR project](https://github.com/VAST-AI-Research/TripoSR)

The company site publishes release hashes alongside its downloads. For a
signed release, verify the manifest and the artifact with a trusted Ed25519
public key obtained independently. Verification uses OpenSSL 3.

```console
wardr verify-release --manifest latest.json --signature latest.json.sig --public-key trusted.pem wardr-0.2.0-py3-none-any.whl
```

See the [security policy](SECURITY.md) for private vulnerability reporting and
release provenance.
