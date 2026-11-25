# Wardr security

Wardr is open source under the [MIT License](LICENSE). Wardr's local dashboard accepts authenticated
requests on IPv4 loopback (`127.0.0.1`) with strict `Host`, `Origin`, constant-time
token verification, and a strict Content Security Policy (zero inline scripts or styles).
The assessment engine reads local security settings, socket tables, event records,
self-pen-test probes, and local supply-chain manifests without transmitting secrets.

- **Security Audit Report:** See [docs/security-audit.md](docs/security-audit.md) for our
  full adversarial codebase audit, threat model controls, and applied remediations.
- **Privacy Policy & Terms of Use:** See [PRIVACY.md](PRIVACY.md) and [TERMS.md](TERMS.md).
- **Offline / Air-Gapped Mode:** Run `wardr serve --offline` to disable all outbound
  network requests, account sync, advisory downloads, and optional cloud AI.

Use a current, trusted build and keep the dashboard launch link private. An
offline model can be prepared while connected and used through the local Ollama
runtime. Imported inventories and generated plans can identify software and
services in use. Review exports before sharing them.

## Reporting a Wardr vulnerability

Use the [private GitHub report form](https://github.com/Luminary-Analytics/wardr/security/advisories/new).
Include the Wardr version, affected platform, impact, and the minimum evidence
needed to understand the issue. Remove host names, credentials, raw keys, and
unrelated logs. Avoid public disclosure while maintainers assess the report.

## Release integrity

Starting with Wardr 0.2.1, the download site publishes versioned release
manifests with detached Ed25519 signatures. Each manifest records the
SHA-256 digest and byte count of its artifacts. The updater verifies each
manifest with the release public key bundled in the installed app, then
checks the selected wheel against the signed metadata before installation.
It offers only newer versions to prevent downgrades.

Keep the release private key outside both repositories and the hosting
environment. Public copies on the download site are available for
inspection. For independent manual verification, obtain the trusted public
key through a separate channel. Coordinate any key rotation with the
installed app's key pin before publishing updates under the replacement key.
[Verify a wheel](README.md#build-and-verify) ·
[Site release guide](https://github.com/Luminary-Analytics/wardr-site/blob/main/docs/release-and-hosting.md)
