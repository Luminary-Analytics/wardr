# Wardr security

Wardr Community uses the MIT License. Wardr's local dashboard accepts authenticated
requests on loopback. The assessment engine reads local security settings, socket
tables, event records, and inventory files. Confirmed repairs are limited to the
allowlisted SSH permissions checks. The optional model receives a bounded set of
plan labels and cannot run commands, change settings, or initiate connections.

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
