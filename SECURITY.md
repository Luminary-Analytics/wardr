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

The download site publishes SHA-256 hashes and a versioned manifest. A
release owner can also sign the manifest with an Ed25519 key kept outside
source control and hosting. Verify the release with a public key obtained
through a separate trusted channel. A checksum delivered by the download
site detects mismatched files. A pinned signing key establishes provenance.

The README describes how to verify a wheel. The company site repository
documents the signing and publication workflow.
