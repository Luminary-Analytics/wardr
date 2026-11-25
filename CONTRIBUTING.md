# Contributing to Wardr

Thank you for contributing to Wardr! The entire Wardr project—including the local dashboard, CLI, Self-Pen-Test Lab, Supply-Chain Scanner, Wardr Fleet control plane, Threat Network server, and native desktop wrappers—is open source under the [MIT License](LICENSE).

## Getting started

Wardr requires Python 3.11+ (with a single runtime dependency, `cryptography`) and optionally Rust for the native desktop shell in `desktop/`.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for platform-specific setup, troubleshooting, and packaging details.

## Running checks before opening a PR

```sh
python -m unittest discover -s tests -v
node --check wardr/static/wardr.js
node --check wardr/static/fleet.js
python -m py_compile wardr/*.py scripts/*.py
python scripts/pr_guard.py --mode repo
```

If you modify the Rust desktop wrapper under `desktop/`:

```sh
cargo check --manifest-path desktop/Cargo.toml
```

## Review tiers & PR intake

To keep reviews both fast and safe for a local security tool, pull requests are triaged by the highest-risk path they touch (enforced via `.github/CODEOWNERS` and the **PR Security Guard** workflow):

- **Tier 0 — Lockdown** (`wardr/keys/`, `.github/`, `packaging/`, `deploy/`, `pyproject.toml`, `desktop/Cargo.*`, `desktop/build.rs`, `wardr/updater.py`, `wardr/update_session.py`, `wardr/release.py`): Open a proposal issue first and get maintainer agreement before writing code. Runtime dependency additions require the maintainer-applied `approved-dependency` label.
- **Tier 1 — Security Core** (`wardr/server.py`, `wardr/oauth_broker.py`, `wardr/account.py`, `wardr/remediation.py`, `wardr/actions.py`, `wardr/fleet*.py`, `wardr/pentest.py`, `wardr/service.py`, `wardr/threat_network.py`, `wardr/local_ai.py`, `wardr/supply_chain.py`, `desktop/src/`): Include targeted unit tests and clearly explain the threat model and rollback/offline behavior.
- **Tier 2 — Fast Lane** (`docs/`, `tests/`, read-only collectors/reporting, `wardr/static/`): Fastest path to merge once CI and CSP/syntax checks are green.

AI-assisted contributions are welcome provided you have personally reviewed, tested, and understand every line you submit. Unexplained large diffs or drive-by changes to Tier 0/1 paths without an issue may be closed until scoped.

## Architecture & security principles

Please keep Wardr's core guarantees intact in every contribution:

- **Ultra-low overhead & minimal dependencies:** Keep the core Python package to its single runtime dependency (`cryptography`) unless a new dependency is explicitly discussed and approved.
- **Local-first & offline-capable:** Core checks, repairs, hunting, and reports must continue to work cleanly under `wardr serve --offline`.
- **Zero-RCE & rollback-safe remediation:** Automated fixes and Fleet remote actions must remain strictly allowlisted, non-destructive, diff-previewed, and rollback-safe—never arbitrary remote script execution.
- **Strict loopback & CSP hygiene:** Preserve IPv4 loopback binding (`127.0.0.1`), single-use auth exchange, constant-time token checks, and zero inline scripts/styles in the web UI.
- **No secrets in git:** Never commit private signing keys, OAuth secrets, tokens, or personal data.

## Pull requests & licensing

1. Fork the repository and create a focused branch from `main`.
2. Add or update unit tests covering your change.
3. Keep PR descriptions clear about the threat model or user workflow affected.
4. By submitting a contribution, you agree that your work will be licensed under the [MIT License](LICENSE) and that you will abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

To report a security vulnerability, **do not open a public issue**—follow [SECURITY.md](SECURITY.md) instead.
