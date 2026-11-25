## Summary

<!-- Briefly describe what this PR changes and why. -->

- **Related issue / RFC:** <!-- e.g. Closes #123 (required for non-trivial features or Tier 0/1 changes) -->
- **Change type:**
  - [ ] Bug fix
  - [ ] New check / collector / documentation (low risk)
  - [ ] Security-sensitive core change (`server`, `oauth_broker`, `remediation`, `fleet`, `pentest`, `desktop/src`)
  - [ ] Build, CI, packaging, dependency, or updater change (requires prior discussion)

## Threat Model & Architectural Invariants

Please confirm how this PR preserves Wardr's core guarantees:

- [ ] **Minimal dependencies:** Does not add new runtime dependencies to `pyproject.toml` (or was explicitly pre-approved in an issue).
- [ ] **Offline-capable:** Core functionality still works cleanly under `wardr serve --offline` with no unexpected outbound network calls.
- [ ] **Zero-RCE & rollback-safe:** Any remediation or Fleet change remains strictly allowlisted, non-destructive, diff-previewed, and rollback-safe.
- [ ] **Loopback & CSP hygiene:** Preserves `127.0.0.1` loopback binding, constant-time auth checks, and zero inline `<script>` / `<style>` / `on*=` handlers in `wardr/static/`.
- [ ] **No secrets or opaque binaries:** Contains no credentials, tokens, private keys, or unnecessary binary blobs.

## Verification

<!-- List the commands you ran locally and any platform-specific notes. -->

- [ ] `python -m unittest discover -s tests -v`
- [ ] `node --check wardr/static/wardr.js && node --check wardr/static/fleet.js`
- [ ] `python -m py_compile wardr/*.py`
- [ ] `cargo check --manifest-path desktop/Cargo.toml` (if `desktop/` was modified)

## AI-Assisted Contribution Disclosure

<!-- Using AI tools is welcome, provided you have personally reviewed, tested, and understand every line submitted. -->

- [ ] No AI tools were used, OR
- [ ] AI tools were used and I have personally audited and verified all generated code and tests.
