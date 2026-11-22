# Wardr `v0.4.0` Go-Live Release Checklist

Use this runbook to ship `v0.4.0` live (upgrading existing `v0.3.1` users seamlessly) and activate the full central telemetry → signed security updates loop.

## 1. Pre-Flight Code & Test Verification
Run locally before pushing `main`:
```bash
node --check wardr/static/wardr.js
.venv/bin/python -m py_compile wardr/*.py
.venv/bin/python -m unittest discover -s tests -q
```
Verify:
- `pyproject.toml` version matches `wardr/changelog.py` (`0.4.0`).
- Zero secrets or local OAuth config files (`sso-config.json`, private `.pem` keys, `.env`) exist in `git status`.
- `wardr/keys/release.pem` contains the public Ed25519 key matching `~/.config/wardr-release/community-ed25519.pem`.

## 2. Commit, Push & Pass Cross-Platform CI (`checks.yml`)
```bash
git push origin main
```
Confirm `.github/workflows/checks.yml` passes on all three platforms (`ubuntu-latest`, `macos-latest`, `windows-latest`).

## 3. Build, Sign & Publish `v0.4.0` to GitHub Releases & `getwardr.com`
Preview the full release plan (read-only):
```bash
python3.11 packaging/release.py --version 0.4.0 \
  --site ../Wardr-Site \
  --signing-repo ../resonant-client \
  --signing-key ~/.config/wardr-release/community-ed25519.pem \
  --plan
```
Then execute the live release (builds & seals `0.4.0`, triggers signed Windows/macOS/Linux native installers, updates `../Wardr-Site` + Render deploy on `getwardr.com`, promotes GitHub release `v0.4.0`, and verifies live `0.3.1 → 0.4.0` upgrades across all 5 OS/arch targets):
```bash
python3.11 packaging/release.py --version 0.4.0 \
  --site ../Wardr-Site \
  --signing-repo ../resonant-client \
  --signing-key ~/.config/wardr-release/community-ed25519.pem
```

## 4. Deploy Central Telemetry & Threat Network (`api.getwardr.com`)
Choose either **Render** (same platform as `getwardr.com`) using `deploy/threat-network/render.yaml`, or **Docker + Caddy** using `deploy/threat-network/docker-compose.yml`:
- Verify health: `curl -sS https://api.getwardr.com/v1/health`
- Pull central system & scan telemetry analytics:
  ```bash
  curl -sS -H "Authorization: Bearer $WARDR_ADMIN_TOKEN" \
    https://api.getwardr.com/api/v1/telemetry/summary | python3 -m json.tool
  ```
- Pull zero-day / vulnerability clusters:
  ```bash
  curl -sS -H "Authorization: Bearer $WARDR_ADMIN_TOKEN" \
    https://api.getwardr.com/v1/clusters | python3 -m json.tool
  ```

## 5. SSO Sign-In Configuration for Packaged Builds
- **Microsoft SSO:** Public PKCE (`S256`) Entra client ID (`d88b005f-fc08-40cd-8037-873321f31433`) is built into `wardr/account.py` — works out of the box with zero secrets.
- **Google SSO:** For public desktop builds, either configure a hosted OAuth broker (`WARDR_AUTH_BROKER_URL`) on `api.getwardr.com` (recommended so no client secret ships in desktop binaries) or supply `WARDR_GOOGLE_CLIENT_ID` / `WARDR_GOOGLE_CLIENT_SECRET` via environment / `sso-config.json`.

## Ongoing Update Loop (`v0.4.0` → `v0.4.1+`)
1. Pull `GET /api/v1/telemetry/summary` and `GET /v1/clusters` regularly to spot top failing checks, risky ports, and compromised package trends.
2. For urgent zero-day rules or emerging CVEs, publish a signed Rapid-Defense Feed immediately via `POST /v1/feeds/publish` (zero app reinstall needed).
3. For new checks, auto-fixes, or UI improvements, bump `pyproject.toml` + `wardr/changelog.py`, push `main`, and run `packaging/release.py` — customers automatically receive the signed update via **Updates → Check for updates** and see your release highlights in **"What's New?"**.
