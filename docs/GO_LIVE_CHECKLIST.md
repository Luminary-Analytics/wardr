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
- **Google SSO (Stateless PKCE OAuth Broker on `api.getwardr.com`):**
  1. In Google Cloud Console → **APIs & Services → Credentials**, create an **OAuth 2.0 Client ID** of type **Web application**.
  2. Add Authorized redirect URI: `https://api.getwardr.com/oauth/google/callback`.
  3. In Render (`wardr-threat-network` → **Environment**), set `WARDR_PUBLIC_URL=https://api.getwardr.com`, `WARDR_GOOGLE_CLIENT_ID`, and `WARDR_GOOGLE_CLIENT_SECRET`.
  4. Verify `curl -sS https://api.getwardr.com/oauth/providers` returns `{"providers": {"google": true, ...}}`. Desktop installs discover this automatically and enable **Continue with Google** with zero secrets shipped in client binaries.

## Automated Feedback → Release Loop (`v0.4.0` → `v0.4.1+`)
1. **One-time secret setup for automated daily GitHub triage:**
   Copy `WARDR_ADMIN_TOKEN` from Render (`wardr-threat-network` → **Environment**) into GitHub Actions Secrets:
   ```bash
   gh secret set WARDR_ADMIN_TOKEN --repo Luminary-Analytics/wardr
   ```
   `.github/workflows/telemetry-triage.yml` then runs daily at 13:00 UTC (or on demand via `workflow_dispatch`), fetches live telemetry + zero-day clusters from `https://api.getwardr.com`, and automatically creates/updates the pinned **`[Telemetry Triage] Wardr Release Candidate Digest`** GitHub Issue with top failing checks, pen-test exposures, risky ports, compromised packages, and a validated `defense-v1.draft.json` feed bundle.
2. **Urgent zero-day rapid defense (no app reinstall needed):**
   Review `defense-v1.draft.json` and publish an Ed25519-signed Rapid-Defense Feed via `wardr feed --sign` / `POST /v1/feeds/publish`.
3. **Prepare & ship the next reviewed signed release (`v0.4.1+`):**
   ```bash
   # Pull live telemetry into pyproject.toml + changelog.py ("What's New?")
   WARDR_ADMIN_TOKEN=... wardr feedback-loop prepare-release --bump patch --from-live

   # Review changes / add targeted check or hardening fixes, commit, then publish:
   wardr feedback-loop publish-release --version 0.4.1
   ```
   Every existing customer receives the Ed25519-signed update via **Updates → Check for updates** and sees the new release highlights in **"What's New?"**.
