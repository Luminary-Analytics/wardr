# Wardr Comprehensive Security Audit & Hardening Report

**Audit Date:** November 22, 2026  
**Scope:** Full open-source codebase (`wardr/*.py`, `wardr/static/*`, packaging & release verification, `pyproject.toml`)  
**Methodology:** Adversarial white-box review covering authentication/CSRF/DNS-rebinding, command execution & privilege boundaries, filesystem symlink/TOCTOU/permission safety, SSRF & outbound PII redaction, cryptographic signature verification, and frontend CSP/XSS hygiene.

---

## Verified Baseline Security Controls

- **Local Dashboard (`wardr/server.py`, `wardr/static/wardr.js`):**
  - Exact `Host` header check (`_trusted_host`), exact `Origin` validation on all `POST` endpoints, constant-time `hmac.compare_digest` on `X-Wardr-Token`.
  - Strict Content-Security-Policy (`default-src 'none'; script-src 'self'; style-src 'self' 'sha256-...'; frame-ancestors 'none'; form-action 'none'`), `Cross-Origin-Resource-Policy: same-origin`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`.
  - Zero `innerHTML`, `outerHTML`, `eval`, `Function`, `postMessage`, or inline `style=` attributes across `index.html`, `wardr.js`, and `report.py` (enforced by automated unit tests).
  - `#access=` launch token stripped immediately from browser address bar via `history.replaceState`.
- **Cryptographic Release & Feed Verification (`wardr/updater.py`, `wardr/feeds.py`):**
  - Ed25519 signature verification prior to wheel installation or rule activation, SHA-256 checksum comparison via `hmac.compare_digest`, downgrade protection, and wheel dependency-change blocking.
- **Credential & SSH Remediation (`wardr/checks.py`, `wardr/remediation.py`):**
  - Uses `pwd.getpwuid()`, `O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK`, `st_nlink == 1`, `(st_dev, st_ino)` checks, and macOS/Linux extended ACL checks.
- **Dependencies (`pyproject.toml`):**
  - Minimal attack surface: single runtime dependency (`cryptography>=50.0.2`), zero third-party web frameworks or frontend npm bundles.

---

## Findings & Remediations Applied

| ID | Severity | Component | Finding Summary | Status |
|---|---|---|---|---|
| **HIGH-01** | High | `wardr/ai_tiers.py` | DNS-based SSRF / non-canonical IP bypass / DNS rebinding on custom Tier 2 Cloud AI endpoints. | **Fixed** — Added single-resolution `_resolve_public_ip()` validating every resolved address (including IPv4-mapped IPv6) is globally routable, plus `_PinnedHTTPSConnection` pinning connect to the validated IP while preserving TLS SNI & `Host` verification. |
| **HIGH-02** | High | `wardr/fleet.py` | Slicing serialized `result_json` at 16,384 bytes caused malformed JSON and persistent HTTP 500 DoS on `overview()` / `host_detail()`. | **Fixed** — Oversized command results are now stored in a valid bounded JSON envelope (`{"truncated": true, "preview": ...}`), and readers safely handle malformed JSON. |
| **HIGH-03** | High | `wardr/fleet.py` | Unauthenticated `GET /api/fleet/health` exposed full fleet posture summary (`total_hosts`, `fleet_score`, `open_critical`, `risky_services`, `fim_failures`). | **Fixed** — `/api/fleet/health` now returns only `{"ok": true}`; posture metrics require operator authentication on `/api/fleet/overview`. |
| **HIGH-04** | High | `wardr/fleet.py` | Fleet login held global `self._lock` during 200k-iteration PBKDF2 (mutex DoS), skipped PBKDF2 on unknown usernames (timing oracle), and lacked rate limiting. | **Fixed** — PBKDF2 now runs outside `self._lock`, executes constant-work dummy PBKDF2 for missing/disabled users, prunes expired sessions, and enforces per-IP sliding-window rate limiting on `/api/fleet/login` and `/api/fleet/enroll`. |
| **HIGH-05** | High | `wardr/fleet.py`, `wardr/threat_network.py` | Missing socket timeouts (`settimeout`) enabled Slowloris thread exhaustion; `_read_json` lacked `Transfer-Encoding` rejection & strict ASCII `Content-Length` checks. | **Fixed** — Added `settimeout(30)` in `setup()`, rejected `Transfer-Encoding`, enforced ASCII bounded `Content-Length`, caught `(ValueError, RecursionError, OSError)`, and guarded broken pipes. |
| **HIGH-06** | High | `wardr/feeds.py` | Missing anti-rollback freshness check on `refresh_feed()`/`import_feed()` and implicit default `rules`/`advisories` fields allowed cross-protocol replay risk. | **Fixed** — Required explicit `rules` and `advisories` fields in `_parse_feed_document()`, enforced monotonic `published_at` anti-rollback via `_enforce_monotonic_freshness()`, caught `http.client.HTTPException`, and applied `os.fchmod(..., 0o600)`. |
| **MEDIUM-01** | Medium | `wardr/actions.py` | Unvalidated `SystemRoot` interpolation in Windows PowerShell elevation and PATH-resolved `pkexec`/`ufw`/`sysctl` on Linux. | **Fixed** — Enforced absolute `SystemRoot` + file verification + quote escaping on Windows, and pinned absolute paths `/usr/bin/pkexec`, `/usr/sbin/ufw`, `/usr/sbin/sysctl` on Linux. |
| **MEDIUM-02** | Medium | `wardr/pentest.py` | Bare `launchctl`/`osascript`/`open` calls and missing `O_NONBLOCK` / `st_nlink == 1` / non-root checks in `_safe_chmod_owned_file()`. | **Fixed** — Pinned `/bin/launchctl`, `/usr/bin/osascript`, `/usr/bin/open` and added `O_NONBLOCK`, `st_nlink == 1`, and non-root checks. |
| **MEDIUM-03** | Medium | `wardr/state.py`, `wardr/threat_network.py`, `wardr/account.py` | `prepare_state_dir` checked `0o022` instead of `0o077`; state JSON temp files relied on ambient umask. | **Fixed** — Enforced `0o077` in `prepare_state_dir()`, explicit `os.fchmod(..., 0o600)` in `save_local_json()` & `account._save_private_json()`, and `0o600` on `threat-network.sqlite3`. |
| **MEDIUM-04** | Medium | `wardr/server.py`, `wardr/static/wardr.js` | Reusable bearer token in `webbrowser.open()` launch URL could be scraped from process `argv` on multi-user systems. | **Fixed** — `#access=<nonce>` is now a **single-use bootstrap nonce** exchanged once on load via `POST /api/auth/exchange` for a fresh session token and immediately invalidated. |
| **MEDIUM-05** | Medium | `wardr/reporting.py` | Redactor missed compressed IPv6 (`::`), case-insensitive `/users/` or `/root/`, and Groq (`gsk_`), OpenRouter (`sk-or-v1-`), GitLab, npm, PyPI, AWS STS, `Basic` auth, and URL credentials. | **Fixed** — Expanded `_REDACT_PATTERNS` to cover all of the above before any outbound Cloud AI, intake, or telemetry transmission. |
| **MEDIUM-06** | Medium | `wardr/threat_network.py` | Single IP could spoof `zero_day_votes` escalation via repeated reports, and ephemeral per-restart salt reset reporter deduplication. | **Fixed** — Persisted `reporter_salt` in SQLite `meta` table and counted distinct reporters (`COUNT(DISTINCT CASE WHEN suspected_zero_day = 1 THEN reporter_hash END)`). |
| **MEDIUM-07** | Medium | `wardr/updater.py`, `wardr/release.py` | PATH-resolved `uv` fallback lacked owner/permission verification; `release.sign_manifest` invoked bare `openssl` CLI. | **Fixed** — Verified `uv` binary and parent dir ownership/mode (`0o022 == 0`) on POSIX; replaced `openssl` subprocess in `release.sign_manifest()` with native PyCA `cryptography` Ed25519 signing. |
| **LOW-01** | Low | `wardr/service.py` | Unescaped paths/args in `systemd`, `launchd` XML, and elevated Windows PowerShell templates. | **Fixed** — Rejected control chars/newlines and applied format-specific escaping (`systemd` quoting, `xml.sax.saxutils.escape`, PowerShell escaping). |
| **LOW-02** | Low | `wardr/remediation.py` | `undo_fix` did not verify recorded directory/filename against the allowlisted spec and used `0o7777` mode mask. | **Fixed** — Verified `rel_dir` and `name` strictly against the allowlisted spec for `check_id` and masked restored permissions to `0o0777`. |
| **LOW-03 / LOW-04 / LOW-05** | Low | `wardr/fleet.py`, `wardr/ai_tiers.py`, `wardr/threat_network.py` | Missing `CORP: same-origin` on Fleet, unbounded `host_ids`, CR/LF allowed in API key, unpruned Fleet sessions, non-ASCII `admin_token` crash. | **Fixed** — Added `CORP: same-origin`, bounded `host_ids <= 500`, rejected control chars in `cloud_api_key`, pruned expired Fleet sessions, and UTF-8 encoded admin token comparison. |

---

## Remaining Roadmap Hardening Items (Tracked for Hosted Cloud Release)

1. **Dedicated Feed Ed25519 Key & Domain Separation (`HIGH-06` follow-up):** Rotate to a dedicated `wardr/keys/feed.pem` with explicit domain-separation prefixes (`wardr-release-v1\0` vs `wardr-defense-feed-v1\0`) when the hosted Rapid-Defense Feed publisher rotates keys.
2. **Hosted OAuth Broker & Telemetry Intake (`auth.getwardr.com` / `api.getwardr.com`):** Deploy the hosted Google OAuth broker and central telemetry collector for public community installs (local/self-hosted and Microsoft Public Client PKCE work immediately).
