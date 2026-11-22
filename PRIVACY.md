# Wardr Privacy Policy

**Effective Date:** November 22, 2026  
**Policy Version:** `2026-11-22`

> **Notice:** This privacy policy reflects Wardr's technical privacy architecture and security commitments. Have qualified legal counsel review and adapt this document for applicable jurisdictions (GDPR, CCPA/CPRA, etc.) before commercial launch.

## 1. Our Security-First Privacy Commitment
Wardr is engineered as a **local-first** cybersecurity platform. Your private SSH keys, passwords, API tokens, source code contents, and personal files are **never** uploaded to Wardr servers. All device security checks, file-integrity hashes, authorized self-pen-tests, and supply-chain inspections execute locally on your machine.

## 2. Account Information
When you create or sign into a Wardr account (via Email, Google SSO, or Microsoft SSO), Wardr collects only the minimum account metadata needed to authenticate you and provide support:
- Account ID, email address, display name, and sign-in provider (`email`, `google`, or `microsoft`)
- Timestamp and policy version of your Terms & Privacy acceptance
- Your explicit opt-in telemetry preferences

Email account passwords are protected with memory-hard salted `scrypt` hashes and constant-time verification — never stored in plaintext.

## 3. Strictly Opt-In System & Threat Telemetry
Telemetry is **disabled by default** and requires your explicit opt-in. If you choose to opt in to help improve Wardr's detections, debugging, and security updates:
- **Redacted System & Scan Diagnostics (`share_system_diagnostics`):** OS family/version, CPU architecture, Python/Wardr version, scan profile/duration, aggregate posture metrics, per-check ID/status/severity summaries (never raw file paths or evidence text), and self-pen-test probe outcomes.
- **Redacted Threat Intelligence (`share_threat_intelligence`):** Hashed threat fingerprints, exposed risky service port types (never IP addresses or hostnames), matched CVE/supply-chain package identifiers, and zero-day cluster metadata.
- **Local PII Redaction Before Transmission:** Before any telemetry leaves your machine, Wardr's local redactor (`wardr/reporting.py`) strips usernames, hostnames, home directory paths, IP addresses, email addresses, and API key patterns. You can preview the exact redacted JSON payload in the dashboard at any time.

## 4. Optional Cloud AI Offload (Tier 2)
- **Tier 1 (Always-On Local Radar)** and **Tier 3 (Local Ollama AI)** run 100% locally with zero outbound AI calls.
- If you explicitly enable **Tier 2 Free Cloud AI Offload**, Wardr transmits only a redacted posture summary over HTTPS to the provider endpoint you configured. Your API key is stored locally with owner-only (`0600`) file permissions.

## 5. Offline / Air-Gapped Mode
Security researchers and air-gapped environments can run `wardr serve --offline` to disable all outbound network requests, account sync, advisory downloads, and cloud telemetry.

## 6. Storage, Export, and Deletion Rights
- **Local storage:** All local Wardr state files are stored under owner-only (`0700` directory / `0600` credential files) permissions in your OS user state directory and may be deleted at any time.
- **Account & telemetry deletion:** You can opt out of telemetry at any time inside Wardr's **Account & Privacy** modal, or request full export/deletion of cloud account records by contacting `privacy@getwardr.com`.
