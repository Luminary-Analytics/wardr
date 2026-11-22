# Wardr Terms of Use

**Effective Date:** November 22, 2026  
**Policy Version:** `2026-11-22`

> **Notice:** These Terms of Use reflect Wardr's operational boundaries and open-source licensing. Have qualified legal counsel review and adapt this document before commercial launch.

## 1. Authorized Use Only
Wardr's security scans, network exposure audits, supply-chain scanners, and Self-Pen-Test probes are designed exclusively for devices, networks, and code repositories that you own or have explicit written authorization to test. You agree not to use or modify Wardr to scan, probe, or disrupt third-party systems without authorization.

## 2. Automated Remediations & Self-Pen-Testing
Wardr restricts built-in automated fixes and Self-Pen-Test probes to allowlisted, non-destructive, locally scoped actions. Modifying host firewalls, service bindings (such as localhost-only binding), or file permissions may impact local development workflows. You remain responsible for reviewing confirmation dialogs and maintaining appropriate backups.

## 3. Open-Source License & Disclaimer of Warranty
Wardr Community is licensed under the [MIT License](LICENSE). While Wardr strives to deliver defense-in-depth visibility and timely advisories, no security software can prevent every attack or zero-day exploit. Wardr is provided **"AS IS"**, without warranty of any kind, express or implied, to the maximum extent permitted by law.

## 4. Accounts, SSO & Security Responsibilities
- You are responsible for safeguarding your Wardr account credentials, SSO sessions, and private local dashboard launch links.
- Software updates distributed by Wardr are cryptographically verified via Ed25519 manifest signatures and SHA-256 checksums before installation.
- Opt-in telemetry is governed by the [Wardr Privacy Policy](PRIVACY.md).

## 5. Vulnerability Disclosure
If you discover a security vulnerability in Wardr itself, please report it privately following [SECURITY.md](SECURITY.md) rather than publishing an uncoordinated exploit.
