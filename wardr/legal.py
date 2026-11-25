"""Structured Privacy Policy and Terms of Use served both in-app and mirrored in PRIVACY.md / TERMS.md."""

from __future__ import annotations

POLICY_VERSION = "2026-11-22"
EFFECTIVE_DATE = "November 22, 2026"

PRIVACY_SECTIONS: tuple[dict, ...] = (
    {
        "heading": "1. Our Security-First Privacy Commitment",
        "body": (
            "Wardr is built as a local-first security platform. Your private SSH keys, passwords, API secrets, "
            "source code contents, and personal files are NEVER uploaded to Wardr servers. All security scans, "
            "file-integrity hashes, self-pen-tests, and supply-chain inspections execute locally on your device."
        ),
    },
    {
        "heading": "2. Account Information You Provide",
        "body": (
            "When you create or sign into a Wardr account (via Email, Google SSO, or Microsoft SSO), we store "
            "only the minimum identity data needed to authenticate your session and provide support: your account "
            "identifier, email address, display name, sign-in provider, and your explicit consent/telemetry preferences. "
            "Password credentials for email accounts are stored using memory-hard salted scrypt hashes — never plaintext."
        ),
    },
    {
        "heading": "3. Strictly Opt-In System & Threat Telemetry",
        "body": (
            "Diagnostic and threat telemetry is OFF by default and requires your explicit opt-in. When opted in, "
            "Wardr strips usernames, hostnames, home directory paths, local IP addresses, email addresses, and API key "
            "patterns locally BEFORE transmission. You can inspect the exact redacted JSON payload in-app at any time "
            "and opt out with one click."
        ),
    },
    {
        "heading": "4. Optional Cloud AI Offload (Tier 2)",
        "body": (
            "Tier 1 (Local Radar) and Tier 3 (Local Ollama AI) run 100% locally with zero outbound AI calls. "
            "If you explicitly configure Tier 2 Cloud AI Offload with your own API key, Wardr sends only a redacted "
            "posture summary over HTTPS to your chosen provider. API keys are stored locally with owner-only (0600) permissions."
        ),
    },
    {
        "heading": "5. Data Retention, Export & Deletion Rights",
        "body": (
            "Local state files live in your user profile directory under owner-only permissions and can be deleted "
            "at any time. For cloud account data, you may request export or permanent deletion of your account and "
            "associated redacted diagnostics at any time via privacy@getwardr.com or your account settings."
        ),
    },
)

TERMS_SECTIONS: tuple[dict, ...] = (
    {
        "heading": "1. Authorized Local Use Only",
        "body": (
            "Wardr's security scans, network exposure tables, supply-chain audits, and Self-Pen-Test probes are "
            "strictly for devices, networks, and codebases you own or have explicit written authorization to assess. "
            "You may not repurpose Wardr to probe, scan, or attack unauthorized third-party systems."
        ),
    },
    {
        "heading": "2. Non-Destructive Hardening & User Responsibility",
        "body": (
            "Wardr designs all automated remediations and Self-Pen-Test probes to be allowlisted, non-destructive, "
            "and reversible where technically possible. However, modifying OS firewall rules, service bindings, or "
            "file permissions can affect local developer workflows. You are responsible for reviewing prompts and "
            "maintaining backups of critical systems."
        ),
    },
    {
        "heading": "3. No Absolute Guarantee of Security",
        "body": (
            "No cybersecurity tool can guarantee 100% immunity against all threats or zero-day attacks. Wardr "
            "provides continuous defense-in-depth visibility, hardening, and verified advisories on an 'AS IS' basis "
            "under the MIT License without warranty of uninterrupted or error-free protection."
        ),
    },
    {
        "heading": "4. Accounts, Acceptable Use & Updates",
        "body": (
            "Keep your account credentials and local dashboard launch link private. Wardr verifies signed software "
            "releases using Ed25519 signatures and SHA-256 checksums before installation. Air-gapped and security "
            "research environments may run Wardr locally with the '--offline' flag."
        ),
    },
    {
        "heading": "5. Contact & Security Disclosures",
        "body": (
            "Report security vulnerabilities privately via GitHub Security Advisories (see SECURITY.md). "
            "If you self-host Wardr services for an organization, review these terms with legal counsel for applicable compliance requirements (GDPR, CCPA, SOC 2)."
        ),
    },
)


def legal_payload() -> dict:
    return {
        "policy_version": POLICY_VERSION,
        "effective_date": EFFECTIVE_DATE,
        "privacy": [dict(s) for s in PRIVACY_SECTIONS],
        "terms": [dict(s) for s in TERMS_SECTIONS],
    }
