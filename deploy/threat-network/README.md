# Deploying Wardr Threat Network & Central Telemetry (`api.getwardr.com`)

This production stack runs `wardr threat-network` as a hardened, read-only non-root container behind Caddy (automatic Let's Encrypt HTTPS).

It powers:
- `POST /api/v1/telemetry/ingest` — opt-in, locally redacted system & scan diagnostics
- `GET /api/v1/telemetry/summary` — admin analytics (top failing checks, pen-test exposures, risky ports, supply-chain CVE hits, OS/version breakdown)
- `POST /v1/reports` & `GET /v1/clusters` — vulnerability & zero-day report intake and clustering
- `GET /feeds/defense-v1.json` & `.sig` + `POST /v1/feeds/publish` — Ed25519-signed Rapid-Defense Feeds

## 1. Point DNS
Create an `A` / `AAAA` record for `api.getwardr.com` pointing to your host's public IP (ports `80` and `443` open).

## 2. Configure Secrets & Launch
```bash
cd deploy/threat-network
python3 -c "import secrets; print('WARDR_ADMIN_TOKEN=' + secrets.token_urlsafe(32))" > .env
chmod 600 .env

# Optional: place your Ed25519 private signing key (matching wardr/keys/release.pem)
# at ./secrets/feed-ed25519.pem (chmod 600) and uncomment the bind mount in docker-compose.yml.

docker compose up -d --build
```

## 3. Verify Health & Pull Central Analytics
```bash
# Public health check
curl -sS https://api.getwardr.com/v1/health | python3 -m json.tool

# Pull aggregated opt-in system & scan telemetry (requires admin Bearer token)
source .env
curl -sS -H "Authorization: Bearer $WARDR_ADMIN_TOKEN" \
  https://api.getwardr.com/api/v1/telemetry/summary | python3 -m json.tool

# Pull clustered zero-day / vulnerability reports
curl -sS -H "Authorization: Bearer $WARDR_ADMIN_TOKEN" \
  https://api.getwardr.com/v1/clusters | python3 -m json.tool
```
