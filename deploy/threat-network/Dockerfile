FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Create an unprivileged service user and owner-only state directory
RUN groupadd --gid 10001 wardr \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin wardr \
    && mkdir -p /data \
    && chown wardr:wardr /data \
    && chmod 0700 /data

COPY pyproject.toml LICENSE README.md PRIVACY.md TERMS.md SECURITY.md ./
COPY wardr ./wardr

RUN pip install --no-cache-dir .

USER wardr

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/v1/health', timeout=3)" || exit 1

ENTRYPOINT ["/bin/sh", "-ec", "\
  ARGS=\"--state-dir /data threat-network --host 0.0.0.0 --port 8787\"; \
  if [ -n \"${WARDR_ADMIN_TOKEN:-}\" ]; then ARGS=\"$ARGS --admin-token $WARDR_ADMIN_TOKEN\"; fi; \
  if [ -f \"/run/secrets/feed-ed25519.pem\" ]; then ARGS=\"$ARGS --signing-key /run/secrets/feed-ed25519.pem\"; fi; \
  exec wardr $ARGS"]
