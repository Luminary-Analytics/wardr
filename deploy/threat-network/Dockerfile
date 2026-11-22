FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Create an unprivileged service user (UID 1000 matches standard cloud persistent disk mounts)
RUN groupadd --gid 1000 wardr \
    && useradd --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin wardr \
    && mkdir -p /data/state \
    && chown -R wardr:wardr /data \
    && chmod 0755 /data \
    && chmod 0700 /data/state

COPY pyproject.toml LICENSE README.md PRIVACY.md TERMS.md SECURITY.md ./
COPY wardr ./wardr

RUN pip install --no-cache-dir .

USER wardr

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\", \"8787\")}/v1/health', timeout=3)" || exit 1

ENTRYPOINT ["/bin/sh", "-ec", "\
  PORT=\"${PORT:-8787}\"; \
  STATE_DIR=\"${WARDR_STATE_DIR:-/data/state}\"; \
  mkdir -p \"$STATE_DIR\"; \
  chmod 0700 \"$STATE_DIR\"; \
  ARGS=\"--state-dir $STATE_DIR threat-network --host 0.0.0.0 --port $PORT\"; \
  if [ -n \"${WARDR_ADMIN_TOKEN:-}\" ]; then ARGS=\"$ARGS --admin-token $WARDR_ADMIN_TOKEN\"; fi; \
  if [ -f \"/run/secrets/feed-ed25519.pem\" ]; then ARGS=\"$ARGS --signing-key /run/secrets/feed-ed25519.pem\"; fi; \
  exec wardr $ARGS"]
