# ─────────────────────────────────────────────────────────────────────────────
# SECURITY RULE 1: Pin the base image version
# python:3.11-slim = minimal Debian + Python 3.11, ~120 MB (vs ~900 MB full)
# '3.11-slim' is explicit — 'latest' resolves to different content over time
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# ─────────────────────────────────────────────────────────────────────────────
# SECURITY RULE 2: Copy dependencies BEFORE source code (layer caching)
# requirements.txt rarely changes. app.py changes on every push.
# Copying requirements.txt first caches the pip install layer —
# skipped on every push that does not touch dependencies. Saves 60–120 sec.
# ─────────────────────────────────────────────────────────────────────────────
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# .dockerignore prevents .env, *.key, .git from entering the image build context
COPY app/ .

# ─────────────────────────────────────────────────────────────────────────────
# SECURITY RULE 3: Never run the container as root
# Docker runs processes as root (UID 0) by default. This is dangerous:
# a code execution vulnerability gives an attacker root inside the container.
# adduser creates 'appuser' with no password and no shell. USER switches to it.
# ─────────────────────────────────────────────────────────────────────────────
RUN adduser --disabled-password --gecos '' appuser
USER appuser

EXPOSE 5000

# Exec form (JSON array) — makes Python PID 1 so it receives SIGTERM directly
# for graceful shutdown. Shell form uses /bin/sh as PID 1 instead.
CMD ["python", "app.py"]
