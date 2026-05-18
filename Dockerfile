# Dockerfile  —  CorpDirectory SECURE (Week 5)
# ─────────────────────────────────────────────────────────────────────────────
# FIXES from Dockerfile.vulnerable:
#
#   1. FROM python:3.11-slim        ← pinned slim image (reduces attack surface + CVEs)
#      was: FROM python:3.11        ← full image, hundreds of extra packages
#
#   2. Deps layer BEFORE source     ← correct cache ordering
#      COPY requirements.txt first, pip install, THEN copy app source
#      was: COPY . . first          ← every code change invalidates the dep cache
#
#   3. Non-root user                ← container does not run as root
#      RUN adduser --disabled-password appuser
#      USER appuser
#      was: no USER instruction     ← process ran as root inside the container
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim

WORKDIR /app

# Install dependencies first — this layer is cached unless requirements.txt changes
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source after dependencies
COPY app/ .

# Create a non-root user and switch to it
# Security: if the container is compromised, the attacker has no root privileges
RUN adduser --disabled-password --gecos "" appuser
USER appuser

EXPOSE 5000

CMD ["python", "app.py"]
