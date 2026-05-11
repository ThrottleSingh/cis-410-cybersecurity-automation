# Dockerfile.vulnerable
# ─────────────────────────────────────────────────────────────────────────────
# INTENTIONALLY INSECURE — for Week 4 observation and Week 5 scanning exercise.
# Do NOT use this Dockerfile for staging or production.
#
# HOW TO USE:
#   Before deploying, copy the vulnerable app files into app/ first:
#     cp vulnerable_app/app.py app/app.py
#     cp vulnerable_app/requirements.txt app/requirements.txt
#     cp -r vulnerable_app/templates/. app/templates/
#   Then swap this file over the main Dockerfile:
#     cp Dockerfile.vulnerable Dockerfile
#   Then commit and push.
#
#   The deploy workflow copies app/ and Dockerfile to the VM.
#   app/ now contains the vulnerable app files.
#
# Violations present for Week 5 scanners to detect:
#
#   VIOLATION 1: Unpinned base image — 'python:3.11' instead of 'python:3.11-slim'
#   The full image is ~900MB vs ~120MB for slim. 'python:3.11' resolves to a
#   different digest on every pull — builds are not reproducible and may
#   silently include new vulnerabilities. Trivy will report CVEs.
#
#   VIOLATION 2: Source code copied before dependencies (no layer caching)
#   COPY . . copies everything before pip install runs. Every push rebuilds
#   from scratch — no caching.
#
#   VIOLATION 3: No USER instruction — container runs as root (UID 0)
#   If the app has a code execution vulnerability, attacker gets root inside
#   the container. Trivy and Semgrep will both flag this.
#   Verify: docker compose exec web whoami  →  returns 'root' not 'appuser'
# ─────────────────────────────────────────────────────────────────────────────

# VIOLATION 1: Unpinned base image
FROM python:3.11

WORKDIR /app

# VIOLATION 2: Copy everything before installing dependencies — no layer caching
COPY . .

# app/requirements.txt is populated by copying vulnerable_app/requirements.txt
# into app/ before committing (see HOW TO USE above)
RUN pip install --no-cache-dir -r app/requirements.txt

EXPOSE 5000

# VIOLATION 3: No USER instruction — runs as root
CMD ["python", "app/app.py"]
