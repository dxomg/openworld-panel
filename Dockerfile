# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm AS base

# Tini for proper signal handling (gunicorn + worker graceful shutdown)
RUN apt-get update \
 && apt-get install -y --no-install-recommends tini \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (deps installed in image — do NOT copy local venv)
COPY core/ ./core/
COPY utils/ ./utils/
COPY templates/ ./templates/
COPY static/ ./static/
COPY main.py worker.py createdb.py populatedb.py ./
COPY entrypoint.sh ./
RUN chmod +x /app/entrypoint.sh

# Persistent data mount point (sqlite db, worker heartbeat, uploaded assets)
RUN mkdir -p /data && chown -R 10001:10001 /app /data

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# non-root
RUN useradd -r -u 10001 -g users openworld
USER openworld

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/', timeout=3)" || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/app/entrypoint.sh"]
