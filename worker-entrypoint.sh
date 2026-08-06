#!/bin/sh
set -e

cd /app

# --- Database config (db_config.json) from environment (mirrors the web entrypoint) ---
ENGINE="${DB_ENGINE:-mysql}"
cat > /app/db_config.json <<EOF
{
  "engine": "$ENGINE",
  "sqlite": {"path": "${SQLITE_PATH:-/data/database.db}"},
  "mysql": {
    "host": "${MYSQL_HOST:-db}",
    "port": ${MYSQL_PORT:-3306},
    "user": "${MYSQL_USER:-openworld}",
    "password": "${MYSQL_PASSWORD:-changeme}",
    "database": "${MYSQL_DATABASE:-openworld}",
    "charset": "utf8mb4"
  }
}
EOF
echo "[worker-entrypoint] wrote db_config.json (engine=$ENGINE)"

# --- config.json: shared with web via the panel-config volume ---
if [ ! -f /app/config.json ]; then
  echo "[worker-entrypoint] no config.json — generating one with defaults"
fi

# --- Wait for MySQL before starting the job loop (we don't create the schema
#     here — the web service owns schema init; we just need the DB reachable) ---
if [ "$ENGINE" = "mysql" ]; then
  echo "[worker-entrypoint] waiting for MySQL at ${MYSQL_HOST:-db}:${MYSQL_PORT:-3306} ..."
  python - <<'PYEOF'
import os, sys, time, pymysql
host = os.environ.get("MYSQL_HOST", "db")
port = int(os.environ.get("MYSQL_PORT", "3306"))
deadline = time.time() + 60
last_err = None
while time.time() < deadline:
    try:
        conn = pymysql.connect(
            host=host, port=port,
            user=os.environ.get("MYSQL_USER", "openworld"),
            password=os.environ.get("MYSQL_PASSWORD", "changeme"),
            database=os.environ.get("MYSQL_DATABASE", "openworld"),
            charset="utf8mb4",
        )
        conn.close()
        print("[worker-entrypoint] MySQL is up", file=sys.stderr)
        break
    except Exception as e:
        last_err = e
        time.sleep(2)
else:
    print(f"[worker-entrypoint] FATAL: MySQL not reachable after 60s: {last_err}", file=sys.stderr)
    sys.exit(1)
PYEOF
fi

echo "[worker-entrypoint] exec: $@"
exec "$@"
