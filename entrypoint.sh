#!/bin/sh
set -e

# Where the app lives
cd /app

# --- Database config (db_config.json) from environment ---
# Written into the mounted PANEL_DATA folder so it persists alongside
# config.json when using host folders. Set DB_CONFIG_PATH to override.
DB_CFG="${DB_CONFIG_PATH:-/data/db_config.json}"
ENGINE="${DB_ENGINE:-mysql}"
mkdir -p "$(dirname "$DB_CFG")" 2>/dev/null || true
cat > "$DB_CFG" <<EOF
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
echo "[entrypoint] wrote $DB_CFG (engine=$ENGINE)"

# --- panel config.json ---
# The app reads/writes config.json at CONFIG_PATH (env), which in Docker points
# at /data/config.json inside the mounted PANEL_DATA folder. It's auto-generated
# with defaults on first run if missing — no pre-creation needed.
PANEL_CFG="${CONFIG_PATH:-/data/config.json}"
if [ ! -f "$PANEL_CFG" ]; then
  echo "[entrypoint] no config.json at $PANEL_CFG — app will generate one with defaults"
fi

# --- Writable check ---
# If using a host-folder bind mount for /data, the folder must be writable by
# the container user (uid 10001). Give a clear error instead of a confusing
# write failure later.
if ! [ -w "$(dirname "$PANEL_CFG")" ]; then
  echo "[entrypoint] FATAL: $(dirname "$PANEL_CFG") is not writable by uid $(id -u)." >&2
  echo "[entrypoint] On the host, run: chown -R 10001:10001 <your PANEL_DATA folder>" >&2
  exit 1
fi

# --- Schema init (idempotent: CREATE TABLE IF NOT EXISTS) ---
# Wait for MySQL to be reachable before creating schema.
if [ "$ENGINE" = "mysql" ]; then
  echo "[entrypoint] waiting for MySQL at ${MYSQL_HOST:-db}:${MYSQL_PORT:-3306} ..."
  python - <<'PYEOF'
import os, sys, time, pymysql
host = os.environ.get("MYSQL_HOST", "db")
port = int(os.environ.get("MYSQL_PORT", "3306"))
user = os.environ.get("MYSQL_USER", "openworld")
password = os.environ.get("MYSQL_PASSWORD", "changeme")
database = os.environ.get("MYSQL_DATABASE", "openworld")
deadline = time.time() + 60
last_err = None
while time.time() < deadline:
    try:
        conn = pymysql.connect(host=host, port=port, user=user, password=password, database=database, charset="utf8mb4")
        # ensure the database exists (CREATE DATABASE ... might fail if user lacks priv;
        # in compose we grant it, but be tolerant)
        try:
            conn.cursor().execute(f"CREATE DATABASE IF NOT EXISTS `{database}` CHARACTER SET utf8mb4")
            conn.commit()
        except Exception:
            pass
        conn.close()
        print("[entrypoint] MySQL is up", file=sys.stderr)
        break
    except Exception as e:
        last_err = e
        time.sleep(2)
else:
    print(f"[entrypoint] FATAL: MySQL not reachable after 60s: {last_err}", file=sys.stderr)
    sys.exit(1)
PYEOF
fi

echo "[entrypoint] creating schema (idempotent) ..."
python createdb.py || {
  echo "[entrypoint] WARNING: createdb.py failed — continuing in case schema already exists"
}

# --- Run the actual command (gunicorn / worker / etc.) ---
echo "[entrypoint] exec: $@"
exec "$@"
