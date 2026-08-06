# Openworld Panel

A self-hostable VPS hosting panel (Flask) that provisions and manages LXC
containers on Proxmox nodes. Includes billing (PayPal + manual), a web SSH
console, tickets, plans, and an optional math-captcha microservice.

```
hosting/
├── captcha/   # standalone math-captcha service (FastAPI)
└── client/    # the panel itself (Flask + gunicorn + worker)
```

This guide covers running the panel in **development** and **production**.

---

## Requirements

- Python 3.12+ (the Docker image uses 3.12-slim; dev was tested on 3.13)
- (Production) Docker + Docker Compose
- (Production) A Proxmox node to actually provision VPS on
- (Optional) The captcha service for login anti-bot

---

## 1. Development mode

Dev runs the panel directly with Flask's built-in server, SQLite on disk, and
the job worker as an in-process thread. No Docker needed.

### 1.1 Create a virtualenv and install deps

```bash
cd client
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 1.2 Initialize the database

The panel uses SQLite by default (`database.db` in the project dir). Create the
schema once (idempotent — `CREATE TABLE IF NOT EXISTS`):

```bash
python createdb.py
```

On first run the app also auto-generates two config files if missing:

- `config.json` — panel settings (project name, paypal, captcha, billing…)
- `db_config.json` — database engine/credentials (defaults to sqlite)

### 1.3 Create the first admin user

There is no self-registration route. Pick **one** of:

**Option A — Discord login (recommended if Discord is configured):**
Sign in via Discord at `/discord-login`. The **first** user created becomes an
admin automatically (see `utils/services.findorcreatediscorduser`).

**Option B — manual SQL (email/password login):**

```bash
python - <<'PY'
from utils import services
from core import db
import uuid
db.adduser(
    uuid=str(uuid.uuid4()),
    username="admin",
    email="admin@example.com",
    password=services.hashpassword("change-me"),
    role="admin",
    verified=1,
)
PY
```

Then log in at `/login`.

### 1.4 Run the panel

```bash
python main.py
```

This starts Flask on `http://0.0.0.0:5000` (debug on) **and** the in-process
job worker thread (`worker.enabled_in_web` defaults to `true` in dev). Open
http://localhost:5000 and log in with the admin you just created.

> Optional: run the captcha service so the login captcha works.
> ```bash
> cd ../captcha
> python -m venv .venv && source .venv/bin/activate
> pip install -r requirements.txt
> uvicorn main:app --host 0.0.0.0 --port 8000
> ```
> Then set `captcha.url` / `captcha.api_key` / `captcha.secret` in `config.json`.

### 1.5 Configure a node + plan (so you can create a VPS)

In the admin UI:

1. **Settings → Database / General / Billing / Captcha** — review defaults.
2. **Locations** — add a location.
3. **Nodes** — add your Proxmox node (host, user `root@pam`, password, node
   name, port 8006). Manage → fetch storage pools + image storage, create a
   network.
4. **OS Images** — add an image (e.g. `ubuntu-24.04-standard`) and assign it
   to the node's image storage.
5. **Plans** — create a Free plan (price 0) and/or a Paid plan (price > 0),
   assign to the node + storage pool.
6. Generate IPs under the node's network.

You can now create a VPS from the dashboard.

### 1.6 Dev with a separate worker (optional)

To run the worker out-of-process (useful when debugging jobs):

```bash
# terminal 1 — web only (disable in-web worker)
WORKER_ENABLED_IN_WEB=false python main.py
# terminal 2 — standalone worker
python worker.py
```

---

## 2. Production mode (Docker)

The panel ships as a 3-service Compose stack: MariaDB, gunicorn web, and a
standalone job worker — all from one image.

### 2.1 Configure

```bash
cd client
cp .env.example .env
```

Edit `.env`:

- `FLASK_SECRET_KEY` — generate with
  `python -c "import secrets; print(secrets.token_hex(32))"`
- `MYSQL_PASSWORD`, `MYSQL_ROOT_PASSWORD` — strong, unique
- (Optional) leave `DB_ENGINE=mysql` (default) or set `DB_ENGINE=sqlite` to
  store `database.db` in the `panel-data` volume instead.
- (Optional) **Use host folders instead of Docker volumes** — see §2.1.1.

### 2.1.1 Use host folders (bind mounts) instead of named volumes

By default the stack persists data in Docker named volumes (`db-data`,
`panel-config`, `panel-data`). To keep everything on the host filesystem
(e.g. for easy backups or inspection), set these in `.env` to local paths
and `mkdir -p` them first:

```bash
mkdir -p ./data/mysql ./data
touch ./data/config.json          # PANEL_CONFIG is a FILE, not a folder
# then in .env:
#   DB_DATA=./data/mysql
#   PANEL_DATA=./data
#   PANEL_CONFIG=./data/config.json
```

Docker treats a relative/absolute path as a **bind mount** (vs. a bare
identifier → named volume). The folders must be writable by uid 10001 (the
container user). The three mount points are:

| variable        | default (volume) | bind example          | what it holds |
|-----------------|------------------|-----------------------|---------------|
| `DB_DATA`       | `db-data`        | `./data/mysql`        | MariaDB data dir |
| `PANEL_DATA`    | `panel-data`     | `./data`              | SQLite db (if used) + worker heartbeat |
| `PANEL_CONFIG`  | `panel-config`   | `./data/config.json`  | `config.json` — **a file**, not a folder |

### 2.2 Build & launch

```bash
docker compose up -d --build
```

The panel is on **http://localhost:5000**.

On first boot each service's entrypoint writes `db_config.json` from the
`MYSQL_*` env vars and waits for MariaDB. The **web** service then runs
`createdb.py` (idempotent schema) before starting gunicorn; the **worker**
service (its own slimmer image) just waits for the DB and starts `worker.py`
(it depends on `web` so the schema exists first).

`config.json` is auto-generated and persisted in the `panel-config` volume,
so panel settings survive restarts. To pre-seed settings, mount your own
`config.json` over `/app/config.json`.

### 2.3 Create the first admin (production)

Same options as dev (§1.3), run inside the web container:

```bash
docker compose exec web python - <<'PY'
from utils import services
from core import db
import uuid
db.adduser(
    uuid=str(uuid.uuid4()),
    username="admin",
    email="admin@example.com",
    password=services.hashpassword("change-me"),
    role="admin",
    verified=1,
)
PY
```

Or configure Discord OAuth (`discord.clientid` / `clientsecret` in
`config.json`) and sign in via `/discord-login` — the first user becomes admin.

### 2.4 Services & scaling

The web and worker are **separate images**: the web image (`openworld-panel`,
`Dockerfile`) carries templates/static/gunicorn; the worker image
(`openworld-worker`, `Dockerfile.worker`) is slimmer — no web server, no port,
just the job loop — and is health-checked via its heartbeat file.

| service  | image                  | role                                            | scale |
|----------|------------------------|-------------------------------------------------|-------|
| `db`     | `mariadb:11`           | database (data in `db-data` volume)             | 1 |
| `web`    | `openworld-panel`      | gunicorn serving the panel on `:5000`           | 1+ (raise `-w` workers; add replicas behind a LB) |
| `worker` | `openworld-worker`     | background job loop (provision/suspend/upgrade) | 1+ (jobs are row-locked, so replicas are safe) |

The worker depends on `web` (so the web service has run `createdb.py` first)
and on `db` being healthy. The web container sets `WORKER_ENABLED_IN_WEB=false`
and both containers point `WORKER_HEARTBEAT_PATH=/data/worker.heartbeat` at the
shared `panel-data` volume, so the web container can report worker liveness.

### 2.5 Captcha in production

Build & run the captcha image alongside the stack (see `captcha/Dockerfile`),
then set in `config.json`:

```json
"captcha": { "enabled": true, "url": "http://captcha:8000",
              "api_key": "...", "secret": "..." }
```

### 2.6 Reverse proxy / TLS

Put a reverse proxy (Caddy, nginx, Traefik) in front of `web:5000` for TLS and
to set `X-Forwarded-For` / `X-Real-IP`. The panel reads the client IP from
`network.ip_source` in `config.json` (`remote_addr` default, or
`x_forwarded_for` / `x_real_ip` behind a proxy). Note: session cookies are set
`Secure=true`, so the panel **must** be served over HTTPS in production.

---

## 3. Configuration reference

### `config.json` (panel settings)

Auto-generated on first run; editable in **Admin → Settings** or by mounting
the file. Key sections:

| section     | notable keys |
|-------------|--------------|
| `general`   | `projectname`, `timezone`, `defaultcookiettl`, `discord` |
| `server`    | `host`, `port`, `debug` (dev only) |
| `paypal`    | `email`, `sandbox`, `base_url` |
| `discord`   | `clientid`, `clientsecret`, `redirecturl` |
| `billing`   | `paid_period_days`, `free_period_days`, `warn_days`, `free_renew_cooldown_hours` |
| `ratelimit` | `enabled`, `global`, `login`, `checkout`, `renew`, … |
| `captcha`   | `enabled`, `url`, `api_key`, `secret` |
| `worker`    | `enabled_in_web`, `poll_seconds`, `maintenance_seconds` |
| `network`   | `ip_source` (`remote_addr` / `x_forwarded_for` / `x_real_ip`) |
| `console`   | `timeout`, `metrics` |

### `db_config.json` (database)

Auto-generated on first run; in Docker it is written from env by the
entrypoint. Editable in **Admin → Settings → Database**.

```json
{
  "engine": "mysql",
  "sqlite": { "path": "database.db" },
  "mysql": { "host": "db", "port": 3306, "user": "openworld",
             "password": "...", "database": "openworld", "charset": "utf8mb4" }
}
```

To switch engines in a running deployment: change it in the admin UI (or edit
the file), then restart the panel and run `python createdb.py` once.

### Environment variables (Docker)

| variable | purpose | default |
|----------|---------|---------|
| `FLASK_SECRET_KEY` | Flask session signing key | generated if unset |
| `WORKER_ENABLED_IN_WEB` | `false` to run the worker as a separate service | `true` |
| `WORKER_HEARTBEAT_PATH` | where the worker writes its liveness file | `worker.heartbeat` |
| `DB_ENGINE` | `mysql` or `sqlite` | `mysql` |
| `MYSQL_HOST` / `MYSQL_PORT` / `MYSQL_USER` / `MYSQL_PASSWORD` / `MYSQL_DATABASE` | MySQL connection | `db` / `3306` / `openworld` / … |
| `SQLITE_PATH` | sqlite db path (when `DB_ENGINE=sqlite`) | `/data/database.db` |

---

## 4. Operations

### Backups

- **MariaDB:** `docker compose exec db mariadb-dump -u root -p openworld > backup.sql`
- **Named volumes (default):** `db-data` (the database), `panel-config` (panel
  settings), `panel-data` (sqlite + worker heartbeat if used).
- **Host folders (bind mounts):** if you set `DB_DATA`/`PANEL_DATA`/`PANEL_CONFIG`
  to local paths, just back up those folders directly — no `docker volume` step
  needed.

### Logs

```bash
docker compose logs -f web
docker compose logs -f worker
```

### Re-run schema migrations

The schema is idempotent. To re-apply (e.g. after a code update that adds a
column via a `ensure*` live-migrate helper):

```bash
docker compose exec web python createdb.py
```

### Update the image

```bash
git pull
docker compose up -d --build
```

---

## 5. Troubleshooting

- **Can't log in / "Invalid email or password"** — the captcha may be
  enabled without a running captcha service. Set `captcha.enabled=false` in
  `config.json` or start the captcha container. To create an admin without
  the login form, use the `docker compose exec web python …` snippet in §2.3.
- **VPS stuck in `creating`** — the worker isn't processing jobs. Check
  `docker compose logs worker` and that the Proxmox node is reachable and
  correctly configured under **Admin → Nodes**.
- **Cookies rejected / can't stay logged in over HTTP** — session cookies are
  `Secure`; serve the panel over HTTPS (e.g. via a reverse proxy) in
  production.
- **`VPS not found` when an admin opens another user's console** — this was a
  bug in the WebSocket ownership check; ensure you're running the latest code.

