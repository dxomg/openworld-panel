# Deploying with Docker

The panel ships as a multi-service Docker Compose stack: a MariaDB database,
a gunicorn web process, and a standalone job worker. All three are built from
the same image.

## Quick start

```bash
cp .env.example .env
# edit .env — set FLASK_SECRET_KEY and MYSQL_PASSWORD / MYSQL_ROOT_PASSWORD
docker compose up -d --build
```

The panel listens on **http://localhost:5000**.

On first boot the entrypoint:

1. writes `db_config.json` from the `MYSQL_*` env vars,
2. waits for MariaDB to be healthy,
3. runs `createdb.py` (idempotent — `CREATE TABLE IF NOT EXISTS`),
4. starts the service (`gunicorn` for `web`, `python worker.py` for `worker`).

`config.json` (panel settings) is auto-generated on first run and persisted in
the `panel-config` volume, so settings survive restarts. To pre-configure it,
mount your own `config.json` over `/app/config.json`.

## Services

| service | image | role |
|---------|-------|------|
| `db`     | `mariadb:11`            | database (data in `db-data` volume) |
| `web`    | `openworld-panel:latest`| gunicorn serving the panel on `:5000` |
| `worker` | `openworld-panel:latest`| background job loop (provision / suspend / upgrade …) |

The web container has `WORKER_ENABLED_IN_WEB=false` so the in-process worker
thread is disabled — the separate `worker` service owns job processing. The
worker container runs `worker.py` (which sets `OPENWORLD_WORKER=1`).

## Configuration (env)

See `.env.example`. Key variables:

- `FLASK_SECRET_KEY` — Flask session secret (generate with
  `python -c "import secrets; print(secrets.token_hex(32))"`).
- `MYSQL_PASSWORD`, `MYSQL_USER`, `MYSQL_DATABASE`, `MYSQL_ROOT_PASSWORD`
- `DB_ENGINE` — `mysql` (default) or `sqlite` (stores `database.db` in the
  `panel-data` volume at `/data/database.db`).

## Building the image manually

```bash
docker build -t openworld-panel:latest .
```

## Captcha

The panel expects a captcha microservice (see `../captcha`). Build and run
that image alongside this stack, then point the panel at it via
`config.json` → `captcha.url` / `captcha.api_key` / `captcha.secret`.

## Notes

- Containers run as a non-root user (`openworld`, uid 10001).
- `cap_drop: ALL` on every service; the DB gets the few caps MariaDB needs.
- Healthcheck hits `/admin/worker-status` on the web service.
