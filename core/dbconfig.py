"""Database engine bootstrap (file, not DB — needed before first connect)."""
import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Env override so Docker can place db_config.json in a mounted folder alongside
# config.json. Falls back to the repo-root db_config.json for dev.
CONFIG_PATH = os.environ.get("DB_CONFIG_PATH") or os.path.join(BASE_DIR, "db_config.json")

DEFAULTS = {
    "engine": "sqlite",
    "sqlite": {"path": "database.db"},
    "mysql": {
        "host": "127.0.0.1",
        "port": 3306,
        "user": "root",
        "password": "",
        "database": "openworld",
        "charset": "utf8mb4",
    },
}


def load():
    cfg = {
        "engine": DEFAULTS["engine"],
        "sqlite": dict(DEFAULTS["sqlite"]),
        "mysql": dict(DEFAULTS["mysql"]),
    }
    if not os.path.isfile(CONFIG_PATH):
        save(cfg)
        return cfg
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        return cfg
    if not isinstance(raw, dict):
        return cfg
    eng = (raw.get("engine") or "sqlite").lower().strip()
    cfg["engine"] = eng if eng in ("sqlite", "mysql") else "sqlite"
    if isinstance(raw.get("sqlite"), dict):
        cfg["sqlite"].update({k: raw["sqlite"][k] for k in raw["sqlite"] if k in cfg["sqlite"]})
    if isinstance(raw.get("mysql"), dict):
        for k, v in raw["mysql"].items():
            if k in cfg["mysql"]:
                cfg["mysql"][k] = v
    return cfg


def save(cfg):
    eng = (cfg.get("engine") or "sqlite").lower().strip()
    if eng not in ("sqlite", "mysql"):
        eng = "sqlite"
    out = {
        "engine": eng,
        "sqlite": {
            "path": (cfg.get("sqlite") or {}).get("path") or DEFAULTS["sqlite"]["path"],
        },
        "mysql": {
            "host": (cfg.get("mysql") or {}).get("host") or DEFAULTS["mysql"]["host"],
            "port": int((cfg.get("mysql") or {}).get("port") or DEFAULTS["mysql"]["port"]),
            "user": (cfg.get("mysql") or {}).get("user") or DEFAULTS["mysql"]["user"],
            "password": (cfg.get("mysql") or {}).get("password", ""),
            "database": (cfg.get("mysql") or {}).get("database") or DEFAULTS["mysql"]["database"],
            "charset": (cfg.get("mysql") or {}).get("charset") or DEFAULTS["mysql"]["charset"],
        },
    }
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    return out


def engine():
    return load()["engine"]


def is_mysql():
    return engine() == "mysql"


def sqlite_path():
    path = load()["sqlite"]["path"] or "database.db"
    if not os.path.isabs(path):
        path = os.path.join(BASE_DIR, path)
    return path
