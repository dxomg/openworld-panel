"""Panel settings in config.json (not the DB)."""
import copy
import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

DEFAULTS = {
    "general": {
        "projectname": "Openworld",
        "theme": "catppuccin",
        "timezone": "UTC",
        "passwordlength": 24,
        "cookielength": 128,
        "defaultcookiettl": 7,
        "favicon": "/static/favicon.ico",
        "logo": "/static/logo.png",
        "discord": "https://discord.gg/ZJrg5sGr5R",
    },
    "server": {
        "host": "0.0.0.0",
        "port": 5000,
        "debug": True,
    },
    "paypal": {
        "email": "example@example.com",
        "sandbox": True,
        "base_url": "http://localhost:5000",
    },
    "discord": {
        "clientid": "changeme",
        "clientsecret": "changeme",
        "redirecturl": "http://localhost:5000/discord-callback",
        "discordbaseurl": "https://discord.com/api",
    },
    "loadbalancing": {
        "strategy": "both",
    },
    "console": {
        "timeout": 10,
        "metrics": "dynamic",
    },
    "network": {
        "ip_source": "remote_addr",
    },
    "billing": {
        "paid_period_days": 30,
        "free_period_days": 7,
        "warn_days": 7,
        "free_renew_cooldown_hours": 24,
    },
    "ratelimit": {
        "enabled": True,
        "global": "120/minute",
        "login": "10/minute",
        "discord": "20/minute",
        "create_vps_free": "2/day",
        "create_vps_paid": "10/hour",
        "renew": "20/hour",
        "ticket": "15/hour",
        "console": "30/minute",
        "checkout": "20/hour",
    },
    "captcha": {
        "enabled": True,
        "url": "http://127.0.0.1:8000",
        "api_key": "",
        "secret": "",
    },
    "worker": {
        # In production with gunicorn -w N: set enabled_in_web false and run `python worker.py`
        "enabled_in_web": True,
        "poll_seconds": 2,
        "maintenance_seconds": 60,
        "stale_job_minutes": 45,
        "heartbeat_path": "worker.heartbeat",
    },
}


def _deep_merge(base, overlay):
    out = copy.deepcopy(base)
    if not isinstance(overlay, dict):
        return out
    for k, v in overlay.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load():
    cfg = copy.deepcopy(DEFAULTS)
    if not os.path.isfile(CONFIG_PATH):
        return cfg
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        return cfg
    if not isinstance(raw, dict):
        return cfg
    return _deep_merge(cfg, raw)


def save(cfg):
    """Write nested config (merge with defaults so missing keys survive)."""
    merged = _deep_merge(DEFAULTS, cfg if isinstance(cfg, dict) else {})
    # never store database section here
    merged.pop("database", None)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2)
        f.write("\n")
    return merged


def get(section, key, default=None):
    cfg = load()
    if section in cfg and isinstance(cfg[section], dict) and key in cfg[section]:
        return cfg[section][key]
    if default is not None:
        return default
    return DEFAULTS.get(section, {}).get(key)


def set_value(section, key, value):
    cfg = load()
    if section not in cfg or not isinstance(cfg[section], dict):
        cfg[section] = {}
    cfg[section][key] = value
    save(cfg)
    return cfg


def update_section(section, values):
    cfg = load()
    if section not in cfg or not isinstance(cfg[section], dict):
        cfg[section] = {}
    cfg[section].update(values)
    save(cfg)
    return cfg


def migrate_from_db_flat(flat: dict):
    """One-shot: flat 'section.key' dict from old settings table → config.json."""
    if not flat or os.path.isfile(CONFIG_PATH):
        return load()
    nested = {}
    for flatkey, val in flat.items():
        if flatkey.startswith("database."):
            continue
        parts = flatkey.split(".", 1)
        if len(parts) == 2:
            section, key = parts
            nested.setdefault(section, {})[key] = val
        else:
            nested[flatkey] = val
    return save(nested)
