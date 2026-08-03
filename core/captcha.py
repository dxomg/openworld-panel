"""Client module for math-captcha REST API service."""
import requests
from core import appconfig

DEFAULT_CAPTCHA_URL = "http://localhost:8000"


def get_config():
    try:
        return appconfig.load().get("captcha") or {}
    except Exception:
        return {}


def is_enabled():
    cfg = get_config()
    return bool(cfg.get("enabled", True))


def get_base_url():
    cfg = get_config()
    url = (cfg.get("url") or DEFAULT_CAPTCHA_URL).rstrip("/")
    return url


def get_ws_url():
    """Derive WebSocket endpoint URL from base URL."""
    url = get_base_url()
    if url.startswith("https://"):
        ws_base = "wss://" + url[8:]
    elif url.startswith("http://"):
        ws_base = "ws://" + url[7:]
    else:
        ws_base = "ws://" + url
    return f"{ws_base}/ws/captcha"


def mint_captcha():
    """Mint a new captcha challenge. Returns dict with id and img_src or None."""
    if not is_enabled():
        return None
    base_url = get_base_url()
    cfg = get_config()
    headers = {}
    if cfg.get("api_key"):
        headers["X-API-Key"] = cfg["api_key"]
    try:
        r = requests.post(f"{base_url}/captcha", headers=headers, timeout=3)
        if r.status_code == 200:
            data = r.json()
            cid = data.get("id")
            gif_url = data.get("gif_url")
            if cid and gif_url:
                # Absolute or relative image URL
                img_url = f"{base_url}{gif_url}" if gif_url.startswith("/") else gif_url
                return {"id": cid, "img_url": img_url}
    except Exception:
        pass
    return None


def verify_captcha(cid, answer):
    """Verify answer for a given challenge ID. Returns True if valid."""
    if not is_enabled():
        return True
    if not cid or answer is None or str(answer).strip() == "":
        return False
    base_url = get_base_url()
    cfg = get_config()
    headers = {}
    if cfg.get("api_key"):
        headers["X-API-Key"] = cfg["api_key"]
    try:
        ans_num = int(str(answer).strip())
    except ValueError:
        return False
    try:
        r = requests.post(
            f"{base_url}/captcha/verify",
            json={"id": str(cid).strip(), "answer": ans_num},
            headers=headers,
            timeout=3,
        )
        if r.status_code == 200:
            res = r.json()
            return bool(res.get("ok"))
    except Exception:
        pass
    return False
