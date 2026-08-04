"""Client module for math-captcha service (WebSocket-only).

The captcha service exposes only a WebSocket endpoint for minting challenges
and receiving signed verification tokens. The panel verifies those tokens
locally via HMAC-SHA256 using the shared CAPTCHA_SECRET — no REST verify call
is needed. This keeps verification server-side (the browser can't forge a
token without the secret) while requiring no REST surface on the captcha API.
"""
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
    """Derive WebSocket endpoint URL of the *captcha service* (used server-side
    by the panel's WS proxy, never by the browser). The browser connects to the
    panel's own /ws/captcha endpoint; the panel forwards to this URL using the
    API key held server-side."""
    url = get_base_url()
    if url.startswith("https://"):
        ws_base = "wss://" + url[8:]
    elif url.startswith("http://"):
        ws_base = "ws://" + url[7:]
    else:
        ws_base = "ws://" + url
    return f"{ws_base}/ws/captcha"


def get_secret():
    """Shared HMAC secret for verifying captcha tokens."""
    cfg = get_config()
    return cfg.get("secret") or ""


def verify_token(token):
    """Verify a signed captcha token returned by the WebSocket flow.

    Returns True if the token's HMAC signature is valid (signed with the shared
    CAPTCHA_SECRET) and the token has not expired. Returns False if captcha is
    disabled, the token is missing/invalid, or the secret is not configured.
    """
    if not is_enabled():
        return True
    if not token or not token.strip():
        return False
    secret = get_secret()
    if not secret:
        # No shared secret configured — cannot verify tokens. Fail closed.
        return False
    try:
        from store import CaptchaStore  # type: ignore
    except ImportError:
        # The captcha service's store module isn't on the panel's path.
        # Implement verification inline using the same algorithm.
        import base64
        import hashlib
        import hmac
        import json
        import time

        def _b64u_decode(s):
            pad = "=" * (-len(s) % 4)
            return base64.urlsafe_b64decode(s + pad)

        if "." not in token:
            return False
        payload_b64, sig = token.rsplit(".", 1)
        try:
            payload = _b64u_decode(payload_b64)
            expected = hmac.new(secret.encode(), payload, hashlib.sha256).digest()
            given = _b64u_decode(sig)
        except Exception:
            return False
        if not hmac.compare_digest(expected, given):
            return False
        try:
            data = json.loads(payload)
        except Exception:
            return False
        exp = data.get("exp")
        if not isinstance(exp, int) or exp < int(time.time()):
            return False
        return True
    return CaptchaStore.verify_token(token, secret)
