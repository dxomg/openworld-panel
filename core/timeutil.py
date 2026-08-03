"""App-wide timezone helpers. Config: general.timezone (IANA name, default UTC)."""
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DEFAULT_TZ = "UTC"

# Common choices for settings UI
COMMON_TIMEZONES = [
    "UTC",
    "Europe/London",
    "Europe/Paris",
    "Europe/Berlin",
    "Europe/Amsterdam",
    "Europe/Madrid",
    "Europe/Rome",
    "Europe/Warsaw",
    "Europe/Moscow",
    "Europe/Istanbul",
    "America/New_York",
    "America/Chicago",
    "America/Denver",
    "America/Los_Angeles",
    "America/Toronto",
    "America/Sao_Paulo",
    "Asia/Dubai",
    "Asia/Kolkata",
    "Asia/Shanghai",
    "Asia/Tokyo",
    "Asia/Singapore",
    "Asia/Seoul",
    "Asia/Jakarta",
    "Australia/Sydney",
    "Australia/Melbourne",
    "Pacific/Auckland",
    "Africa/Cairo",
    "Africa/Johannesburg",
]


def _cfg_tz_name():
    try:
        from core import appconfig
        name = (appconfig.load().get("general") or {}).get("timezone") or DEFAULT_TZ
        return str(name).strip() or DEFAULT_TZ
    except Exception:
        return DEFAULT_TZ


def get_tz_name():
    return _cfg_tz_name()


def get_tz():
    name = _cfg_tz_name()
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, Exception):
        return ZoneInfo(DEFAULT_TZ)


def now():
    """Current time in app timezone (naive, wall-clock in that zone)."""
    return datetime.now(get_tz()).replace(tzinfo=None)


def now_aware():
    return datetime.now(get_tz())


def now_str(fmt="%Y-%m-%d %H:%M:%S"):
    return now().strftime(fmt)


def parse_local(val):
    """Parse stored timestamp as naive local app time."""
    if not val:
        return None
    if isinstance(val, datetime):
        return val.replace(tzinfo=None) if val.tzinfo else val
    s = str(val).strip().replace("Z", "")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            piece = s[:19] if len(s) >= 19 and " " in s or "T" in s else s[:10]
            if fmt == "%Y-%m-%d" and len(s) >= 10:
                return datetime.strptime(s[:10], fmt)
            if len(s) >= 19:
                return datetime.strptime(s[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S")
            return datetime.strptime(s[: len(fmt.replace("%", "X"))], fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s.replace("T", " ")[:19])
    except ValueError:
        return None


def format_local(val, fmt="%Y-%m-%d %H:%M:%S", with_tz=False):
    """Format for UI. Optionally append timezone name."""
    dt = parse_local(val) if not isinstance(val, datetime) else (
        val.replace(tzinfo=None) if val.tzinfo else val
    )
    if not dt:
        return "—" if val is None else str(val)
    s = dt.strftime(fmt)
    if with_tz:
        s = f"{s} ({get_tz_name()})"
    return s


def to_mysql_offset():
    """
    Return ±HH:MM for SET time_zone when named zones unavailable.
    """
    aware = now_aware()
    off = aware.utcoffset() or timedelta(0)
    total = int(off.total_seconds())
    sign = "+" if total >= 0 else "-"
    total = abs(total)
    hh, rem = divmod(total, 3600)
    mm = rem // 60
    return f"{sign}{hh:02d}:{mm:02d}"
