"""In-process sliding-window rate limiter.
ponytail: shared Redis store when multi-worker / multi-host.
"""
import threading
import time
from collections import defaultdict, deque


_lock = threading.Lock()
_buckets = defaultdict(deque)


def _parse_rate(spec, default_limit=60, default_window=60):
    """Parse '10/minute' | '5/hour' | '30/second' or int limit with 60s window."""
    if spec is None:
        return default_limit, default_window
    if isinstance(spec, (int, float)):
        return max(1, int(spec)), default_window
    s = str(spec).strip().lower()
    if "/" not in s:
        try:
            return max(1, int(s)), default_window
        except ValueError:
            return default_limit, default_window
    left, right = s.split("/", 1)
    try:
        limit = max(1, int(left.strip()))
    except ValueError:
        limit = default_limit
    unit = right.strip()
    if unit in ("s", "sec", "second", "seconds"):
        window = 1
    elif unit in ("m", "min", "minute", "minutes"):
        window = 60
    elif unit in ("h", "hr", "hour", "hours"):
        window = 3600
    elif unit in ("d", "day", "days"):
        window = 86400
    else:
        try:
            window = max(1, int(unit))
        except ValueError:
            window = default_window
    return limit, window


def hit(key, limit=60, window=60):
    """Record a hit. Returns (allowed: bool, retry_after_sec: int)."""
    now = time.monotonic()
    limit = max(1, int(limit))
    window = max(1, int(window))
    with _lock:
        q = _buckets[key]
        cutoff = now - window
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= limit:
            retry = int(window - (now - q[0])) + 1
            return False, max(1, retry)
        q.append(now)
        # occasional prune of empty keys would need extra bookkeeping; skip
        return True, 0


def hit_rate(key, rate_spec, default_limit=60, default_window=60):
    limit, window = _parse_rate(rate_spec, default_limit, default_window)
    return hit(key, limit, window)


def reset(key=None):
    with _lock:
        if key is None:
            _buckets.clear()
        elif key in _buckets:
            del _buckets[key]
