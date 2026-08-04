from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, make_response, g, abort, has_request_context
from flask_sock import Sock
import os
import secrets
import requests
import uuid
import json
import socket
import hmac
import time
import threading
import paramiko
from simple_websocket import Client as SimpleWsClient
from urllib.parse import urlencode
from datetime import datetime
from functools import wraps

# Global worker thread
worker_thread = None

from core import db
from core import dbconfig
from core import appconfig
from core import timeutil
from core import ratelimit
from core import captcha
from utils import services

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_CONFIG = appconfig.DEFAULTS


def simple_ws_connect(url, headers=None, timeout=5):
    """Open a client WebSocket connection using simple-websocket.
    `headers` is a list of (name, value) tuples sent on the upgrade request.
    `timeout` is unused (simple-websocket doesn't support a connect timeout)
    but kept for API compatibility."""
    return SimpleWsClient.connect(url, headers=headers or [])


def loadorcreateconfig():
    """Load panel settings from config.json (migrate once from old DB settings)."""
    if not os.path.isfile(appconfig.CONFIG_PATH):
        try:
            flat = db.getallsettings()
            if flat:
                return appconfig.migrate_from_db_flat(flat)
        except Exception:
            pass
        return appconfig.save(appconfig.DEFAULTS)
    return appconfig.load()


def reloadconfig():
    """Reload config.json into the global dict."""
    global config
    config = loadorcreateconfig()


db.ensurejobssuspendtype()
db.ensurevpssuspensioncolumns()
db.ensurevpspaiduntilcolumn()
db.ensurecaptchalogtable()
config = loadorcreateconfig()

OS_TYPES = {
    "alpine": {"name": "Alpine", "icon": "https://cdn.simpleicons.org/alpinelinux/0D597F"},
    "debian": {"name": "Debian", "icon": "https://cdn.simpleicons.org/debian/A81D33"},
    "ubuntu": {"name": "Ubuntu", "icon": "https://cdn.simpleicons.org/ubuntu/E95420"},
    "centos": {"name": "CentOS", "icon": "https://cdn.simpleicons.org/centos/262577"},
    "fedora": {"name": "Fedora", "icon": "https://cdn.simpleicons.org/fedora/51A2DA"},
    "rocky": {"name": "Rocky Linux", "icon": "https://cdn.simpleicons.org/rockylinux/10B981"},
    "arch": {"name": "Arch Linux", "icon": "https://cdn.simpleicons.org/archlinux/1793D1"},
    "linux": {"name": "Linux", "icon": "https://cdn.simpleicons.org/linux/FCC624"},
}


def addosmeta(images):
    for image in images:
        image["os_meta"] = OS_TYPES.get(image.get("os_type") or "linux", OS_TYPES["linux"])
    return images


def getpaypalurl():
    return "https://www.sandbox.paypal.com/cgi-bin/webscr" if config['paypal']['sandbox'] else "https://www.paypal.com/cgi-bin/webscr"

def getverifyurl():
    return "https://ipnpb.sandbox.paypal.com/cgi-bin/webscr" if config['paypal']['sandbox'] else "https://ipnpb.paypal.com/cgi-bin/webscr"

def daystoseconds(days: int) -> int:
    return int(days) * 86400


def getclientip():
    if not has_request_context():
        return None

    ipSource = config.get("network", {}).get("ip_source", "remote_addr")
    if ipSource == "x_forwarded_for":
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",", 1)[0].strip()
    if ipSource == "x_real_ip":
        realIp = request.headers.get("X-Real-IP")
        if realIp:
            return realIp
    return request.remote_addr if request else None


def auditlog(action, target_type=None, target_id=None, details=None):
    """Log an action to the audit trail."""
    user = getattr(g, 'userinfo', None) if has_request_context() else None
    db.addauditlog(
        uuid=str(uuid.uuid4()),
        userid=user['id'] if user else None,
        username=user.get('username', 'system') if user else 'system',
        role=user.get('role', 'system') if user else 'system',
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id else None,
        details=details,
        ip=getclientip(),
    )


def logcaptcha(action, result, endpoint=None, details=None):
    """Log a captcha verification attempt to the separate captcha log.

    Logs the user (or 'guest' if not logged in), their IP, the endpoint that
    triggered the captcha, and whether the attempt passed or failed.
    """
    user = getattr(g, 'userinfo', None) if has_request_context() else None
    userid = user['id'] if user else None
    username = user.get('username') if user else 'guest'
    db.addcaptchalog(
        userid=userid,
        username=username,
        action=action,
        result=result,
        endpoint=endpoint or (request.endpoint if has_request_context() else None),
        ip=getclientip(),
        details=details,
    )


app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
sock = Sock(app)

# Server-side SSH session tokens: {token: {"vpsUuid", "userid", "hostname", "port", "username", "password", "created"}}
# Credentials are stored server-side only - never sent to the client.
_ssh_sessions = {}
_SSH_SESSION_TTL = 120  # 2 minutes to connect
_SSH_IDLE_TIMEOUT = 300  # 5 minutes idle disconnect
_SSH_MAX_DURATION = 3600  # 1 hour max session

COOKIE_NAME = "sessioncookie"
SESSION_TTL_DAYS = config["general"]["defaultcookiettl"]

# --- Job Worker ---

def _processjob(job):
    """Process a single job. Returns True on success, False on failure."""
    jobtype = job['type']
    vpsUuid = job['vpsuuid']
    payload = json.loads(job['payload']) if job.get('payload') else {}

    if jobtype == 'provision':
        services.provisiononnode(vpsUuid)

    elif jobtype == 'start':
        vps = db.getvps(vpsUuid)
        if vps:
            # performvpsaction writes live Proxmox status
            services.performvpsaction(vps['id'], 'start', actorUserId=job['userid'])

    elif jobtype == 'stop':
        vps = db.getvps(vpsUuid)
        if vps:
            services.performvpsaction(vps['id'], 'stop', actorUserId=job['userid'])

    elif jobtype == 'restart':
        vps = db.getvps(vpsUuid)
        if vps:
            services.performvpsaction(vps['id'], 'restart', actorUserId=job['userid'])

    elif jobtype == 'suspend':
        vps = db.getvps(vpsUuid)
        if vps:
            # Status often already 'suspended' when job runs; still stop the instance
            try:
                services.performvpsaction(vps['id'], 'stop', actorUserId=job['userid'])
            except Exception:
                pass
            db.updatevps(vpsUuid, status='suspended')

    elif jobtype == 'delete':
        # Row stays status=deleted until node CT is gone, then hard-delete.
        vps = db.getvps(vpsUuid)
        if not vps:
            return
        if vps.get("status") != "deleted":
            db.updatevps(vpsUuid, status="deleted")
            vps = db.getvps(vpsUuid) or vps
        vmid = services.getvmidmapping(vpsUuid) or vps.get("vmid")
        if vmid:
            _deletevpsnode(vps)
        # Node clean (or never provisioned) — drop DB row
        db.deletevpsrecord(vps["id"])

    elif jobtype == 'reinstall':
        vps = db.getvps(vpsUuid)
        if vps:
            # Reinstall destroys CT then recreates — keep DB row
            _deletevpsnode(vps)
            db.unassignipbyvpsid(vps['id'])
            new_password = services.generaterandompassword()
            imageId = payload.get('imageId')
            updatefields = {
                'status': 'creating',
                'password': new_password,
                'container': None,
                'vmid': None,
                'ipv4': None,
                'ipv6': None,
            }
            if imageId:
                updatefields['imageid'] = imageId
            db.updatevps(vpsUuid, **updatefields)
            services.provisiononnode(vpsUuid)

    elif jobtype == 'enable_tun':
        vps = db.getvps(vpsUuid)
        if vps:
            services.enable_tun_for_lxc(vps['nodeid'], payload.get('vmid'))

    elif jobtype == 'create':
        services.provisiononnode(vpsUuid)

    else:
        raise ValueError(f"Unknown job type: {jobtype}")


def _deletevpsnode(vps):
    """Delete VPS LXC from Proxmox node. Treats already-gone CT as success."""
    vpsUuid = vps['uuid']
    node = db.getnodebyid(vps['nodeid'])
    if not node:
        return
    vmid = services.getvmidmapping(vpsUuid) or vps.get('vmid')
    if not vmid:
        return
    # longer HTTP timeout — stop+delete can exceed default 10s
    pve = services.getproxmoxclient(node, timeout=60)
    node_name = node.get('proxmoxnode', 'pve')
    try:
        services.pveclient.deletelxc(pve, node_name, vmid, timeout=180)
    except Exception as e:
        msg = str(e).lower()
        # already gone
        if (
            "does not exist" in msg
            or "not found" in msg
            or "configuration file" in msg
        ):
            pass
        else:
            raise
    try:
        services.removevmidmapping(vpsUuid)
    except Exception:
        pass


def _softdeletevps(vps, free_resources=True):
    """
    Mark VPS deleted in DB and free stock/IPs/storage.
    Row stays until delete job removes CT from node, then hard-deletes row.
    """
    if not vps:
        return
    already = vps.get("status") == "deleted"
    if not already:
        db.updatevps(vps["uuid"], status="deleted")
    if free_resources and not already:
        try:
            db.unassignipbyvpsid(vps["id"])
        except Exception:
            pass
        try:
            db.updatevps(vps["uuid"], ipv4=None, ipv6=None)
        except Exception:
            pass
        if vps.get("storagepoolid") and vps.get("disk"):
            try:
                db.increasestorageavailable(vps["storagepoolid"], vps["disk"])
            except Exception:
                pass
        if vps.get("planid"):
            try:
                with db.getconnection() as conn:
                    conn.execute(
                        "UPDATE plans SET stock = stock + 1, updated = CURRENT_TIMESTAMP "
                        "WHERE id = ? AND stock >= 0",
                        (vps["planid"],),
                    )
            except Exception:
                pass


def _queuedeletevps(vps, actor_userid=None):
    """Soft-delete + enqueue node purge job."""
    _softdeletevps(vps, free_resources=True)
    uid = actor_userid if actor_userid is not None else vps["userid"]
    return enqueuejob(vps["id"], vps["uuid"], uid, "delete")


def _requeue_stuck_deletes():
    """
    Re-queue delete for VPS stuck as status=deleted with no active job
    (node purge failed earlier — row kept until CT is gone).
    """
    stuck = db.listdeletedvpsneedingpurge(limit=20)
    for vps in stuck:
        if db.haspendingjobs(vps["uuid"]):
            continue
        # Do not free resources again — only purge node + row
        try:
            enqueuejob(vps["id"], vps["uuid"], vps["userid"], "delete")
        except Exception:
            pass



def _releaseunpaidreservation(vps):
    """Release stock/storage/IPs for an unpaid checkout without destroying the row."""
    db.unassignipbyvpsid(vps['id'])
    db.updatevps(vps['uuid'], ipv4=None, ipv6=None)
    if vps.get('storagepoolid') and vps.get('disk'):
        db.increasestorageavailable(vps['storagepoolid'], vps['disk'])
    if vps.get('planid'):
        with db.getconnection() as conn:
            conn.execute(
                "UPDATE plans SET stock = stock + 1, updated = CURRENT_TIMESTAMP WHERE id = ? AND stock >= 0",
                (vps['planid'],)
            )


def _rereserveunpaidreservation(vps):
    """Re-take stock/storage/IPs when a late valid payment arrives for a soft-expired checkout."""
    if vps.get('planid'):
        with db.getconnection() as conn:
            row = conn.execute("SELECT stock FROM plans WHERE id = ?", (vps['planid'],)).fetchone()
            if row and row['stock'] == 0:
                raise ValueError("Plan is out of stock")
            conn.execute(
                "UPDATE plans SET stock = stock - 1, updated = CURRENT_TIMESTAMP WHERE id = ? AND stock > 0",
                (vps['planid'],)
            )
    if vps.get('storagepoolid') and vps.get('disk'):
        with db.getconnection() as conn:
            conn.execute(
                "UPDATE storagepools SET used = used + ?, updated = CURRENT_TIMESTAMP WHERE id = ?",
                (vps['disk'], vps['storagepoolid'])
            )
    plan = db.getplanbyid(vps['planid'])
    if plan:
        db.reserveplanipsforvps(vps, plan, network_type=vps.get('network_type', 'proxmox'))


def _expireunpaidvps():
    """Soft-expire unpaid pendingpayment VPS after timeout and restore stock/storage."""
    expired = db.listexpiredpendingpaymentvps(maxageminutes=30)
    for vps in expired:
        _releaseunpaidreservation(vps)
        db.updatevps(vps['uuid'], status='deleted')
        auditlog("vps.expire_unpaid", "vps", vps['uuid'], f"Soft-expired unpaid pendingpayment VPS {vps.get('hostname')}")


def _billing_days(kind="paid"):
    """Period length from config.json billing section."""
    b = config.get("billing") or {}
    if kind == "free":
        try:
            return max(1, int(b.get("free_period_days") or 7))
        except (TypeError, ValueError):
            return 7
    try:
        return max(1, int(b.get("paid_period_days") or 30))
    except (TypeError, ValueError):
        return 30


def _suspendoverduevps():
    """Suspend VPS (paid or free) whose paid_until has passed."""
    overdue = db.listoverduevps(include_free=True, include_paid=True)
    for vps in overdue:
        if vps.get("status") == "suspended":
            continue
        if db.haspendingjobs(vps["uuid"]):
            continue
        try:
            price = float(vps.get("plan_price") or 0)
        except (TypeError, ValueError):
            price = 0
        if price > 0:
            reason = "Automatic suspension: monthly payment period ended"
            action = "vps.suspend_unpaid"
        else:
            reason = "Automatic suspension: free period expired — renew to restore"
            action = "vps.suspend_free_expired"
        try:
            db.addvpssuspension(
                str(uuid.uuid4()),
                vps["id"],
                vps["userid"],
                None,
                reason,
            )
        except Exception:
            pass
        db.updatevps(vps["uuid"], status="suspended")
        try:
            enqueuejob(vps["id"], vps["uuid"], vps["userid"], "suspend")
        except Exception:
            pass
        auditlog(
            action,
            "vps",
            vps["uuid"],
            f"Auto-suspended {vps.get('hostname')} (paid_until={vps.get('paid_until')})",
        )


def _markvpspaid(vpsUuid, days=None):
    """Record successful paid period on VPS."""
    if days is None:
        days = _billing_days("paid")
    try:
        return db.extendvpspaiduntil(vpsUuid, days=days)
    except Exception:
        return None


def _markvpsfreerenewal(vpsUuid, days=None):
    """Reset free VPS period to now + days (cap; does not stack)."""
    if days is None:
        days = _billing_days("free")
    try:
        return db.extendvpspaiduntil(vpsUuid, days=days, from_now=False)
    except Exception:
        return None


def _worker_cfg():
    w = config.get("worker") or {}
    return {
        "enabled_in_web": bool(w.get("enabled_in_web", True)),
        "poll_seconds": max(0.5, float(w.get("poll_seconds") or 2)),
        "maintenance_seconds": max(15, int(w.get("maintenance_seconds") or 60)),
        "stale_job_minutes": max(5, int(w.get("stale_job_minutes") or 45)),
        "heartbeat_path": w.get("heartbeat_path") or "worker.heartbeat",
    }


def _worker_heartbeat_file():
    path = _worker_cfg()["heartbeat_path"]
    if not os.path.isabs(path):
        path = os.path.join(BASE_DIR, path)
    return path


def _touch_worker_heartbeat(extra=None):
    """Write heartbeat so web process can report external worker health."""
    try:
        payload = {
            "ts": time.time(),
            "pid": os.getpid(),
            "iso": timeutil.now_str(),
        }
        if extra:
            payload.update(extra)
        path = _worker_heartbeat_file()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, path)
    except Exception:
        pass


def _read_worker_heartbeat(max_age=120):
    path = _worker_heartbeat_file()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        age = time.time() - float(data.get("ts") or 0)
        data["age_seconds"] = age
        data["fresh"] = age <= max_age
        return data
    except Exception:
        return None


def _run_maintenance_tasks():
    """Periodic billing/cleanup (safe to call from one worker only ideally)."""
    cfg = _worker_cfg()
    try:
        n = db.reclaimstalejobs(stale_minutes=cfg["stale_job_minutes"])
        if n:
            app.logger.info("Reclaimed %s stale running job(s)", n)
    except Exception as e:
        app.logger.exception("reclaimstalejobs: %s", e)
    try:
        _expireunpaidvps()
    except Exception as e:
        app.logger.exception("expire unpaid: %s", e)
    try:
        _suspendoverduevps()
    except Exception as e:
        app.logger.exception("suspend overdue: %s", e)
    try:
        _requeue_stuck_deletes()
    except Exception as e:
        app.logger.exception("requeue deletes: %s", e)


def _jobworker(stop_event=None):
    """
    Background job loop. stop_event: threading.Event for clean shutdown.
    """
    stop_event = stop_event or threading.Event()
    last_maint = 0
    app.logger.info("Job worker started pid=%s", os.getpid())
    _touch_worker_heartbeat({"event": "start"})

    while not stop_event.is_set():
        try:
            cfg = _worker_cfg()
            now = time.time()
            if now - last_maint >= cfg["maintenance_seconds"]:
                _run_maintenance_tasks()
                last_maint = now
            _touch_worker_heartbeat({"event": "tick"})

            job = db.getnextpendingjob()
            if not job:
                stop_event.wait(cfg["poll_seconds"])
                continue

            jid = job.get("uuid")
            jtype = job.get("type")
            app.logger.info("Job start %s type=%s vps=%s", jid, jtype, job.get("vpsuuid"))
            try:
                _processjob(job)
                db.updatejob(jid, status="completed", result="ok")
                auditlog(
                    f"job.{jtype}",
                    "vps",
                    job.get("vpsuuid"),
                    f"Job {jtype} completed for {job.get('vpsuuid')}",
                )
                app.logger.info("Job done %s type=%s", jid, jtype)
            except Exception as e:
                err = str(e)[:2000]
                app.logger.exception("Job failed %s type=%s: %s", jid, jtype, e)
                try:
                    db.updatejob(jid, status="failed", result=err)
                except Exception:
                    pass
                try:
                    auditlog(
                        f"job.{jtype}_failed",
                        "vps",
                        job.get("vpsuuid"),
                        f"Job {jtype} failed: {err[:500]}",
                    )
                except Exception:
                    pass
                if jtype in ("provision", "create", "reinstall"):
                    try:
                        db.updatevps(job["vpsuuid"], status="error")
                    except Exception:
                        pass

        except Exception as e:
            app.logger.exception("Worker loop error: %s", e)
            stop_event.wait(5)

    _touch_worker_heartbeat({"event": "stop"})
    app.logger.info("Job worker stopped pid=%s", os.getpid())


def start_job_worker():
    """Start in-process daemon worker if not already running."""
    global worker_thread, _worker_stop
    if worker_thread is not None and worker_thread.is_alive():
        return worker_thread
    _worker_stop = threading.Event()
    worker_thread = threading.Thread(
        target=_jobworker,
        kwargs={"stop_event": _worker_stop},
        daemon=True,
        name="JobWorker",
    )
    worker_thread.start()
    return worker_thread


def stop_job_worker(timeout=10):
    global worker_thread, _worker_stop
    if _worker_stop is not None:
        _worker_stop.set()
    if worker_thread is not None and worker_thread.is_alive():
        worker_thread.join(timeout=timeout)
    worker_thread = None


_worker_stop = None
# Auto-start in web process only when configured.
# Skip when running standalone worker.py (OPENWORLD_WORKER=1) or enabled_in_web false.
if (
    os.environ.get("OPENWORLD_WORKER") != "1"
    and _worker_cfg()["enabled_in_web"]
):
    start_job_worker()



def enqueuejob(vpsid, vpsuuid, userid, jobtype, payload=None):
    """Create and enqueue a job. Returns the job UUID."""
    jobuuid = str(uuid.uuid4())
    payload_json = json.dumps(payload) if payload else None
    db.addjob(uuid=jobuuid, vpsid=vpsid, vpsuuid=vpsuuid, userid=userid,
              jobtype=jobtype, payload=payload_json)
    return jobuuid


def vpsissuspended(vps):
    active = db.getactivejobforvps(vps["uuid"])
    return vps["status"] == "suspended" or (active and active["type"] == "suspend")

# CSRF protection
@app.before_request
def csrfprotect():
    if request.method == "POST":
        # Skip CSRF for PayPal IPN (external webhook)
        if request.path == "/paypal/ipn":
            return
        token = request.form.get('_csrf_token') or request.headers.get('X-CSRFToken')
        sessionToken = request.cookies.get('csrf_token')
        if not token or not sessionToken or not hmac.compare_digest(token, sessionToken):
            return "CSRF validation failed", 403


_RL_SKIP_ENDPOINTS = frozenset({"static", "paypalipn"})
_RL_SKIP_PREFIXES = ("/static/", "/paypal/ipn")


def _rl_cfg():
    return config.get("ratelimit") or {}


def _rl_enabled():
    return bool(_rl_cfg().get("enabled", True))


def _rl_rate(name, default):
    return _rl_cfg().get(name) or default


def _ratelimit_response(retry_after):
    retry_after = max(1, int(retry_after or 1))
    body = None
    try:
        body = render_template(
            "429.html",
            retry_after=retry_after,
            **guestuserinfo(),
        )
    except Exception:
        body = "Too many requests. Try again later."
    resp = make_response(body, 429)
    resp.headers["Retry-After"] = str(retry_after)
    return resp


def checkratelimit(bucket, rate_key, default_rate, identity=None):
    """Hit a named bucket. Returns response if limited, else None."""
    if not _rl_enabled():
        return None
    ip = getclientip() or "unknown"
    key = f"{bucket}:{identity or ip}"
    ok, retry = ratelimit.hit_rate(key, _rl_rate(rate_key, default_rate))
    if ok:
        return None
    return _ratelimit_response(retry)


@app.before_request
def globalratelimit():
    if not _rl_enabled():
        return
    if request.endpoint in _RL_SKIP_ENDPOINTS:
        return
    path = request.path or ""
    if any(path.startswith(p) for p in _RL_SKIP_PREFIXES):
        return
    ip = getclientip() or "unknown"
    ok, retry = ratelimit.hit_rate(f"global:{ip}", _rl_rate("global", "120/minute"))
    if not ok:
        return _ratelimit_response(retry)


@app.after_request
def setcsrfcookie(response):
    if request.endpoint and request.endpoint != 'static':
        if not request.cookies.get('csrf_token'):
            token = secrets.token_hex(32)
            response.set_cookie('csrf_token', token, httponly=False, samesite='Lax')
    return response

app.jinja_env.globals['csrf_token'] = lambda: request.cookies.get('csrf_token', '')


def loginrequired(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get(COOKIE_NAME)
        user = services.validatesession(token) if token else None

        if not user:
            return redirect(url_for("login"))

        ban = services.isuserbanned(user["id"])
        if ban:
            return render_template("banned.html", **paneluserinfo(user, ban=ban))

        g.userinfo = user
        return f(*args, **kwargs)
    return decorated

def adminrequired(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Accessing by key name is much safer than by index
        if g.userinfo.get('role') != "admin":
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

THEMES = [
    {"id": "midnight", "name": "Midnight", "class": ""},
    {"id": "catppuccin", "name": "Catppuccin Mocha", "class": "theme-catppuccin"},
    {"id": "dracula", "name": "Dracula", "class": "theme-dracula"},
    {"id": "nord", "name": "Nord", "class": "theme-nord"},
    {"id": "gruvbox", "name": "Gruvbox", "class": "theme-gruvbox"},
    {"id": "tokyonight", "name": "Tokyo Night", "class": "theme-tokyonight"},
    {"id": "solarized", "name": "Solarized Dark", "class": "theme-solarized"},
]

def get_theme_class(user=None):
    # User's personal theme takes priority
    theme_id = None
    if user:
        theme_id = user.get('theme')
    # Cookie for guests (or if user has no theme set)
    if not theme_id and request:
        theme_id = request.cookies.get("theme")
    # Fall back to global default
    if not theme_id:
        theme_id = config.get("general", {}).get("theme", "catppuccin")
    for t in THEMES:
        if t["id"] == theme_id:
            return t["class"]
    return ""

def _panel_ws_url(endpoint):
    """Build a ws/wss URL for a panel WebSocket route, honoring the reverse
    proxy's X-Forwarded-Proto so wss is used behind HTTPS."""
    if not request:
        return ""
    proto = request.headers.get("X-Forwarded-Proto", request.scheme).lower()
    ws_proto = "wss" if proto in ("https", "wss") else "ws"
    host = request.headers.get("X-Forwarded-Host", request.host)
    # url_for on a flask-sock route may return a full ws:// URL; extract the path.
    raw = url_for(endpoint)
    if raw.startswith("ws://") or raw.startswith("wss://"):
        # strip scheme + host
        from urllib.parse import urlsplit
        path = urlsplit(raw).path
    else:
        path = raw
    return f"{ws_proto}://{host}{path}"

def guestuserinfo():
    cookie_theme = request.cookies.get("theme") if request else None
    return {
        "favicon": config["general"]["favicon"],
        "logo": config["general"]["logo"],
        "projectname": config["general"]["projectname"],
        "globaltotalvps": db.countvps(),
        "globaltotalnodes": db.countnodes(),
        "theme_class": get_theme_class(),
        "themes": THEMES,
        "current_theme": cookie_theme or config.get("general", {}).get("theme", "catppuccin"),
        "app_timezone": timeutil.get_tz_name(),
        "captcha_enabled": captcha.is_enabled(),
        "captcha_ws_url": _panel_ws_url("ws_captcha_proxy") if captcha.is_enabled() else "",
    }

def paneluserinfo(user, ban=None):
    if ban is None:
        ban = services.isuserbanned(user["id"])

    return {
        "favicon": config["general"]["favicon"],
        "logo": config["general"]["logo"],
        "userid": user["id"],
        "username": user["username"],
        "email": user["email"],
        "regdate": user.get("created"),
        "projectname": config["general"]["projectname"],
        "profilepic": user.get("profile_pic") or "/static/img/avatar.png",
        "role": user.get("role", "user"),
        "usertotalvps": db.countvps(userid=user["id"]),
        "vpsplans": db.listplans(active=1),
        "globaltotalvps": db.countvps(),
        "discordserver": config["general"]["discord"],
        "banreason": ban["reason"] if ban else None,
        "theme_class": get_theme_class(user),
        "themes": THEMES,
        "current_theme": user.get('theme') or (request.cookies.get("theme") if request else None) or config.get("general", {}).get("theme", "catppuccin"),
        "app_timezone": timeutil.get_tz_name(),
        "captcha_enabled": captcha.is_enabled(),
        "captcha_ws_url": _panel_ws_url("ws_captcha_proxy") if captcha.is_enabled() else "",
    }

def paneladmininfo(user, ban=None):
    if ban is None:
        ban = services.isuserbanned(user["id"])

    return {
        "totalusers": db.countusers(),
        "totalresourceallocation": db.getallocatedresources()
    }

#############
#
# Page Routes
#
#############

@app.route("/")
def index():
    return render_template("landing.html", **guestuserinfo())

@app.route("/tos")
def tos():
    return render_template("tos.html", **guestuserinfo())

@app.route("/privacy")
def privacy():
    return render_template("privacy.html", **guestuserinfo())


@app.route("/dashboard")
@loginrequired
def dashboard():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    vpsData = services.listvpsforuserpanel(g.userinfo["id"], page=page, perPage=10, search=q)
    for inst in vpsData.get("vps") or []:
        inst["os_meta"] = OS_TYPES.get(inst.get("os_type") or "linux", OS_TYPES["linux"])
    billingDue = [v for v in vpsData.get("vps") or [] if v.get("billing_due")]
    return render_template(
        "dashboard.html",
        vpsData=vpsData,
        search=q or '',
        billingDue=billingDue,
        **paneluserinfo(g.userinfo),
    )

@app.route("/createvps", methods=["GET", "POST"])
@loginrequired
def createvps():
    if request.method == "POST":
        token = request.form.get("captcha_token")
        if captcha.is_enabled():
            if not captcha.verify_token(token):
                logcaptcha("createvps", "failed", "createvps", "Invalid or missing captcha token")
                flash("Invalid or expired captcha answer.", "error")
                return redirect(url_for('createvps'))
            logcaptcha("createvps", "passed", "createvps")
    db.ensureplanassignmenttables()
    if request.method == "POST":
        planId = request.form.get("planId", type=int)
        imageId = request.form.get("imageId", type=int)

        plan = db.getplanbyid(planId)
        if not plan:
            flash("Invalid plan selected.", "error")
            return redirect(url_for('createvps'))

        isPaid = float(plan.get('price') or 0) > 0

        # Rate limit check for free vs paid creation
        if isPaid:
            limited = checkratelimit("create_vps_paid", "create_vps_paid", "10/hour", identity=g.userinfo["id"])
        else:
            limited = checkratelimit("create_vps_free", "create_vps_free", "2/day", identity=g.userinfo["id"])
        if limited:
            return limited

        if plan['stock'] == 0:
            flash("This plan is out of stock.", "error")
            return redirect(url_for('createvps'))

        isPaid = float(plan['price']) > 0

        # Check free plan limit
        if not isPaid and db.userhasfreevps(g.userinfo["id"]):
            flash("You already have a free VPS. Free users can only create one free instance.", "error")
            return redirect(url_for('createvps'))

        if isPaid and db.countpendingpaymentvps(g.userinfo["id"]) > 0:
            flash("You already have an unpaid VPS checkout. Pay or wait for it to expire before creating another.", "error")
            return redirect(url_for('dashboard'))

        image = db.getimagebyid(imageId)
        if not image or not image.get('active'):
            flash("Invalid image selected.", "error")
            return redirect(url_for('createvps'))
        if image.get('node_type', 'proxmox') != plan.get('node_type', 'proxmox'):
            flash("Selected image does not match plan platform.", "error")
            return redirect(url_for('createvps'))
        if not db.getnodesforimage(image['id']):
            flash("Selected image is not assigned to any node.", "error")
            return redirect(url_for('createvps'))

        locationId = request.form.get("locationId", type=int)
        if locationId == 0:
            locationId = None

        nodeId, storagePoolId = db.getsuitablenodeandstorage(
            plan['id'],
            strategy=config.get('loadbalancing', {}).get('strategy', 'both'),
            node_type=plan['node_type'],
            imageid=image['id'],
            disk_mb=plan.get('disk', 0),
            locationid=locationId
        )
        
        if not nodeId:
            if locationId:
                flash("No available servers in the selected location for this plan (location may be full or offline).", "error")
            else:
                flash("No nodes available for this plan (check plan node assignments and image).", "error")
            return redirect(url_for('createvps'))

        # Auto-assign network from the node
        node = db.getnodebyid(nodeId)
        nodeNetType = node.get('type', 'proxmox') if node else 'proxmox'
        nodeNetworks = db.listnetworks(nodeid=nodeId, network_type=nodeNetType)
        if not nodeNetworks:
            flash("No network configured for this node. Contact an admin.", "error")
            return redirect(url_for('createvps'))
        network = nodeNetworks[0]
        networkId = network['id']
        ipError = db.planipavailabilityerror(plan, network, network_type=nodeNetType)
        if ipError:
            flash(ipError, "error")
            return redirect(url_for('createvps'))

        if not storagePoolId:
            flash("No storage pool assigned to this plan for the selected node. Contact an admin.", "error")
            return redirect(url_for('createvps'))

        vpsUuid = str(uuid.uuid4())
        initialStatus = 'pendingpayment' if isPaid else 'creating'

        try:
            hostname = services.generaterandomhostname()
            db.createvpswithjob(
                uuid=vpsUuid,
                userid=int(g.userinfo["id"]),
                plan=plan,
                imageid=imageId,
                nodeid=nodeId,
                storageid=storagePoolId,
                networkid=networkId,
                network_type=nodeNetType,
                storagepoolid=storagePoolId,
                hostname=hostname,
                password=services.generaterandompassword(),
                status=initialStatus,
                jobtype=None if isPaid else 'provision'
            )

            # Hold required IPs immediately so payment can't succeed into an empty pool
            if isPaid:
                vpsRow = db.getvps(vpsUuid)
                try:
                    db.reserveplanipsforvps(vpsRow, plan, network_type=nodeNetType)
                except ValueError as e:
                    _releaseunpaidreservation(vpsRow)
                    db.unassignipbyvpsid(vpsRow['id'])
                    db.deletevpsrecord(vpsRow['id'])
                    flash(str(e), "error")
                    return redirect(url_for('createvps'))

            auditlog("vps.create", "vps", vpsUuid, f"Created VPS {hostname} with plan '{plan['name']}'")

            if isPaid:
                return redirect(url_for('checkout', vpsUuid=vpsUuid))

            # Free: start renewal period immediately
            until = _markvpsfreerenewal(vpsUuid)
            auditlog(
                "vps.free_period",
                "vps",
                vpsUuid,
                f"Free period started until {until}" if until else "Free period started",
            )
            days = _billing_days("free")
            flash(f"Free VPS is being created! Renew every {days} days to keep it.", "success")
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f"An error occurred while creating the VPS: {e}", "error")
            return redirect(url_for('createvps'))

    images = [img for img in db.listimages(active=1) if db.getnodesforimage(img['id'])]
    plansList = db.listplans(active=1)
    for p in plansList:
        p['locations'] = db.getlocationsforplan(p['id'])
    return render_template("createvps.html", plansList=plansList, images=addosmeta(images), **paneluserinfo(g.userinfo))

@app.route("/checkout/<string:vpsUuid>")
@loginrequired
def checkout(vpsUuid):
    vpsRecord = db.getvps(vpsUuid) # Rename to be distinct
    
    if not vpsRecord or vpsRecord['userid'] != g.userinfo['id']:
        flash("Invoice not found.", "error")
        return redirect(url_for('dashboard'))
    
    if vpsRecord['status'] != 'pendingpayment':
        flash("This instance is already being processed.", "info")
        return redirect(url_for('dashboard'))

    # Visiting checkout restarts the 30-minute unpaid expiry timer
    db.touchpendingpaymentvps(vpsUuid)
    vpsRecord = db.getvps(vpsUuid)

    plan = db.getplanbyid(vpsRecord['planid'])
    methods = db.listallpaymentmethods()
    
    # Pass it as checkoutVps to avoid collision with paneluserinfo['vps']
    return render_template(
        "checkout.html", 
        checkoutVps=vpsRecord, 
        plan=plan, 
        methods=methods, 
        **paneluserinfo(g.userinfo)
    )

@app.route("/checkout/<string:vpsUuid>/cancel", methods=["POST"])
@loginrequired
def cancelcheckout(vpsUuid):
    vps = db.getvps(vpsUuid)
    if not vps or str(vps['userid']) != str(g.userinfo['id']):
        flash("Invoice not found.", "error")
        return redirect(url_for('dashboard'))

    if vps['status'] != 'pendingpayment':
        flash("This checkout can no longer be cancelled.", "error")
        return redirect(url_for('dashboard'))

    _releaseunpaidreservation(vps)
    db.updatevps(vpsUuid, status='deleted')
    auditlog("vps.cancel_unpaid", "vps", vpsUuid, f"User cancelled unpaid checkout {vps.get('hostname')}")
    flash("Checkout cancelled. Reserved stock has been released.", "success")
    return redirect(url_for('dashboard'))


@app.route("/checkout/processpayment", methods=["POST"])
@loginrequired
def processpayment():
    limited = checkratelimit("checkout", "checkout", "20/hour", identity=g.userinfo["id"])
    if limited:
        return limited
    vpsUuid = request.form.get("vpsUuid")
    methodSlug = request.form.get("methodSlug")

    vps = db.getvps(vpsUuid)
    if not vps:
        flash("Invalid Session: VPS not found.", "error")
        return redirect(url_for('dashboard'))

    if str(vps['userid']) != str(g.userinfo['id']):
        flash("Invalid Session: Ownership mismatch.", "error")
        return redirect(url_for('dashboard'))

    currentStatus = str(vps['status']).strip()
    if currentStatus != 'pendingpayment':
        flash(f"Invalid Session: Status is {currentStatus}.", "error")
        return redirect(url_for('dashboard'))

    plan = db.getplanbyid(vps['planid'])

    if methodSlug == 'paypal':
        base = request.host_url.rstrip('/')
        returnUrl = f"{base}/vps/{vpsUuid}"
        notifyUrl = f"{base}/paypal/ipn"
        cancelUrl = f"{base}/checkout/{vpsUuid}"
        params = {
            "cmd": "_xclick",
            "business": config['paypal']['email'],
            "item_name": f"VPS: {plan['name']} ({vps['hostname']})",
            "amount": f"{plan['price']:.2f}",
            "currency_code": "USD",
            "notify_url": notifyUrl,
            "return": returnUrl,
            "cancel_return": cancelUrl,
            "custom": vpsUuid,
        }
        paypalRedirect = getpaypalurl() + "?" + urlencode(params)
        app.logger.info(f"PayPal redirect: base={base} return={returnUrl} notify={notifyUrl}")
        return redirect(paypalRedirect)

    # Manual / Balance activation
    paidUntil = _markvpspaid(vpsUuid, days=30)
    db.updatevps(vpsUuid, status='creating')
    manualMethod = db.getpaymentmethodbyslug(methodSlug)
    txnUuid = str(uuid.uuid4())
    db.addtransaction(
        uuid=txnUuid,
        userid=vps['userid'],
        transactionid=f"manual-{uuid.uuid4().hex[:8]}",
        amount=float(plan['price']),
        currency="USD",
        status="completed",
        paymentprocessorid=manualMethod['id'] if manualMethod else 1,
        vpsid=vps['id'],
        planid=vps['planid']
    )

    auditlog(
        "payment.manual",
        "vps",
        vpsUuid,
        f"Manual payment of ${plan['price']:.2f} via {methodSlug}"
        + (f" (paid until {paidUntil})" if paidUntil else ""),
    )

    enqueuejob(vps['id'], vpsUuid, vps['userid'], 'provision')
    flash("Payment confirmed. VPS is being created!", "success")
    return redirect(url_for('dashboard'))

@app.route("/paypal/ipn", methods=["POST"])
def paypalipn():
    app.logger.info("PayPal IPN received")

    # 1. Verify with PayPal
    verifyData = request.form.to_dict(flat=True)
    verifyData["cmd"] = "_notify-validate"
    try:
        r = requests.post(getverifyurl(), data=verifyData, headers={"Connection": "close"}, timeout=15)
    except Exception as e:
        app.logger.error(f"PayPal IPN verification request failed: {e}")
        return "Verification failed", 500

    if r.text.strip() != "VERIFIED":
        app.logger.warning(f"PayPal IPN not verified. Response: {r.text[:200]}")
        return "INVALID", 400

    # 2. Extract Data
    vpsUuid = request.form.get("custom")
    paymentStatus = request.form.get("payment_status")
    amount = request.form.get("mc_gross")
    receiver = request.form.get("receiver_email")
    txnId = request.form.get("txn_id") or request.form.get("transaction_id")

    app.logger.info(f"PayPal IPN: txn={txnId} status={paymentStatus} amount={amount} vps={vpsUuid}")

    # 3. Replay protection: reject if txn_id already processed
    if txnId and db.gettransactionbytxnid(txnId):
        app.logger.info(f"PayPal IPN: already processed txn {txnId}")
        return "Already processed", 200

    # 4. Validation Logic
    vps = db.getvps(vpsUuid)
    if not vps:
        app.logger.warning(f"PayPal IPN: VPS not found: {vpsUuid}")
        return "VPS not found", 400

    plan = db.getplanbyid(vps['planid'])

    # Security Checks
    if paymentStatus != "Completed":
        app.logger.info(f"PayPal IPN: payment not completed, status={paymentStatus}")
        return "Not completed", 200

    # Require receiver_email to be present and match our configured PayPal address.
    # The previous `if receiver:` guard skipped the check when the field was absent,
    # allowing an attacker to strip the field and bypass the receiver check.
    paypal_email = (config.get('paypal', {}).get('email') or '').lower().strip()
    if not paypal_email:
        app.logger.error("PayPal IPN: no paypal.email configured on the panel")
        return "Receiver not configured", 500
    if not receiver or receiver.lower() != paypal_email:
        app.logger.warning(f"PayPal IPN: receiver mismatch: {receiver!r} != {paypal_email!r}")
        return "Wrong receiver", 400

    # Require exact amount + currency match. The previous `float(amount) < price`
    # check allowed overpayment attacks (pay exact amount for a cheap plan, attach
    # `custom` pointing at someone else's expensive pendingpayment VPS). Use exact
    # equality with a small epsilon to absorb float rounding from PayPal.
    currency = (request.form.get("mc_currency") or "USD").upper()
    plan_currency = (plan.get('currency') or "USD").upper()
    try:
        paid_amount = float(amount)
    except (TypeError, ValueError):
        app.logger.warning(f"PayPal IPN: invalid amount {amount!r}")
        return "Invalid amount", 400
    plan_price = float(plan['price'])
    if currency != plan_currency:
        app.logger.warning(f"PayPal IPN: currency mismatch: {currency} != {plan_currency}")
        return "Wrong currency", 400
    if abs(paid_amount - plan_price) > 0.01:
        app.logger.warning(f"PayPal IPN: amount mismatch: {paid_amount} != {plan_price} ({currency})")
        return "Amount mismatch", 400

    # 5. Success Action: Update Database
    # Accept late IPN for soft-expired/cancelled unpaid checkouts (status deleted).
    if vps['status'] in ('pendingpayment', 'deleted'):
        if vps['status'] == 'deleted':
            try:
                _rereserveunpaidreservation(vps)
            except ValueError as e:
                app.logger.error(f"PayPal IPN: paid but resources unavailable for {vpsUuid}: {e}")
                paypalMethod = db.getpaymentmethodbyslug("paypal")
                db.addtransaction(
                    uuid=str(uuid.uuid4()),
                    userid=vps['userid'],
                    transactionid=txnId,
                    amount=float(amount),
                    currency=request.form.get("mc_currency", "USD"),
                    status="completed",
                    paymentprocessorid=paypalMethod['id'] if paypalMethod else 1,
                    vpsid=vps['id'],
                    planid=vps['planid']
                )
                db.updatevps(vpsUuid, status='error')
                auditlog("payment.paypal_resource_fail", "vps", vpsUuid, f"Paid ${amount} but resources unavailable: {e}")
                return "OK", 200
            app.logger.info(f"PayPal IPN: revived soft-expired checkout {vpsUuid}")
        paidUntil = _markvpspaid(vpsUuid, days=30)
        db.updatevps(vpsUuid, status='creating')
        paypalMethod = db.getpaymentmethodbyslug("paypal")
        txnUuid = str(uuid.uuid4())
        db.addtransaction(
            uuid=txnUuid,
            userid=vps['userid'],
            transactionid=txnId,
            amount=float(amount),
            currency=request.form.get("mc_currency", "USD"),
            status="completed",
            paymentprocessorid=paypalMethod['id'] if paypalMethod else 1,
            vpsid=vps['id'],
            planid=vps['planid']
        )

        auditlog(
            "payment.paypal",
            "vps",
            vpsUuid,
            f"PayPal payment of ${amount} (txn: {txnId})"
            + (f" (paid until {paidUntil})" if paidUntil else ""),
        )

        enqueuejob(vps['id'], vpsUuid, vps['userid'], 'provision')
        app.logger.info(f"PayPal IPN: payment processed, provisioning queued for {vpsUuid}")
    else:
        app.logger.info(f"PayPal IPN: VPS {vpsUuid} not payable (status={vps['status']})")

    return "OK", 200


@app.route("/vps/<vpsUuid>")
@loginrequired
def vpspanel(vpsUuid):
    vps = db.getvps(vpsUuid)
    if not vps or vps["userid"] != g.userinfo["id"]:
        abort(404)

    # Fast path: DB only. Live Proxmox status/metrics via /vps/<uuid>/status poll.
    instance = services.getvpsdetails(vps["id"])
    if instance:
        os_type = instance.get('os_type') or 'linux'
        instance['os_meta'] = OS_TYPES.get(os_type, OS_TYPES['linux'])

    assignedIpv4 = instance.get('ipv4') if instance else vps.get('ipv4')
    assignedIpv6 = instance.get('ipv6') if instance else vps.get('ipv6')

    networkDns = None
    if vps.get('networkid'):
        with db.getconnection() as conn:
            net = conn.execute(
                "SELECT dns FROM proxmox_networks WHERE id = ?", (vps['networkid'],)
            ).fetchone()
        if net and net.get('dns'):
            networkDns = net['dns']

    return render_template(
        "vpspanel.html",
        **paneluserinfo(g.userinfo),
        instance=instance,
        metric=None,
        assignedIpv4=assignedIpv4,
        assignedIpv6=assignedIpv6,
        networkDns=networkDns,
        reinstallImages=db.getimagesfornode(vps['nodeid'], active=1),
        metrics_mode=config.get("console", {}).get("metrics", "dynamic"),
    )


#############
#
# Action Routes (AJAX)
#
#############

@app.route("/vps/<vpsUuid>/jobs")
@loginrequired
def vpsjobs(vpsUuid):
    vps = db.getvps(vpsUuid)
    if not vps:
        return jsonify({"error": "VPS not found"}), 404

    isAdmin = g.userinfo.get('role') == 'admin'
    if not isAdmin and vps["userid"] != g.userinfo["id"]:
        return jsonify({"error": "VPS not found"}), 404

    jobs = db.getrecentjobsforvps(vpsUuid, limit=5)
    active = db.getactivejobforvps(vpsUuid)
    return jsonify({
        "active": active,
        "jobs": jobs,
    })

@app.route("/vps/<vpsUuid>/action/<action>", methods=["POST"])
@loginrequired
def vpsaction(vpsUuid, action):
    if action not in ("start", "stop", "restart", "enable-tun"):
        flash("Invalid action.", "error")
        return redirect(url_for('dashboard'))

    vps = db.getvps(vpsUuid)
    if not vps:
        flash("VPS not found.", "error")
        return redirect(url_for('dashboard'))

    isAdmin = g.userinfo.get('role') == 'admin'
    if not isAdmin and vps["userid"] != g.userinfo["id"]:
        flash("VPS not found.", "error")
        return redirect(url_for('dashboard'))

    referer = request.headers.get('Referer', '')
    backUrl = url_for('adminvpspanel', vpsUuid=vpsUuid) if 'admin' in referer and isAdmin else url_for('vpspanel', vpsUuid=vpsUuid)
    
    if vpsissuspended(vps):
        flash("This VPS is suspended.", "error")
        return redirect(backUrl)

    # Handle enable-tun action for Proxmox VPS
    if action == "enable-tun":
        vpsDetails = services.getvpsdetails(vps["id"])
        if vpsDetails and vpsDetails.get('node_type') == 'proxmox':
            try:
                if services.is_tun_enabled_for_lxc(vps["nodeid"], vps.get("vmid")):
                    flash("TUN is already enabled for this VPS.", "error")
                else:
                    # Queue the TUN enable job
                    db.addjob(
                        uuid=str(uuid.uuid4()),
                        vpsid=vps["id"],
                        vpsuuid=vpsUuid,
                        userid=g.userinfo["id"],
                        jobtype="enable_tun",
                        payload=json.dumps({"vmid": vps.get("vmid"), "nodeid": vps["nodeid"]})
                    )
                    flash("TUN enable request queued. Your VPS will restart shortly.", "info")
            except Exception as e:
                flash(f"Failed to enable TUN: {str(e)}", "error")
        else:
            flash("TUN enable is only available for Proxmox VPS.", "error")
        return redirect(backUrl)

    if db.haspendingjobs(vpsUuid):
        flash("This VPS already has a pending action.", "error")
        return redirect(backUrl)

    enqueuejob(vps['id'], vpsUuid, g.userinfo["id"], action)
    auditlog(f"vps.{action}", "vps", vpsUuid, f"Queued {action} on {vps['hostname']}")
    flash(f"VPS {action} queued.", "success")
    return redirect(backUrl)


@app.route("/vps/<vpsUuid>/renew", methods=["POST"])
@loginrequired
def renewfreevps(vpsUuid):
    """Extend free VPS period (no payment)."""
    limited = checkratelimit("renew", "renew", "20/hour", identity=g.userinfo["id"])
    if limited:
        return limited
    token = request.form.get("captcha_token")
    if captcha.is_enabled():
        if not captcha.verify_token(token):
            logcaptcha("renew", "failed", "renewfreevps", f"VPS {vpsUuid}: invalid or missing captcha token")
            flash("Invalid or expired captcha answer.", "error")
            return redirect(url_for("vpspanel", vpsUuid=vpsUuid))
        logcaptcha("renew", "passed", "renewfreevps", f"VPS {vpsUuid}")
    vps = db.getvps(vpsUuid)
    if not vps or vps["userid"] != g.userinfo["id"]:
        flash("VPS not found.", "error")
        return redirect(url_for("dashboard"))

    plan = db.getplanbyid(vps["planid"])
    if not plan or float(plan.get("price") or 0) > 0:
        flash("Only free VPS can be renewed here.", "error")
        return redirect(url_for("vpspanel", vpsUuid=vpsUuid))

    if vps.get("status") == "deleted":
        flash("This VPS is deleted.", "error")
        return redirect(url_for("dashboard"))

    try:
        b_cfg = config.get("billing") or {}
        cooldown_hours = float(b_cfg.get("free_renew_cooldown_hours") if b_cfg.get("free_renew_cooldown_hours") is not None else 24)
    except (TypeError, ValueError):
        cooldown_hours = 24

    if cooldown_hours > 0:
        last_renew = db.getlastfreerenewtime(vpsUuid)
        if last_renew:
            now = timeutil.now()
            elapsed_sec = (now - last_renew).total_seconds()
            cooldown_sec = cooldown_hours * 3600.0
            if elapsed_sec < cooldown_sec:
                remain_hours = (cooldown_sec - elapsed_sec) / 3600.0
                if remain_hours >= 1:
                    time_str = f"{int(remain_hours)} hour{'s' if int(remain_hours) != 1 else ''}"
                else:
                    remain_mins = max(1, int(remain_hours * 60))
                    time_str = f"{remain_mins} minute{'s' if remain_mins != 1 else ''}"
                cd_num = int(cooldown_hours) if cooldown_hours.is_integer() else cooldown_hours
                flash(f"Free VPS can only be renewed once every {cd_num} hours. Please try again in {time_str}.", "error")
                return redirect(url_for("vpspanel", vpsUuid=vpsUuid))

    days = _billing_days("free")
    until = _markvpsfreerenewal(vpsUuid, days=days)
    # If was auto-suspended for free expiry, restore to stopped so user can start
    if vps.get("status") == "suspended":
        sus = db.getsuspensionbyvpsid(vps["id"])
        reason = (sus or {}).get("reason") or ""
        if "free period" in reason.lower() or "free" in reason.lower():
            db.liftvpssuspension(vps["id"])
            db.updatevps(vpsUuid, status="stopped")
            flash(
                f"Free period renewed until {until}. VPS unsuspended — start it when ready.",
                "success",
            )
        else:
            flash(
                f"Free period renewed until {until}. Contact support if still suspended for another reason.",
                "success",
            )
    else:
        flash(f"Free period renewed until {until} ({days} days).", "success")

    auditlog("vps.free_renew", "vps", vpsUuid, f"User renewed free VPS until {until}")
    return redirect(url_for("vpspanel", vpsUuid=vpsUuid))


@app.route("/vps/<vpsUuid>/delete", methods=["POST"])
@loginrequired
def deletevps(vpsUuid):
    vps = db.getvps(vpsUuid)
    if not vps or vps["userid"] != g.userinfo["id"]:
        flash("VPS not found.", "error")
        return redirect(url_for('dashboard'))

    if vpsissuspended(vps):
        flash("This VPS is suspended.", "error")
        return redirect(url_for('vpspanel', vpsUuid=vpsUuid))

    if db.haspendingjobs(vpsUuid):
        flash("This VPS has a pending action. Wait for it to complete.", "error")
        return redirect(url_for('vpspanel', vpsUuid=vpsUuid))

    _queuedeletevps(vps, actor_userid=g.userinfo["id"])
    auditlog("vps.delete", "vps", vpsUuid, f"Queued delete for {vps['hostname']}")
    flash("VPS marked deleted. Removing from node…", "success")
    return redirect(url_for('dashboard'))


@app.route("/vps/<vpsUuid>/reinstall", methods=["POST"])
@loginrequired
def reinstallvps(vpsUuid):
    vps = db.getvps(vpsUuid)
    isAdmin = g.userinfo.get('role') == 'admin'
    if not vps or (not isAdmin and vps["userid"] != g.userinfo["id"]):
        flash("VPS not found.", "error")
        return redirect(url_for('adminvps' if isAdmin else 'dashboard'))

    backUrl = url_for('adminvpspanel', vpsUuid=vpsUuid) if isAdmin else url_for('vpspanel', vpsUuid=vpsUuid)

    plan = db.getplanbyid(vps['planid'])
    if not isAdmin and (not plan or float(plan['price']) <= 0):
        flash("Reinstall is only available for paid VPS.", "error")
        return redirect(backUrl)

    if vpsissuspended(vps) and not isAdmin:
        flash("This VPS is suspended.", "error")
        return redirect(backUrl)

    imageId = request.form.get("imageId", type=int)
    image = db.getimagebyid(imageId) if imageId else None
    if not image or not db.isimageassignedtonode(image['id'], vps['nodeid']):
        flash("Invalid OS image selected for this node.", "error")
        return redirect(backUrl)

    if db.haspendingjobs(vpsUuid):
        flash("This VPS has a pending action. Wait for it to complete.", "error")
        return redirect(backUrl)

    enqueuejob(vps['id'], vpsUuid, g.userinfo["id"], 'reinstall', payload={'imageId': imageId})
    auditlog("vps.reinstall", "vps", vpsUuid, f"Queued reinstall for {vps['hostname']}")
    flash("VPS reinstall queued. A new root password will be generated.", "success")
    return redirect(backUrl)


@app.route("/vps/<vpsUuid>/status")
@loginrequired
def vpsstatuspoll(vpsUuid):
    vps = db.getvps(vpsUuid)
    if not vps:
        return jsonify({"error": "VPS not found"}), 404
    isAdmin = g.userinfo.get("role") == "admin"
    if not isAdmin and vps["userid"] != g.userinfo["id"]:
        return jsonify({"error": "VPS not found"}), 404

    # Single Proxmox call: status sync + metrics
    details = services.getvpsdetails(vps["id"])
    details, metric = services.fetchlivevps(vps["id"], details=details)
    status = (details or vps).get("status") or vps["status"]
    return jsonify({"status": status, "metrics": metric})


@app.route("/dashboard/vps-status")
@loginrequired
def dashboardvpsstatus():
    """Live status for VPS UUIDs currently shown on the user dashboard."""
    raw = (request.args.get("uuids") or "").strip()
    if not raw:
        return jsonify({"statuses": {}})
    uuids = [u.strip() for u in raw.split(",") if u.strip()][:30]
    out = {}
    for u in uuids:
        vps = db.getvps(u)
        if not vps or vps["userid"] != g.userinfo["id"]:
            continue
        # Skip heavy Proxmox calls for terminal/payment states
        if vps.get("status") in ("pendingpayment", "deleted", "creating", "suspended"):
            out[u] = vps["status"]
            continue
        details = services.synclivestatus(vps["id"]) or vps
        out[u] = details.get("status") if isinstance(details, dict) else vps["status"]
    return jsonify({"statuses": out})


@app.route("/vps/<vpsUuid>/console/token", methods=["POST"])
@loginrequired
def vpsconsoletoken(vpsUuid):
    limited = checkratelimit("console", "console", "30/minute", identity=g.userinfo["id"])
    if limited:
        return limited
    vps = db.getvps(vpsUuid)
    if not vps:
        return jsonify({"error": "VPS not found"}), 404

    isAdmin = g.userinfo.get('role') == 'admin'
    if not isAdmin and vps["userid"] != g.userinfo["id"]:
        return jsonify({"error": "VPS not found"}), 404

    if vpsissuspended(vps):
        return jsonify({"error": "This VPS is suspended"}), 400

    if vps["status"] != "running":
        return jsonify({"error": "VPS must be running to open console"}), 400

    body = request.get_json(silent=True) or {}
    requestedIp = body.get("ip") or request.form.get("ip")
    ips = [ip for ip in (vps.get("ipv4"), vps.get("ipv6")) if ip]
    ip = requestedIp if requestedIp in ips else (ips[0] if ips else None)
    if not ip:
        return jsonify({"error": "No IP assigned to this VPS"}), 400

    # Store credentials server-side only; client receives a non-reversible token
    token = secrets.token_urlsafe(32)
    _ssh_sessions[token] = {
        "vpsUuid": vpsUuid,
        "userid": g.userinfo["id"],
        "hostname": ip,
        "port": 22,
        "username": "root",
        "password": vps["password"],
        "created": time.time(),
    }
    auditlog("vps.console", "vps", vpsUuid, f"Opened console for {vps.get('hostname')} via {ip}")
    return jsonify({"token": token})


@app.route("/vps/<vpsUuid>/password", methods=["GET"])
@loginrequired
def vpspasswordreveal(vpsUuid):
    """Return VPS password on demand. Rate-limited to prevent brute-force."""
    limited = checkratelimit("pwreveal", "pwreveal", "10/minute", identity=g.userinfo["id"])
    if limited:
        return limited
    vps = db.getvps(vpsUuid)
    if not vps:
        return jsonify({"error": "VPS not found"}), 404

    isAdmin = g.userinfo.get('role') == 'admin'
    if not isAdmin and vps["userid"] != g.userinfo["id"]:
        return jsonify({"error": "VPS not found"}), 404

    auditlog("vps.revealpassword", "vps", vpsUuid, f"Password revealed for {vps.get('hostname')}")
    return jsonify({"password": vps["password"]})


@app.route("/vps/<vpsUuid>/console")
@loginrequired
def vpsconsole(vpsUuid):
    # Purge expired SSH session tokens
    now = time.time()
    expired_ssh = [t for t, v in _ssh_sessions.items() if now - v.get("created", 0) > _SSH_SESSION_TTL]
    for t in expired_ssh:
        del _ssh_sessions[t]

    token = request.args.get("t")
    if not token or token not in _ssh_sessions:
        return "Invalid or expired console token", 403

    ct = _ssh_sessions.pop(token)
    if ct["vpsUuid"] != vpsUuid:
        return "Invalid or expired console token", 403

    # Verify the requesting user still owns this VPS
    vps = db.getvps(vpsUuid)
    if not vps:
        return "VPS not found", 404

    isAdmin = g.userinfo.get('role') == 'admin'
    if not isAdmin and vps["userid"] != g.userinfo["id"]:
        return "VPS not found", 404

    if vpsissuspended(vps):
        return "This VPS is suspended", 403

    # Create a short-lived SSH session token for the WebSocket connection
    # This token maps to server-side credentials - nothing sensitive reaches the client
    ssh_token = secrets.token_urlsafe(32)
    _ssh_sessions[ssh_token] = {
        "vpsUuid": vpsUuid,
        "userid": g.userinfo["id"],
        "hostname": ct["hostname"],
        "port": ct["port"],
        "username": ct["username"],
        "password": ct["password"],
        "created": time.time(),
    }

    return render_template(
        "console.html",
        ssh_token=ssh_token,
        hostname_display=vps.get("ipv4") or vps.get("ipv6", "unknown"),
        theme=get_theme_class(g.userinfo),
    )


@sock.route("/ws/ssh")
def ws_ssh(ws):
    # Authenticate via session cookie
    token = request.cookies.get(COOKIE_NAME)
    user = services.validatesession(token) if token else None
    if not user:
        try:
            ws.close(1008, "Unauthorized")
        except Exception:
            pass
        return

    # Rate limit SSH connections per user
    rl_key = f"ssh:{user['id']}"
    ok, retry = ratelimit.hit(rl_key, limit=10, window=60)
    if not ok:
        try:
            ws.close(1013, "Too many connection attempts. Try again later.")
        except Exception:
            pass
        return

    # Accept only a one-time session token - credentials never reach the client
    ssh_token = request.args.get("token", "")
    if not ssh_token or ssh_token not in _ssh_sessions:
        try:
            ws.close(1008, "Invalid or expired session")
        except Exception:
            pass
        return

    # Pop the token (single-use)
    session = _ssh_sessions.pop(ssh_token)

    # Validate ownership: the session must belong to this user
    if session["userid"] != user["id"]:
        try:
            ws.close(1008, "Unauthorized")
        except Exception:
            pass
        return

    # Validate the VPS still belongs to this user and is in good standing
    vps = db.getvps(session["vpsUuid"])
    if not vps or vps.get("userid") != user["id"]:
        try:
            ws.close(1008, "VPS not found")
        except Exception:
            pass
        return

    if vpsissuspended(vps):
        try:
            ws.close(1003, "VPS is suspended")
        except Exception:
            pass
        return

    host = session["hostname"]
    port = session["port"]
    username = session["username"]
    password = session["password"]

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(host, port=port, username=username, password=password,
                    timeout=config.get("console", {}).get("timeout", 10),
                    banner_timeout=15, auth_timeout=15, look_for_keys=False)
    except Exception:
        try:
            ws.close(1011, "SSH connection failed")
        except Exception:
            pass
        return

    try:
        transport = ssh.get_transport()
        if transport:
            transport.set_keepalive(15)
        chan = ssh.invoke_shell(term="xterm-256color", width=120, height=40)
    except Exception:
        try:
            chan = ssh.invoke_shell(term="xterm", width=120, height=40)
        except Exception:
            ssh.close()
            try:
                ws.close(1011, "Shell initialization failed")
            except Exception:
                pass
            return

    chan.settimeout(0.1)

    closed = threading.Event()
    last_activity = time.time()
    session_started = time.time()

    def ssh_to_ws():
        """Read from SSH channel, send to WebSocket."""
        nonlocal last_activity
        try:
            while not closed.is_set():
                try:
                    data = chan.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    break
                last_activity = time.time()
                try:
                    ws.send(bytes(data))
                except Exception:
                    break
        finally:
            closed.set()

    reader = threading.Thread(target=ssh_to_ws, daemon=True)
    reader.start()

    try:
        while not closed.is_set():
            # Enforce max session duration
            if time.time() - session_started > _SSH_MAX_DURATION:
                try:
                    ws.close(1000, "Session timeout")
                except Exception:
                    pass
                break

            # Enforce idle timeout
            if time.time() - last_activity > _SSH_IDLE_TIMEOUT:
                try:
                    ws.close(1000, "Idle timeout")
                except Exception:
                    pass
                break

            try:
                msg = ws.receive(timeout=0.5)
            except Exception:
                break
            if msg is None:
                continue
            last_activity = time.time()
            try:
                d = json.loads(msg)
            except (json.JSONDecodeError, TypeError):
                d = None
            if d:
                if "data" in d:
                    try:
                        chan.send(d["data"])
                    except Exception:
                        break
                if "resize" in d and len(d["resize"]) == 2:
                    try:
                        chan.resize_pty(width=d["resize"][0], height=d["resize"][1])
                    except Exception:
                        pass
    finally:
        closed.set()
        try:
            chan.close()
        except Exception:
            pass
        try:
            ssh.close()
        except Exception:
            pass


@sock.route("/ws/captcha")
def ws_captcha_proxy(ws):
    """Proxy WebSocket for the captcha service.

    The browser connects here without needing the captcha API key. The panel
    opens a server-side WebSocket to the captcha service with the API key held
    in config, and forwards frames both ways. The API key (and the captcha
    service's address) never reach the browser.
    """
    if not captcha.is_enabled():
        try:
            ws.close(1008, "Captcha disabled")
        except Exception:
            pass
        return

    upstream_url = captcha.get_ws_url()
    api_key = (captcha.get_config().get("api_key") or "").strip()
    if not upstream_url or not api_key:
        try:
            ws.close(1011, "Captcha service not configured")
        except Exception:
            pass
        return

    # Connect upstream to the captcha service with the API key in the header.
    headers = [("X-API-Key", api_key)]
    try:
        upstream = simple_ws_connect(upstream_url, headers=headers, timeout=5)
    except Exception:
        try:
            ws.close(1011, "Captcha service unreachable")
        except Exception:
            pass
        return

    closed = threading.Event()

    def upstream_to_browser():
        try:
            while not closed.is_set():
                try:
                    data = upstream.receive(timeout=0.5)
                except Exception:
                    break
                if data is None:
                    continue
                if isinstance(data, (bytes, bytearray)):
                    try:
                        ws.send(bytes(data))
                    except Exception:
                        break
                else:
                    try:
                        ws.send(str(data))
                    except Exception:
                        break
        finally:
            closed.set()

    reader = threading.Thread(target=upstream_to_browser, daemon=True)
    reader.start()

    try:
        while not closed.is_set():
            try:
                msg = ws.receive(timeout=0.5)
            except Exception:
                break
            if msg is None:
                continue
            try:
                if isinstance(msg, (bytes, bytearray)):
                    upstream.send(bytes(msg))
                else:
                    upstream.send(str(msg))
            except Exception:
                break
    finally:
        closed.set()
        try:
            upstream.close()
        except Exception:
            pass


#Admin

@app.route("/dashboard/admin")
@loginrequired
@adminrequired
def admindashboard():
    return render_template("admindashboard.html", **paneluserinfo(g.userinfo), **paneladmininfo(g.userinfo))

@app.route("/dashboard/admin/users", methods=["GET", "POST"])
@loginrequired
@adminrequired
def adminusers():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        if username and email and password:
            userUuid = str(uuid.uuid4())
            hashedPw = services.hashpassword(password)
            role = 'admin' if db.countusers() == 0 else 'user'
            try:
                db.adduser(uuid=userUuid, username=username, email=email, password=hashedPw, role=role)
                auditlog("user.create", "user", userUuid, f"Created user '{username}' (role={role})")
                flash("User created.", "success")
            except Exception:
                flash("Error creating user.", "error")
        else:
            flash("All fields required.", "error")
        return redirect(url_for('adminusers'))

    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    perpage = 12 
    
    paginationData = db.listuserspaginated(page=page, perpage=perpage, search=q)
    
    return render_template(
        "adminusers.html", 
        **paneluserinfo(g.userinfo), 
        **paneladmininfo(g.userinfo),
        allUsers=paginationData['users'],
        pagination=paginationData,
        search=q or ''
    )
@app.route("/dashboard/admin/users/update/<string:userUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminupdateusers(userUuid):
    username = request.form.get('username')
    email = request.form.get('email')
    role = request.form.get('role')
    
    if role not in ('user', 'admin'):
        flash("Invalid role.", "error")
        return redirect(url_for('adminusers'))

    # Prevent admin from demoting themselves
    targetUser = db.getuser(userUuid)
    if targetUser and targetUser['id'] == g.userinfo['id'] and role != 'admin':
        flash("You cannot demote yourself.", "error")
        return redirect(url_for('adminusers'))
    
    db.updateuser(
        userUuid,
        username=username,
        email=email,
        role=role
    )
    
    auditlog("user.update", "user", userUuid, f"Updated user: username={username}, role={role}")
    flash("User updated successfully!", "success")
    return redirect(url_for('adminusers'))

@app.route("/dashboard/admin/users/ban/<int:userId>", methods=["POST"])
@loginrequired
@adminrequired
def adminbanuser(userId):
    if userId == g.userinfo["id"]:
        flash("You cannot ban yourself.", "error")
        return redirect(url_for('adminusers'))

    target = db.getuserbyid(userId)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for('adminusers'))

    reason = request.form.get("reason", "No reason provided")
    banUuid = str(uuid.uuid4())
    adminId = g.userinfo["id"] 
    
    db.addban(banUuid, userId, adminId, reason, expires=None)
    db.updateuser(userId, status="banned")

    # Invalidate all sessions for the banned user
    with db.getconnection() as conn:
        conn.execute("DELETE FROM sessions WHERE userid = ?", (userId,))

    # Suspend all of the user's VPS
    suspendReason = f"Owner banned: {reason}"
    userVps = db.listvpspaginated(page=1, perpage=10000, userid=userId)["vps"]
    suspendedCount = 0
    for v in userVps:
        if vpsissuspended(v) or v["status"] in ("deleted", "pendingpayment"):
            continue
        if db.haspendingjobs(v["uuid"]):
            continue
        db.addvpssuspension(str(uuid.uuid4()), v["id"], userId, adminId, suspendReason)
        db.updatevps(v["uuid"], status="suspended")
        enqueuejob(v["id"], v["uuid"], adminId, "suspend")
        suspendedCount += 1
    
    auditlog("user.ban", "user", userId, f"Banned user '{target['username']}': {reason} (suspended {suspendedCount} VPS)")
    flash(f"User banned. {suspendedCount} VPS suspended.", "success")
    return redirect(url_for('adminusers'))


@app.route("/dashboard/admin/users/unban/<int:userId>", methods=["POST"])
@loginrequired
@adminrequired
def adminunbanuser(userId):
    # Find their active ban and remove it
    activeBan = db.getbanbyuserid(userId)
    if activeBan:
        db.removeban(activeBan["uuid"])
    
    # Restore the user's STATUS column to "active"
    db.updateuser(userId, status="active")
    
    auditlog("user.unban", "user", userId, f"Unbanned user")
    flash("User has been unbanned.", "success")
    return redirect(url_for('adminusers'))


@app.route("/dashboard/admin/vps")
@loginrequired
@adminrequired
def adminvps():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    status = request.args.get('status', '').strip() or None
    vpsData = db.listvpspaginated(page=page, perpage=12, search=q, status=status)
    suspendedCount = db.listvpspaginated(page=1, perpage=1, status='suspended')['totalCount']
    
    users = db.listallusers()
    plans = db.listplans(active=1)
    images = db.listimages(active=1, node_type='proxmox')
    networks = db.listnetworks(network_type='proxmox')
    allNodes = db.listallnodes()
    storagePools = db.liststoragepools()
    
    return render_template(
        "adminvps.html", 
        allVps=vpsData['vps'],
        pagination=vpsData,
        users=users,
        plans=plans,
        images=images,
        networks=networks,
        allNodes=allNodes,
        storagePools=storagePools,
        search=q or '',
        statusFilter=status or '',
        suspendedCount=suspendedCount,
        **paneluserinfo(g.userinfo), 
        **paneladmininfo(g.userinfo)
    )


@app.route("/dashboard/admin/vps/remove-suspended", methods=["POST"])
@loginrequired
@adminrequired
def adminvpsremovesuspended():
    suspended = db.listvpspaginated(page=1, perpage=10000, status='suspended')['vps']
    queued = 0
    skipped = 0
    for v in suspended:
        if db.haspendingjobs(v['uuid']):
            skipped += 1
            continue
        _queuedeletevps(v, actor_userid=g.userinfo['id'])
        auditlog("vps.delete", "vps", v['uuid'], f"Bulk-removed suspended VPS {v['hostname']}")
        queued += 1
    flash(f"Queued delete for {queued} suspended VPS." + (f" Skipped {skipped} with pending jobs." if skipped else ""), "success" if queued else "warning")
    return redirect(url_for('adminvps'))

@app.route("/dashboard/admin/vps/<vpsUuid>")
@loginrequired
@adminrequired
def adminvpspanel(vpsUuid):
    vps = db.getvps(vpsUuid)
    if not vps:
        abort(404)

    # Fast path: DB only. Live Proxmox via /vps/<uuid>/status poll.
    instance = services.getvpsdetails(vps["id"])
    owner = db.getuserbyid(vps["userid"])
    suspension = db.getsuspensionbyvpsid(vps["id"])

    if instance:
        os_type = instance.get('os_type') or 'linux'
        instance['os_meta'] = OS_TYPES.get(os_type, OS_TYPES['linux'])

    assignedIpv4 = instance.get('ipv4') if instance else vps.get('ipv4')
    assignedIpv6 = instance.get('ipv6') if instance else vps.get('ipv6')

    networkDns = None
    if vps.get('networkid'):
        with db.getconnection() as conn:
            net = conn.execute(
                "SELECT dns FROM proxmox_networks WHERE id = ?", (vps['networkid'],)
            ).fetchone()
        if net and net.get('dns'):
            networkDns = net['dns']

    return render_template(
        "adminvpspanel.html",
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo),
        instance=instance,
        metric=None,
        owner=owner,
        assignedIpv4=assignedIpv4,
        assignedIpv6=assignedIpv6,
        networkDns=networkDns,
        suspension=suspension,
        reinstallImages=db.getimagesfornode(vps['nodeid'], active=1),
        metrics_mode=config.get("console", {}).get("metrics", "dynamic"),
    )

@app.route("/dashboard/admin/vps/<string:vpsUuid>/suspend", methods=["POST"])
@loginrequired
@adminrequired
def adminvpssuspend(vpsUuid):
    vps = db.getvps(vpsUuid)
    if not vps:
        flash("VPS not found.", "error")
        return redirect(url_for('adminvps'))

    if vpsissuspended(vps):
        flash("VPS is already suspended.", "error")
        return redirect(url_for('adminvpspanel', vpsUuid=vpsUuid))

    if db.haspendingjobs(vpsUuid):
        flash("This VPS has a pending action. Wait for it to complete.", "error")
        return redirect(url_for('adminvpspanel', vpsUuid=vpsUuid))

    reason = (request.form.get("reason") or "Suspended by admin").strip()
    db.addvpssuspension(str(uuid.uuid4()), vps["id"], vps["userid"], g.userinfo["id"], reason)
    db.updatevps(vpsUuid, status="suspended")
    enqueuejob(vps["id"], vpsUuid, g.userinfo["id"], "suspend")
    auditlog("vps.suspend", "vps", vpsUuid, f"Suspended VPS {vps['hostname']}: {reason}")
    flash("VPS suspension queued.", "success")
    return redirect(url_for('adminvpspanel', vpsUuid=vpsUuid))


@app.route("/dashboard/admin/vps/<string:vpsUuid>/unsuspend", methods=["POST"])
@loginrequired
@adminrequired
def adminvpsunsuspend(vpsUuid):
    vps = db.getvps(vpsUuid)
    if not vps:
        flash("VPS not found.", "error")
        return redirect(url_for('adminvps'))

    if vps["status"] != "suspended":
        flash("VPS is not suspended.", "error")
        return redirect(url_for('adminvpspanel', vpsUuid=vpsUuid))

    db.liftvpssuspension(vps["id"])
    db.updatevps(vpsUuid, status="stopped")
    auditlog("vps.unsuspend", "vps", vpsUuid, f"Unsuspended VPS {vps['hostname']}")
    flash("VPS unsuspended. It remains stopped until started.", "success")
    return redirect(url_for('adminvpspanel', vpsUuid=vpsUuid))


@app.route("/dashboard/admin/vps/<string:vpsUuid>/delete", methods=["POST"])
@loginrequired
@adminrequired
def adminvpsdelete(vpsUuid):
    vps = db.getvps(vpsUuid)
    if not vps:
        flash("VPS not found.", "error")
        return redirect(url_for('adminvps'))

    force = request.form.get("force") == "1"

    if force:
        # Force: free resources + drop DB row, skip waiting on node
        _softdeletevps(vps, free_resources=(vps.get("status") != "deleted"))
        try:
            _deletevpsnode(vps)
        except Exception:
            pass
        if db.getvps(vpsUuid):
            db.deletevpsrecord(vps["id"])
        auditlog("vps.delete", "vps", vpsUuid, f"Admin force-deleted VPS {vps['hostname']}")
        flash("VPS force-removed from DB.", "warning")
    else:
        _queuedeletevps(vps, actor_userid=g.userinfo["id"])
        auditlog("vps.delete", "vps", vpsUuid, f"Admin queued delete for {vps['hostname']}")
        flash("VPS marked deleted. Removing from node…", "success")

    return redirect(url_for('adminvps'))

@app.route("/dashboard/admin/vps/create", methods=["GET", "POST"])
@loginrequired
@adminrequired
def admincreatevps():
    if request.method == "POST":
        # 1. Automatic UUID Generation
        vpsUuid = str(uuid.uuid4())
        
        # 2. Extract basic info from the form
        userid = request.form.get('userid', type=int)
        planid = request.form.get('planid', type=int)
        imageid = request.form.get('imageid', type=int)
        nodeid = request.form.get('nodeid', type=int)
        storageid = request.form.get('storageid', type=int)
        networkid = request.form.get('networkid', type=int)
        hostname = request.form.get('hostname')
        password = request.form.get('password')

        # 3. Fetch Plan resources from Database (The "Source of Truth")
        plan = db.getplanbyid(planid)
        
        if not plan:
            flash("Invalid plan selected.", "danger")
            return redirect(url_for('adminvps'))

        if plan['stock'] == 0:
            flash("This plan is out of stock.", "danger")
            return redirect(url_for('adminvps'))

        isPaid = float(plan['price']) > 0

        # Check free plan limit for the target user
        if not isPaid and db.userhasfreevps(userid):
            flash("This user already has a free VPS. Free users can only create one free instance.", "danger")
            return redirect(url_for('adminvps'))

        if not db.getuserbyid(userid):
            flash("Invalid user selected.", "danger")
            return redirect(url_for('adminvps'))

        image = db.getimagebyid(imageid)
        if not image:
            flash("Invalid image selected.", "danger")
            return redirect(url_for('adminvps'))
        if not nodeid:
            flash("You must select a node.", "danger")
            return redirect(url_for('adminvps'))
        if not db.isimageassignedtonode(imageid, nodeid):
            flash("Selected image is not assigned to that node.", "danger")
            return redirect(url_for('adminvps'))

        if not networkid:
            flash("You must select a network.", "danger")
            return redirect(url_for('adminvps'))

        network_type = request.form.get('network_type', 'proxmox')
        network = db.getnetworkbyid(networkid, network_type=network_type)
        if not network:
            flash("Selected network not found.", "danger")
            return redirect(url_for('adminvps'))

        if network['nodeid'] != nodeid:
            flash("Selected network is not on the assigned node.", "danger")
            return redirect(url_for('adminvps'))

        ipError = db.planipavailabilityerror(plan, network, network_type=network_type)
        if ipError:
            flash(ipError, "danger")
            return redirect(url_for('adminvps'))

        storagepoolid = request.form.get('storagepoolid', type=int)

        try:
            db.createvpswithjob(
                uuid=vpsUuid,
                userid=userid,
                plan=plan,
                imageid=imageid,
                nodeid=nodeid,
                storageid=storageid,
                networkid=networkid,
                network_type=network_type,
                storagepoolid=storagepoolid,
                hostname=hostname,
                password=password,
                status='creating',
                jobtype='provision'
            )
            if not isPaid:
                _markvpsfreerenewal(vpsUuid)
            else:
                _markvpspaid(vpsUuid)
            auditlog("vps.admin_create", "vps", vpsUuid, f"Admin created VPS {hostname} for user {userid}")
            flash(f"Instance {hostname} created successfully with {plan['name']} resources.", "success")
            return redirect(url_for('adminvps'))
            
        except Exception as e:
            flash("Deployment error.", "danger")
            return redirect(url_for('adminvps'))

    return redirect(url_for('adminvps'))


@app.route("/dashboard/admin/plans", methods=["GET", "POST"])
@loginrequired
@adminrequired
def adminplans():
    db.ensureplanassignmenttables()
    if request.method == "POST":
        planUuid = str(uuid.uuid4())
        db.addplan(
            uuid=planUuid,
            name=request.form.get("name"),
            cpu=int(request.form.get("cpu")),
            ram=int(request.form.get("ram")),
            swap=int(request.form.get("swap")),
            disk=int(request.form.get("disk")),
            description=request.form.get("description"),
            ipv4=1 if request.form.get("ipv4") else 0,
            ipv6=1 if request.form.get("ipv6") else 0,
            price=float(request.form.get("price") or 0),
            active=1 if request.form.get("active") else 0,
            stock=int(request.form.get("stock", -1)),
            netmbps=int(request.form.get("netmbps", 0)),
            node_type=request.form.get("node_type", "proxmox"),
        )
        plan = db.getplanbyuuid(planUuid)
        if plan:
            nodeIds = request.form.getlist("node_ids")
            db.setplannodes(plan["id"], nodeIds)
            db.setplanstoragepools(plan["id"], request.form.getlist("storagepool_ids"), nodeids=nodeIds)
        auditlog("plan.create", "plan", planUuid, f"Created plan '{request.form.get('name')}'")
        return redirect(url_for('adminplans'))

    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    plansData = db.listplanspaginated(page=page, perpage=12, search=q)
    allNodes = db.listallnodes()
    # attach each node's existing storage pools (from storagepools table)
    for n in allNodes:
        n['pools'] = db.liststoragepools(nodeid=n['id'])
    for plan in plansData['plans']:
        plan['assigned_node_ids'] = db.getplannodeids(plan['id'])
        plan['assigned_pool_ids'] = db.getplanstoragepoolids(plan['id'])
        plan['assigned_nodes'] = db.listplannodes(plan['id'])
        plan['assigned_pools'] = db.listplanstoragepools(plan['id'])

    defaultNodeType = allNodes[0].get('type', 'proxmox') if allNodes else 'proxmox'
    defaultNodeId = allNodes[0]['id'] if allNodes else None
    defaultPoolId = None
    if allNodes and allNodes[0].get('pools'):
        defaultPoolId = allNodes[0]['pools'][0]['id']

    return render_template(
        "adminplans.html", 
        allPlans=plansData['plans'],
        pagination=plansData,
        search=q or '',
        allNodes=allNodes,
        defaultNodeType=defaultNodeType,
        defaultNodeId=defaultNodeId,
        defaultPoolId=defaultPoolId,
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/plans/update/<string:planUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminupdateplans(planUuid):
    db.ensureplanassignmenttables()
    plan = db.getplanbyuuid(planUuid)
    if not plan:
        flash("Plan not found.", "error")
        return redirect(url_for('adminplans'))

    db.updateplan(
        uuid=planUuid,
        name=request.form.get("name"),
        cpu=int(request.form.get("cpu")),
        ram=int(request.form.get("ram")),
        swap=int(request.form.get("swap")),
        disk=int(request.form.get("disk")),
        description=request.form.get("description"),
        ipv4=1 if request.form.get("ipv4") else 0,
        ipv6=1 if request.form.get("ipv6") else 0,
        price=float(request.form.get("price")),
        active=1 if request.form.get("active") else 0,
        stock=int(request.form.get("stock", -1)),
        netmbps=int(request.form.get("netmbps", 0)),
        node_type=request.form.get("node_type", "proxmox")
    )
    nodeIds = request.form.getlist("node_ids")
    db.setplannodes(plan["id"], nodeIds)
    db.setplanstoragepools(plan["id"], request.form.getlist("storagepool_ids"), nodeids=nodeIds)
    
    auditlog("plan.update", "plan", planUuid, f"Updated plan '{request.form.get('name')}'")
    return redirect(url_for('adminplans'))

@app.route("/dashboard/admin/plans/delete/<string:planUuid>", methods=["POST"])
@loginrequired
@adminrequired
def admindeleteplans(planUuid):
    db.removeplan(uuid=planUuid)
    auditlog("plan.delete", "plan", planUuid, "Deleted plan")
    return redirect(url_for('adminplans'))

@app.route("/dashboard/admin/nodes")
@loginrequired
@adminrequired
def adminnodes():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    # Fast path: DB only. Live online/offline via /nodes/status poll in template.
    nodesData = db.listnodespaginated(page=page, perpage=12, search=q)
    return render_template(
        "adminnodes.html", 
        allNodes=nodesData['nodes'],
        allLocations=db.listalllocations(),
        pagination=nodesData,
        search=q or '',
        **paneluserinfo(g.userinfo), 
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/nodes/create", methods=["POST"])
@loginrequired
@adminrequired
def adminnodescreate():
    try:
        nodeUuid = str(uuid.uuid4())
        loc_id = request.form.get("locationid")
        location_id = int(loc_id) if loc_id and loc_id.isdigit() else None
        max_vps = int(request.form.get("max_vps", 0))
        db.addnode(
            uuid=nodeUuid,
            name=request.form.get("name"),
            hostname=request.form.get("hostname"),
            address=request.form.get("address"),
            locationid=location_id,
            max_vps=max_vps,
            url=request.form.get("url", ""),
            apikey=request.form.get("apikey") or "",
            cpu=int(request.form.get("cpu", 0)),
            ram=int(request.form.get("ram", 0)),
            status=request.form.get("status", "online"),
            tier=request.form.get("tier", "free"),
            nodeType="proxmox",
            proxmoxhost=request.form.get("proxmoxhost"),
            proxmoxuser=request.form.get("proxmoxuser"),
            proxmoxpassword=request.form.get("proxmoxpassword"),
            proxmoxnode=request.form.get("proxmoxnode", "pve"),
            proxmoxport=int(request.form.get("proxmoxport", 8006)),
            proxmoxssl=1 if request.form.get("proxmoxssl") == "1" else 0
        )
        auditlog("node.create", "node", nodeUuid, f"Registered proxmox node '{request.form.get('name')}'")
        flash(f"Node '{request.form.get('name')}' registered successfully.", "success")
    except Exception as e:
        flash("Error creating node.", "danger")
    
    return redirect(url_for('adminnodes'))

@app.route("/dashboard/admin/nodes/update/<string:nodeUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminnodesupdate(nodeUuid):
    node = db.getnode(nodeUuid)
    if not node:
        flash("Node not found.", "error")
        return redirect(url_for('adminnodes'))

    try:
        loc_id = request.form.get("locationid")
        location_id = int(loc_id) if loc_id and loc_id.isdigit() else None
        max_vps = int(request.form.get("max_vps", node.get("max_vps") or 0))
        updateData = {
            "name": request.form.get("name"),
            "hostname": request.form.get("hostname"),
            "address": request.form.get("address"),
            "locationid": location_id,
            "max_vps": max_vps,
            "cpu": int(request.form.get("cpu", node.get("cpu") or 0)),
            "ram": int(request.form.get("ram", node.get("ram") or 0)),
            "status": request.form.get("status", node.get("status", "online")),
            "tier": request.form.get("tier", node.get("tier", "free")),
            "proxmoxhost": request.form.get("proxmoxhost"),
            "proxmoxuser": request.form.get("proxmoxuser"),
            "proxmoxnode": request.form.get("proxmoxnode", "pve"),
            "proxmoxport": int(request.form.get("proxmoxport", 8006)),
            "proxmoxssl": 1 if request.form.get("proxmoxssl") == "1" else 0,
        }
        pvePass = request.form.get("proxmoxpassword")
        if pvePass and pvePass.strip() != "":
            updateData["proxmoxpassword"] = pvePass

        db.updatenode(nodeUuid, **updateData)
        auditlog("node.update", "node", nodeUuid, f"Updated node '{request.form.get('name')}'")
        flash("Node configuration updated.", "success")
    except Exception:
        flash("Error updating node.", "danger")

    return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='overview'))

@app.route("/dashboard/admin/nodes/delete/<string:nodeUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminnodesdelete(nodeUuid):
    try:
        db.removenode(nodeUuid)
        auditlog("node.delete", "node", nodeUuid, "Deleted node")
        flash("Node removed successfully.", "warning")
    except Exception as e:
        flash("Error deleting node.", "danger")
        
    return redirect(url_for('adminnodes'))

# --- Node Profile (Unified View) ---

@app.route("/dashboard/admin/nodes/<string:nodeUuid>/profile")
@loginrequired
@adminrequired
def adminnodeprofile(nodeUuid):
    node = db.getnode(nodeUuid)
    if not node:
        flash("Node not found.", "error")
        return redirect(url_for('adminnodes'))

    # Fast path: DB only. Live probe/stats via /nodes/<uuid>/stats poll in template.
    nodeType = node.get('type', 'proxmox')
    tab = request.args.get('tab', 'overview')

    node['vps_count'] = db.countvpsfornode(node['id'])
    node['disk'] = db.getnodediskcapacity(node['id'])

    networks = db.listnetworks(nodeid=node['id'], network_type=nodeType)
    storagePools = db.liststoragepools(nodeid=node['id'])
    imageStorages = db.listimagestorage(nodeid=node['id'])
    nodeImages = db.listimagesfornode(node['id'])

    ipStats = {}
    for net in networks:
        ipStats[net['id']] = db.countips(net['id'], network_type=nodeType)

    return render_template(
        "adminnodeprofile.html",
        node=node,
        nodeType=nodeType,
        activeTab=tab,
        networks=networks,
        storagePools=storagePools,
        imageStorages=imageStorages,
        nodeImages=nodeImages,
        ipStats=ipStats,
        allLocations=db.listalllocations(),
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/nodes/status")
@loginrequired
@adminrequired
def adminnodesstatus():
    """Probe listed nodes in parallel; return uuid→status. Does NOT update the DB."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    uuids = request.args.getlist("uuid")
    alln = db.listallnodes()
    nodes = alln if not uuids else [n for n in alln if n["uuid"] in set(uuids)]
    # cap work
    nodes = nodes[:30]
    out = {n["uuid"]: n.get("status") or "offline" for n in nodes}

    def _one(n):
        try:
            ok, _ = services.probenode(n, timeout=2)
            return n["uuid"], "online" if ok else "offline"
        except Exception:
            return n["uuid"], "offline"

    if nodes:
        with ThreadPoolExecutor(max_workers=min(8, len(nodes))) as pool:
            futs = [pool.submit(_one, n) for n in nodes]
            for fut in as_completed(futs):
                try:
                    uid, st = fut.result()
                    out[uid] = st
                except Exception:
                    pass
    return jsonify({"statuses": out})


@app.route("/dashboard/admin/nodes/<string:nodeUuid>/stats")
@loginrequired
@adminrequired
def adminnodestats(nodeUuid):
    """API endpoint to fetch live node stats. Sets online/offline from reachability."""
    node = db.getnode(nodeUuid)
    if not node:
        return jsonify({"error": "Node not found"}), 404

    ok, raw = services.probenode(node, timeout=5)
    fresh = db.getnode(nodeUuid) or node
    live_status = fresh.get('status', 'offline')

    if not ok:
        return jsonify({
            "error": "Node unreachable",
            "node_status": live_status,
        }), 503

    status = raw or {}
    cpu_val = status.get('cpu', 0)
    cpu_percent = round(cpu_val * 100, 1) if isinstance(cpu_val, (int, float)) else 0

    memory_info = status.get('memory', {})
    if isinstance(memory_info, dict):
        mem_total = memory_info.get('total', 0)
        mem_used = memory_info.get('used', 0)
        mem_free = memory_info.get('free', 0)
    else:
        mem_total = status.get('memtotal', status.get('maxmem', 0))
        mem_used = status.get('memused', status.get('mem', 0))
        mem_free = mem_total - mem_used

    mem_percent = round((mem_used / mem_total * 100), 1) if mem_total > 0 else 0

    rootfs_info = status.get('rootfs', {})
    if isinstance(rootfs_info, dict):
        disk_total = rootfs_info.get('total', 0)
        disk_used = rootfs_info.get('used', 0)
        disk_free = rootfs_info.get('free', rootfs_info.get('avail', 0))
    else:
        disk_total = status.get('maxdisk', 0)
        disk_used = status.get('disk', 0)
        disk_free = disk_total - disk_used

    disk_percent = round((disk_used / disk_total * 100), 1) if disk_total > 0 else 0

    loadavg = status.get('loadavg', [0, 0, 0])
    if isinstance(loadavg, list) and len(loadavg) >= 3:
        load_1, load_5, load_15 = loadavg[0], loadavg[1], loadavg[2]
    else:
        load_1 = load_5 = load_15 = 0

    stats = {
        'cpu_percent': cpu_percent,
        'memory_total': mem_total,
        'memory_used': mem_used,
        'memory_free': mem_free,
        'memory_percent': mem_percent,
        'disk_total': disk_total,
        'disk_used': disk_used,
        'disk_free': disk_free,
        'disk_percent': disk_percent,
        'load_1': load_1,
        'load_5': load_5,
        'load_15': load_15,
        'uptime': status.get('uptime', 0),
        'node_status': live_status,
    }

    # net rates optional; don't fail whole stats if RRD slow/missing
    stats['network_rx_bytes'] = 0
    stats['network_tx_bytes'] = 0
    try:
        pve = services.getproxmoxclient(node, timeout=5)
        node_name = node.get('proxmoxnode', 'pve')
        rrd = pve.nodes(node_name).rrddata.get(timeframe='hour', cf='AVERAGE')
        if rrd and len(rrd) > 0:
            latest = rrd[-1]
            net_in_rate = latest.get('netin', 0) or 0
            net_out_rate = latest.get('netout', 0) or 0
            uptime = status.get('uptime', 0) or 0
            stats['network_rx_bytes'] = int(net_in_rate * uptime) if uptime > 0 else 0
            stats['network_tx_bytes'] = int(net_out_rate * uptime) if uptime > 0 else 0
    except Exception:
        pass

    return jsonify(stats)


@app.route("/dashboard/admin/nodes/<string:nodeUuid>/images")
@loginrequired
@adminrequired
def adminnodeimageslist(nodeUuid):
    """API endpoint to fetch paginated images for a node."""
    node = db.getnode(nodeUuid)
    if not node:
        return jsonify({"error": "Node not found"}), 404
    
    page = int(request.args.get('page', 1))
    per_page = 20
    
    # Get all images for this node
    all_images = db.listimagesfornode(node['id'])
    
    # Paginate
    total = len(all_images)
    total_pages = (total + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    images = all_images[start:end]
    
    return jsonify({
        'images': images,
        'pagination': {
            'currentPage': page,
            'totalPages': total_pages,
            'perPage': per_page,
            'total': total,
            'hasNext': page < total_pages,
            'hasPrev': page > 1
        }
    })

# --- Node Profile: Network Management ---

@app.route("/dashboard/admin/nodes/<string:nodeUuid>/networks/create", methods=["POST"])
@loginrequired
@adminrequired
def adminnodenetworkcreate(nodeUuid):
    node = db.getnode(nodeUuid)
    if not node:
        flash("Node not found.", "error")
        return redirect(url_for('adminnodes'))

    nodeType = node.get('type', 'proxmox')
    name = request.form.get("name")
    ipv4 = int(request.form.get("ipv4", 0))
    ipv6 = int(request.form.get("ipv6", 1))
    ipv4_subnet = request.form.get("ipv4_subnet") or None
    ipv4_gateway = request.form.get("ipv4_gateway") or None
    ipv6_subnet = request.form.get("ipv6_subnet") or None
    ipv6_gateway = request.form.get("ipv6_gateway") or None
    dns = request.form.get("dns", "1.1.1.1,8.8.8.8,2606:4700:4700::1111,2001:4860:4860::8888")

    if not name:
        flash("Network name required.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='networks'))

    if db.getnetworkbynamenodeid(name, node['id'], network_type=nodeType):
        flash("Network already exists for this node.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='networks'))

    netUuid = str(uuid.uuid4())
    db.addnetwork(uuid=netUuid, nodeid=node['id'], name=name, network_type=nodeType,
                  subnet=ipv6_subnet, gateway=ipv6_gateway, ipv4=ipv4, ipv6=ipv6,
                  ipv4_subnet=ipv4_subnet, ipv4_gateway=ipv4_gateway, dns=dns)
    auditlog("network.create", "network", netUuid, f"Created {nodeType} network '{name}' on node '{node['name']}'")
    flash(f"Network '{name}' created.", "success")
    return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='networks'))

@app.route("/dashboard/admin/nodes/<string:nodeUuid>/networks/<string:netUuid>/update", methods=["POST"])
@loginrequired
@adminrequired
def adminnodenetworkupdate(nodeUuid, netUuid):
    node = db.getnode(nodeUuid)
    if not node:
        flash("Node not found.", "error")
        return redirect(url_for('adminnodes'))

    nodeType = node.get('type', 'proxmox')
    network = db.getnetwork(netUuid, network_type=nodeType)
    if not network:
        flash("Network not found.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='networks'))

    name = request.form.get("name", "").strip()
    ipv4 = int(request.form.get("ipv4", 0))
    ipv6 = int(request.form.get("ipv6", 1))
    ipv4_subnet = request.form.get("ipv4_subnet") or None
    ipv4_gateway = request.form.get("ipv4_gateway") or None
    ipv6_subnet = request.form.get("ipv6_subnet") or None
    ipv6_gateway = request.form.get("ipv6_gateway") or None
    dns = request.form.get("dns", "")

    if not name:
        flash("Network name required.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='networks'))

    existing = db.getnetworkbynamenodeid(name, node['id'], network_type=nodeType)
    if existing and existing['uuid'] != netUuid:
        flash("Network already exists for this node.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='networks'))

    db.updatenetwork(netUuid, network_type=nodeType, name=name, subnet=ipv6_subnet, gateway=ipv6_gateway,
                     ipv4=ipv4, ipv6=ipv6, ipv4_subnet=ipv4_subnet, ipv4_gateway=ipv4_gateway, dns=dns)
    auditlog("network.update", "network", netUuid, f"Updated {nodeType} network '{name}'")
    flash("Network updated.", "success")
    return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='networks'))

@app.route("/dashboard/admin/nodes/<string:nodeUuid>/networks/<string:netUuid>/delete", methods=["POST"])
@loginrequired
@adminrequired
def adminnodenetworkdelete(nodeUuid, netUuid):
    node = db.getnode(nodeUuid)
    if not node:
        flash("Node not found.", "error")
        return redirect(url_for('adminnodes'))

    nodeType = node.get('type', 'proxmox')
    network = db.getnetwork(netUuid, network_type=nodeType)
    if not network:
        flash("Network not found.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='networks'))

    vpsCount = db.countvpsbynetwork(network['id'], network_type=nodeType)
    if vpsCount > 0:
        flash(f"Cannot delete: {vpsCount} VPS instance(s) using this network.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='networks'))

    db.removenetwork(netUuid, network_type=nodeType)
    auditlog("network.delete", "network", netUuid, f"Deleted network '{network['name']}'")
    flash("Network removed.", "warning")
    return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='networks'))

# --- Node Profile: IP Management ---

@app.route("/dashboard/admin/nodes/<string:nodeUuid>/networks/<string:netUuid>/ips")
@loginrequired
@adminrequired
def adminnodeips(nodeUuid, netUuid):
    node = db.getnode(nodeUuid)
    if not node:
        return jsonify({"error": "Node not found"}), 404

    nodeType = node.get('type', 'proxmox')
    network = db.getnetwork(netUuid, network_type=nodeType)
    if not network:
        return jsonify({"error": "Network not found"}), 404

    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    version = request.args.get('version')
    if version not in ('ipv4', 'ipv6'):
        version = None
    ipsData = db.listnetworkips(network['id'], network_type=nodeType, page=page, perpage=50, search=q, version=version)
    ipStats = db.countips(network['id'], network_type=nodeType)

    return jsonify({
        "ips": ipsData['ips'],
        "pagination": {
            "currentPage": ipsData['currentPage'],
            "totalPages": ipsData['totalPages'],
            "totalCount": ipsData['totalCount'],
            "hasPrev": ipsData['hasPrev'],
            "hasNext": ipsData['hasNext'],
        },
        "stats": ipStats,
    })

@app.route("/dashboard/admin/nodes/<string:nodeUuid>/ips/add", methods=["POST"])
@loginrequired
@adminrequired
def adminnodeipadd(nodeUuid):
    node = db.getnode(nodeUuid)
    if not node:
        flash("Node not found.", "error")
        return redirect(url_for('adminnodes'))

    nodeType = node.get('type', 'proxmox')
    networkid = request.form.get("networkid", type=int)
    ip = request.form.get("ip", "").strip()
    version = request.form.get("version")

    if not networkid or not ip or version not in ('ipv4', 'ipv6'):
        flash("Network, pool, and IP required.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='ips'))

    network = db.getnetworkbyid(networkid, network_type=nodeType)
    if not network or network['nodeid'] != node['id']:
        flash("Network not found on this node.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='ips'))

    try:
        if (version == 'ipv6') != (':' in ip):
            flash("IP does not match selected pool.", "error")
            return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='ips'))
        db.addnetworkip(str(uuid.uuid4()), networkid, ip, network_type=nodeType)
        auditlog("ip.add", "network", network.get("uuid") or nodeUuid, f"Added {ip} to '{network['name']}' on '{node['name']}'")
        flash(f"IP {ip} added to {network['name']}.", "success")
    except Exception:
        flash("IP already exists or invalid.", "error")
    return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='ips'))

@app.route("/dashboard/admin/nodes/<string:nodeUuid>/ips/generate", methods=["POST"])
@loginrequired
@adminrequired
def adminnodeipsgenerate(nodeUuid):
    node = db.getnode(nodeUuid)
    if not node:
        flash("Node not found.", "error")
        return redirect(url_for('adminnodes'))

    nodeType = node.get('type', 'proxmox')
    networkid = request.form.get("networkid", type=int)
    baseip = request.form.get("baseip")
    count = request.form.get("count", type=int)
    version = request.form.get("version")

    if not networkid or not baseip or not count or count < 1 or version not in ('ipv4', 'ipv6'):
        flash("Network, pool, base IP, and count required.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='ips'))

    network = db.getnetworkbyid(networkid, network_type=nodeType)
    if not network or network['nodeid'] != node['id']:
        flash("Network not found on this node.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='ips'))

    isipv6 = version == 'ipv6'
    if isipv6 != (':' in baseip):
        flash("Base IP does not match selected pool.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='ips'))
    generated = db.generateipsfornetwork(network['id'], baseip, count, network_type=nodeType, isipv6=isipv6)
    auditlog("ip.generate", "network", nodeUuid, f"Generated {len(generated)} IP(s) on '{network['name']}'")
    flash(f"Generated {len(generated)} IP(s) on {network['name']}.", "success")
    return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='ips'))

@app.route("/dashboard/admin/nodes/<string:nodeUuid>/ips/<string:ipUuid>/delete", methods=["POST"])
@loginrequired
@adminrequired
def adminnodeipdelete(nodeUuid, ipUuid):
    ip = db.getnetworkip(ipUuid)
    if ip and ip['assigned']:
        flash("Cannot delete an assigned IP.", "error")
    else:
        ipAddr = (ip or {}).get("ip") or ipUuid
        db.removenetworkip(ipUuid)
        auditlog("ip.delete", "network", nodeUuid, f"Removed IP {ipAddr}")
        flash("IP removed.", "warning")
    return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='ips'))

@app.route("/dashboard/admin/nodes/<string:nodeUuid>/ips/bulk-delete", methods=["POST"])
@loginrequired
@adminrequired
def adminnodeipsbulkdelete(nodeUuid):
    node = db.getnode(nodeUuid)
    if not node:
        flash("Node not found.", "error")
        return redirect(url_for('adminnodes'))

    uuids = request.form.getlist("uuids")
    if not uuids:
        flash("No IPs selected.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='ips'))

    deleted = db.removenetworkips(uuids)
    if deleted:
        auditlog("ip.bulk_delete", "network", nodeUuid, f"Bulk removed {deleted} IP(s)")
        flash(f"Removed {deleted} IP(s).", "warning")
    else:
        flash("No free IPs deleted (assigned IPs are skipped).", "error")
    return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='ips'))

# --- Node Profile: Storage Pool Management ---

@app.route("/dashboard/admin/nodes/<string:nodeUuid>/storagepools/create", methods=["POST"])
@loginrequired
@adminrequired
def adminnodestoragecreate(nodeUuid):
    node = db.getnode(nodeUuid)
    if not node:
        flash("Node not found.", "error")
        return redirect(url_for('adminnodes'))

    name = request.form.get("name")
    source = request.form.get("source") or None
    size = int(request.form.get("size", 0))

    if not name:
        flash("Pool name required.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='storage'))

    poolUuid = str(uuid.uuid4())
    db.addstoragepool(uuid=poolUuid, nodeid=node['id'], name=name, source=source, size=size, nodeType=node.get('type', 'proxmox'))
    auditlog("storage.create", "storage", poolUuid, f"Created storage pool '{name}' on '{node['name']}'")
    flash(f"Storage pool '{name}' created.", "success")
    return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='storage'))

@app.route("/dashboard/admin/nodes/<string:nodeUuid>/storagepools/<string:poolUuid>/update", methods=["POST"])
@loginrequired
@adminrequired
def adminnodestorageupdate(nodeUuid, poolUuid):
    pool = db.getstoragepool(poolUuid)
    if not pool:
        flash("Pool not found.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='storage'))

    name = request.form.get("name")
    size = int(request.form.get("size", 0))
    db.updatestoragepool(poolUuid, name=name, size=size)
    auditlog("storage.update", "storage", poolUuid, f"Updated storage pool '{name}'")
    flash("Storage pool updated.", "success")
    return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='storage'))

@app.route("/dashboard/admin/nodes/<string:nodeUuid>/storagepools/<string:poolUuid>/delete", methods=["POST"])
@loginrequired
@adminrequired
def adminnodestoragedelete(nodeUuid, poolUuid):
    pool = db.getstoragepool(poolUuid)
    if not pool:
        flash("Pool not found.", "error")
    else:
        db.removestoragepool(poolUuid)
        auditlog("storage.delete", "storage", poolUuid, f"Deleted storage pool '{pool['name']}'")
        flash("Storage pool removed.", "warning")
    return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='storage'))

# --- Node Profile: Image Storage Management ---

@app.route("/dashboard/admin/nodes/<string:nodeUuid>/imagestorage/create", methods=["POST"])
@loginrequired
@adminrequired
def adminnodeimagestoragecreate(nodeUuid):
    node = db.getnode(nodeUuid)
    if not node:
        flash("Node not found.", "error")
        return redirect(url_for('adminnodes'))

    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip() or None

    if not name:
        flash("Storage name required.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='imagestorage'))

    storageUuid = str(uuid.uuid4())
    db.addimagestorage(uuid=storageUuid, nodeid=node['id'], name=name, description=description)
    auditlog("imagestorage.create", "imagestorage", storageUuid, f"Added image storage '{name}' to '{node['name']}'")
    flash(f"Image storage '{name}' added.", "success")
    return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='imagestorage'))

@app.route("/dashboard/admin/nodes/<string:nodeUuid>/imagestorage/<string:storageUuid>/update", methods=["POST"])
@loginrequired
@adminrequired
def adminnodeimagestorageupdate(nodeUuid, storageUuid):
    storage = db.getimagestorage(storageUuid)
    if not storage:
        flash("Image storage not found.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='imagestorage'))

    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip() or None
    if not name:
        flash("Storage name cannot be empty.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='imagestorage'))

    db.updateimagestorage(storageUuid, name=name, description=description)
    auditlog("imagestorage.update", "imagestorage", storageUuid, f"Updated image storage '{name}'")
    flash("Image storage updated.", "success")
    return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='imagestorage'))

@app.route("/dashboard/admin/nodes/<string:nodeUuid>/imagestorage/<string:storageUuid>/delete", methods=["POST"])
@loginrequired
@adminrequired
def adminnodeimagestoragedelete(nodeUuid, storageUuid):
    storage = db.getimagestorage(storageUuid)
    if not storage:
        flash("Image storage not found.", "error")
    else:
        db.removeimagestorage(storageUuid)
        auditlog("imagestorage.delete", "imagestorage", storageUuid, f"Deleted image storage '{storage['name']}'")
        flash(f"Image storage '{storage['name']}' removed.", "warning")
    return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='imagestorage'))

@app.route("/dashboard/admin/nodes/<string:nodeUuid>/imagestorage/fetch")
@loginrequired
@adminrequired
def adminnodeimagestoragefetch(nodeUuid):
    node = db.getnode(nodeUuid)
    if not node:
        return jsonify({"error": "Node not found"}), 404
    if node.get('type') != 'proxmox':
        return jsonify({"error": "Not a Proxmox node"}), 400

    try:
        pve = services.getproxmoxclient(node)
        node_name = node.get('proxmoxnode', 'pve')
        storageList = services.pveclient.liststorage(pve, node_name, content_type='vztmpl')

        result = []
        for s in storageList:
            storageId = s.get('storage', '')
            try:
                templates = services.pveclient.listtemplates(pve, node_name, storageId)
                for t in templates:
                    result.append({
                        "storage": storageId,
                        "name": t.get('volid', '').replace(f"{storageId}:vztmpl/", ''),
                        "size": t.get('size', 0),
                        "format": t.get('format', ''),
                    })
            except Exception:
                continue

        return jsonify({"templates": result, "storages": [s.get('storage', '') for s in storageList]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/dashboard/admin/osimage")
@loginrequired
@adminrequired
def adminosimage():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    nodeType = request.args.get('type', '').strip() or None
    imagesData = db.listimagespaginated(page=page, perpage=12, search=q, node_type=nodeType)
    allNodes = db.listallnodes()
    allImageStorages = db.listimagestorage()

    for img in imagesData['images']:
        addosmeta([img])
        img['assigned_nodes'] = db.getnodesforimage(img['id'])

    return render_template(
        "adminosimage.html",
        allImages=imagesData['images'],
        pagination=imagesData,
        activeImagesCount=sum(1 for i in imagesData['images'] if i['active']),
        allNodes=allNodes,
        allImageStorages=allImageStorages,
        search=q or '',
        nodeType=nodeType or '',
        osTypes=OS_TYPES,
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/osimage/create", methods=["POST"])
@loginrequired
@adminrequired
def adminosimagecreate():
    try:
        db.addimage(
            uuid=str(uuid.uuid4()),
            name=request.form.get("name"),
            image=request.form.get("image"),
            description=request.form.get("description"),
            active=int(request.form.get("active", 1)),
            node_type=request.form.get("node_type", "proxmox"),
            os_type=request.form.get("os_type", "linux")
        )
        auditlog("image.create", "image", None, f"Added OS image '{request.form.get('name')}'")
        flash("OS Image added successfully.", "success")
    except Exception as e:
        flash("Error adding image.", "danger")
    return redirect(url_for('adminosimage'))

@app.route("/dashboard/admin/osimage/update/<string:imageUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminosimageupdate(imageUuid):
    try:
        updateData = {
            "name": request.form.get("name"),
            "image": request.form.get("image"),
            "description": request.form.get("description"),
            "active": int(request.form.get("active")),
            "node_type": request.form.get("node_type", "proxmox"),
            "os_type": request.form.get("os_type", "linux")
        }
        db.updateimage(imageUuid, **updateData)
        auditlog("image.update", "image", imageUuid, f"Updated OS image '{request.form.get('name')}'")
        flash("OS Image updated.", "success")
    except Exception as e:
        flash("Error updating image.", "danger")
    return redirect(url_for('adminosimage'))

@app.route("/dashboard/admin/osimage/delete/<string:imageUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminosimagedelete(imageUuid):
    try:
        db.removeimage(imageUuid)
        auditlog("image.delete", "image", imageUuid, "Deleted OS image")
        flash("OS Image removed.", "warning")
    except Exception as e:
        flash("Error deleting image.", "danger")
    return redirect(url_for('adminosimage'))

@app.route("/dashboard/admin/osimage/<string:imageUuid>/assign", methods=["POST"])
@loginrequired
@adminrequired
def adminosimageassign(imageUuid):
    image = db.getimage(imageUuid)
    if not image:
        flash("Image not found.", "error")
        return redirect(url_for('adminosimage'))

    nodeid = request.form.get("nodeid", type=int)
    imagestorageid = request.form.get("imagestorageid", type=int) or None

    if not nodeid:
        flash("Node required.", "error")
        return redirect(url_for('adminosimage'))

    node = db.getnodebyid(nodeid)
    if not node:
        flash("Node not found.", "error")
        return redirect(url_for('adminosimage'))

    if not imagestorageid and node.get('type', 'proxmox') == 'proxmox':
        default = db.getdefaultimagestorage(nodeid)
        if default:
            imagestorageid = default['id']

    db.addimagetonode(nodeid, image['id'], imagestorageid=imagestorageid)
    auditlog("image.assign", "image", imageUuid, f"Assigned image '{image['name']}' to node '{node['name']}'")
    flash(f"Image assigned to {node['name']}.", "success")
    return redirect(url_for('adminosimage'))

@app.route("/dashboard/admin/osimage/<string:imageUuid>/unassign", methods=["POST"])
@loginrequired
@adminrequired
def adminosimageunassign(imageUuid):
    image = db.getimage(imageUuid)
    if not image:
        flash("Image not found.", "error")
        return redirect(url_for('adminosimage'))

    nodeid = request.form.get("nodeid", type=int)
    if not nodeid:
        flash("Node required.", "error")
        return redirect(url_for('adminosimage'))

    db.removeimagefromnode(nodeid, image['id'])
    auditlog("image.unassign", "image", imageUuid, f"Unassigned image from node")
    flash("Image unassigned from node.", "warning")
    return redirect(url_for('adminosimage'))

@app.route("/dashboard/admin/osimage/imagestorages/<int:nodeId>")
@loginrequired
@adminrequired
def adminosimagestorages(nodeId):
    storages = db.listimagestorage(nodeid=nodeId)
    return jsonify([{"id": s['id'], "name": s['name']} for s in storages])


@app.route("/dashboard/admin/locations")
@loginrequired
@adminrequired
def adminlocations():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    locsData = db.listlocationspaginated(page=page, perpage=12, search=q)
    totalVps = sum(loc.get('vps_count', 0) for loc in db.listalllocations())
    return render_template(
        "adminlocations.html",
        allLocations=locsData['locations'],
        pagination=locsData,
        totalLocations=db.countlocations(),
        totalLocationVps=totalVps,
        search=q or '',
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )


@app.route("/dashboard/admin/locations/create", methods=["POST"])
@loginrequired
@adminrequired
def adminlocationscreate():
    try:
        locUuid = str(uuid.uuid4())
        name = request.form.get("name")
        code = request.form.get("code")
        flag = request.form.get("flag", "")
        description = request.form.get("description", "")
        db.addlocation(uuid=locUuid, name=name, code=code, flag=flag, description=description)
        auditlog("location.create", "location", locUuid, f"Created location '{name}' ({code})")
        flash(f"Location '{name}' created successfully.", "success")
    except Exception:
        flash("Error creating location. Ensure code is unique.", "danger")
    return redirect(url_for('adminlocations'))


@app.route("/dashboard/admin/locations/update/<string:locationUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminlocationsupdate(locationUuid):
    try:
        updateData = {
            "name": request.form.get("name"),
            "code": request.form.get("code"),
            "flag": request.form.get("flag", ""),
            "description": request.form.get("description", "")
        }
        db.updatelocation(locationUuid, **updateData)
        auditlog("location.update", "location", locationUuid, f"Updated location '{request.form.get('name')}'")
        flash("Location updated successfully.", "success")
    except Exception:
        flash("Error updating location.", "danger")
    return redirect(url_for('adminlocations'))


@app.route("/dashboard/admin/locations/delete/<string:locationUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminlocationsdelete(locationUuid):
    try:
        db.removelocation(locationUuid)
        auditlog("location.delete", "location", locationUuid, "Deleted location")
        flash("Location removed.", "warning")
    except Exception:
        flash("Error deleting location.", "danger")
    return redirect(url_for('adminlocations'))




@app.route("/dashboard/admin/paymentmethods")
@loginrequired
@adminrequired
def adminpaymentmethods():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    methodsData = db.listpaymentmethodspaginated(page=page, perpage=12, search=q)
    stats = db.gettransactionstats()

    return render_template(
        "adminpaymentmethods.html",
        allPaymentMethods=methodsData['methods'],
        pagination=methodsData,
        activeMethodsCount=db.countactivepaymentmethods(),
        totalTransactions=stats["total_transactions"],
        totalRevenue=stats["total_revenue"],
        search=q or '',
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )


@app.route("/dashboard/admin/paymentmethods/create", methods=["POST"])
@loginrequired
@adminrequired
def adminpaymentmethodscreate():
    try:
        paymentmethodUuid = str(uuid.uuid4())
        db.addpaymentmethod(
            uuid=paymentmethodUuid,
            name=request.form.get("name"),
            slug=request.form.get("slug"),
            active=int(request.form.get("active", 1))
        )
        auditlog("paymentmethod.create", "paymentmethod", paymentmethodUuid, f"Added payment method '{request.form.get('name')}'")
        flash(f"Payment method '{request.form.get('name')}' added successfully.", "success")
    except Exception:
        flash("Error adding payment method.", "danger")
    return redirect(url_for('adminpaymentmethods'))


@app.route("/dashboard/admin/payment-methods/update/<string:paymentmethodUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminpaymentmethodsupdate(paymentmethodUuid):
    try:
        updateData = {
            "name": request.form.get("name"),
            "slug": request.form.get("slug"),
            "active": int(request.form.get("active", 1))
        }
        db.updatepaymentmethods(paymentmethodUuid, **updateData)
        auditlog("paymentmethod.update", "paymentmethod", paymentmethodUuid, f"Updated payment method '{request.form.get('name')}'")
        flash("Payment method updated.", "success")
    except Exception:
        flash("Error updating payment method.", "danger")
    return redirect(url_for('adminpaymentmethods'))


@app.route("/dashboard/admin/payment-methods/delete/<string:paymentmethodUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminpaymentmethodsdelete(paymentmethodUuid):
    try:
        db.removepaymentmethods(paymentmethodUuid)
        auditlog("paymentmethod.delete", "paymentmethod", paymentmethodUuid, "Deleted payment method")
        flash("Payment method removed.", "warning")
    except Exception:
        flash("Error deleting payment method.", "danger")
    return redirect(url_for('adminpaymentmethods'))

@app.route("/dashboard/admin/receipts")
@loginrequired
@adminrequired
def adminreceipts():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    receiptsData = db.listreceiptspaginated(page=page, perpage=12, search=q)
    
    allReceipts = []
    totalRevenue = totalTax = receiptsThisMonth = 0
    currentMonth = datetime.utcnow().strftime("%Y-%m")

    for row in receiptsData['receipts']:
        receipt = dict(row)
        receipt["transactionid_display"] = row["txn_public_id"] or "N/A"
        allReceipts.append(receipt)
        totalRevenue += row["amount"] or 0
        totalTax += row["taxamount"] or 0
        if (row["created"] or "").startswith(currentMonth): receiptsThisMonth += 1

    return render_template("adminreceipts.html", allReceipts=allReceipts, 
        pagination=receiptsData,
        allTransactions=db.geteligibletransactions(), totalRevenue=f"{totalRevenue:.2f}", 
        totalTax=f"{totalTax:.2f}", receiptsThisMonth=receiptsThisMonth,
        search=q or '',
        **paneluserinfo(g.userinfo), **paneladmininfo(g.userinfo))

@app.route("/dashboard/admin/receipts/create", methods=["POST"])
@loginrequired
@adminrequired
def adminreceiptscreate():
    tid = request.form.get("transactionid", type=int)
    txn = db.gettransaction(tid)
    
    if not txn:
        flash("Transaction not found.", "error")
    elif db.getreceiptbytransaction(tid):
        flash("Receipt already exists.", "error")
    else:
        txnFull = db.gettransactionfull(tid)
        amount = request.form.get("amount", type=float)
        if not amount and txnFull:
            amount = txnFull['amount']
        
        data = {
            "transactionid": tid, "userid": txn["userid"],
            "amount": amount or 0,
            "currency": (request.form.get("currency") or (txnFull['currency'] if txnFull else "USD")).strip().upper(),
            "taxamount": request.form.get("taxamount", type=float) or 0,
            "receiptnumber": request.form.get("receiptnumber") or db.generatereceiptnumber(),
            "billingname": request.form.get("billingname"),
            "billingemail": request.form.get("billingemail"),
            "billingaddress": request.form.get("billingaddress"),
            "notes": request.form.get("notes")
        }
        db.addreceipt(data)
        auditlog("receipt.create", "receipt", None, f"Created receipt {data['receiptnumber']}")
        flash("Receipt created.", "success")
    return redirect(url_for("adminreceipts"))

@app.route("/dashboard/admin/receipts/<receiptUuid>/update", methods=["POST"])
@loginrequired
@adminrequired
def adminreceiptsupdate(receiptUuid):
    if not db.getreceipt(receiptUuid):
        flash("Receipt not found.", "error")
    else:
        data = {
            "amount": request.form.get("amount", type=float),
            "currency": (request.form.get("currency") or "USD").strip().upper(),
            "taxamount": request.form.get("taxamount", type=float) or 0,
            "receiptnumber": request.form.get("receiptnumber"),
            "billingname": request.form.get("billingname"),
            "billingemail": request.form.get("billingemail"),
            "billingaddress": request.form.get("billingaddress"),
            "notes": request.form.get("notes")
        }
        db.updatereceipt(receiptUuid, data)
        auditlog("receipt.update", "receipt", receiptUuid, f"Updated receipt {data.get('receiptnumber', receiptUuid)}")
        flash("Receipt updated.", "success")
    return redirect(url_for("adminreceipts"))

@app.route("/dashboard/admin/receipts/<receiptUuid>/delete", methods=["POST"])
@loginrequired
@adminrequired
def adminreceiptsdelete(receiptUuid):
    db.deletereceipt(receiptUuid)
    auditlog("receipt.delete", "receipt", receiptUuid, "Deleted receipt")
    flash("Receipt deleted.", "success")
    return redirect(url_for("adminreceipts"))

# --- Audit Log ---

@app.route("/dashboard/admin/auditlog")
@loginrequired
@adminrequired
def adminauditlog():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    actionFilter = request.args.get('action', '').strip() or None
    userFilter = request.args.get('user', '').strip() or None

    logsData = db.listauditlogspaginated(page=page, perpage=50, search=q, action_filter=actionFilter, user_filter=userFilter)
    actionTypes = db.getauditlogactions()

    return render_template(
        "adminauditlog.html",
        logsData=logsData,
        actionTypes=actionTypes,
        search=q or '',
        actionFilter=actionFilter or '',
        userFilter=userFilter or '',
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )

# --- Captcha Log ---

@app.route("/dashboard/admin/captchalog")
@loginrequired
@adminrequired
def admincaptchalog():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    resultFilter = request.args.get('result', '').strip() or None

    logsData = db.listcaptchalogpaginated(page=page, perpage=50, search=q, result_filter=resultFilter)

    return render_template(
        "admincaptchalog.html",
        logsData=logsData,
        search=q or '',
        resultFilter=resultFilter or '',
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )

# --- Settings ---

SETTINGS_SCHEMA = {
    "general": {
        "projectname": {"label": "Project Name", "type": "text", "desc": "Displayed in the header and title."},
        "theme": {"label": "Theme", "type": "theme", "desc": "Color theme for the entire UI."},
        "timezone": {
            "label": "Timezone",
            "type": "select",
            "options": list(timeutil.COMMON_TIMEZONES),
            "desc": "IANA timezone for billing periods, renewals, suspend checks, and displayed dates.",
        },
        "passwordlength": {"label": "Password Length", "type": "number", "desc": "Generated password length."},
        "cookielength": {"label": "Cookie Length", "type": "number", "desc": "Session cookie length."},
        "defaultcookiettl": {"label": "Session TTL (days)", "type": "number", "desc": "Days before session expires."},
        "favicon": {"label": "Favicon Path", "type": "text", "desc": "Path to favicon."},
        "logo": {"label": "Logo Path", "type": "text", "desc": "Path to logo image."},
        "discord": {"label": "Discord Invite URL", "type": "text", "desc": "Discord server invite link."},
    },
    "paypal": {
        "email": {"label": "PayPal Email", "type": "text", "desc": "Receiver email for PayPal payments."},
        "sandbox": {"label": "Sandbox Mode", "type": "bool", "desc": "Use PayPal sandbox."},
        "base_url": {"label": "Base URL", "type": "text", "desc": "Public URL for IPN callbacks."},
    },
    "discord": {
        "clientid": {"label": "Client ID", "type": "text", "desc": "Discord OAuth application ID."},
        "clientsecret": {"label": "Client Secret", "type": "password", "desc": "Discord OAuth secret."},
        "redirecturl": {"label": "Redirect URL", "type": "text", "desc": "OAuth callback URL."},
        "discordbaseurl": {"label": "API Base URL", "type": "text", "desc": "Discord API base URL."},
    },
    "loadbalancing": {
        "strategy": {"label": "Strategy", "type": "select", "options": ["random", "least_vps", "resources", "both"], "desc": "Node selection strategy."},
    },
    "console": {
        "timeout": {"label": "SSH Timeout (s)", "type": "number", "desc": "SSH connection timeout."},
        "metrics": {"label": "Metrics Mode", "type": "select", "options": ["dynamic", "static"], "desc": "How metrics are displayed."},
    },
    "network": {
        "ip_source": {"label": "IP Source", "type": "select", "options": ["remote_addr", "x_forwarded_for", "x_real_ip"], "desc": "Source for session and audit log IPs."},
    },
    "billing": {
        "paid_period_days": {"label": "Paid period (days)", "type": "number", "desc": "How long a paid VPS stays active after payment before it is due again. Early payment stacks."},
        "free_period_days": {"label": "Free period (days)", "type": "number", "desc": "Free VPS period length. Renew resets to this many days from now (cap, no stack). Auto-suspend if not renewed."},
        "warn_days": {"label": "Warning window (days)", "type": "number", "desc": "Show free/paid renewal warnings this many days before period ends. 0 = only on due day / overdue."},
        "free_renew_cooldown_hours": {"label": "Free renew cooldown (hours)", "type": "number", "desc": "Minimum hours between free renewals for a VPS (e.g. 24 for once per day). 0 = no cooldown."},
    },
    "ratelimit": {
        "enabled": {"label": "Enable rate limits", "type": "bool", "desc": "In-process limits per IP/user. Disable only for trusted internal use."},
        "global": {"label": "Global (per IP)", "type": "text", "desc": "All non-static requests. Format: N/minute, N/hour, N/second."},
        "login": {"label": "Login", "type": "text", "desc": "Password login attempts per IP."},
        "discord": {"label": "Discord OAuth", "type": "text", "desc": "Discord login + callback per IP."},
        "create_vps_free": {"label": "Create Free VPS", "type": "text", "desc": "Free VPS creation limit per user (e.g. 2/day)."},
        "create_vps_paid": {"label": "Create Paid VPS", "type": "text", "desc": "Paid VPS creation limit per user (e.g. 10/hour)."},
        "renew": {"label": "Free renew", "type": "text", "desc": "Free VPS renewals per user."},
        "ticket": {"label": "Tickets", "type": "text", "desc": "Ticket create + reply per user."},
        "console": {"label": "Console token", "type": "text", "desc": "Console open requests per user."},
        "checkout": {"label": "Checkout", "type": "text", "desc": "Payment start attempts per user."},
    },
    "captcha": {
        "enabled": {"label": "Enable captcha", "type": "bool", "desc": "Require anti-bot math captcha on VPS creation, support tickets, and forms."},
        "url": {"label": "API Base URL", "type": "text", "desc": "Base URL of captcha service (WebSocket endpoint is derived from this)."},
        "api_key": {"label": "API Key", "type": "password", "desc": "X-API-Key required by the captcha service WebSocket."},
        "secret": {"label": "Signing Secret", "type": "password", "desc": "Shared HMAC secret (CAPTCHA_SECRET) for verifying captcha tokens. Must match the captcha service's CAPTCHA_SECRET."},
    },
    "worker": {
        "enabled_in_web": {"label": "Run worker inside web process", "type": "bool", "desc": "On for single-process dev. Off in production with gunicorn multi-worker — run `python worker.py` instead."},
        "poll_seconds": {"label": "Job poll interval (s)", "type": "number", "desc": "How often to check for pending jobs when idle."},
        "maintenance_seconds": {"label": "Maintenance interval (s)", "type": "number", "desc": "Billing expiry, overdue suspend, stuck delete requeue."},
        "stale_job_minutes": {"label": "Stale job reclaim (min)", "type": "number", "desc": "Re-queue jobs stuck in running longer than this (crash recovery)."},
    },
    "database": {
        "engine": {"label": "Engine", "type": "select", "options": ["sqlite", "mysql"], "desc": "Database engine. Restart panel after save."},
        "sqlite_path": {"label": "SQLite Path", "type": "text", "desc": "Relative to client/ or absolute path."},
        "mysql_host": {"label": "MySQL Host", "type": "text", "desc": "MySQL / MariaDB host."},
        "mysql_port": {"label": "MySQL Port", "type": "number", "desc": "Default 3306."},
        "mysql_user": {"label": "MySQL User", "type": "text", "desc": "Database user."},
        "mysql_password": {"label": "MySQL Password", "type": "password", "desc": "Leave blank to keep current."},
        "mysql_database": {"label": "MySQL Database", "type": "text", "desc": "Database name (created if missing via createdb.py)."},
    },
}


@app.route("/dashboard/admin/settings/reload", methods=["POST"])
@loginrequired
@adminrequired
def adminsettingsreload():
    reloadconfig()
    auditlog("settings.reload", "settings", None, "Reloaded config from config.json")
    flash("Configuration reloaded from config.json.", "success")
    return redirect(url_for('adminsettings'))


@app.route("/dashboard/admin/settings/captcha/test", methods=["POST"])
@loginrequired
@adminrequired
def admincaptchatest():
    """Test the captcha service connection end-to-end.

    Performs the same flow the browser does:
    1. Connect to the captcha service WS with the configured API key.
    2. Mint a challenge (receive JSON meta + binary GIF).
    3. Verify the shared secret can validate a signed token.
    Reports which steps passed/failed so the admin can diagnose config issues.
    """
    import json as _json

    cfg = captcha.get_config()
    upstream_url = captcha.get_ws_url()
    api_key = (cfg.get("api_key") or "").strip()
    secret = (cfg.get("secret") or "").strip()

    if not upstream_url:
        return jsonify({"ok": False, "error": "Captcha URL is not configured."}), 400
    if not api_key:
        return jsonify({"ok": False, "error": "Captcha API key is not configured."}), 400
    if not secret:
        return jsonify({"ok": False, "error": "Captcha signing secret is not configured."}), 400

    results = {"url": upstream_url, "steps": []}

    # Step 1: WebSocket connect with API key
    try:
        upstream = simple_ws_connect(upstream_url, headers=[("X-API-Key", api_key)])
        results["steps"].append({"step": "connect", "ok": True, "detail": "WebSocket connection accepted"})
    except Exception as e:
        msg = str(e)
        if "403" in msg or "401" in msg or "Unauthorized" in msg.lower():
            results["steps"].append({"step": "connect", "ok": False, "detail": "API key rejected by captcha service"})
        else:
            results["steps"].append({"step": "connect", "ok": False, "detail": f"Connection failed: {msg[:120]}"})
        return jsonify({"ok": False, "results": results, "error": "Could not connect to the captcha service. Check the URL and API key."}), 200

    try:
        # Step 2: Mint a challenge
        upstream.send("new")
        meta_raw = upstream.receive(timeout=5)
        gif_raw = upstream.receive(timeout=5)

        if not isinstance(meta_raw, str):
            results["steps"].append({"step": "mint", "ok": False, "detail": "Expected JSON metadata, got non-text frame"})
            return jsonify({"ok": False, "results": results, "error": "Captcha service returned an unexpected response."}), 200

        try:
            meta = _json.loads(meta_raw)
            cid = meta.get("id", "")
            ttl = meta.get("ttl", 0)
        except (ValueError, TypeError):
            results["steps"].append({"step": "mint", "ok": False, "detail": f"Invalid JSON metadata: {meta_raw[:80]}"})
            return jsonify({"ok": False, "results": results, "error": "Captcha service returned invalid metadata."}), 200

        if not cid:
            results["steps"].append({"step": "mint", "ok": False, "detail": "No challenge ID in metadata"})
            return jsonify({"ok": False, "results": results, "error": "Captcha service did not return a challenge ID."}), 200

        gif_size = len(gif_raw) if gif_raw else 0
        results["steps"].append({"step": "mint", "ok": True, "detail": f"Challenge minted: id={cid[:12]}… ttl={ttl}s gif={gif_size} bytes"})

        # Step 3: Verify the shared secret by generating a test token and
        # checking it verifies locally. We can't solve the captcha (we don't
        # know the answer), but we can confirm the secret is valid by signing
        # and verifying a dummy token with the same algorithm.
        import base64 as _b64
        import hashlib as _hashlib
        import hmac as _hmac
        import time as _time

        def _b64u(b):
            return _b64.urlsafe_b64encode(b).rstrip(b"=").decode()

        payload = _json.dumps(
            {"cid": "test", "ans": 0, "exp": int(_time.time()) + 60},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        sig = _b64u(_hmac.new(secret.encode(), payload, _hashlib.sha256).digest())
        test_token = _b64u(payload) + "." + sig

        if captcha.verify_token(test_token):
            results["steps"].append({"step": "secret", "ok": True, "detail": "Signing secret verifies correctly"})
        else:
            results["steps"].append({"step": "secret", "ok": False, "detail": "Token verification failed with configured secret"})
            return jsonify({"ok": False, "results": results, "error": "The signing secret does not match. Ensure it equals the captcha service's 'secret' in config.json."}), 200

        # All good
        upstream.close()
        auditlog("settings.captcha_test", "settings", None, "Captcha service test passed")
        return jsonify({"ok": True, "results": results, "message": "Captcha service is reachable and the signing secret matches."}), 200

    except Exception as e:
        results["steps"].append({"step": "mint", "ok": False, "detail": f"Error during test: {str(e)[:120]}"})
        try:
            upstream.close()
        except Exception:
            pass
        return jsonify({"ok": False, "results": results, "error": f"Test failed: {str(e)[:120]}"}), 200


@app.route("/dashboard/admin/settings", methods=["GET", "POST"])
@loginrequired
@adminrequired
def adminsettings():
    if request.method == "POST":
        section = request.form.get("section")
        if section == "database":
            # Connection details live in db_config.json (needed before DB connect)
            fileCfg = dbconfig.load()
            engine = (request.form.get("engine") or fileCfg.get("engine") or "sqlite").lower().strip()
            if engine not in ("sqlite", "mysql"):
                engine = "sqlite"
            sqlite_path = (request.form.get("sqlite_path") or "").strip() or fileCfg["sqlite"]["path"]
            mysql_host = (request.form.get("mysql_host") or "").strip() or fileCfg["mysql"]["host"]
            try:
                mysql_port = int((request.form.get("mysql_port") or "").strip() or fileCfg["mysql"]["port"])
            except ValueError:
                mysql_port = 3306
            mysql_user = (request.form.get("mysql_user") or "").strip() or fileCfg["mysql"]["user"]
            mysql_password = request.form.get("mysql_password") or ""
            if not mysql_password.strip():
                mysql_password = fileCfg["mysql"].get("password") or ""
            mysql_database = (request.form.get("mysql_database") or "").strip() or fileCfg["mysql"]["database"]
            try:
                dbconfig.save({
                    "engine": engine,
                    "sqlite": {"path": sqlite_path},
                    "mysql": {
                        "host": mysql_host,
                        "port": mysql_port,
                        "user": mysql_user,
                        "password": mysql_password,
                        "database": mysql_database,
                        "charset": fileCfg["mysql"].get("charset") or "utf8mb4",
                    },
                })
                auditlog("settings.update", "settings", None, f"Updated database engine to {engine}")
                flash("Database settings saved to db_config.json. Restart the panel for changes to take effect. Run createdb.py after switching to MySQL.", "success")
            except Exception as e:
                flash(f"Failed to save database config: {e}", "error")
            return redirect(url_for('adminsettings'))

        if section and section in SETTINGS_SCHEMA and section != "database":
            section_vals = dict(config.get(section, {}))
            for key, meta in SETTINGS_SCHEMA[section].items():
                if meta['type'] == 'bool':
                    val = request.form.get(key) in ('on', '1', 'true', 'True')
                elif meta['type'] == 'number':
                    raw = (request.form.get(key) or '').strip()
                    default_num = DEFAULT_CONFIG.get(section, {}).get(key, 0)
                    try:
                        # allow float for poll_seconds etc.
                        if isinstance(default_num, float) or (raw and '.' in raw):
                            val = float(raw) if raw else float(default_num or 0)
                        else:
                            val = int(raw) if raw else int(default_num or 0)
                    except ValueError:
                        val = default_num
                elif meta['type'] == 'theme':
                    val = request.form.get(key) or DEFAULT_CONFIG.get(section, {}).get(key, 'catppuccin')
                    valid = {t['id'] for t in THEMES}
                    if val not in valid:
                        val = 'catppuccin'
                elif key == 'timezone':
                    val = (request.form.get(key) or '').strip() or 'UTC'
                    try:
                        from zoneinfo import ZoneInfo
                        ZoneInfo(val)
                    except Exception:
                        val = 'UTC'
                    if val not in timeutil.COMMON_TIMEZONES:
                        # allow custom IANA if valid ZoneInfo above
                        pass
                else:
                    val = (request.form.get(key) or '').strip()
                    if not val and key in DEFAULT_CONFIG.get(section, {}):
                        if meta['type'] == 'password':
                            existing = section_vals.get(key) or config.get(section, {}).get(key)
                            if existing:
                                continue
                    if not val and meta['type'] == 'password':
                        continue
                section_vals[key] = val
            appconfig.update_section(section, section_vals)
            auditlog("settings.update", "settings", None, f"Updated {section} settings")
            reloadconfig()
            flash(f"{section.title()} settings saved to config.json.", "success")
        else:
            flash("Unknown settings section.", "error")
        return redirect(url_for('adminsettings'))

    live = {}
    file_cfg = appconfig.load()
    # ensure timezone select includes current value
    tz_opts = list(timeutil.COMMON_TIMEZONES)
    cur_tz = (file_cfg.get("general") or {}).get("timezone") or config.get("general", {}).get("timezone") or "UTC"
    if cur_tz not in tz_opts:
        tz_opts = [cur_tz] + tz_opts
    SETTINGS_SCHEMA["general"]["timezone"]["options"] = tz_opts

    for section, fields in SETTINGS_SCHEMA.items():
        if section == "database":
            continue
        live[section] = {}
        for key in fields:
            default = DEFAULT_CONFIG.get(section, {}).get(key, '')
            live[section][key] = file_cfg.get(section, {}).get(key, config.get(section, {}).get(key, default))

    fileCfg = dbconfig.load()
    live["database"] = {
        "engine": fileCfg.get("engine", "sqlite"),
        "sqlite_path": fileCfg.get("sqlite", {}).get("path", "database.db"),
        "mysql_host": fileCfg.get("mysql", {}).get("host", "127.0.0.1"),
        "mysql_port": fileCfg.get("mysql", {}).get("port", 3306),
        "mysql_user": fileCfg.get("mysql", {}).get("user", "root"),
        "mysql_password": fileCfg.get("mysql", {}).get("password") or "",
        "mysql_database": fileCfg.get("mysql", {}).get("database", "openworld"),
    }

    return render_template(
        "adminsettings.html",
        config=live,
        schema=SETTINGS_SCHEMA,
        defaults=DEFAULT_CONFIG,
        current_theme_global=config.get("general", {}).get("theme", "catppuccin"),
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )

# ===== ADMIN TICKETS =====

@app.route("/dashboard/admin/tickets")
@loginrequired
@adminrequired
def admintickets():
    """List all support tickets (admin view)."""
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', '')
    
    ticket_data = db.listtickets(
        userid=None,  # None = get all tickets
        status=status_filter if status_filter else None,
        page=page,
        per_page=20
    )
    
    # Get counts by status
    open_count = db.counttickets(status='open')
    replied_count = db.counttickets(status='replied')
    closed_count = db.counttickets(status='closed')
    
    return render_template(
        "admintickets.html",
        ticketData=ticket_data,
        statusFilter=status_filter,
        openCount=open_count,
        repliedCount=replied_count,
        closedCount=closed_count,
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/tickets/<string:ticket_uuid>/close", methods=["POST"])
@loginrequired
@adminrequired
def admincloseticket(ticket_uuid):
    """Close a support ticket (admin only)."""
    ticket = db.getticket(ticket_uuid)
    
    if not ticket:
        flash("Ticket not found.", "error")
        return redirect(url_for('admintickets'))
    
    db.updateticketstatus(ticket_uuid, 'closed')
    auditlog("ticket.close", "ticket", ticket['id'], f"Closed ticket: {ticket['subject']}")
    
    flash("Ticket closed successfully.", "success")
    
    # Redirect back to where they came from
    referer = request.referrer
    if referer and 'tickets' in referer:
        return redirect(referer)
    return redirect(url_for('admintickets'))

@app.route("/dashboard/admin/transactions")
@loginrequired
@adminrequired
def admintransactions():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    txnData = db.listtransactionspaginated(page=page, perpage=12, search=q)
    stats = db.gettransactionstats()

    return render_template(
        "admintransactions.html",
        allTransactions=txnData['transactions'],
        pagination=txnData,
        totalTransactions=stats["total_transactions"],
        totalRevenue=stats["total_revenue"],
        search=q or '',
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )

###############
#
# Login Backend
#
###############

@app.route("/login", methods=["GET", "POST"])
def login():
    sessionCookie = request.cookies.get(COOKIE_NAME)
    if sessionCookie:
        user = services.validatesession(sessionCookie)
        if user:
            return redirect(url_for("dashboard"))
        return redirect(url_for("logout"))

    if request.method == "POST":
        limited = checkratelimit("login", "login", "10/minute")
        if limited:
            return limited
        token = request.form.get("captcha_token")
        if captcha.is_enabled():
            if not captcha.verify_token(token):
                logcaptcha("login", "failed", "login", "Invalid or missing captcha token")
                flash("Invalid or expired captcha answer.", "error")
                return render_template("login.html", **guestuserinfo())
            logcaptcha("login", "passed", "login")
        email = request.form.get("email")
        password = request.form.get("password")

        user = services.authenticateuser(email, password)

        if user:
            userIp = getclientip()
            userAgent = request.headers.get("User-Agent", "unknown")

            rawToken = services.createsession(
                userId=user["id"],
                ipAddress=userIp,
                userAgent=userAgent,
                ttlDays=SESSION_TTL_DAYS,
            )

            # Set g.userinfo for auditlog
            g.userinfo = user
            auditlog("user.login", "user", user['id'], f"Login from {userIp}")
            g.userinfo = None

            response = make_response(redirect(url_for("dashboard")))
            response.set_cookie(
                COOKIE_NAME,
                rawToken,
                max_age=daystoseconds(config["general"]["defaultcookiettl"]),
                httponly=True,
                secure=True,
                samesite="Lax"
            )
            return response
        else:
            auditlog("user.login_failed", None, None, f"Failed login for {email}")
            flash("Invalid email or password", "error")

    return render_template("login.html", **guestuserinfo())


@app.route("/discord-login")
def discordlogin():
    limited = checkratelimit("discord", "discord", "20/minute")
    if limited:
        return limited
    discordAuthUrl = (
        f"{config['discord']['discordbaseurl']}/oauth2/authorize?client_id={config['discord']['clientid']}"
        f"&redirect_uri={config['discord']['redirecturl']}&response_type=code&scope=identify%20email"
    )
    return redirect(discordAuthUrl)


@app.route("/discord-callback")
def discordcallback():
    limited = checkratelimit("discord", "discord", "20/minute")
    if limited:
        return limited
    code = request.args.get("code")
    if not code:
        flash("Discord login failed.", "error")
        return redirect(url_for("login"))

    tokenResponse = requests.post(
        f"{config['discord']['discordbaseurl']}/oauth2/token",
        data={
            "client_id": config["discord"]["clientid"],
            "client_secret": config["discord"]["clientsecret"],
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": config["discord"]["redirecturl"],
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    ).json()

    if "access_token" not in tokenResponse:
        flash("Could not verify Discord token.", "error")
        return redirect(url_for("login"))

    accessToken = tokenResponse["access_token"]
    userData = requests.get(
        f"{config['discord']['discordbaseurl']}/users/@me",
        headers={"Authorization": f"Bearer {accessToken}"},
    ).json()

    email = userData.get("email")
    if not email:
        flash("Your Discord account must have a verified email to log in.", "error")
        return redirect(url_for("login"))

    profilePic = None
    if userData.get("avatar"):
        profilePic = f"https://cdn.discordapp.com/avatars/{userData['id']}/{userData['avatar']}.png"

    try:
        user = services.findorcreatediscorduser(
            discordId=userData["id"], 
            email=email, 
            username=userData["username"], 
            profilePic=profilePic
        )
    except Exception as e:
        flash("Database error during login.", "error")
        return redirect(url_for("login"))

    userIp = getclientip()
    userAgent = request.headers.get("User-Agent", "unknown")
    rawToken = services.createsession(user["id"], userIp, userAgent, ttlDays=SESSION_TTL_DAYS)

    g.userinfo = user
    auditlog("user.login", "user", user["id"], f"Discord login from {userIp}")
    g.userinfo = None

    response = make_response(redirect(url_for("dashboard")))
    response.set_cookie(
        COOKIE_NAME,
        rawToken,
        max_age=daystoseconds(config["general"]["defaultcookiettl"]),
        httponly=True,
        secure=True,
        samesite="Lax"
    )
    return response


@app.route("/set-theme", methods=["POST"])
def settheme():
    theme_id = request.form.get("theme", "")
    valid_ids = [t["id"] for t in THEMES]
    if theme_id not in valid_ids:
        flash("Invalid theme.", "error")
        return redirect(request.referrer or url_for("index"))

    resp = make_response(redirect(request.referrer or url_for("index")))
    resp.set_cookie("theme", theme_id, max_age=86400 * 365, samesite="Lax")

    user = getattr(g, 'userinfo', None)
    if user:
        db.updateuser(user['uuid'], theme=theme_id)
        auditlog("user.theme", "user", user['id'], f"Changed theme to {theme_id}")

    return resp


# ===== SUPPORT TICKETS =====

@app.route("/tickets")
@loginrequired
def tickets():
    """List user's support tickets."""
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', '')
    
    ticket_data = db.listtickets(
        userid=g.userinfo['id'],
        status=status_filter if status_filter else None,
        page=page,
        per_page=10
    )
    
    return render_template("tickets.html", ticketData=ticket_data, statusFilter=status_filter, **paneluserinfo(g.userinfo))

@app.route("/tickets/create", methods=["POST"])
@loginrequired
def createticket():
    """Create a new support ticket."""
    limited = checkratelimit("ticket", "ticket", "15/hour", identity=g.userinfo["id"])
    if limited:
        return limited
    token = request.form.get("captcha_token")
    if captcha.is_enabled():
        if not captcha.verify_token(token):
            logcaptcha("createticket", "failed", "createticket", "Invalid or missing captcha token")
            flash("Invalid or expired captcha answer.", "error")
            return redirect(url_for('tickets'))
        logcaptcha("createticket", "passed", "createticket")
    subject = request.form.get("subject", "").strip()
    priority = request.form.get("priority", "normal")
    message = request.form.get("message", "").strip()
    
    if not subject or not message:
        flash("Subject and message are required.", "error")
        return redirect(url_for('tickets'))
    
    if priority not in ['low', 'normal', 'high']:
        priority = 'normal'
    
    ticket_uuid = str(uuid.uuid4())
    ticket = db.createticket(ticket_uuid, g.userinfo['id'], subject, priority)
    
    if ticket:
        # Add initial message
        db.addticketmessage(ticket['id'], g.userinfo['id'], message, is_staff=0)
        auditlog("ticket.create", "ticket", ticket_uuid, f"Created ticket: {subject} ({priority})")
        flash("Support ticket created successfully.", "success")
        return redirect(url_for('viewticket', ticket_uuid=ticket_uuid))
    else:
        flash("Failed to create ticket.", "error")
        return redirect(url_for('tickets'))

@app.route("/tickets/<string:ticket_uuid>")
@loginrequired
def viewticket(ticket_uuid):
    """View a single ticket with all messages."""
    ticket = db.getticket(ticket_uuid)
    
    if not ticket:
        flash("Ticket not found.", "error")
        return redirect(url_for('tickets'))
    
    # Ensure user owns this ticket (or is admin)
    if ticket['userid'] != g.userinfo['id'] and g.userinfo['role'] != 'admin':
        flash("Access denied.", "error")
        return redirect(url_for('tickets'))
    
    messages = db.getticketmessages(ticket['id'])
    
    return render_template("ticket.html", ticket=ticket, messages=messages, **paneluserinfo(g.userinfo))

@app.route("/tickets/<string:ticket_uuid>/reply", methods=["POST"])
@loginrequired
def replyticket(ticket_uuid):
    """Add a reply to a ticket."""
    limited = checkratelimit("ticket", "ticket", "15/hour", identity=g.userinfo["id"])
    if limited:
        return limited
    token = request.form.get("captcha_token")
    if captcha.is_enabled():
        if not captcha.verify_token(token):
            logcaptcha("replyticket", "failed", "replyticket", f"Ticket {ticket_uuid}: invalid or missing captcha token")
            flash("Invalid or expired captcha answer.", "error")
            return redirect(url_for('viewticket', ticket_uuid=ticket_uuid))
        logcaptcha("replyticket", "passed", "replyticket", f"Ticket {ticket_uuid}")
    ticket = db.getticket(ticket_uuid)
    
    if not ticket:
        flash("Ticket not found.", "error")
        return redirect(url_for('tickets'))
    
    # Ensure user owns this ticket (or is admin)
    if ticket['userid'] != g.userinfo['id'] and g.userinfo['role'] != 'admin':
        flash("Access denied.", "error")
        return redirect(url_for('tickets'))
    
    message = request.form.get("message", "").strip()
    if not message:
        flash("Message cannot be empty.", "error")
        return redirect(url_for('viewticket', ticket_uuid=ticket_uuid))
    
    is_staff = 1 if g.userinfo['role'] == 'admin' else 0
    db.addticketmessage(ticket['id'], g.userinfo['id'], message, is_staff=is_staff)
    who = "staff" if is_staff else "user"
    auditlog("ticket.reply", "ticket", ticket_uuid, f"{who} reply on ticket: {ticket.get('subject', ticket_uuid)}")
    
    flash("Reply added successfully.", "success")
    return redirect(url_for('viewticket', ticket_uuid=ticket_uuid))


@app.route("/logout")
def logout():
    token = request.cookies.get(COOKIE_NAME)
    if token:
        user = services.validatesession(token)
        if user:
            g.userinfo = user
            auditlog("user.logout", "user", user['id'], "User logged out")
            g.userinfo = None
        services.logout(token)
    resp = make_response(redirect(url_for("index")))
    resp.set_cookie(COOKIE_NAME, "", expires=0)
    return resp


@app.errorhandler(404)
def pagenotfound(e):
    return render_template("404.html", **guestuserinfo()), 404


@app.route('/admin/worker-status', methods=['GET'])
@loginrequired
@adminrequired
def worker_status():
    """Job worker health: in-process thread and/or external heartbeat file."""
    cfg = _worker_cfg()
    inproc = bool(worker_thread and worker_thread.is_alive())
    hb = _read_worker_heartbeat(max_age=max(90, cfg["maintenance_seconds"] * 2))
    external = bool(hb and hb.get("fresh"))
    counts = {}
    try:
        counts = db.countjobsbystatus()
    except Exception:
        pass
    ok = inproc or external or (not cfg["enabled_in_web"] and external)
    # If web-embedded expected, require thread; if disabled, require heartbeat
    if cfg["enabled_in_web"]:
        healthy = inproc
    else:
        healthy = external
    return jsonify({
        "healthy": healthy,
        "enabled_in_web": cfg["enabled_in_web"],
        "in_process": inproc,
        "external_heartbeat": hb,
        "external_fresh": external,
        "job_counts": counts,
        "pid": os.getpid(),
        "message": (
            "ok" if healthy else
            ("in-web worker dead" if cfg["enabled_in_web"] else "no fresh worker heartbeat — start python worker.py")
        ),
    }), (200 if healthy else 503)


if __name__ == "__main__":
    if _worker_cfg()["enabled_in_web"]:
        start_job_worker()
    app.run(
        host=config["server"]["host"],
        port=config["server"]["port"],
        debug=config["server"]["debug"],
    )