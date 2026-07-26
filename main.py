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
from urllib.parse import urlencode
from datetime import datetime
from functools import wraps

# Global worker thread
worker_thread = None

from core import db
from utils import services



BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_CONFIG = {
    "general": {
        "projectname": "Openworld",
        "passwordlength": 24,
        "cookielength": 128,
        "defaultcookiettl": 7,
        "favicon": "/static/favicon.ico",
        "logo": "/static/logo.png",
        "discord": "https://discord.gg/ZJrg5sGr5R"
    },
    "server": {
        "host": "0.0.0.0",
        "port": 5000,
        "debug": True
    },
    "paypal": {
        "email": "example@example.com",
        "sandbox": True,
        "base_url": "http://localhost:5000"
    },
    "discord": {
        "clientid": "changeme",
        "clientsecret": "changeme",
        "redirecturl": "http://localhost:5000/discord-callback",
        "discordbaseurl": "https://discord.com/api"
    },
    "loadbalancing": {
        "strategy": "both"  # random | least_vps | resources | both
    },
    "console": {
        "timeout": 10,
        "metrics": "dynamic"
    },
    "network": {
        "ip_source": "remote_addr"
    },
}


def loadorcreateconfig():
    """Load config from DB, creating default settings when empty."""
    dbSettings = db.getallsettings()
    if not dbSettings:
        _migrateconfigtodb(DEFAULT_CONFIG, DEFAULT_CONFIG)
        dbSettings = db.getallsettings()

    nested = {}
    for flatkey, val in dbSettings.items():
        parts = flatkey.split('.', 1)
        if len(parts) == 2:
            section, key = parts
            if section not in nested:
                nested[section] = {}
            nested[section][key] = val
        else:
            nested[flatkey] = val

    merged = {}
    for section, defaults in DEFAULT_CONFIG.items():
        merged[section] = {**defaults, **nested.get(section, {})}
    for section in nested:
        if section not in merged:
            merged[section] = nested[section]
    return merged


def _migrateconfigtodb(cfg, defaults):
    """Write a nested config dict into the DB as flat keys."""
    for section, values in defaults.items():
        if isinstance(values, dict):
            for key, defaultval in values.items():
                flatkey = f"{section}.{key}"
                actual = cfg.get(section, {}).get(key, defaultval)
                db.setsetting(flatkey, actual, f"{section} → {key}")
        else:
            db.setsetting(section, values, section)


def reloadconfig():
    """Reload config from DB into the global dict."""
    global config
    config = loadorcreateconfig()


config = loadorcreateconfig()

db.ensurecolumn("images", "os_type", "TEXT NOT NULL DEFAULT 'linux'")
db.ensurecolumn("jobs", "result", "TEXT")
db.ensurecolumn("jobs", "updated", "TEXT")
db.ensurecolumn("plans", "netmbps", "INTEGER NOT NULL DEFAULT 0")
db.ensurevpssuspensiontable()
db.ensurenetworkiptables()


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


app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
sock = Sock(app)

# One-time console tokens: {token: {"vpsUuid", "hostname", "ip", "port", "username", "password", "used", "created"}}
_console_tokens = {}
_CONSOLE_TOKEN_TTL = 300  # 5 minutes

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
            services.performvpsaction(vps['id'], 'start', actorUserId=job['userid'])
            db.updatevps(vpsUuid, status='running')

    elif jobtype == 'stop':
        vps = db.getvps(vpsUuid)
        if vps:
            services.performvpsaction(vps['id'], 'stop', actorUserId=job['userid'])
            db.updatevps(vpsUuid, status='stopped')

    elif jobtype == 'restart':
        vps = db.getvps(vpsUuid)
        if vps:
            services.performvpsaction(vps['id'], 'restart', actorUserId=job['userid'])
            db.updatevps(vpsUuid, status='running')

    elif jobtype == 'suspend':
        vps = db.getvps(vpsUuid)
        if vps:
            if vps['status'] == 'running':
                services.performvpsaction(vps['id'], 'stop', actorUserId=job['userid'])
            db.updatevps(vpsUuid, status='suspended')

    elif jobtype == 'delete':
        vps = db.getvps(vpsUuid)
        if vps:
            _deletevpsnode(vps)
            db.unassignipbyvpsid(vps['id'])
            if vps.get('storagepoolid') and vps.get('disk'):
                db.increasestorageavailable(vps['storagepoolid'], vps['disk'])
            if vps.get('planid'):
                with db.getconnection() as conn:
                    conn.execute("UPDATE plans SET stock = stock + 1, updated = CURRENT_TIMESTAMP WHERE id = ? AND stock >= 0", (vps['planid'],))
            db.deletevpsrecord(vps['id'])

    elif jobtype == 'reinstall':
        vps = db.getvps(vpsUuid)
        if vps:
            _deletevpsnode(vps)
            db.unassignipbyvpsid(vps['id'])
            new_password = services.generaterandompassword()
            imageId = payload.get('imageId')
            updatefields = {'status': 'creating', 'password': new_password, 'container': None, 'vmid': None}
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
    """Delete VPS container from node (Docker or Proxmox)."""
    vpsUuid = vps['uuid']
    node = db.getnodebyid(vps['nodeid'])
    if not node:
        return
    nodeType = node.get('type', 'docker')
    if nodeType == 'proxmox':
        vmid = services.getvmidmapping(vpsUuid)
        if vmid:
            pve = services.getproxmoxclient(node)
            node_name = node.get('proxmoxnode', 'pve')
            services.pveclient.deletelxc(pve, node_name, vmid)
            services.removevmidmapping(vpsUuid)
    else:
        services.nodeapi(node, f"/vps/{vpsUuid}", method="DELETE")



def _jobworker():
    """Background worker that processes queued jobs."""
    while True:
        try:
            job = db.getnextpendingjob()
            if not job:
                time.sleep(2)
                continue

            try:
                _processjob(job)
                db.updatejob(job['uuid'], status='completed')
                auditlog(f"job.{job['type']}", "vps", job['vpsuuid'],
                         f"Job {job['type']} completed for {job['vpsuuid']}")
            except Exception as e:
                db.updatejob(job['uuid'], status='failed', result=str(e))
                auditlog(f"job.{job['type']}_failed", "vps", job['vpsuuid'],
                         f"Job {job['type']} failed: {e}")
                # Set VPS to error state if it was being created/provisioned
                if job['type'] in ('provision', 'create', 'reinstall'):
                    db.updatevps(job['vpsuuid'], status='error')

        except Exception:
            time.sleep(5)


worker_thread = threading.Thread(target=_jobworker, daemon=True, name="JobWorker")
worker_thread.start()



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
        theme_id = db.getsetting("general.theme", "catppuccin")
    for t in THEMES:
        if t["id"] == theme_id:
            return t["class"]
    return ""

def guestuserinfo():
    cookie_theme = request.cookies.get("theme") if request else None
    return {
        "favicon": config["general"]["favicon"],
        "logo": config["general"]["logo"],
        "projectname": config["general"]["projectname"],
        "globaltotalvps": db.countvps(),
        "theme_class": get_theme_class(),
        "themes": THEMES,
        "current_theme": cookie_theme or db.getsetting("general.theme", "catppuccin"),
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
        "current_theme": user.get('theme') or (request.cookies.get("theme") if request else None) or db.getsetting("general.theme", "catppuccin"),
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
    return render_template("dashboard.html", vpsData=vpsData, search=q or '', **paneluserinfo(g.userinfo))

@app.route("/createvps", methods=["GET", "POST"])
@loginrequired
def createvps():
    if request.method == "POST":
        planId = request.form.get("planId", type=int)
        imageId = request.form.get("imageId", type=int)

        plan = db.getplanbyid(planId)
        if not plan:
            flash("Invalid plan selected.", "error")
            return redirect(url_for('createvps'))

        if plan['stock'] == 0:
            flash("This plan is out of stock.", "error")
            return redirect(url_for('createvps'))

        isPaid = float(plan['price']) > 0

        # Check free plan limit
        if not isPaid and db.userhasfreevps(g.userinfo["id"]):
            flash("You already have a free VPS. Free users can only create one free instance.", "error")
            return redirect(url_for('createvps'))

        image = db.getimagebyid(imageId)
        if not image or not image.get('active'):
            flash("Invalid image selected.", "error")
            return redirect(url_for('createvps'))
        if image.get('node_type', 'docker') != plan.get('node_type', 'docker'):
            flash("Selected image does not match plan platform.", "error")
            return redirect(url_for('createvps'))
        if not db.getnodesforimage(image['id']):
            flash("Selected image is not assigned to any node.", "error")
            return redirect(url_for('createvps'))

        nodeId, storageId = db.getsuitablenodeandstorage(
            plan['price'],
            strategy=config.get('loadbalancing', {}).get('strategy', 'both'),
            node_type=plan['node_type'],
            imageid=image['id']
        )
        
        if not nodeId:
            flash("No nodes available with this image assigned.", "error")
            return redirect(url_for('createvps'))

        # Auto-assign network from the node
        node = db.getnodebyid(nodeId)
        nodeNetType = node.get('type', 'docker') if node else 'docker'
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

        # Auto-assign storage pool from the node (proxmox only)
        storagePoolId = None
        if nodeNetType == 'proxmox':
            nodePools = db.liststoragepools(nodeid=nodeId)
            if not nodePools:
                flash("No storage pool configured for this node. Contact an admin.", "error")
                return redirect(url_for('createvps'))
            storagePoolId = nodePools[0]['id']

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
                storageid=storageId,
                networkid=networkId,
                network_type=nodeNetType,
                storagepoolid=storagePoolId,
                hostname=hostname,
                password=services.generaterandompassword(),
                status=initialStatus,
                jobtype=None if isPaid else 'provision'
            )

            auditlog("vps.create", "vps", vpsUuid, f"Created VPS {hostname} with plan '{plan['name']}'")

            if isPaid:
                return redirect(url_for('checkout', vpsUuid=vpsUuid))

            flash("Free VPS is being created!", "success")
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f"An error occurred while creating the VPS: {e}", "error")
            return redirect(url_for('createvps'))

    images = [img for img in db.listimages(active=1) if db.getnodesforimage(img['id'])]
    return render_template("createvps.html", plansList=db.listplans(active=1), images=addosmeta(images), **paneluserinfo(g.userinfo))

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

@app.route("/checkout/processpayment", methods=["POST"])
@loginrequired
def processpayment():
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

    auditlog("payment.manual", "vps", vpsUuid, f"Manual payment of ${plan['price']:.2f} via {methodSlug}")

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

    if receiver:
        paypal_email = config['paypal']['email'].lower()
        if receiver.lower() != paypal_email:
            app.logger.warning(f"PayPal IPN: receiver mismatch: {receiver} != {paypal_email}")
            return "Wrong receiver", 400

    if float(amount) < float(plan['price']):
        app.logger.warning(f"PayPal IPN: insufficient amount: {amount} < {plan['price']}")
        return "Insufficient amount", 400

    # 5. Success Action: Update Database
    if vps['status'] == 'pendingpayment':
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

        auditlog("payment.paypal", "vps", vpsUuid, f"PayPal payment of ${amount} (txn: {txnId})")

        enqueuejob(vps['id'], vpsUuid, vps['userid'], 'provision')
        app.logger.info(f"PayPal IPN: payment processed, provisioning queued for {vpsUuid}")
    else:
        app.logger.info(f"PayPal IPN: VPS {vpsUuid} not in pendingpayment (status={vps['status']})")

    return "OK", 200


@app.route("/vps/<vpsUuid>")
@loginrequired
def vpspanel(vpsUuid):
    vps = db.getvps(vpsUuid)
    if not vps or vps["userid"] != g.userinfo["id"]:
        abort(404)

    instance = services.getvpsdetails(vps["id"])
    metric = services.getlatestvpsmetric(vps["id"])
    
    # Add OS metadata for icon display
    if instance:
        os_type = instance.get('os_type') or 'linux'
        instance['os_meta'] = OS_TYPES.get(os_type, OS_TYPES['linux'])

    assignedIpv4 = vps.get('ipv4')
    assignedIpv6 = vps.get('ipv6')

    # Get DNS from network
    networkDns = None
    if vps.get('networkid'):
        netTable = "proxmox_networks" if vps.get('network_type') == 'proxmox' else "docker_networks"
        with db.getconnection() as conn:
            net = conn.execute(f"SELECT dns FROM {netTable} WHERE id = ?", (vps['networkid'],)).fetchone()
        if net and net['dns']:
            networkDns = net['dns']

    return render_template(
        "vpspanel.html",
        **paneluserinfo(g.userinfo),
        instance=instance,
        metric=metric,
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

    db.updatevps(vpsUuid, status='deleted')
    enqueuejob(vps['id'], vpsUuid, g.userinfo["id"], 'delete')
    auditlog("vps.delete", "vps", vpsUuid, f"Queued delete for {vps['hostname']}")
    flash("VPS deletion queued.", "success")
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
    if not vps or vps["userid"] != g.userinfo["id"]:
        return jsonify({"error": "VPS not found"}), 404

    metric = services.getlatestvpsmetric(vps["id"])
    return jsonify({"status": vps["status"], "metrics": metric})


@app.route("/vps/<vpsUuid>/console/token", methods=["POST"])
@loginrequired
def vpsconsoletoken(vpsUuid):
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

    token = secrets.token_urlsafe(32)
    _console_tokens[token] = {
        "vpsUuid": vpsUuid,
        "hostname": ip,
        "port": 22,
        "username": "root",
        "password": vps["password"],
        "used": False,
        "created": time.time(),
    }
    return jsonify({"token": token})


@app.route("/vps/<vpsUuid>/console")
@loginrequired
def vpsconsole(vpsUuid):
    # Purge expired tokens
    now = time.time()
    expired = [t for t, v in _console_tokens.items() if now - v.get("created", 0) > _CONSOLE_TOKEN_TTL]
    for t in expired:
        del _console_tokens[t]

    token = request.args.get("t")
    if not token or token not in _console_tokens:
        return "Invalid or expired console token", 403

    ct = _console_tokens.pop(token)
    if ct["vpsUuid"] != vpsUuid:
        return "Invalid or expired console token", 403

    vps = db.getvps(vpsUuid)
    if not vps:
        return "VPS not found", 404

    isAdmin = g.userinfo.get('role') == 'admin'
    if not isAdmin and vps["userid"] != g.userinfo["id"]:
        return "VPS not found", 404

    if vpsissuspended(vps):
        return "This VPS is suspended", 403

    return render_template(
        "console.html",
        hostname=ct["hostname"],
        port=ct["port"],
        username=ct["username"],
        password=ct["password"],
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

    host = request.args.get("host", "")
    port = int(request.args.get("port", 22))
    username = request.args.get("user", "root")
    password = request.args.get("pass", "")

    if not host:
        try:
            ws.close(1008, "Missing host")
        except Exception:
            pass
        return

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(host, port=port, username=username, password=password,
                    timeout=config.get("console", {}).get("timeout", 10),
                    banner_timeout=15, auth_timeout=15, look_for_keys=False)
    except Exception as e:
        try:
            ws.close(1011, f"SSH connect failed: {e}")
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
        except Exception as e:
            ssh.close()
            try:
                ws.close(1011, f"Shell failed: {e}")
            except Exception:
                pass
            return

    chan.settimeout(0.1)

    closed = threading.Event()

    def ssh_to_ws():
        """Read from SSH channel, send to WebSocket."""
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
            try:
                msg = ws.receive(timeout=0.5)
            except Exception:
                break
            if msg is None:
                continue
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
    
    auditlog("user.ban", "user", userId, f"Banned user '{target['username']}': {reason}")
    flash("User has been banned.", "success")
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
    vpsData = db.listvpspaginated(page=page, perpage=12, search=q)
    
    users = db.listallusers()
    plans = db.listplans(active=1)
    dockerImages = db.listimages(active=1, node_type='docker')
    proxmoxImages = db.listimages(active=1, node_type='proxmox')
    images = dockerImages + proxmoxImages
    networks = db.listnetworks(network_type='docker') + db.listnetworks(network_type='proxmox')
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
        **paneluserinfo(g.userinfo), 
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/vps/<vpsUuid>")
@loginrequired
@adminrequired
def adminvpspanel(vpsUuid):
    vps = db.getvps(vpsUuid)
    if not vps:
        abort(404)

    instance = services.getvpsdetails(vps["id"])
    metric = services.getlatestvpsmetric(vps["id"])
    owner = db.getuserbyid(vps["userid"])
    suspension = db.getsuspensionbyvpsid(vps["id"])
    
    # Add OS metadata for icon display
    if instance:
        os_type = instance.get('os_type') or 'linux'
        instance['os_meta'] = OS_TYPES.get(os_type, OS_TYPES['linux'])

    assignedIpv4 = vps.get('ipv4')
    assignedIpv6 = vps.get('ipv6')

    # Get DNS from network
    networkDns = None
    if vps.get('networkid'):
        netTable = "proxmox_networks" if vps.get('network_type') == 'proxmox' else "docker_networks"
        with db.getconnection() as conn:
            net = conn.execute(f"SELECT dns FROM {netTable} WHERE id = ?", (vps['networkid'],)).fetchone()
        if net and net['dns']:
            networkDns = net['dns']

    return render_template(
        "adminvpspanel.html",
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo),
        instance=instance,
        metric=metric,
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
        # Force delete: just clean DB, skip node
        db.unassignipbyvpsid(vps['id'])
        if vps.get('storagepoolid') and vps.get('disk'):
            db.increasestorageavailable(vps['storagepoolid'], vps['disk'])
        if vps.get('planid'):
            with db.getconnection() as conn:
                conn.execute("UPDATE plans SET stock = stock + 1, updated = CURRENT_TIMESTAMP WHERE id = ? AND stock >= 0", (vps['planid'],))
        db.deletevpsrecord(vps['id'])
        auditlog("vps.delete", "vps", vpsUuid, f"Admin force-deleted VPS {vps['hostname']}")
        flash("VPS force-removed from DB.", "warning")
    else:
        db.updatevps(vpsUuid, status='deleted')
        enqueuejob(vps['id'], vpsUuid, g.userinfo["id"], 'delete')
        auditlog("vps.delete", "vps", vpsUuid, f"Admin queued delete for {vps['hostname']}")
        flash("VPS deletion queued.", "success")

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

        network_type = request.form.get('network_type', 'docker')
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
    # Handle New Plan Creation
    if request.method == "POST":
        db.addplan(
            uuid=str(uuid.uuid4()),
            name=request.form.get("name"),
            cpu=request.form.get("cpu"),
            ram=request.form.get("ram"),
            swap=request.form.get("swap"),
            disk=request.form.get("disk"),
            price=request.form.get("price"),
            stock=int(request.form.get("stock", -1)),
            netmbps=int(request.form.get("netmbps", 0)),
            node_type=request.form.get("node_type", "docker")
        )
        auditlog("plan.create", "plan", None, f"Created plan '{request.form.get('name')}'")
        return redirect(url_for('adminplans'))

    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    plansData = db.listplanspaginated(page=page, perpage=12, search=q)

    return render_template(
        "adminplans.html", 
        allPlans=plansData['plans'],
        pagination=plansData,
        search=q or '',
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/plans/update/<string:planUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminupdateplans(planUuid):
    # Retrieve form data
    # Note: Use request.form.get() for inputs, 
    # check for checkbox values if you add them later (they might return 'on')
    
    db.updateplan(
        uuid=planUuid,
        name=request.form.get("name"),
        cpu=int(request.form.get("cpu")),
        ram=int(request.form.get("ram")),
        swap=int(request.form.get("swap")),
        disk=int(request.form.get("disk")),
        description=request.form.get("description"),
        ipv4=int(request.form.get("ipv4", 0)),
        ipv6=int(request.form.get("ipv6", 1)),
        price=float(request.form.get("price")),
        active=int(request.form.get("active", 1)),
        stock=int(request.form.get("stock", -1)),
        netmbps=int(request.form.get("netmbps", 0)),
        node_type=request.form.get("node_type", "docker")
    )
    
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
    nodesData = db.listnodespaginated(page=page, perpage=12, search=q)
    
    return render_template(
        "adminnodes.html", 
        allNodes=nodesData['nodes'],
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
        nodeType = request.form.get("type", "docker")
        
        db.addnode(
            uuid=nodeUuid,
            name=request.form.get("name"),
            hostname=request.form.get("hostname"),
            address=request.form.get("address"),
            url=request.form.get("url", ""),
            apikey=request.form.get("apikey"),
            cpu=int(request.form.get("cpu", 0)),
            ram=int(request.form.get("ram", 0)),
            status=request.form.get("status", "online"),
            tier=request.form.get("tier", "free"),
            nodeType=nodeType,
            proxmoxhost=request.form.get("proxmoxhost") if nodeType == "proxmox" else None,
            proxmoxuser=request.form.get("proxmoxuser") if nodeType == "proxmox" else None,
            proxmoxpassword=request.form.get("proxmoxpassword") if nodeType == "proxmox" else None,
            proxmoxnode=request.form.get("proxmoxnode", "pve") if nodeType == "proxmox" else "pve",
            proxmoxport=int(request.form.get("proxmoxport", 8006)) if nodeType == "proxmox" else 8006,
            proxmoxssl=1 if request.form.get("proxmoxssl") == "1" else 0
        )
        auditlog("node.create", "node", nodeUuid, f"Registered {nodeType} node '{request.form.get('name')}'")
        flash(f"Node '{request.form.get('name')}' registered successfully.", "success")
    except Exception as e:
        flash("Error creating node.", "danger")
    
    return redirect(url_for('adminnodes'))

@app.route("/dashboard/admin/nodes/update/<string:nodeUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminnodesupdate(nodeUuid):
    try:
        nodeType = request.form.get("type")
        updateData = {
            "name": request.form.get("name"),
            "hostname": request.form.get("hostname"),
            "address": request.form.get("address"),
            "url": request.form.get("url", ""),
            "ram": int(request.form.get("ram", 0)),
            "status": request.form.get("status"),
            "tier": request.form.get("tier"),
            "type": nodeType
        }
        
        newKey = request.form.get("apikey")
        if newKey and newKey.strip() != "":
            updateData["apikey"] = newKey

        # Proxmox-specific updates
        if nodeType == "proxmox":
            updateData["proxmoxhost"] = request.form.get("proxmoxhost")
            updateData["proxmoxuser"] = request.form.get("proxmoxuser")
            pvePass = request.form.get("proxmoxpassword")
            if pvePass and pvePass.strip() != "":
                updateData["proxmoxpassword"] = pvePass
            updateData["proxmoxnode"] = request.form.get("proxmoxnode", "pve")
            updateData["proxmoxport"] = int(request.form.get("proxmoxport", 8006))
            updateData["proxmoxssl"] = 1 if request.form.get("proxmoxssl") == "1" else 0

        db.updatenode(nodeUuid, **updateData)
        auditlog("node.update", "node", nodeUuid, f"Updated node '{request.form.get('name')}'")
        flash("Node configuration updated.", "success")
    except Exception as e:
        flash("Error updating node.", "danger")

    return redirect(url_for('adminnodes'))

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

    nodeType = node.get('type', 'docker')
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
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/nodes/<string:nodeUuid>/stats")
@loginrequired
@adminrequired
def adminnodestats(nodeUuid):
    """API endpoint to fetch live node stats."""
    node = db.getnode(nodeUuid)
    if not node:
        return jsonify({"error": "Node not found"}), 404
    
    nodeType = node.get('type', 'docker')
    
    if nodeType == 'docker':
        # Fetch stats from Docker node agent
        result = services.nodeapi(node, "/node/stats", method="GET", timeout=5)
        if not result or result.get('error'):
            return jsonify({"error": result.get('error', 'Node unreachable') if result else "Node unreachable"}), 503
        return jsonify(result.get('stats', {}))
    
    elif nodeType == 'proxmox':
        # Fetch stats from Proxmox API
        try:
            from utils.proxmox import getproxmoxclient
            pve = getproxmoxclient(node)
            node_name = node.get('proxmoxnode', 'pve')
            
            # Get node status - returns current resource usage
            status = pve.nodes(node_name).status.get()
            
            # Proxmox returns different keys, handle both formats
            # CPU is returned as decimal (0.05 = 5%)
            cpu_val = status.get('cpu', 0)
            if isinstance(cpu_val, (int, float)):
                cpu_percent = round(cpu_val * 100, 1)
            else:
                cpu_percent = 0
            
            # Memory - can be dict or separate keys
            memory_info = status.get('memory', {})
            if isinstance(memory_info, dict):
                mem_total = memory_info.get('total', 0)
                mem_used = memory_info.get('used', 0)
                mem_free = memory_info.get('free', 0)
            else:
                # Alternative format with separate keys
                mem_total = status.get('memtotal', status.get('maxmem', 0))
                mem_used = status.get('memused', status.get('mem', 0))
                mem_free = mem_total - mem_used
            
            mem_percent = round((mem_used / mem_total * 100), 1) if mem_total > 0 else 0
            
            # Disk/rootfs - can be dict or separate keys
            rootfs_info = status.get('rootfs', {})
            if isinstance(rootfs_info, dict):
                disk_total = rootfs_info.get('total', 0)
                disk_used = rootfs_info.get('used', 0)
                disk_free = rootfs_info.get('free', rootfs_info.get('avail', 0))
            else:
                # Alternative format
                disk_total = status.get('maxdisk', 0)
                disk_used = status.get('disk', 0)
                disk_free = disk_total - disk_used
            
            disk_percent = round((disk_used / disk_total * 100), 1) if disk_total > 0 else 0
            
            # Load average
            loadavg = status.get('loadavg', [0, 0, 0])
            if isinstance(loadavg, list) and len(loadavg) >= 3:
                load_1, load_5, load_15 = loadavg[0], loadavg[1], loadavg[2]
            else:
                load_1 = load_5 = load_15 = 0
            
            # Format stats to match our format
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
                'uptime': status.get('uptime', 0)
            }
            
            # Try to get network stats from RRD data
            try:
                # Get RRD data for the last data point (current stats)
                # timeframe 'hour' with CF 'AVERAGE' gives us current rates
                rrd = pve.nodes(node_name).rrddata.get(timeframe='hour', cf='AVERAGE')
                if rrd and len(rrd) > 0:
                    # Get the most recent data point
                    latest = rrd[-1]
                    # netin and netout are in bytes/sec, multiply by uptime for cumulative estimate
                    net_in_rate = latest.get('netin', 0) or 0
                    net_out_rate = latest.get('netout', 0) or 0
                    uptime = status.get('uptime', 0)
                    
                    # Estimate cumulative bytes (rate * uptime)
                    stats['network_rx_bytes'] = int(net_in_rate * uptime) if uptime > 0 else 0
                    stats['network_tx_bytes'] = int(net_out_rate * uptime) if uptime > 0 else 0
                else:
                    stats['network_rx_bytes'] = 0
                    stats['network_tx_bytes'] = 0
            except:
                stats['network_rx_bytes'] = 0
                stats['network_tx_bytes'] = 0
            
            return jsonify(stats)
        except Exception as e:
            import traceback
            return jsonify({"error": f"Proxmox API error: {str(e)}", "trace": traceback.format_exc()}), 503
    
    return jsonify({"error": "Unknown node type"}), 400

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

    nodeType = node.get('type', 'docker')
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

    if nodeType == 'docker':
        payload = {
            "name": name, "ipv4": bool(ipv4), "ipv6": bool(ipv6), "nat": False,
            "dns": [s.strip() for s in dns.split(',') if s.strip()] if dns else [],
        }
        if ipv6_subnet:
            payload["subnet"] = ipv6_subnet
        if ipv6_gateway:
            payload["gateway"] = ipv6_gateway
        result = services.nodeapi(node, "/networks", method="POST", data=payload, timeout=30)
        if not result:
            flash("Node unreachable. Could not create network.", "error")
            return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='networks'))
        if result.get("error"):
            flash(f"Node error: {result['error']}", "error")
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

    nodeType = node.get('type', 'docker')
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

    if nodeType == 'docker' and name != network['name']:
        flash("Docker network names cannot be edited. Delete and recreate network instead.", "error")
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

    nodeType = node.get('type', 'docker')
    network = db.getnetwork(netUuid, network_type=nodeType)
    if not network:
        flash("Network not found.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='networks'))

    vpsCount = db.countvpsbynetwork(network['id'], network_type=nodeType)
    if vpsCount > 0:
        flash(f"Cannot delete: {vpsCount} VPS instance(s) using this network.", "error")
        return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='networks'))

    if nodeType == 'docker':
        info = services.nodeapi(node, f"/networks/{network['name']}", method="GET")
        if info and not info.get("error"):
            containers = info.get("containers", {})
            if containers:
                flash(f"Cannot delete: {len(containers)} container(s) still connected.", "error")
                return redirect(url_for('adminnodeprofile', nodeUuid=nodeUuid, tab='networks'))
        services.nodeapi(node, f"/networks/{network['name']}", method="DELETE")

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

    nodeType = node.get('type', 'docker')
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

    nodeType = node.get('type', 'docker')
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

    nodeType = node.get('type', 'docker')
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
        db.removenetworkip(ipUuid)
        flash("IP removed.", "warning")
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
            node_type=request.form.get("node_type", "docker"),
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
            "node_type": request.form.get("node_type", "docker"),
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

# --- Settings ---

SETTINGS_SCHEMA = {
    "general": {
        "projectname": {"label": "Project Name", "type": "text", "desc": "Displayed in the header and title."},
        "theme": {"label": "Theme", "type": "theme", "desc": "Color theme for the entire UI."},
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
}


@app.route("/dashboard/admin/settings", methods=["GET", "POST"])
@loginrequired
@adminrequired
def adminsettings():
    if request.method == "POST":
        section = request.form.get("section")
        if section and section in SETTINGS_SCHEMA:
            for key, meta in SETTINGS_SCHEMA[section].items():
                flatkey = f"{section}.{key}"
                if meta['type'] == 'bool':
                    val = request.form.get(key) == 'on' or request.form.get(key) == '1'
                elif meta['type'] == 'number':
                    raw = request.form.get(key, '')
                    val = int(raw) if raw else DEFAULT_CONFIG.get(section, {}).get(key, 0)
                else:
                    val = request.form.get(key, '')
                db.setsetting(flatkey, val, f"{section} → {key}")
            auditlog("settings.update", "settings", None, f"Updated {section} settings")
            reloadconfig()
            flash(f"{section.title()} settings saved.", "success")
        return redirect(url_for('adminsettings'))

    return render_template(
        "adminsettings.html",
        config=config,
        schema=SETTINGS_SCHEMA,
        defaults=DEFAULT_CONFIG,
        current_theme_global=db.getsetting("general.theme", "catppuccin"),
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
    discordAuthUrl = (
        f"{config['discord']['discordbaseurl']}/oauth2/authorize?client_id={config['discord']['clientid']}"
        f"&redirect_uri={config['discord']['redirecturl']}&response_type=code&scope=identify%20email"
    )
    return redirect(discordAuthUrl)


@app.route("/discord-callback")
def discordcallback():
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
    """Check if the job worker is running."""
    status = "running" if worker_thread and worker_thread.is_alive() else "stopped"
    return jsonify({
        "worker_status": status,
        "message": f"Job worker is {status}"
    })


if __name__ == "__main__":
    # Ensure job worker is running
    if worker_thread is None or not worker_thread.is_alive():
        worker_thread = threading.Thread(target=_jobworker, daemon=True, name="JobWorker")
        worker_thread.start()
    
    app.run(
        host=config["server"]["host"], 
        port=config["server"]["port"], 
        debug=config["server"]["debug"]
    )