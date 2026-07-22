from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, make_response, g
from flask_sock import Sock
import os
import secrets
import requests
import toml
import uuid
import math
import json
import socket
import hmac
import time
import threading
import paramiko
from urllib.parse import urlencode
from datetime import datetime
from functools import wraps

from core import db
from utils import services

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.toml")

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
}


def loadorcreateconfig():
    """Load config from DB, fall back to config.toml, then to defaults."""
    dbSettings = db.getallsettings()

    # If DB has settings, use them
    if dbSettings:
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

        # Merge with defaults (DB takes priority)
        merged = {}
        for section, defaults in DEFAULT_CONFIG.items():
            merged[section] = {**defaults, **nested.get(section, {})}
        for section in nested:
            if section not in merged:
                merged[section] = nested[section]
        return merged

    # Fall back to config.toml
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            fileConfig = toml.load(f)
        # Migrate file config to DB
        _migrateconfigtodb(fileConfig, DEFAULT_CONFIG)
        return fileConfig

    # No config.toml, use defaults and save to DB
    _migrateconfigtodb(DEFAULT_CONFIG, DEFAULT_CONFIG)
    return DEFAULT_CONFIG


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


def getpaypalurl():
    return "https://www.sandbox.paypal.com/cgi-bin/webscr" if config['paypal']['sandbox'] else "https://www.paypal.com/cgi-bin/webscr"

def getverifyurl():
    return "https://ipnpb.sandbox.paypal.com/cgi-bin/webscr" if config['paypal']['sandbox'] else "https://ipnpb.paypal.com/cgi-bin/webscr"




def daystoseconds(days: int) -> int:
    return int(days) * 86400


def auditlog(action, target_type=None, target_id=None, details=None):
    """Log an action to the audit trail."""
    user = getattr(g, 'userinfo', None)
    db.addauditlog(
        uuid=str(uuid.uuid4()),
        userid=user['id'] if user else None,
        username=user.get('username', 'system') if user else 'system',
        role=user.get('role', 'system') if user else 'system',
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id else None,
        details=details,
        ip=request.remote_addr if request else None,
    )


app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
sock = Sock(app)

# One-time console tokens: {token: {"vpsUuid", "hostname", "ip", "port", "username", "password", "used", "created"}}
_console_tokens = {}
_CONSOLE_TOKEN_TTL = 300  # 5 minutes

COOKIE_NAME = "sessioncookie"
SESSION_TTL_DAYS = config["general"]["defaultcookiettl"]

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

        nodeId, storageId = db.getsuitablenodeandstorage(
            plan['price'],
            strategy=config.get('loadbalancing', {}).get('strategy', 'both')
        )
        
        if not nodeId:
            flash("No nodes available for this tier.", "error")
            return redirect(url_for('createvps'))

        # Auto-assign network from the node
        node = db.getnodebyid(nodeId)
        nodeNetType = node.get('type', 'docker') if node else 'docker'
        nodeNetworks = db.listnetworks(nodeid=nodeId, network_type=nodeNetType)
        if not nodeNetworks:
            flash("No network configured for this node. Contact an admin.", "error")
            return redirect(url_for('createvps'))
        networkId = nodeNetworks[0]['id']

        # Auto-assign storage pool from the node (proxmox only)
        storagePoolId = None
        if nodeNetType == 'proxmox':
            nodePools = db.liststoragepools(nodeid=nodeId)
            if not nodePools:
                flash("No storage pool configured for this node. Contact an admin.", "error")
                return redirect(url_for('createvps'))
            storagePoolId = nodePools[0]['id']

        # Check IP availability
        availIp = db.getavailableip(networkId, network_type=nodeNetType)
        if not availIp:
            flash("No IPs available for this network. Contact an admin.", "error")
            return redirect(url_for('createvps'))

        vpsUuid = str(uuid.uuid4())
        initialStatus = 'pendingpayment' if isPaid else 'creating'

        try:
            hostname = services.generaterandomhostname()
            db.addvps(
                uuid=vpsUuid,
                userid=int(g.userinfo["id"]),
                planid=plan['id'],
                imageid=imageId,
                nodeid=nodeId,
                storageid=storageId,
                networkid=networkId,
                network_type=nodeNetType,
                storagepoolid=storagePoolId,
                hostname=hostname,
                password=services.generaterandompassword(),
                cpu=plan['cpu'], ram=plan['ram'],
                swap=plan['swap'], disk=plan['disk'],
                status=initialStatus
            )
            
            db.decrementplanstock(plan['id'])
            if storagePoolId:
                db.decreasestorageavailable(storagePoolId, plan['disk'])
            
            auditlog("vps.create", "vps", vpsUuid, f"Created VPS {hostname} with plan '{plan['name']}'")

            if isPaid:
                return redirect(url_for('checkout', vpsUuid=vpsUuid))
            
            # Free VPS: provision on node immediately
            try:
                services.provisiononnode(vpsUuid)
                flash("Free VPS is being created!", "success")
            except ValueError as e:
                db.updatevps(vpsUuid, status='error')
                flash(f"VPS created but node provisioning failed: {e}", "error")
            
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f"An error occurred while creating the VPS: {e}", "error")
            return redirect(url_for('createvps'))

    return render_template("createvps.html", plansList=db.listplans(active=1), images=db.listimages(active=1), **paneluserinfo(g.userinfo))

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
        params = {
            "cmd": "_xclick",
            "business": config['paypal']['email'],
            "item_name": f"VPS: {plan['name']} ({vps['hostname']})",
            "amount": f"{plan['price']:.2f}",
            "currency_code": "USD",
            "notify_url": f"{config['paypal']['base_url']}/paypal/ipn",
            "return": f"{config['paypal']['base_url']}/vps/{vpsUuid}",
            "cancel_return": f"{config['paypal']['base_url']}/checkout/{vpsUuid}",
            "custom": vpsUuid
        }
        paypalRedirect = getpaypalurl() + "?" + urlencode(params)
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

    try:
        services.provisiononnode(vpsUuid)
        flash("Payment confirmed. VPS is being created!", "success")
    except ValueError as e:
        db.updatevps(vpsUuid, status='error')
        flash(f"Payment confirmed but provisioning failed: {e}", "error")

    return redirect(url_for('dashboard'))

@app.route("/paypal/ipn", methods=["POST"])
def paypalipn():
    # 1. Verify with PayPal
    verifyData = request.form.to_dict(flat=True)
    verifyData["cmd"] = "_notify-validate"
    r = requests.post(getverifyurl(), data=verifyData, headers={"Connection": "close"})

    if r.text != "VERIFIED":
        return "INVALID", 400

    # 2. Extract Data
    vpsUuid = request.form.get("custom")
    paymentStatus = request.form.get("payment_status")
    amount = request.form.get("mc_gross")
    receiver = request.form.get("receiver_email")
    txnId = request.form.get("txn_id") or request.form.get("transaction_id")

    # 3. Replay protection: reject if txn_id already processed
    if txnId and db.gettransactionbytxnid(txnId):
        return "Already processed", 200

    # 4. Validation Logic
    vps = db.getvps(vpsUuid)
    if not vps:
        return "VPS not found", 400
    
    plan = db.getplanbyid(vps['planid'])

    # Security Checks
    if paymentStatus != "Completed":
        return "Not completed", 200
    if receiver.lower() != config['paypal']['email'].lower():
        return "Wrong receiver", 400
    if float(amount) < float(plan['price']):
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

        try:
            services.provisiononnode(vpsUuid)
        except ValueError:
            db.updatevps(vpsUuid, status='error')

    return "OK", 200

@app.route("/vps/<vpsUuid>")
@loginrequired
def vpspanel(vpsUuid):
    vps = db.getvps(vpsUuid)
    if not vps or vps["userid"] != g.userinfo["id"]:
        return "VPS not found", 404

    instance = services.getvpsdetails(vps["id"])
    metric = services.getlatestvpsmetric(vps["id"])

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
        metrics_mode=config.get("console", {}).get("metrics", "dynamic"),
    )


#############
#
# Action Routes (AJAX)
#
#############

@app.route("/vps/<vpsUuid>/action/<action>", methods=["POST"])
@loginrequired
def vpsaction(vpsUuid, action):
    if action not in ("start", "stop", "restart"):
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

    if vps["status"] == "suspended":
        flash("This VPS is suspended.", "error")
        return redirect(backUrl)

    try:
        services.performvpsaction(vps["id"], action, actorUserId=g.userinfo["id"])
        auditlog(f"vps.{action}", "vps", vpsUuid, f"VPS {action} on {vps['hostname']}")
        flash(f"VPS {action} successful.", "success")
    except ValueError as e:
        flash(f"Action failed: {e}", "error")

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

    if vps["status"] != "running":
        return jsonify({"error": "VPS must be running to open console"}), 400

    ip = vps.get("ipv4") or vps.get("ipv6")
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

    return render_template(
        "console.html",
        hostname=ct["hostname"],
        port=ct["port"],
        username=ct["username"],
        password=ct["password"],
        hostname_display=vps.get("ipv4") or vps.get("ipv6", "unknown"),
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
        flash("VPS not found.", "error")
        return redirect(url_for('adminvps'))

    instance = services.getvpsdetails(vps["id"])
    metric = services.getlatestvpsmetric(vps["id"])
    owner = db.getuserbyid(vps["userid"])

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
        metrics_mode=config.get("console", {}).get("metrics", "dynamic"),
    )

@app.route("/dashboard/admin/vps/<string:vpsUuid>/delete", methods=["POST"])
@loginrequired
@adminrequired
def adminvpsdelete(vpsUuid):
    vps = db.getvps(vpsUuid)
    if not vps:
        flash("VPS not found.", "error")
        return redirect(url_for('adminvps'))

    force = request.form.get("force") == "1"
    nodeError = None

    # Try to delete on node
    node = db.getnodebyid(vps['nodeid'])
    if node:
        nodeType = node.get('type', 'docker')
        if nodeType == 'proxmox':
            vmid = services.getvmidmapping(vpsUuid)
            if vmid:
                try:
                    pve = services.getproxmoxclient(node)
                    node_name = node.get('proxmoxnode', 'pve')
                    services.pveclient.deletelxc(pve, node_name, vmid)
                    services.removevmidmapping(vpsUuid)
                except Exception as e:
                    nodeError = str(e)
            else:
                nodeError = "VMID not found"
        else:
            result = services.nodeapi(node, f"/vps/{vpsUuid}", method="DELETE")
            if not result:
                nodeError = "Node unreachable"
            elif result.get("error"):
                nodeError = result['error']

    if nodeError and not force:
        flash(f"Node error: {nodeError}. Use Force Delete to remove from DB anyway.", "error")
        return redirect(url_for('adminvpspanel', vpsUuid=vpsUuid))

    # Release assigned IP
    db.unassignipbyvpsid(vps['id'])

    # Restore storage pool usage
    if vps.get('storagepoolid') and vps.get('disk'):
        db.increasestorageavailable(vps['storagepoolid'], vps['disk'])

    # Restore plan stock
    if vps.get('planid'):
        with db.getconnection() as conn:
            conn.execute("UPDATE plans SET stock = stock + 1, updated = CURRENT_TIMESTAMP WHERE id = ? AND stock >= 0", (vps['planid'],))

    # Remove from DB
    with db.getconnection() as conn:
        conn.execute("DELETE FROM vps WHERE id = ?", (vps['id'],))

    auditlog("vps.delete", "vps", vpsUuid, f"Deleted VPS {vps['hostname']} (force={force}, node_error={nodeError})")
    if nodeError:
        flash(f"VPS removed from DB (node delete failed: {nodeError}).", "warning")
    else:
        flash("VPS deleted.", "success")

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

        if not db.getimagebyid(imageid):
            flash("Invalid image selected.", "danger")
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

        availIp = db.getavailableip(networkid, network_type=network_type)
        if not availIp:
            flash("No IPs available for this network. Generate more IPs first.", "danger")
            return redirect(url_for('adminvps'))

        storagepoolid = request.form.get('storagepoolid', type=int)
        poolName = "default"
        if storagepoolid:
            pool = db.getstoragepoolbyid(storagepoolid)
            if pool:
                poolName = pool['name']

        try:
            db.addvps(
                uuid=vpsUuid,
                userid=userid,
                planid=planid,
                imageid=imageid,
                nodeid=nodeid,
                storageid=storageid,
                networkid=networkid,
                network_type=network_type,
                storagepoolid=storagepoolid,
                hostname=hostname,
                password=password,
                cpu=plan['cpu'],
                ram=plan['ram'],
                swap=plan['swap'],
                disk=plan['disk'],
                status='creating'
            )
            db.decrementplanstock(plan['id'])
            if storagepoolid:
                db.decreasestorageavailable(storagepoolid, plan['disk'])
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
            readbps=int(request.form.get("readbps", 0)),
            writebps=int(request.form.get("writebps", 0))
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
        readbps=int(request.form.get("readbps", 0)),
        writebps=int(request.form.get("writebps", 0))
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
            disk=int(request.form.get("disk", 0)),
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

@app.route("/dashboard/admin/osimage")
@loginrequired
@adminrequired
def adminosimage():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    nodeType = request.args.get('type', '').strip() or None
    imagesData = db.listimagespaginated(page=page, perpage=12, search=q, node_type=nodeType)
    allImageStorages = db.listimagestorage()
    
    return render_template(
        "adminosimage.html",
        allImages=imagesData['images'],
        pagination=imagesData,
        activeImagesCount=sum(1 for i in imagesData['images'] if i['active']),
        allImageStorages=allImageStorages,
        search=q or '',
        nodeType=nodeType or '',
        **paneluserinfo(g.userinfo), 
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/osimage/create", methods=["POST"])
@loginrequired
@adminrequired
def adminosimagecreate():
    try:
        imagestorageid = request.form.get("imagestorageid", type=int) or None
        db.addimage(
            uuid=str(uuid.uuid4()),
            name=request.form.get("name"),
            image=request.form.get("image"),
            description=request.form.get("description"),
            active=int(request.form.get("active", 1)),
            node_type=request.form.get("node_type", "docker"),
            imagestorageid=imagestorageid
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
        imagestorageid = request.form.get("imagestorageid", type=int) or None
        updateData = {
            "name": request.form.get("name"),
            "image": request.form.get("image"),
            "description": request.form.get("description"),
            "active": int(request.form.get("active")),
            "node_type": request.form.get("node_type", "docker"),
            "imagestorageid": imagestorageid
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



# --- Storage Pool Management ---

@app.route("/dashboard/admin/storagepools")
@loginrequired
@adminrequired
def adminstoragepools():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    nodeType = request.args.get('type', 'proxmox').strip() or None
    poolsData = db.liststoragepoolspaginated(page=page, perpage=12, search=q, nodeType=nodeType)
    allNodes = db.listallnodes()
    return render_template(
        "adminstoragepools.html",
        allPools=poolsData['pools'],
        pagination=poolsData,
        allNodes=allNodes,
        search=q or '',
        nodeType=nodeType or '',
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/storagepools/create", methods=["POST"])
@loginrequired
@adminrequired
def adminstoragepoolscreate():
    nodeid = request.form.get("nodeid", type=int)
    name = request.form.get("name")
    size = int(request.form.get("size", 0))

    if not nodeid or not name:
        flash("Node and disk name required.", "error")
        return redirect(url_for('adminstoragepools'))

    node = db.getnodebyid(nodeid)
    if not node:
        flash("Node not found.", "error")
        return redirect(url_for('adminstoragepools'))

    if node.get('type') != 'proxmox':
        flash("Storage pools are only for Proxmox nodes.", "error")
        return redirect(url_for('adminstoragepools'))

    poolUuid = str(uuid.uuid4())
    db.addstoragepool(uuid=poolUuid, nodeid=nodeid, name=name, size=size, nodeType='proxmox')
    auditlog("storage.create", "storage", poolUuid, f"Created storage pool '{name}' on node '{node['name']}'")
    flash(f"Storage pool '{name}' created.", "success")
    return redirect(url_for('adminstoragepools'))

@app.route("/dashboard/admin/storagepools/delete/<string:poolUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminstoragepoolsdelete(poolUuid):
    pool = db.getstoragepool(poolUuid)
    if not pool:
        flash("Pool not found.", "error")
        return redirect(url_for('adminstoragepools'))

    db.removestoragepool(poolUuid)
    auditlog("storage.delete", "storage", poolUuid, f"Deleted storage pool '{pool['name']}'")
    flash("Storage pool removed.", "warning")
    return redirect(url_for('adminstoragepools'))

@app.route("/dashboard/admin/storagepools/update/<string:poolUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminstoragepoolsupdate(poolUuid):
    pool = db.getstoragepool(poolUuid)
    if not pool:
        flash("Pool not found.", "error")
        return redirect(url_for('adminstoragepools'))

    name = request.form.get("name")
    size = int(request.form.get("size", 0))

    db.updatestoragepool(poolUuid, name=name, size=size)
    auditlog("storage.update", "storage", poolUuid, f"Updated storage pool '{name}'")
    flash("Storage pool updated.", "success")
    return redirect(url_for('adminstoragepools'))

# --- Image Storage Management ---

@app.route("/dashboard/admin/imagestorage")
@loginrequired
@adminrequired
def adminimagestorage():
    allStorages = db.listimagestorage()
    allNodes = db.listallnodes()
    proxmoxNodes = [n for n in allNodes if n.get('type') == 'proxmox']
    return render_template(
        "adminimagestorage.html",
        allStorages=allStorages,
        proxmoxNodes=proxmoxNodes,
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/imagestorage/create", methods=["POST"])
@loginrequired
@adminrequired
def adminimagestoragecreate():
    nodeid = request.form.get("nodeid", type=int)
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip() or None

    if not nodeid or not name:
        flash("Node and storage name required.", "error")
        return redirect(url_for('adminimagestorage'))

    node = db.getnodebyid(nodeid)
    if not node or node.get('type') != 'proxmox':
        flash("Invalid Proxmox node.", "error")
        return redirect(url_for('adminimagestorage'))

    storageUuid = str(uuid.uuid4())
    db.addimagestorage(uuid=storageUuid, nodeid=nodeid, name=name, description=description)
    auditlog("imagestorage.create", "imagestorage", storageUuid, f"Added image storage '{name}' to node '{node['name']}'")
    flash(f"Image storage '{name}' added to '{node['name']}'.", "success")
    return redirect(url_for('adminimagestorage'))

@app.route("/dashboard/admin/imagestorage/update/<string:storageUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminimagestorageupdate(storageUuid):
    storage = db.getimagestorage(storageUuid)
    if not storage:
        flash("Image storage not found.", "error")
        return redirect(url_for('adminimagestorage'))

    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip() or None

    if not name:
        flash("Storage name cannot be empty.", "error")
        return redirect(url_for('adminimagestorage'))

    db.updateimagestorage(storageUuid, name=name, description=description)
    auditlog("imagestorage.update", "imagestorage", storageUuid, f"Updated image storage '{name}'")
    flash(f"Image storage updated.", "success")
    return redirect(url_for('adminimagestorage'))

@app.route("/dashboard/admin/imagestorage/delete/<string:storageUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminimagestoragedelete(storageUuid):
    storage = db.getimagestorage(storageUuid)
    if not storage:
        flash("Image storage not found.", "error")
        return redirect(url_for('adminimagestorage'))

    db.removeimagestorage(storageUuid)
    auditlog("imagestorage.delete", "imagestorage", storageUuid, f"Deleted image storage '{storage['name']}'")
    flash(f"Image storage '{storage['name']}' removed.", "warning")
    return redirect(url_for('adminimagestorage'))

@app.route("/dashboard/admin/imagestorage/fetch/<int:nodeId>")
@loginrequired
@adminrequired
def adminimagestoragefetch(nodeId):
    node = db.getnodebyid(nodeId)
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

# --- Network Management ---

@app.route("/dashboard/admin/networks")
@loginrequired
@adminrequired
def adminnetworks():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    nodeType = request.args.get('type', '').strip() or None
    networksData = db.listnetworkspaginated(page=page, perpage=12, search=q, network_type=nodeType)
    allNodes = db.listallnodes()
    return render_template(
        "adminnetworks.html",
        allNetworks=networksData['networks'],
        pagination=networksData,
        allNodes=allNodes,
        search=q or '',
        nodeType=nodeType or '',
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/networks/create", methods=["POST"])
@loginrequired
@adminrequired
def adminnetworkscreate():
    nodeid = request.form.get("nodeid", type=int)
    name = request.form.get("name")
    ipv4 = int(request.form.get("ipv4", 0))
    ipv6 = int(request.form.get("ipv6", 1))
    ipv4_subnet = request.form.get("ipv4_subnet") or None
    ipv4_gateway = request.form.get("ipv4_gateway") or None
    ipv6_subnet = request.form.get("ipv6_subnet") or None
    ipv6_gateway = request.form.get("ipv6_gateway") or None
    dns = request.form.get("dns", "1.1.1.1,8.8.8.8,2606:4700:4700::1111,2001:4860:4860::8888")
    network_type = request.form.get("node_type", "docker")

    if not nodeid or not name:
        flash("Node and network name required.", "error")
        return redirect(url_for('adminnetworks'))

    node = db.getnodebyid(nodeid)
    if not node:
        flash("Node not found.", "error")
        return redirect(url_for('adminnetworks'))

    if db.getnetworkbynamenodeid(name, nodeid, network_type=network_type):
        flash("Network already registered for this node.", "error")
        return redirect(url_for('adminnetworks'))

    # Create on node (only for docker nodes)
    if network_type == 'docker':
        payload = {
            "name": name,
            "ipv4": bool(ipv4),
            "ipv6": bool(ipv6),
            "nat": False,
            "dns": [s.strip() for s in dns.split(',') if s.strip()] if dns else [],
        }
        if ipv6_subnet:
            payload["subnet"] = ipv6_subnet
        if ipv6_gateway:
            payload["gateway"] = ipv6_gateway

        result = services.nodeapi(node, "/networks", method="POST", data=payload, timeout=30)
        if not result:
            flash("Node unreachable. Could not create network.", "error")
            return redirect(url_for('adminnetworks'))
        if result.get("error"):
            flash(f"Node error: {result['error']}", "error")
            return redirect(url_for('adminnetworks'))

    netUuid = str(uuid.uuid4())
    db.addnetwork(uuid=netUuid, nodeid=nodeid, name=name, network_type=network_type,
                  subnet=ipv6_subnet, gateway=ipv6_gateway, ipv4=ipv4, ipv6=ipv6,
                  ipv4_subnet=ipv4_subnet, ipv4_gateway=ipv4_gateway, dns=dns)
    auditlog("network.create", "network", netUuid, f"Created {network_type} network '{name}'")
    flash(f"Network '{name}' created and registered.", "success")
    return redirect(url_for('adminnetworks'))

@app.route("/dashboard/admin/networks/delete/<string:netUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminnetworksdelete(netUuid):
    network_type = request.form.get("network_type", "docker")
    network = db.getnetwork(netUuid, network_type=network_type)
    if not network:
        flash("Network not found.", "error")
        return redirect(url_for('adminnetworks'))

    # Check if any VPS is using this network
    vpsCount = db.countvpsbynetwork(network['id'], network_type=network_type)
    if vpsCount > 0:
        flash(f"Cannot delete: {vpsCount} VPS instance(s) are assigned to this network.", "error")
        return redirect(url_for('adminnetworks'))

    # Check if any containers are connected on the node (docker only)
    if network_type == 'docker':
        node = db.getnodebyid(network['nodeid'])
        if node:
            info = services.nodeapi(node, f"/networks/{network['name']}", method="GET")
            if info and not info.get("error"):
                containers = info.get("containers", {})
                if containers:
                    flash(f"Cannot delete: {len(containers)} container(s) still connected on the node.", "error")
                    return redirect(url_for('adminnetworks'))
            # Delete from node
            services.nodeapi(node, f"/networks/{network['name']}", method="DELETE")

    db.removenetwork(netUuid, network_type=network_type)
    auditlog("network.delete", "network", netUuid, f"Deleted network '{network['name']}'")
    flash("Network removed.", "warning")
    return redirect(url_for('adminnetworks'))

# --- Network IP Management ---

@app.route("/dashboard/admin/ips")
@loginrequired
@adminrequired
def adminips():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    allDockerNetworks = db.listnetworks(network_type='docker')
    allProxmoxNetworks = db.listnetworks(network_type='proxmox')
    allNetworks = allDockerNetworks + allProxmoxNetworks

    with db.getconnection() as conn:
        offset = (page - 1) * 50
        where = ""
        params = []
        if q:
            where = "WHERE ni.ip LIKE ? OR nd.name LIKE ? OR COALESCE(dn.name, pn.name) LIKE ?"
            params = [f"%{q}%", f"%{q}%", f"%{q}%"]
        total = conn.execute(f"""
            SELECT COUNT(*) FROM networkips ni
            LEFT JOIN docker_networks dn ON ni.networkid = dn.id AND ni.network_type = 'docker'
            LEFT JOIN proxmox_networks pn ON ni.networkid = pn.id AND ni.network_type = 'proxmox'
            JOIN nodes nd ON nd.id = COALESCE(dn.nodeid, pn.nodeid)
            {where}
        """, params).fetchone()[0]
        assigned = conn.execute(f"""
            SELECT COUNT(*) FROM networkips ni
            LEFT JOIN docker_networks dn ON ni.networkid = dn.id AND ni.network_type = 'docker'
            LEFT JOIN proxmox_networks pn ON ni.networkid = pn.id AND ni.network_type = 'proxmox'
            JOIN nodes nd ON nd.id = COALESCE(dn.nodeid, pn.nodeid)
            {where + (' AND' if where else 'WHERE')} ni.assigned = 1
        """, params).fetchone()[0]
        rows = conn.execute(f"""
            SELECT ni.*, COALESCE(dn.name, pn.name) as network_name, nd.name as node_name, v.hostname as vps_hostname
            FROM networkips ni
            LEFT JOIN docker_networks dn ON ni.networkid = dn.id AND ni.network_type = 'docker'
            LEFT JOIN proxmox_networks pn ON ni.networkid = pn.id AND ni.network_type = 'proxmox'
            JOIN nodes nd ON nd.id = COALESCE(dn.nodeid, pn.nodeid)
            LEFT JOIN vps v ON ni.vpsid = v.id
            {where}
            ORDER BY nd.name, network_name, ni.ip ASC
            LIMIT ? OFFSET ?
        """, params + [50, offset]).fetchall()
        ipsList = [dict(r) for r in rows]

    ipsData = {
        "ips": ipsList,
        "totalCount": total,
        "currentPage": page,
        "perPage": 50,
        "totalPages": math.ceil(total / 50) if total else 1,
        "hasPrev": page > 1,
        "hasNext": (page * 50) < total,
    }

    ipStats = {"total": total, "assigned": assigned, "available": total - assigned}

    return render_template(
        "adminips.html",
        ipsList=ipsList,
        pagination=ipsData,
        ipStats=ipStats,
        allNetworks=allNetworks,
        search=q or '',
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/ips/add", methods=["POST"])
@loginrequired
@adminrequired
def adminipadd():
    networkid = request.form.get("networkid", type=int)
    network_type = request.form.get("network_type", "docker")
    ip = request.form.get("ip", "").strip()

    if not networkid or not ip:
        flash("Network and IP address required.", "error")
        return redirect(url_for('adminips'))

    network = db.getnetworkbyid(networkid, network_type=network_type)
    if not network:
        flash("Network not found.", "error")
        return redirect(url_for('adminips'))

    ipuuid = str(uuid.uuid4())
    try:
        db.addnetworkip(ipuuid, networkid, ip, network_type=network_type)
        flash(f"IP {ip} added to {network['name']}.", "success")
    except Exception:
        flash("IP already exists or invalid.", "error")
    return redirect(url_for('adminips'))

@app.route("/dashboard/admin/ips/generate", methods=["POST"])
@loginrequired
@adminrequired
def adminipsgenerate():
    networkid = request.form.get("networkid", type=int)
    network_type = request.form.get("network_type", "docker")
    baseip = request.form.get("baseip")
    count = request.form.get("count", type=int)

    if not networkid or not baseip or not count or count < 1:
        flash("Network, base IP, and count required.", "error")
        return redirect(url_for('adminips'))

    network = db.getnetworkbyid(networkid, network_type=network_type)
    if not network:
        flash("Network not found.", "error")
        return redirect(url_for('adminips'))

    isipv6 = ":" in baseip
    generated = db.generateipsfornetwork(networkid, baseip, count, network_type=network_type, isipv6=isipv6)
    auditlog("ip.generate", "network", None, f"Generated {len(generated)} IP(s) on network {networkid}")
    flash(f"Generated {len(generated)} IP(s) on {network['name']}.", "success")
    return redirect(url_for('adminips'))

@app.route("/dashboard/admin/ips/delete/<string:ipUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminipdelete(ipUuid):
    ip = db.getnetworkip(ipUuid)
    if ip and ip['assigned']:
        flash("Cannot delete an assigned IP. Unassign it first.", "error")
    else:
        db.removenetworkip(ipUuid)
        auditlog("ip.delete", "ip", ipUuid, f"Deleted IP {ip['ip'] if ip else ipUuid}")
        flash("IP removed.", "warning")
    return redirect(url_for('adminips'))

@app.route("/dashboard/admin/networks/<string:netUuid>/ips")
@loginrequired
@adminrequired
def adminnetworkips(netUuid):
    network_type = request.args.get('type', 'docker')
    network = db.getnetwork(netUuid, network_type=network_type)
    if not network:
        flash("Network not found.", "error")
        return redirect(url_for('adminnetworks'))

    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    ipsData = db.listnetworkips(network['id'], network_type=network_type, page=page, perpage=50, search=q)
    ipStats = db.countips(network['id'], network_type=network_type)

    return render_template(
        "adminnetworkips.html",
        network=network,
        network_type=network_type,
        ipsList=ipsData['ips'],
        pagination=ipsData,
        ipStats=ipStats,
        search=q or '',
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/networks/<string:netUuid>/ips/generate", methods=["POST"])
@loginrequired
@adminrequired
def adminnetworkipsgenerate(netUuid):
    network_type = request.form.get("network_type", "docker")
    network = db.getnetwork(netUuid, network_type=network_type)
    if not network:
        flash("Network not found.", "error")
        return redirect(url_for('adminnetworks'))

    baseip = request.form.get("baseip")
    count = request.form.get("count", type=int)

    if not baseip or not count or count < 1:
        flash("Base IP and count required.", "error")
        return redirect(url_for('adminnetworkips', netUuid=netUuid, type=network_type))

    isipv6 = ":" in baseip
    generated = db.generateipsfornetwork(network['id'], baseip, count, network_type=network_type, isipv6=isipv6)
    auditlog("ip.generate", "network", netUuid, f"Generated {len(generated)} IP(s) on network '{network['name']}'")
    flash(f"Generated {len(generated)} IP(s).", "success")
    return redirect(url_for('adminnetworkips', netUuid=netUuid, type=network_type))

@app.route("/dashboard/admin/networks/<string:netUuid>/ips/delete/<string:ipUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminnetworkipdelete(netUuid, ipUuid):
    network_type = request.form.get("network_type", "docker")
    ip = db.getnetworkip(ipUuid)
    if ip and ip['assigned']:
        flash("Cannot delete an assigned IP. Unassign it first.", "error")
    else:
        db.removenetworkip(ipUuid)
        flash("IP removed.", "warning")
    return redirect(url_for('adminnetworkips', netUuid=netUuid, type=network_type))

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
            userIp = request.headers.get("X-Forwarded-For", request.remote_addr)
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
        # Printing the error to console helps you debug specific SQL issues
        print(f"Login Error: {e}")
        flash("Database error during login.", "error")
        return redirect(url_for("login"))

    userIp = request.headers.get("X-Forwarded-For", request.remote_addr)
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
    return render_template("404.html"), 404

if __name__ == "__main__":
    app.run(
        host=config["server"]["host"], 
        port=config["server"]["port"], 
        debug=config["server"]["debug"]
    )