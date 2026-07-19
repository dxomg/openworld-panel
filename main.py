from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, make_response, g
import os
import secrets
import requests
import toml
import uuid
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
}


def loadorcreateconfig():
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            toml.dump(DEFAULT_CONFIG, f)
        print(f"[init] generated client config at {CONFIG_PATH}")
        return DEFAULT_CONFIG
    with open(CONFIG_PATH, "r") as f:
        return toml.load(f)


config = loadorcreateconfig()

PAYPAL_URL = "https://www.sandbox.paypal.com/cgi-bin/webscr" if config['paypal']['sandbox'] else "https://www.paypal.com/cgi-bin/webscr"
VERIFY_URL = "https://ipnpb.sandbox.paypal.com/cgi-bin/webscr" if config['paypal']['sandbox'] else "https://ipnpb.paypal.com/cgi-bin/webscr"




def daystoseconds(days: int) -> int:
    return int(days) * 86400


app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

COOKIE_NAME = "sessioncookie"
SESSION_TTL_DAYS = config["general"]["defaultcookiettl"] * 24

# CSRF protection
def generatecsrftoken():
    if 'csrf_token' not in g:
        g.csrf_token = secrets.token_hex(32)
    return g.csrf_token

@app.before_request
def csrfprotect():
    if request.method == "POST":
        # Skip CSRF for PayPal IPN (external webhook)
        if request.path == "/paypal/ipn":
            return
        token = request.form.get('_csrf_token')
        sessionToken = request.cookies.get('csrf_token')
        if not token or not sessionToken or token != sessionToken:
            return "CSRF validation failed", 403

@app.after_request
def setcsrfcookie(response):
    if request.endpoint and request.endpoint != 'static':
        token = generatecsrftoken()
        response.set_cookie('csrf_token', token, httponly=False, samesite='Lax')
    return response

app.jinja_env.globals['csrf_token'] = generatecsrftoken


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

def guestuserinfo():
    return {
        "favicon": config["general"]["favicon"],
        "logo": config["general"]["logo"],
        "projectname": config["general"]["projectname"],
        "globaltotalvps": db.countvps(),
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
        nodeId, storageId = db.getsuitablenodeandstorage(plan['price'])
        
        if not nodeId or not storageId:
            flash("No nodes or Storage available for this tier.", "error")
            return redirect(url_for('createvps'))

        # Auto-assign network from the node
        nodeNetworks = db.listnetworks(nodeid=nodeId)
        if not nodeNetworks:
            flash("No network configured for this node. Contact an admin.", "error")
            return redirect(url_for('createvps'))
        networkId = nodeNetworks[0]['id']

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
                hostname=hostname,
                password=services.generaterandompassword(),
                cpu=plan['cpu'], ram=plan['ram'],
                swap=plan['swap'], disk=plan['disk'],
                status=initialStatus
            )
            
            db.decrementplanstock(plan['id'])
            
            if isPaid:
                return redirect(url_for('checkout', vpsUuid=vpsUuid))
            
            # Free VPS: provision on node immediately
            try:
                services.provisiononnode(vpsUuid)
                flash("Free VPS is being created!", "success")
            except ValueError as e:
                flash(f"VPS created but node provisioning failed: {e}", "error")
            
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash("An error occurred while creating the VPS.", "error")
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
    methods = db.listallPaymentMethods() 
    
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
        paypalRedirect = PAYPAL_URL + "?" + urlencode(params)
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

    try:
        services.provisiononnode(vpsUuid)
        flash("Payment confirmed. VPS is being created!", "success")
    except ValueError as e:
        flash(f"Payment confirmed but provisioning failed: {e}", "error")

    return redirect(url_for('dashboard'))

@app.route("/paypal/ipn", methods=["POST"])
def paypalipn():
    # 1. Verify with PayPal
    verifyData = request.form.to_dict(flat=True)
    verifyData["cmd"] = "_notify-validate"
    r = requests.post(VERIFY_URL, data=verifyData, headers={"Connection": "close"})

    if r.text != "VERIFIED":
        return "INVALID", 400

    # 2. Extract Data
    vpsUuid = request.form.get("custom")
    paymentStatus = request.form.get("paymentStatus")
    amount = request.form.get("mc_gross")
    receiver = request.form.get("receiver_email")

    # 3. Validation Logic
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

    # 4. Success Action: Update Database
    if vps['status'] == 'pendingpayment':
        db.updatevps(vpsUuid, status='creating')
        txnId = request.form.get("txn_id") or request.form.get("transaction_id")
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

        try:
            services.provisiononnode(vpsUuid)
        except ValueError:
            pass

    return "OK", 200

@app.route("/vps/<vpsUuid>")
@loginrequired
def vpspanel(vpsUuid):
    vps = db.getvps(vpsUuid)
    if not vps or vps["userid"] != g.userinfo["id"]:
        return "VPS not found", 404

    instance = services.getvpsdetails(vps["id"])
    metric = services.getlatestvpsmetric(vps["id"])
    firewallRules = services.listfirewallrulesforvps(vps["id"])

    return render_template(
        "vpspanel.html",
        **paneluserinfo(g.userinfo),
        instance=instance,
        metric=metric,
        firewallRules=firewallRules,
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
        return jsonify({"error": "Invalid action"}), 400

    vps = db.getvps(vpsUuid)
    if not vps or vps["userid"] != g.userinfo["id"]:
        return jsonify({"error": "VPS not found"}), 404
    
    if vps["status"] == "suspended":
        return jsonify({"error": "This VPS is suspended and cannot be modified."}), 403

    try:
        updated = services.performvpsaction(vps["id"], action, actorUserId=g.userinfo["id"])
        return jsonify({"status": updated["status"]})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/vps/<vpsUuid>/status")
@loginrequired
def vpsstatuspoll(vpsUuid):
    vps = db.getvps(vpsUuid)
    if not vps or vps["userid"] != g.userinfo["id"]:
        return jsonify({"error": "VPS not found"}), 404

    metric = services.getlatestvpsmetric(vps["id"])
    return jsonify({"status": vps["status"], "metrics": metric})


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
    images = db.listimages(active=1)
    nodesStorage = db.listnodestorage()
    networks = db.listnetworks()
    
    return render_template(
        "adminvps.html", 
        allVps=vpsData['vps'],
        pagination=vpsData,
        users=users,
        plans=plans,
        images=images,
        nodesStorage=nodesStorage,
        networks=networks,
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
    firewallRules = services.listfirewallrulesforvps(vps["id"])
    owner = db.getuserbyid(vps["userid"])

    return render_template(
        "adminvpspanel.html",
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo),
        instance=instance,
        metric=metric,
        firewallRules=firewallRules,
        owner=owner,
    )

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

        if not db.getuserbyid(userid):
            flash("Invalid user selected.", "danger")
            return redirect(url_for('adminvps'))

        if not db.getimagebyid(imageid):
            flash("Invalid image selected.", "danger")
            return redirect(url_for('adminvps'))

        if not networkid:
            flash("You must select a network.", "danger")
            return redirect(url_for('adminvps'))

        network = db.getnetworkbyid(networkid)
        if not network:
            flash("Selected network not found.", "danger")
            return redirect(url_for('adminvps'))

        if network['nodeid'] != nodeid:
            flash("Selected network is not on the assigned node.", "danger")
            return redirect(url_for('adminvps'))

        try:
            db.addvps(
                uuid=vpsUuid,
                userid=userid,
                planid=planid,
                imageid=imageid,
                nodeid=nodeid,
                storageid=storageid,
                networkid=networkid,
                hostname=hostname,
                password=password,
                cpu=plan['cpu'],
                ram=plan['ram'],
                swap=plan['swap'],
                disk=plan['disk'],
                status='creating'
            )
            db.decrementplanstock(plan['id'])
            flash(f"Instance {hostname} created successfully with {plan['name']} resources.", "success")
            return redirect(url_for('adminvps'))
            
        except Exception as e:
            flash("Deployment error.", "danger")
            return redirect(url_for('adminvps'))

    # GET: Fetching data for the dropdowns
    context = {
        "users": db.listallUsers(),
        "plans": db.listplans(active=1),
        "images": db.listimages(active=1),
        "nodesStorage": db.listnodestorage()
    }

    return render_template(
        "admin_vps_create.html",
        **context,
        **paneluserinfo(g.userinfo), 
        **paneladmininfo(g.userinfo)
    )


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
    
    return redirect(url_for('adminplans'))

@app.route("/dashboard/admin/plans/delete/<string:planUuid>", methods=["POST"])
@loginrequired
@adminrequired
def admindeleteplans(planUuid):
    db.removeplan(uuid=planUuid)
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
            tier=request.form.get("tier", "free")
        )
        flash(f"Node '{request.form.get('name')}' registered successfully.", "success")
    except Exception as e:
        flash("Error creating node.", "danger")
    
    return redirect(url_for('adminnodes'))

@app.route("/dashboard/admin/nodes/update/<string:nodeUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminnodesupdate(nodeUuid):
    try:
        updateData = {
            "name": request.form.get("name"),
            "hostname": request.form.get("hostname"),
            "address": request.form.get("address"),
            "url": request.form.get("url", ""),
            "ram": int(request.form.get("ram", 0)),
            "status": request.form.get("status"),
            "tier": request.form.get("tier")
        }
        
        newKey = request.form.get("apikey")
        if newKey and newKey.strip() != "":
            updateData["apikey"] = newKey

        db.updatenode(nodeUuid, **updateData)
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
    imagesData = db.listimagespaginated(page=page, perpage=12, search=q)
    
    return render_template(
        "adminosimage.html",
        allImages=imagesData['images'],
        pagination=imagesData,
        activeImagesCount=sum(1 for i in imagesData['images'] if i['active']),
        search=q or '',
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
            image=request.form.get("image"), # The actual tag like 'ubuntu-22.04'
            description=request.form.get("description"),
            active=int(request.form.get("active", 1))
        )
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
            "active": int(request.form.get("active"))
        }
        db.updateimage(imageUuid, **updateData)
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
        flash("OS Image removed.", "warning")
    except Exception as e:
        flash("Error deleting image.", "danger")
    return redirect(url_for('adminosimage'))



@app.route("/dashboard/admin/nodesstorage")
@loginrequired
@adminrequired
def adminnodesstorage():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    storageData = db.listnodesstoragepaginated(page=page, perpage=12, search=q)
    nodesList = db.listallnodes()

    return render_template(
        "adminnodesstorage.html", 
        allStorage=storageData['storage'],
        pagination=storageData,
        allNodes=nodesList,
        search=q or '',
        **paneluserinfo(g.userinfo), 
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/nodesstorage/create", methods=["POST"])
@loginrequired
@adminrequired
def adminnodesstoragecreate():
    try:
        db.addnodesstorage( # Updated function name
            uuid=str(uuid.uuid4()),
            nodeid=request.form.get("nodeid"),
            name=request.form.get("name"),
            path=request.form.get("path"),
            type=request.form.get("type"),
            size=int(request.form.get("size", 0))
        )
        flash("Storage unit registered.", "success")
    except Exception:
        flash("Error creating storage.", "danger")
    return redirect(url_for('adminnodesstorage'))

@app.route("/dashboard/admin/nodesstorage/update/<string:sUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminnodesstorageupdate(sUuid):
    try:
        updateData = {
            "name": request.form.get("name"),
            "path": request.form.get("path"),
            "type": request.form.get("type"),
            "size": int(request.form.get("size", 0))
        }
        db.updatenodesstorage(sUuid, **updateData)
        flash("Storage configuration updated.", "success")
    except Exception:
        flash("Error updating storage.", "danger")
    return redirect(url_for('adminnodesstorage'))

@app.route("/dashboard/admin/nodesstorage/delete/<string:sUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminnodesstoragedelete(sUuid):
    try:
        db.removenodesstorage(sUuid)
        flash("Storage unit removed.", "warning")
    except Exception:
        flash("Error deleting storage.", "danger")
    return redirect(url_for('adminnodesstorage'))

# --- Network Management ---

@app.route("/dashboard/admin/networks")
@loginrequired
@adminrequired
def adminnetworks():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    networksData = db.listnetworkspaginated(page=page, perpage=12, search=q)
    allNodes = db.listallnodes()
    return render_template(
        "adminnetworks.html",
        allNetworks=networksData['networks'],
        pagination=networksData,
        allNodes=allNodes,
        search=q or '',
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/networks/create", methods=["POST"])
@loginrequired
@adminrequired
def adminnetworkscreate():
    nodeid = request.form.get("nodeid", type=int)
    name = request.form.get("name")
    subnet = request.form.get("subnet")
    gateway = request.form.get("gateway")
    ipv6 = int(request.form.get("ipv6", 1))

    if not nodeid or not name:
        flash("Node and network name required.", "error")
        return redirect(url_for('adminnetworks'))

    node = db.getnodebyid(nodeid)
    if not node:
        flash("Node not found.", "error")
        return redirect(url_for('adminnetworks'))

    if db.getnetworkbynamenodeid(name, nodeid):
        flash("Network already registered for this node.", "error")
        return redirect(url_for('adminnetworks'))

    # Try to create the network on the node
    payload = {
        "name": name,
        "ipv6": bool(ipv6),
        "enableMasquerade": False,
    }
    if subnet:
        payload["subnet"] = subnet
    if gateway:
        payload["gateway"] = gateway

    result = services.nodeapi(node, "/networks", method="POST", data=payload, timeout=30)
    if not result:
        flash("Node unreachable. Could not create network.", "error")
        return redirect(url_for('adminnetworks'))
    if result.get("error"):
        flash(f"Node error: {result['error']}", "error")
        return redirect(url_for('adminnetworks'))

    # Get the actual subnet/gateway from the node if not provided
    if not subnet or not gateway:
        info = services.nodeapi(node, f"/networks/{name}", method="GET")
        if info and not info.get("error"):
            ipam = info.get("ipam", {})
            configs = ipam.get("Config", [])
            if configs:
                subnet = subnet or configs[0].get("Subnet", "")
                gateway = gateway or configs[0].get("Gateway", "")

    netUuid = str(uuid.uuid4())
    db.addnetwork(uuid=netUuid, nodeid=nodeid, name=name, subnet=subnet, gateway=gateway, ipv6=ipv6)
    flash(f"Network '{name}' created and registered.", "success")
    return redirect(url_for('adminnetworks'))

@app.route("/dashboard/admin/networks/delete/<string:netUuid>", methods=["POST"])
@loginrequired
@adminrequired
def adminnetworksdelete(netUuid):
    network = db.getnetwork(netUuid)
    if not network:
        flash("Network not found.", "error")
        return redirect(url_for('adminnetworks'))

    # Check if any VPS is using this network
    vpsCount = db.countvpsbynetwork(network['id'])
    if vpsCount > 0:
        flash(f"Cannot delete: {vpsCount} VPS instance(s) are assigned to this network.", "error")
        return redirect(url_for('adminnetworks'))

    # Check if any containers are connected on the node
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

    db.removenetwork(netUuid)
    flash("Network removed.", "warning")
    return redirect(url_for('adminnetworks'))

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
        flash("Receipt updated.", "success")
    return redirect(url_for("adminreceipts"))

@app.route("/dashboard/admin/receipts/<receiptUuid>/delete", methods=["POST"])
@loginrequired
@adminrequired
def adminreceiptsdelete(receiptUuid):
    db.deletereceipt(receiptUuid)
    flash("Receipt deleted.", "success")
    return redirect(url_for("adminreceipts"))

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


@app.route("/logout")
def logout():
    token = request.cookies.get(COOKIE_NAME)
    if token:
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