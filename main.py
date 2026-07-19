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


def load_or_create_config():
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            toml.dump(DEFAULT_CONFIG, f)
        print(f"[init] generated client config at {CONFIG_PATH}")
        return DEFAULT_CONFIG
    with open(CONFIG_PATH, "r") as f:
        return toml.load(f)


config = load_or_create_config()

# Auto-migrate: add missing columns to existing DBs
import sqlite3 as _sqlite3
try:
    _conn = _sqlite3.connect("database.db")
    _conn.execute("ALTER TABLE plans ADD COLUMN stock INTEGER NOT NULL DEFAULT -1")
    _conn.commit()
    _conn.close()
except _sqlite3.OperationalError:
    pass  # column already exists

PAYPAL_URL = "https://www.sandbox.paypal.com/cgi-bin/webscr" if config['paypal']['sandbox'] else "https://www.paypal.com/cgi-bin/webscr"
VERIFY_URL = "https://ipnpb.sandbox.paypal.com/cgi-bin/webscr" if config['paypal']['sandbox'] else "https://ipnpb.paypal.com/cgi-bin/webscr"




def daystoseconds(days: int) -> int:
    return int(days) * 86400


app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

COOKIE_NAME = "sessioncookie"
SESSION_TTL_DAYS = config["general"]["defaultcookiettl"] * 24


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get(COOKIE_NAME)
        user = services.validate_session(token) if token else None

        if not user:
            return redirect(url_for("login"))

        ban = services.is_user_banned(user["id"])
        if ban:
            return render_template("banned.html", **paneluserinfo(user, ban=ban))

        g.userinfo = user
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
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
        ban = services.is_user_banned(user["id"])

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
        ban = services.is_user_banned(user["id"])

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
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    vps_data = services.list_vps_for_user_panel(g.userinfo["id"], page=page, per_page=10, search=q)
    return render_template("dashboard.html", vps_data=vps_data, search=q or '', **paneluserinfo(g.userinfo))

@app.route("/createvps", methods=["GET", "POST"])
@login_required
def createvps():
    if request.method == "POST":
        plan_id = request.form.get("plan_id", type=int)
        image_id = request.form.get("image_id", type=int)

        plan = db.getplanbyid(plan_id)
        if not plan:
            flash("Invalid plan selected.", "error")
            return redirect(url_for('createvps'))

        if plan['stock'] == 0:
            flash("This plan is out of stock.", "error")
            return redirect(url_for('createvps'))

        is_paid = float(plan['price']) > 0
        node_id, storage_id = db.get_suitable_node_and_storage(plan['price'])
        
        if not node_id or not storage_id:
            flash("No nodes or Storage available for this tier.", "error")
            return redirect(url_for('createvps'))

        vps_uuid = str(uuid.uuid4())
        # STANDARDIZED: Use 'pendingpayment' (no underscore)
        initial_status = 'pendingpayment' if is_paid else 'creating'

        try:
            db.addvps(
                uuid=vps_uuid,
                userid=int(g.userinfo["id"]),
                planid=plan['id'],
                imageid=image_id,
                nodeid=node_id,
                storageid=storage_id,
                hostname=services.generate_random_hostname(),
                password=services.generate_random_password(),
                cpu=plan['cpu'], ram=plan['ram'],
                swap=plan['swap'], disk=plan['disk'],
                status=initial_status
            )
            
            db.decrementplanstock(plan['id'])
            
            if is_paid:
                return redirect(url_for('checkout', vps_uuid=vps_uuid))
            
            flash("Free VPS is being created!", "success")
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f"Error: {e}", "error")
            return redirect(url_for('createvps'))

    return render_template("createvps.html", plans_list=db.listplans(active=1), images=db.listimages(active=1), **paneluserinfo(g.userinfo))

@app.route("/checkout/<string:vps_uuid>")
@login_required
def checkout(vps_uuid):
    vps_record = db.getvps(vps_uuid) # Rename to be distinct
    
    if not vps_record or vps_record['userid'] != g.userinfo['id']:
        flash("Invoice not found.", "error")
        return redirect(url_for('dashboard'))
    
    if vps_record['status'] != 'pendingpayment':
        flash("This instance is already being processed.", "info")
        return redirect(url_for('dashboard'))

    plan = db.getplanbyid(vps_record['planid'])
    methods = db.listallpaymentmethods() 
    
    # Pass it as checkout_vps to avoid collision with paneluserinfo['vps']
    return render_template(
        "checkout.html", 
        checkout_vps=vps_record, 
        plan=plan, 
        methods=methods, 
        **paneluserinfo(g.userinfo)
    )

@app.route("/checkout/processpayment", methods=["POST"])
@login_required
def processpayment():
    vps_uuid = request.form.get("vps_uuid")
    method_slug = request.form.get("method_slug")

    vps = db.getvps(vps_uuid)
    if not vps:
        flash("Invalid Session: VPS not found.", "error")
        return redirect(url_for('dashboard'))

    if str(vps['userid']) != str(g.userinfo['id']):
        flash("Invalid Session: Ownership mismatch.", "error")
        return redirect(url_for('dashboard'))

    current_status = str(vps['status']).strip()
    if current_status != 'pendingpayment':
        flash(f"Invalid Session: Status is {current_status}.", "error")
        return redirect(url_for('dashboard'))

    plan = db.getplanbyid(vps['planid'])

    if method_slug == 'paypal':
        params = {
            "cmd": "_xclick",
            "business": config['paypal']['email'],
            "item_name": f"VPS: {plan['name']} ({vps['hostname']})",
            "amount": f"{plan['price']:.2f}",
            "currency_code": "USD",
            "notify_url": f"{config['paypal']['base_url']}/paypal/ipn",
            "return": f"{config['paypal']['base_url']}/vps/{vps_uuid}",
            "cancel_return": f"{config['paypal']['base_url']}/checkout/{vps_uuid}",
            "custom": vps_uuid
        }
        paypal_redirect = PAYPAL_URL + "?" + urlencode(params)
        return redirect(paypal_redirect)

    # Manual / Balance activation
    db.updatevps(vps_uuid, status='creating')
    manual_method = db.getpaymentmethodbyslug(method_slug)
    txn_uuid = str(uuid.uuid4())
    db.addtransaction(
        uuid=txn_uuid,
        userid=vps['userid'],
        transactionid=f"manual-{uuid.uuid4().hex[:8]}",
        amount=float(plan['price']),
        currency="USD",
        status="completed",
        paymentprocessorid=manual_method['id'] if manual_method else 1,
        vpsid=vps['id'],
        planid=vps['planid']
    )
    flash("Payment confirmed. Provisioning started.", "success")
    return redirect(url_for('dashboard'))

@app.route("/paypal/ipn", methods=["POST"])
def paypalipn():
    # 1. Verify with PayPal
    verify_data = request.form.to_dict(flat=True)
    verify_data["cmd"] = "_notify-validate"
    r = requests.post(VERIFY_URL, data=verify_data, headers={"Connection": "close"})

    if r.text != "VERIFIED":
        return "INVALID", 400

    # 2. Extract Data
    vps_uuid = request.form.get("custom")
    payment_status = request.form.get("payment_status")
    amount = request.form.get("mc_gross")
    receiver = request.form.get("receiver_email")

    # 3. Validation Logic
    vps = db.getvps(vps_uuid)
    if not vps:
        return "VPS not found", 400
    
    plan = db.getplanbyid(vps['planid'])

    # Security Checks
    if payment_status != "Completed":
        return "Not completed", 200
    if receiver.lower() != config['paypal']['email'].lower():
        return "Wrong receiver", 400
    if float(amount) < float(plan['price']):
        return "Insufficient amount", 400

    # 4. Success Action: Update Database
    if vps['status'] == 'pendingpayment':
        db.updatevps(vps_uuid, status='creating')
        txn_id = request.form.get("txn_id") or request.form.get("transaction_id")
        paypal_method = db.getpaymentmethodbyslug("paypal")
        txn_uuid = str(uuid.uuid4())
        db.addtransaction(
            uuid=txn_uuid,
            userid=vps['userid'],
            transactionid=txn_id,
            amount=float(amount),
            currency=request.form.get("mc_currency", "USD"),
            status="completed",
            paymentprocessorid=paypal_method['id'] if paypal_method else 1,
            vpsid=vps['id'],
            planid=vps['planid']
        )

    return "OK", 200

@app.route("/vps/<vps_uuid>")
@login_required
def vpspanel(vps_uuid):
    vps = db.getvps(vps_uuid)
    if not vps or vps["userid"] != g.userinfo["id"]:
        return "VPS not found", 404

    instance = services.get_vps_details(vps["id"])
    metric = services.get_latest_vps_metric(vps["id"])
    firewall_rules = services.list_firewall_rules_for_vps(vps["id"])

    return render_template(
        "vpspanel.html",
        **paneluserinfo(g.userinfo),
        instance=instance,
        metric=metric,
        firewall_rules=firewall_rules,
    )


#############
#
# Action Routes (AJAX)
#
#############

@app.route("/vps/<vps_uuid>/action/<action>", methods=["POST"])
@login_required
def vps_action(vps_uuid, action):
    vps = db.getvps(vps_uuid)
    if not vps or vps["userid"] != g.userinfo["id"]:
        return jsonify({"error": "VPS not found"}), 404
    
    if vps["status"] == "suspended":
        return jsonify({"error": "This VPS is suspended and cannot be modified."}), 403

    try:
        updated = services.perform_vps_action(vps["id"], action, actor_user_id=g.userinfo["id"])
        return jsonify({"status": updated["status"]})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/vps/<vps_uuid>/status")
@login_required
def vps_status_poll(vps_uuid):
    vps = db.getvps(vps_uuid)
    if not vps or vps["userid"] != g.userinfo["id"]:
        return jsonify({"error": "VPS not found"}), 404

    metric = services.get_latest_vps_metric(vps["id"])
    return jsonify({"status": vps["status"], "metrics": metric})


#Admin

@app.route("/dashboard/admin")
@login_required
@admin_required
def admindashboard():
    return render_template("admindashboard.html", **paneluserinfo(g.userinfo), **paneladmininfo(g.userinfo))

@app.route("/dashboard/admin/users")
@login_required
@admin_required
def adminusers():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    perpage = 12 
    
    pagination_data = db.listuserspaginated(page=page, perpage=perpage, search=q)
    
    return render_template(
        "adminusers.html", 
        **paneluserinfo(g.userinfo), 
        **paneladmininfo(g.userinfo),
        allusers=pagination_data['users'],
        pagination=pagination_data,
        search=q or ''
    )
@app.route("/dashboard/admin/users/update/<string:user_uuid>", methods=["POST"])
@login_required
@admin_required
def adminupdateusers(user_uuid):
    # Retrieve form data
    username = request.form.get('username')
    email = request.form.get('email')
    role = request.form.get('role')
    
    # Update the user in the database
    db.updateuser(
        user_uuid,
        username=username,
        email=email,
        role=role
    )
    
    flash("User updated successfully!", "success")
    
    # Redirect back to the admin users page 
    # (replace 'adminusers' with your actual function name for the user list if different)
    return redirect(url_for('adminusers'))

@app.route("/dashboard/admin/users/ban/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def adminbanuser(user_id):
    reason = request.form.get("reason", "No reason provided")
    ban_uuid = str(uuid.uuid4())
    admin_id = g.userinfo["id"] 
    
    # Add ban record
    db.addban(ban_uuid, user_id, admin_id, reason, expires=None)
    
    # Update the user's STATUS column to "banned"
    db.updateuser(user_id, status="banned") 
    
    flash("User has been banned.", "success")
    return redirect(url_for('adminusers'))


@app.route("/dashboard/admin/users/unban/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def adminunbanuser(user_id):
    # Find their active ban and remove it
    active_ban = db.getbanbyuserid(user_id)
    if active_ban:
        db.removeban(active_ban["uuid"])
    
    # Restore the user's STATUS column to "active"
    db.updateuser(user_id, status="active")
    
    flash("User has been unbanned.", "success")
    return redirect(url_for('adminusers'))


@app.route("/dashboard/admin/vps")
@login_required
@admin_required
def adminvps():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    vps_data = db.listvpspaginated(page=page, perpage=12, search=q)
    
    users = db.listallusers()
    plans = db.listplans(active=1)
    images = db.listimages(active=1)
    nodes_storage = db.listnodestorage()
    
    return render_template(
        "adminvps.html", 
        all_vps=vps_data['vps'],
        pagination=vps_data,
        users=users,
        plans=plans,
        images=images,
        nodes_storage=nodes_storage,
        search=q or '',
        **paneluserinfo(g.userinfo), 
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/vps/<vps_uuid>")
@login_required
@admin_required
def adminvpspanel(vps_uuid):
    vps = db.getvps(vps_uuid)
    if not vps:
        flash("VPS not found.", "error")
        return redirect(url_for('adminvps'))

    instance = services.get_vps_details(vps["id"])
    metric = services.get_latest_vps_metric(vps["id"])
    firewall_rules = services.list_firewall_rules_for_vps(vps["id"])
    owner = db.getuserbyid(vps["userid"])

    return render_template(
        "adminvpspanel.html",
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo),
        instance=instance,
        metric=metric,
        firewall_rules=firewall_rules,
        owner=owner,
    )

@app.route("/dashboard/admin/vps/create", methods=["GET", "POST"])
@login_required
@admin_required
def admincreatevps():
    if request.method == "POST":
        # 1. Automatic UUID Generation
        vps_uuid = str(uuid.uuid4())
        
        # 2. Extract basic info from the form
        userid = request.form.get('userid', type=int)
        planid = request.form.get('planid', type=int)
        imageid = request.form.get('imageid', type=int)
        nodeid = request.form.get('nodeid', type=int)
        storageid = request.form.get('storageid', type=int)
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

        try:
            db.addvps(
                uuid=vps_uuid,
                userid=userid,
                planid=planid,
                imageid=imageid,
                nodeid=nodeid,
                storageid=storageid,
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
            flash(f"Deployment Error: {str(e)}", "danger")
            return redirect(url_for('adminvps'))

    # GET: Fetching data for the dropdowns
    context = {
        "users": db.listallusers(),
        "plans": db.listplans(active=1),
        "images": db.listimages(active=1),
        "nodes_storage": db.listnodestorage()
    }

    return render_template(
        "admin_vps_create.html",
        **context,
        **paneluserinfo(g.userinfo), 
        **paneladmininfo(g.userinfo)
    )


@app.route("/dashboard/admin/plans", methods=["GET", "POST"])
@login_required
@admin_required
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
            stock=int(request.form.get("stock", -1))
        )
        return redirect(url_for('adminplans'))

    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    plans_data = db.listplanspaginated(page=page, perpage=12, search=q)

    return render_template(
        "adminplans.html", 
        allplans=plans_data['plans'],
        pagination=plans_data,
        search=q or '',
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/plans/update/<string:plan_uuid>", methods=["POST"])
@login_required
@admin_required
def adminupdateplans(plan_uuid):
    # Retrieve form data
    # Note: Use request.form.get() for inputs, 
    # check for checkbox values if you add them later (they might return 'on')
    
    db.updateplan(
        uuid=plan_uuid,
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
        stock=int(request.form.get("stock", -1))
    )
    
    return redirect(url_for('adminplans'))

@app.route("/dashboard/admin/plans/delete/<string:plan_uuid>", methods=["POST"])
@login_required
@admin_required
def admindeleteplans(plan_uuid):
    db.removeplan(uuid=plan_uuid)
    return redirect(url_for('adminplans'))

@app.route("/dashboard/admin/nodes")
@login_required
@admin_required
def adminnodes():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    nodes_data = db.listnodespaginated(page=page, perpage=12, search=q)
    
    return render_template(
        "adminnodes.html", 
        all_nodes=nodes_data['nodes'],
        pagination=nodes_data,
        search=q or '',
        **paneluserinfo(g.userinfo), 
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/nodes/create", methods=["POST"])
@login_required
@admin_required
def adminnodescreate():
    try:
        node_uuid = str(uuid.uuid4())
        db.addnode(
            uuid=node_uuid,
            name=request.form.get("name"),
            hostname=request.form.get("hostname"),
            address=request.form.get("address"),
            apikey=request.form.get("apikey"),
            cpu=int(request.form.get("cpu", 0)),
            ram=int(request.form.get("ram", 0)),
            disk=int(request.form.get("disk", 0)),
            status=request.form.get("status", "online"),
            tier=request.form.get("tier", "free") # New field
        )
        flash(f"Node '{request.form.get('name')}' registered successfully.", "success")
    except Exception as e:
        flash(f"Error creating node: {e}", "danger")
    
    return redirect(url_for('adminnodes'))

@app.route("/dashboard/admin/nodes/update/<string:node_uuid>", methods=["POST"])
@login_required
@admin_required
def adminnodesupdate(node_uuid):
    try:
        update_data = {
            "name": request.form.get("name"),
            "hostname": request.form.get("hostname"),
            "address": request.form.get("address"),
            "ram": int(request.form.get("ram", 0)),
            "status": request.form.get("status"),
            "tier": request.form.get("tier") # New field
        }
        
        new_key = request.form.get("apikey")
        if new_key and new_key.strip() != "":
            update_data["apikey"] = new_key

        db.updatenode(node_uuid, **update_data)
        flash("Node configuration updated.", "success")
    except Exception as e:
        flash(f"Error updating node: {e}", "danger")

    return redirect(url_for('adminnodes'))

@app.route("/dashboard/admin/nodes/delete/<string:node_uuid>", methods=["POST"])
@login_required
@admin_required
def adminnodesdelete(node_uuid):
    try:
        db.removenode(node_uuid)
        flash("Node removed successfully.", "warning")
    except Exception as e:
        flash(f"Error deleting node: {e}", "danger")
        
    return redirect(url_for('adminnodes'))

@app.route("/dashboard/admin/osimage")
@login_required
@admin_required
def adminosimage():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    images_data = db.listimagespaginated(page=page, perpage=12, search=q)
    
    return render_template(
        "adminosimage.html",
        all_images=images_data['images'],
        pagination=images_data,
        active_images_count=sum(1 for i in images_data['images'] if i['active']),
        search=q or '',
        **paneluserinfo(g.userinfo), 
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/osimage/create", methods=["POST"])
@login_required
@admin_required
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
        flash(f"Error adding image: {e}", "danger")
    return redirect(url_for('adminosimage'))

@app.route("/dashboard/admin/osimage/update/<string:image_uuid>", methods=["POST"])
@login_required
@admin_required
def adminosimageupdate(image_uuid):
    try:
        update_data = {
            "name": request.form.get("name"),
            "image": request.form.get("image"),
            "description": request.form.get("description"),
            "active": int(request.form.get("active"))
        }
        db.updateimage(image_uuid, **update_data)
        flash("OS Image updated.", "success")
    except Exception as e:
        flash(f"Error updating image: {e}", "danger")
    return redirect(url_for('adminosimage'))

@app.route("/dashboard/admin/osimage/delete/<string:image_uuid>", methods=["POST"])
@login_required
@admin_required
def adminosimagedelete(image_uuid):
    try:
        db.removeimage(image_uuid)
        flash("OS Image removed.", "warning")
    except Exception as e:
        flash(f"Error deleting image: {e}", "danger")
    return redirect(url_for('adminosimage'))



@app.route("/dashboard/admin/nodesstorage")
@login_required
@admin_required
def adminnodesstorage():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    storage_data = db.listnodesstoragepaginated(page=page, perpage=12, search=q)
    nodes_list = db.listallnodes()

    return render_template(
        "adminnodesstorage.html", 
        all_storage=storage_data['storage'],
        pagination=storage_data,
        all_nodes=nodes_list,
        search=q or '',
        **paneluserinfo(g.userinfo), 
        **paneladmininfo(g.userinfo)
    )

@app.route("/dashboard/admin/nodesstorage/create", methods=["POST"])
@login_required
@admin_required
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
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for('adminnodesstorage'))

@app.route("/dashboard/admin/nodesstorage/update/<string:s_uuid>", methods=["POST"])
@login_required
@admin_required
def adminnodesstorageupdate(s_uuid):
    try:
        update_data = {
            "name": request.form.get("name"),
            "path": request.form.get("path"),
            "type": request.form.get("type"),
            "size": int(request.form.get("size", 0))
        }
        db.updatenodesstorage(s_uuid, **update_data) # Updated function name
        flash("Storage configuration updated.", "success")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for('adminnodesstorage'))

@app.route("/dashboard/admin/nodesstorage/delete/<string:s_uuid>", methods=["POST"])
@login_required
@admin_required
def adminnodesstoragedelete(s_uuid):
    try:
        db.removenodesstorage(s_uuid) # Updated function name
        flash("Storage unit removed.", "warning")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for('adminnodesstorage'))

@app.route("/dashboard/admin/paymentmethods")
@login_required
@admin_required
def adminpaymentmethods():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    methods_data = db.listpaymentmethodspaginated(page=page, perpage=12, search=q)
    stats = db.gettransactionstats()

    return render_template(
        "adminpaymentmethods.html",
        allpaymentmethods=methods_data['methods'],
        pagination=methods_data,
        activemethodscount=db.countactivepaymentmethods(),
        totaltransactions=stats["total_transactions"],
        totalrevenue=stats["total_revenue"],
        search=q or '',
        **paneluserinfo(g.userinfo),
        **paneladmininfo(g.userinfo)
    )


@app.route("/dashboard/admin/paymentmethods/create", methods=["POST"])
@login_required
@admin_required
def adminpaymentmethodscreate():
    try:
        paymentmethod_uuid = str(uuid.uuid4())
        db.addpaymentmethod(
            uuid=paymentmethod_uuid,
            name=request.form.get("name"),
            slug=request.form.get("slug"),
            active=int(request.form.get("active", 1))
        )
        flash(f"Payment method '{request.form.get('name')}' added successfully.", "success")
    except Exception as e:
        flash(f"Error adding payment method: {e}", "danger")
    return redirect(url_for('adminpaymentmethods'))


@app.route("/dashboard/admin/payment-methods/update/<string:paymentmethod_uuid>", methods=["POST"])
@login_required
@admin_required
def adminpaymentmethodsupdate(paymentmethod_uuid):
    try:
        update_data = {
            "name": request.form.get("name"),
            "slug": request.form.get("slug"),
            "active": int(request.form.get("active", 1))
        }
        db.updatepaymentmethods(paymentmethod_uuid, **update_data)
        flash("Payment method updated.", "success")
    except Exception as e:
        flash(f"Error updating payment method: {e}", "danger")
    return redirect(url_for('adminpaymentmethods'))


@app.route("/dashboard/admin/payment-methods/delete/<string:paymentmethod_uuid>", methods=["POST"])
@login_required
@admin_required
def adminpaymentmethodsdelete(paymentmethod_uuid):
    try:
        db.removepaymentmethods(paymentmethod_uuid)
        flash("Payment method removed.", "warning")
    except Exception as e:
        flash(f"Error deleting payment method: {e}", "danger")
    return redirect(url_for('adminpaymentmethods'))

@app.route("/dashboard/admin/receipts")
@login_required
@admin_required
def adminreceipts():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    receipts_data = db.listreceiptspaginated(page=page, perpage=12, search=q)
    
    allreceipts = []
    totalrevenue = totaltax = receiptsthismonth = 0
    currentmonth = datetime.utcnow().strftime("%Y-%m")

    for row in receipts_data['receipts']:
        receipt = dict(row)
        receipt["transactionid_display"] = row["txn_public_id"] or "N/A"
        allreceipts.append(receipt)
        totalrevenue += row["amount"] or 0
        totaltax += row["taxamount"] or 0
        if (row["created"] or "").startswith(currentmonth): receiptsthismonth += 1

    return render_template("adminreceipts.html", allreceipts=allreceipts, 
        pagination=receipts_data,
        alltransactions=db.geteligibletransactions(), totalrevenue=f"{totalrevenue:.2f}", 
        totaltax=f"{totaltax:.2f}", receiptsthismonth=receiptsthismonth,
        search=q or '',
        **paneluserinfo(g.userinfo), **paneladmininfo(g.userinfo))

@app.route("/dashboard/admin/receipts/create", methods=["POST"])
@login_required
@admin_required
def adminreceiptscreate():
    tid = request.form.get("transactionid", type=int)
    txn = db.gettransaction(tid)
    
    if not txn:
        flash("Transaction not found.", "error")
    elif db.getreceiptbytransaction(tid):
        flash("Receipt already exists.", "error")
    else:
        txn_full = db.gettransactionfull(tid)
        amount = request.form.get("amount", type=float)
        if not amount and txn_full:
            amount = txn_full['amount']
        
        data = {
            "transactionid": tid, "userid": txn["userid"],
            "amount": amount or 0,
            "currency": (request.form.get("currency") or (txn_full['currency'] if txn_full else "USD")).strip().upper(),
            "taxamount": request.form.get("taxamount", type=float) or 0,
            "receiptnumber": request.form.get("receiptnumber") or db.generate_receipt_number(),
            "billingname": request.form.get("billingname"),
            "billingemail": request.form.get("billingemail"),
            "billingaddress": request.form.get("billingaddress"),
            "notes": request.form.get("notes")
        }
        db.addreceipt(data)
        flash("Receipt created.", "success")
    return redirect(url_for("adminreceipts"))

@app.route("/dashboard/admin/receipts/<receipt_uuid>/update", methods=["POST"])
@login_required
@admin_required
def adminreceiptsupdate(receipt_uuid):
    if not db.getreceipt(receipt_uuid):
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
        db.updatereceipt(receipt_uuid, data)
        flash("Receipt updated.", "success")
    return redirect(url_for("adminreceipts"))

@app.route("/dashboard/admin/receipts/<receipt_uuid>/delete", methods=["POST"])
@login_required
@admin_required
def adminreceiptsdelete(receipt_uuid):
    db.deletereceipt(receipt_uuid)
    flash("Receipt deleted.", "success")
    return redirect(url_for("adminreceipts"))

@app.route("/dashboard/admin/transactions")
@login_required
@admin_required
def admintransactions():
    page = request.args.get('page', 1, type=int)
    q = request.args.get('q', '').strip() or None
    txn_data = db.listtransactionspaginated(page=page, perpage=12, search=q)
    stats = db.gettransactionstats()

    return render_template(
        "admintransactions.html",
        alltransactions=txn_data['transactions'],
        pagination=txn_data,
        totaltransactions=stats["total_transactions"],
        totalrevenue=stats["total_revenue"],
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
    session_cookie = request.cookies.get(COOKIE_NAME)
    if session_cookie:
        user = services.validate_session(session_cookie)
        if user:
            return redirect(url_for("dashboard"))
        return redirect(url_for("logout"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = services.authenticate_user(email, password)

        if user:
            userip = request.headers.get("X-Forwarded-For", request.remote_addr)
            user_agent = request.headers.get("User-Agent", "unknown")

            raw_token = services.create_session(
                user_id=user["id"],
                ip_address=userip,
                user_agent=user_agent,
                ttl_days=SESSION_TTL_DAYS,
            )

            response = make_response(redirect(url_for("dashboard")))
            response.set_cookie(
                COOKIE_NAME,
                raw_token,
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
    discord_auth_url = (
        f"{config['discord']['discordbaseurl']}/oauth2/authorize?client_id={config['discord']['clientid']}"
        f"&redirect_uri={config['discord']['redirecturl']}&response_type=code&scope=identify%20email"
    )
    return redirect(discord_auth_url)


@app.route("/discord-callback")
def discordcallback():
    code = request.args.get("code")
    if not code:
        flash("Discord login failed.", "error")
        return redirect(url_for("login"))

    token_response = requests.post(
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

    if "access_token" not in token_response:
        flash("Could not verify Discord token.", "error")
        return redirect(url_for("login"))

    access_token = token_response["access_token"]
    user_data = requests.get(
        f"{config['discord']['discordbaseurl']}/users/@me",
        headers={"Authorization": f"Bearer {access_token}"},
    ).json()

    # CRITICAL: Discord user email can be None if the account isn't verified
    email = user_data.get("email")
    if not email:
        flash("Your Discord account must have a verified email to log in.", "error")
        return redirect(url_for("login"))

    profile_pic = None
    if user_data.get("avatar"):
        profile_pic = f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data['avatar']}.png"

    try:
        # UPDATED: We now pass the Discord ID (user_data['id'])
        user = services.find_or_create_discord_user(
            discord_id=user_data["id"], 
            email=email, 
            username=user_data["username"], 
            profile_pic=profile_pic
        )
    except Exception as e:
        # Printing the error to console helps you debug specific SQL issues
        print(f"Login Error: {e}")
        flash("Database error during login.", "error")
        return redirect(url_for("login"))

    userip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "unknown")
    raw_token = services.create_session(user["id"], userip, user_agent, ttl_days=SESSION_TTL_DAYS)

    response = make_response(redirect(url_for("dashboard")))
    response.set_cookie(
        COOKIE_NAME,
        raw_token,
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
def page_not_found(e):
    return render_template("404.html"), 404

@app.route("/test/userinfo", methods=["GET"])
@login_required
def test_userinfo():
    """
    Test endpoint to visualize what data is currently 
    available inside g.userinfo for the logged-in user.
    """
    # Check if g.userinfo exists to prevent crashes just in case
    if hasattr(g, 'userinfo'):
        return jsonify(g.userinfo)
    else:
        return jsonify({"error": "g.userinfo is not set"}), 404

if __name__ == "__main__":
    app.run(
        host=config["server"]["host"], 
        port=config["server"]["port"], 
        debug=config["server"]["debug"]
    )