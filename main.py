from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, make_response, g
import os
import secrets
import requests
import toml
import uuid
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
        "debug": True,
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


def daystoseconds(days: int) -> int:
    return int(days) * 86400


app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

COOKIE_NAME = "sessioncookie"
SESSION_TTL_HOURS = config["general"]["defaultcookiettl"] * 24


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
        "vps": services.list_vps_for_user_panel(user["id"], per_page=100),
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
    return render_template("dashboard.html", **paneluserinfo(g.userinfo))


@app.route("/createvps", methods=["GET", "POST"])
@login_required
def createvps():
    if request.method == "POST":
        plan_id = request.form.get("plan_id", type=int)
        image_id = request.form.get("image_id", type=int)
        hostname = (request.form.get("hostname") or "").strip()

        if not plan_id or not image_id or not hostname:
            flash("Plan, image, and hostname are all required.", "error")
        else:
            try:
                vps = services.provision_vps(g.userinfo["id"], plan_id, image_id, hostname)
                flash(
                    f"VPS '{vps['hostname']}' created successfully. "
                    f"Root password: {vps['root_password']} (Shown only once!)",
                    "success",
                )
                return redirect(url_for("vpspanel", vps_uuid=vps["uuid"]))
            except ValueError as e:
                flash(str(e), "error")

    images = db.listimages(active=1)
    return render_template("createvps.html", **paneluserinfo(g.userinfo), images=images)


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
    perpage = 12 
    
    # pagination_data now contains the 'users' key and the metadata keys
    pagination_data = db.listuserspaginated(page=page, perpage=perpage)
    
    return render_template(
        "adminusers.html", 
        **paneluserinfo(g.userinfo), 
        **paneladmininfo(g.userinfo),
        allusers=pagination_data['users'], # Correctly accessing the list
        pagination=pagination_data         # Correctly passing the metadata
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
    return render_template("adminvps.html", **paneluserinfo(g.userinfo), **paneladmininfo(g.userinfo))

@app.route("/dashboard/admin/plans", methods=["GET", "POST"])
@login_required
@admin_required
def adminplans():
    # Handle New Plan Creation
    if request.method == "POST":
        # Ensure you have a 'create' logic here
        db.addplan(
            uuid=str(uuid.uuid4()),
            name=request.form.get("name"),
            cpu=request.form.get("cpu"),
            ram=request.form.get("ram"),
            swap=request.form.get("swap"),
            disk=request.form.get("disk"),
            price=request.form.get("price")
        )
        return redirect(url_for('adminplans'))

    return render_template(
        "adminplans.html", 
        allplans=db.listplans(), 
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
        active=int(request.form.get("active", 1))
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
    return render_template("adminnodes.html", **paneluserinfo(g.userinfo), **paneladmininfo(g.userinfo))

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
                ttl_hours=SESSION_TTL_HOURS,
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

    return render_template("login.html")


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
    raw_token = services.create_session(user["id"], userip, user_agent, ttl_hours=SESSION_TTL_HOURS)

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