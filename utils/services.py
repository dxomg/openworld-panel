import uuid
import secrets
import requests
from datetime import datetime, timedelta, timezone
from core import db

# --- AUTH & SESSION SERVICES ---

def authenticate_user(email, password):
    """Verifies credentials and returns user dict if valid."""
    user = db.getuserbyemail(email)
    if user and user['password'] == password: # In production, use werkzeug.security.check_password_hash
        return user
    return None

def create_session(user_id, ip_address, user_agent, ttl_days):
    """Creates a new session token in the database with a TTL in days."""
    token = secrets.token_urlsafe(64)
    session_uuid = str(uuid.uuid4())
    
    # Calculate expiration using days instead of hours
    expires = (datetime.now(timezone.utc) + timedelta(days=ttl_days)).isoformat()
    
    db.addsession(
        uuid=session_uuid,
        userid=user_id,
        token=token,
        expires=expires,
        ip=ip_address,
        agent=user_agent
    )
    return token

def validate_session(token):
    session = db.getsession(token)
    if not session:
        return None

    expiry = datetime.fromisoformat(session["expires"])

    # Handle legacy naive timestamps
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > expiry:
        db.removesession(token)
        return None

    return db.getuserbyid(session["userid"])

def logout(token):
    """Deletes the session from the database."""
    db.removesession(token)

def is_user_banned(user_id):
    """Checks if the user has an active ban record."""
    ban = db.getbanbyuserid(user_id)
    if not ban:
        return None
    
    # If there is an expiry and it has passed, the ban is no longer active
    if ban['expires']:
        expiry = datetime.fromisoformat(ban['expires'])
        if datetime.utcnow() > expiry:
            return None
            
    return ban

def find_or_create_discord_user(discord_id, email, username, profile_pic):
    """Handles Discord OAuth registration/login correctly."""
    
    # 1. Try to find user by Discord ID first (strongest link)
    user = db.getuserbydiscord(discord_id)
    
    if not user:
        # 2. If not found by Discord ID, try by Email (account linking)
        user = db.getuserbyemail(email)
        
        if user:
            # User exists via email, link their Discord ID now
            db.updateuser(user['uuid'], discordid=discord_id)
        else:
            # 3. Create a brand new user
            user_uuid = str(uuid.uuid4())
            random_pw = secrets.token_urlsafe(16) # Random pass for OAuth users
            
            try:
                # Try creating with the Discord username
                db.adduser(
                    uuid=user_uuid,
                    discordid=discord_id,
                    username=username,
                    email=email,
                    password=random_pw,
                    verified=1
                )
            except Exception:
                # If username exists, append part of the discord ID to make it unique
                unique_username = f"{username}{str(discord_id)[-4:]}"
                db.adduser(
                    uuid=user_uuid,
                    discordid=discord_id,
                    username=unique_username,
                    email=email,
                    password=random_pw,
                    verified=1
                )
            
            user = db.getuser(user_uuid)
            
    return user

# --- VPS & RESOURCE SERVICES ---

def list_vps_for_user_panel(user_id, per_page=100):
    """Returns a list of VPSs owned by the user with plan details."""
    with db.getconnection() as conn:
        # We perform a join here because the panel needs Plan Names/Resources
        query = """
            SELECT v.*, p.name as plan_name, i.name as image_name 
            FROM vps v
            JOIN plans p ON v.planid = p.id
            JOIN images i ON v.imageid = i.id
            WHERE v.userid = ?
            LIMIT ?
        """
        rows = conn.execute(query, (user_id, per_page)).fetchall()
        return [dict(r) for r in rows]

def provision_vps(user_id, plan_id, image_id, hostname):
    """
    Logic to select a node, verify resources, and create the VPS.
    """
    plan = None
    with db.getconnection() as conn:
        plan = conn.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
        image = conn.execute("SELECT * FROM images WHERE id = ?", (image_id,)).fetchone()
        # Find an online node with enough RAM (Simple load balancing)
        node = conn.execute("SELECT * FROM nodes WHERE status = 'online' AND ram >= ? LIMIT 1", (plan['ram'],)).fetchone()
        # Find storage on that node
        storage = conn.execute("SELECT * FROM nodestorage WHERE nodeid = ? LIMIT 1", (node['id'],)).fetchone()

    if not node or not storage:
        raise ValueError("No available nodes have enough resources at this time.")

    vps_uuid = str(uuid.uuid4())
    root_password = secrets.token_urlsafe(12)

    # 1. Save to Database
    db.addvps(
        uuid=vps_uuid,
        userid=user_id,
        planid=plan_id,
        imageid=image_id,
        nodeid=node['id'],
        storageid=storage['id'],
        hostname=hostname,
        password=root_password, # In real life, encrypt this
        cpu=plan['cpu'],
        ram=plan['ram'],
        swap=plan['swap'],
        disk=plan['disk'],
        status='creating'
    )

    # 2. Communicate with Node Agent (Mock API Request)
    # try:
    #     requests.post(f"http://{node['address']}/create", json={...}, headers={"Authorization": node['apikey']})
    # except:
    #     pass

    vps_data = db.getvps(vps_uuid)
    # We return the password once so the UI can show it
    res = dict(vps_data)
    res['root_password'] = root_password
    return res

def get_vps_details(vps_id):
    """Gets full VPS info including node and plan details."""
    with db.getconnection() as conn:
        query = """
            SELECT v.*, p.name as plan_name, n.address as node_ip, i.image as image_path
            FROM vps v
            JOIN plans p ON v.planid = p.id
            JOIN nodes n ON v.nodeid = n.id
            JOIN images i ON v.imageid = i.id
            WHERE v.id = ?
        """
        row = conn.execute(query, (vps_id,)).fetchone()
        return dict(row) if row else None

def perform_vps_action(vps_id, action, actor_user_id):
    """Sends a command (start, stop, restart) to the Node Agent."""
    vps = get_vps_details(vps_id)
    if not vps:
        raise ValueError("VPS not found")

    # Mapping actions to statuses
    status_map = {"start": "running", "stop": "stopped", "restart": "running"}
    new_status = status_map.get(action, "error")

    # Here you would normally do:
    # requests.post(f"http://{vps['node_ip']}/action/{action}", ...)
    
    db.updatevps(vps['uuid'], status=new_status)
    return {"status": new_status}

def get_latest_vps_metric(vps_id):
    """
    Mock metrics. In reality, you would fetch this from 
    Redis or query the Node Agent.
    """
    return {
        "cpu_usage": "12%",
        "ram_usage": "512MB",
        "disk_usage": "10GB",
        "net_in": "1.2MB/s",
        "net_out": "0.5MB/s"
    }

def list_firewall_rules_for_vps(vps_id):
    """Placeholder for firewall logic."""
    return []