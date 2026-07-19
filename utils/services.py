import uuid
import secrets
import requests
import string
import math
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from core import db

# --- AUTH & SESSION SERVICES ---

def hashpassword(password):
    return generate_password_hash(password)

def authenticateuser(email, password):
    """Verifies credentials and returns user dict if valid."""
    user = db.getuserbyemail(email)
    if user and check_password_hash(user['password'], password):
        return user
    return None

def createsession(userId, ipAddress, userAgent, ttlDays):
    """Creates a new session token in the database with a TTL in days."""
    token = secrets.token_urlsafe(64)
    sessionUuid = str(uuid.uuid4())
    
    expires = (datetime.now(timezone.utc) + timedelta(days=ttlDays)).isoformat()
    
    db.addsession(
        uuid=sessionUuid,
        userid=userId,
        token=token,
        expires=expires,
        ip=ipAddress,
        agent=userAgent
    )
    return token

def validatesession(token):
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

def isuserbanned(userId):
    """Checks if the user has an active ban record."""
    ban = db.getbanbyuserid(userId)
    if not ban:
        return None
    
    # If there is an expiry and it has passed, the ban is no longer active
    if ban['expires']:
        expiry = datetime.fromisoformat(ban['expires'])
        if datetime.utcnow() > expiry:
            return None
            
    return ban

def findorcreatediscorduser(discordId, email, username, profilePic):
    """Handles Discord OAuth registration/login correctly."""
    
    user = db.getuserbydiscord(discordId)
    
    if not user:
        user = db.getuserbyemail(email)
        
        if user:
            db.updateuser(user['uuid'], discordid=discordId)
        else:
            userUuid = str(uuid.uuid4())
            randomPw = hashpassword(secrets.token_urlsafe(16))
            role = 'admin' if db.countusers() == 0 else 'user'
            
            try:
                db.adduser(
                    uuid=userUuid,
                    discordid=discordId,
                    username=username,
                    email=email,
                    password=randomPw,
                    verified=1,
                    role=role
                )
            except Exception:
                uniqueUsername = f"{username}{str(discordId)[-4:]}"
                db.adduser(
                    uuid=userUuid,
                    discordid=discordId,
                    username=uniqueUsername,
                    email=email,
                    password=randomPw,
                    verified=1,
                    role=role
                )
            
            user = db.getuser(userUuid)
            
    return user

# --- VPS & RESOURCE SERVICES ---

def listvpsforuserpanel(userId, page=1, perPage=10, search=None):
    """Returns a paginated list of VPSs owned by the user with plan details."""
    with db.getconnection() as conn:
        offset = (page - 1) * perPage
        where = "WHERE v.userid = ?"
        params = [userId]

        if search:
            where += " AND (v.hostname LIKE ? OR v.ipv6 LIKE ? OR v.status LIKE ?)"
            s = f"%{search}%"
            params.extend([s, s, s])

        totalRow = conn.execute(f"SELECT COUNT(*) AS cnt FROM vps v {where}", params).fetchone()
        total = totalRow["cnt"] if totalRow else 0

        query = f"""
            SELECT v.*, p.name as plan_name, i.name as image_name 
            FROM vps v
            JOIN plans p ON v.planid = p.id
            JOIN images i ON v.imageid = i.id
            {where}
            ORDER BY v.created DESC
            LIMIT ? OFFSET ?
        """
        rows = conn.execute(query, params + [perPage, offset]).fetchall()
        return {
            "vps": [dict(r) for r in rows],
            "totalCount": total,
            "currentPage": page,
            "perPage": perPage,
            "totalPages": math.ceil(total / perPage) if perPage else 1,
            "hasPrev": page > 1,
            "hasNext": (page * perPage) < total,
        }

def provisionvps(userId, planId, imageId, hostname):
    plan = None
    with db.getconnection() as conn:
        plan = conn.execute("SELECT * FROM plans WHERE id = ?", (planId,)).fetchone()
        image = conn.execute("SELECT * FROM images WHERE id = ?", (imageId,)).fetchone()
        node = conn.execute("SELECT * FROM nodes WHERE status = 'online' AND ram >= ? LIMIT 1", (plan['ram'],)).fetchone()
        storage = conn.execute("SELECT * FROM nodestorage WHERE nodeid = ? LIMIT 1", (node['id'],)).fetchone()

    if not node or not storage:
        raise ValueError("No available nodes have enough resources at this time.")

    vpsUuid = str(uuid.uuid4())
    rootPassword = secrets.token_urlsafe(16)

    db.addvps(
        uuid=vpsUuid,
        userid=userId,
        planid=planId,
        imageid=imageId,
        nodeid=node['id'],
        storageid=storage['id'],
        hostname=hostname,
        password=rootPassword,
        cpu=plan['cpu'],
        ram=plan['ram'],
        swap=plan['swap'],
        disk=plan['disk'],
        status='creating'
    )

    node = dict(node)
    payload = {
        "uuid": vpsUuid,
        "hostname": hostname,
        "cpu": plan['cpu'],
        "ram": f"{plan['ram']}m",
        "swap": f"{plan['swap']}m",
        "network": "bridge",
        "ip": "::1",
        "dns": ["1.1.1.1", "8.8.8.8"],
        "image": image['image'],
        "rootPassword": rootPassword,
    }

    result = nodeapi(node, "/vps", method="POST", data=payload, timeout=120)
    if result and result.get("containerId"):
        db.updatevps(vpsUuid, status='running', container=result["containerId"])
    else:
        db.updatevps(vpsUuid, status='error')

    vpsData = db.getvps(vpsUuid)
    res = dict(vpsData)
    res['rootPassword'] = rootPassword
    return res

def getvpsdetails(vpsId):
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
        row = conn.execute(query, (vpsId,)).fetchone()
        return dict(row) if row else None

def nodeapi(node, path, method="GET", data=None, timeout=10):
    """Call a node agent API endpoint."""
    base = node.get('url', '').rstrip('/')
    if not base:
        base = node.get('address', '').rstrip('/')
    if not base:
        return None
    if not base.startswith('http'):
        base = f"http://{base}"
    base = f"{base}/api/v1"
    headers = {"X-API-Key": node['apikey'], "Content-Type": "application/json"}
    try:
        if method == "GET":
            r = requests.get(f"{base}{path}", headers=headers, timeout=timeout)
        elif method == "POST":
            r = requests.post(f"{base}{path}", headers=headers, json=data, timeout=timeout)
        elif method == "DELETE":
            r = requests.delete(f"{base}{path}", headers=headers, timeout=timeout)
        else:
            return None
        return r.json() if r.status_code < 500 else None
    except requests.RequestException:
        return None

def performvpsaction(vpsId, action, actorUserId):
    """Sends a command (start, stop, restart) to the Node Agent."""
    vps = getvpsdetails(vpsId)
    if not vps:
        raise ValueError("VPS not found")

    statusMap = {"start": "running", "stop": "stopped", "restart": "running"}
    newStatus = statusMap.get(action, "error")

    with db.getconnection() as conn:
        node = conn.execute("SELECT * FROM nodes WHERE id = ?", (vps['nodeid'],)).fetchone()

    if node and node['apikey']:
        node = dict(node)
        result = nodeapi(node, f"/vps/{vps['hostname']}/{action}", method="POST")
        if result and "status" in result:
            newStatus = result["status"]

    db.updatevps(vps['uuid'], status=newStatus)
    return {"status": newStatus}

def getlatestvpsmetric(vpsId):
    """Fetch live metrics from the node agent."""
    vps = getvpsdetails(vpsId)
    if not vps:
        return None

    with db.getconnection() as conn:
        node = conn.execute("SELECT * FROM nodes WHERE id = ?", (vps['nodeid'],)).fetchone()

    if not node or not node['apikey']:
        return None

    node = dict(node)
    result = nodeapi(node, f"/vps/{vps['hostname']}/stats", method="GET")
    if not result or not result.get("metrics"):
        return None

    m = result["metrics"]
    return {
        "cpu": m.get("cpu", "0%"),
        "ram": m.get("memoryUsage", "0B"),
        "disk": m.get("blockIn", "0B"),
        "netIn": m.get("netIn", "0B"),
        "netOut": m.get("netOut", "0B"),
    }

def listfirewallrulesforvps(vpsId):
    """Placeholder for firewall logic."""
    return []

def generaterandomhostname():
    suffix = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    return f"vps-{suffix}"

def generaterandompassword():
    return secrets.token_urlsafe(16)
