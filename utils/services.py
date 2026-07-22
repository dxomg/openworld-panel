import uuid
import secrets
import requests
import string
import math
import os
import time
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from core import db
from utils import proxmox as pveclient

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
        storage = conn.execute("SELECT * FROM storagepools WHERE nodeid = ? LIMIT 1", (node['id'],)).fetchone()

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

    try:
        provisiononnode(vpsUuid)
    except ValueError:
        pass

    vpsData = db.getvps(vpsUuid)
    res = dict(vpsData)
    res['rootPassword'] = rootPassword
    return res

def getvpsdetails(vpsId):
    """Gets full VPS info including node and plan details."""
    with db.getconnection() as conn:
        query = """
            SELECT v.*, p.name as plan_name, p.price as plan_price, p.readbps, p.writebps,
                   n.address as node_ip, n.url as node_url, n.apikey as node_apikey,
                   i.name as image_name, i.image as image_path, i.imagestorageid,
                   ist.name as image_storage_name
            FROM vps v
            JOIN plans p ON v.planid = p.id
            JOIN nodes n ON v.nodeid = n.id
            JOIN images i ON v.imageid = i.id
            LEFT JOIN imagestorage ist ON i.imagestorageid = ist.id
            WHERE v.id = ?
        """
        row = conn.execute(query, (vpsId,)).fetchone()
        return dict(row) if row else None

def provisiononnode(vpsUuid):
    """Provision a VPS on the node. Routes to Docker or Proxmox based on node type."""
    vps = db.getvps(vpsUuid)
    if not vps:
        raise ValueError("VPS not found")

    # Get node to check type
    with db.getconnection() as conn:
        node = conn.execute("SELECT * FROM nodes WHERE id = ?", (vps['nodeid'],)).fetchone()
    if not node:
        raise ValueError("Node not found")
    node = dict(node)

    nodeType = node.get('type', 'docker')
    
    if nodeType == 'proxmox':
        return provisiononproxmox(vpsUuid)
    else:
        return provisionondocker(vpsUuid)

def provisionondocker(vpsUuid):
    """Provision a VPS container on Docker node."""
    vps = db.getvps(vpsUuid)
    if not vps:
        raise ValueError("VPS not found")

    vpsDetails = getvpsdetails(vps['id'])
    if not vpsDetails:
        raise ValueError("VPS details not found")

    node = {
        'address': vpsDetails.get('node_ip', ''),
        'url': vpsDetails.get('node_url', ''),
        'apikey': vpsDetails.get('node_apikey', ''),
    }

    # Get network info and assign IPs from pool
    networkName = "bridge"
    assignedIp = None
    assignedIpv4 = None
    assignedIpv6 = None
    assignedIpIds = []
    networkDns = ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888"]
    if vps.get('networkid'):
        netTable = "proxmox_networks" if vps.get('network_type') == 'proxmox' else "docker_networks"
        with db.getconnection() as conn:
            net = conn.execute(f"SELECT * FROM {netTable} WHERE id = ?", (vps['networkid'],)).fetchone()
        if net:
            net = dict(net)
            networkName = net['name']
            if net.get('dns'):
                networkDns = [s.strip() for s in net['dns'].split(',') if s.strip()]

        netType = vps.get('network_type', 'docker')

        # Assign IPv6 if network supports it
        if net and net.get('ipv6'):
            availIpv6 = db.getavailableipbyversion(vps['networkid'], network_type=netType, version='ipv6')
            if availIpv6:
                assignedIpv6 = availIpv6['ip']
                assignedIpIds.append(availIpv6['id'])
                db.assignip(availIpv6['id'], vps['id'])

        # Assign IPv4 if network supports it
        if net and net.get('ipv4'):
            availIpv4 = db.getavailableipbyversion(vps['networkid'], network_type=netType, version='ipv4')
            if availIpv4:
                assignedIpv4 = availIpv4['ip']
                assignedIpIds.append(availIpv4['id'])
                db.assignip(availIpv4['id'], vps['id'])

        # Primary IP for container config (prefer IPv6)
        assignedIp = assignedIpv6 or assignedIpv4

    # Get storage pool name
    poolName = "default"
    if vps.get('storagepoolid'):
        with db.getconnection() as conn:
            pool = conn.execute("SELECT name FROM storagepools WHERE id = ?", (vps['storagepoolid'],)).fetchone()
        if pool:
            poolName = pool['name']

    payload = {
        "uuid": vpsUuid,
        "hostname": vps['hostname'],
        "cpu": vps['cpu'],
        "ram": vps['ram'],
        "swap": vps['swap'],
        "diskMb": vps.get('disk', 20) or 20,
        "network": networkName,
        "ip": assignedIp,
        "ipv4": assignedIpv4,
        "ipv6": assignedIpv6,
        "dns": networkDns,
        "image": vpsDetails['image_path'],
        "rootPassword": vps['password'],
        "pool": poolName,
    }

    result = nodeapi(node, "/vps", method="POST", data=payload, timeout=120)
    if not result:
        for ipId in assignedIpIds:
            db.unassignip(ipId)
        db.updatevps(vpsUuid, status='error')
        raise ValueError("Node unreachable or failed to respond")

    if result.get("error"):
        for ipId in assignedIpIds:
            db.unassignip(ipId)
        db.updatevps(vpsUuid, status='error')
        raise ValueError(f"Node error: {result['error']}")

    if not result.get("containerId"):
        for ipId in assignedIpIds:
            db.unassignip(ipId)
        db.updatevps(vpsUuid, status='error')
        raise ValueError("Node did not return a container ID")

    db.updatevps(vpsUuid, status='running', container=result["containerId"], ipv4=assignedIpv4, ipv6=assignedIpv6)
    return result

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
        try:
            return r.json()
        except ValueError:
            return {"error": f"node returned status {r.status_code}"}
    except requests.ConnectionError:
        return {"error": "node unreachable"}
    except requests.Timeout:
        return {"error": "node timeout"}
    except requests.RequestException as e:
        return {"error": str(e)}

def performvpsaction(vpsId, action, actorUserId):
    """Sends a command (start, stop, restart) to the Node."""
    vps = getvpsdetails(vpsId)
    if not vps:
        raise ValueError("VPS not found")

    statusMap = {"start": "running", "stop": "stopped", "restart": "running"}
    newStatus = statusMap.get(action, "error")

    with db.getconnection() as conn:
        node = conn.execute("SELECT * FROM nodes WHERE id = ?", (vps['nodeid'],)).fetchone()

    if not node:
        raise ValueError("Node not found")
    
    node = dict(node)
    nodeType = node.get('type', 'docker')

    if nodeType == 'proxmox':
        vmid = getvmidmapping(vps['uuid'])
        if not vmid:
            raise ValueError("VMID not found for this VPS")
        
        pve = getproxmoxclient(node)
        node_name = node.get('proxmoxnode', 'pve')
        
        try:
            if action == "start":
                pveclient.startlxc(pve, node_name, vmid)
            elif action == "stop":
                pveclient.stoplxc(pve, node_name, vmid)
            elif action == "restart":
                pveclient.restartlxc(pve, node_name, vmid)
            else:
                raise ValueError("Invalid action")
        except Exception as e:
            raise ValueError(f"Proxmox action failed: {e}")
    else:
        if node.get('apikey'):
            result = nodeapi(node, f"/vps/{vps['uuid']}/{action}", method="POST")
            if result and "status" in result:
                newStatus = result["status"]

    db.updatevps(vps['uuid'], status=newStatus)
    return {"status": newStatus}

def getlatestvpsmetric(vpsId):
    """Fetch live metrics from the node."""
    vps = getvpsdetails(vpsId)
    if not vps:
        return None

    with db.getconnection() as conn:
        node = conn.execute("SELECT * FROM nodes WHERE id = ?", (vps['nodeid'],)).fetchone()

    if not node:
        return None

    node = dict(node)
    nodeType = node.get('type', 'docker')

    if nodeType == 'proxmox':
        vmid = getvmidmapping(vps['uuid'])
        if not vmid:
            return None
        
        try:
            pve = getproxmoxclient(node)
            node_name = node.get('proxmoxnode', 'pve')
            status = pveclient.getlxcstatus(pve, node_name, vmid)
        except Exception:
            return None
        
        if not status or status.get('status') != 'running':
            return None
        
        cpu_usage = status.get('cpu', 0)
        mem_usage = status.get('mem', 0)
        mem_max = status.get('maxmem', 0)
        disk_usage = status.get('disk', 0)
        disk_max = status.get('maxdisk', 0)
        
        return {
            "cpu": f"{cpu_usage * 100:.1f}%",
            "ram": f"{mem_usage / (1024**2):.0f}MB",
            "disk": f"{(disk_usage / disk_max * 100):.1f}%" if disk_max > 0 else "0%",
            "diskUsed": f"{disk_usage / (1024**3):.1f}GB",
            "diskTotal": f"{disk_max / (1024**3):.1f}GB",
            "netIn": "N/A",
            "netOut": "N/A",
        }
    else:
        if not node.get('apikey'):
            return None
        
        result = nodeapi(node, f"/vps/{vps['uuid']}/stats", method="GET")
        if not result or not result.get("metrics"):
            return None

        m = result["metrics"]
        return {
            "cpu": m.get("cpu", "0%"),
            "ram": m.get("memoryUsage", "0B"),
            "disk": m.get("diskPercent", "0%"),
            "diskUsed": m.get("diskUsed", "0B"),
            "diskTotal": m.get("diskTotal", "0B"),
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

def getproxmoxclient(node):
    """Create a ProxmoxAPI client from node config."""
    return pveclient.getproxmoxclient(node)

def provisiononproxmox(vpsUuid):
    """Provision a VPS as LXC container on Proxmox."""
    vps = db.getvps(vpsUuid)
    if not vps:
        raise ValueError("VPS not found")

    vpsDetails = getvpsdetails(vps['id'])
    if not vpsDetails:
        raise ValueError("VPS details not found")

    # Get node details
    with db.getconnection() as conn:
        node = conn.execute("SELECT * FROM nodes WHERE id = ?", (vps['nodeid'],)).fetchone()
    if not node:
        raise ValueError("Node not found")
    node = dict(node)

    node_name = node.get('proxmoxnode', 'pve')

    # Get network info and assign IPs
    assignedIpv4 = None
    assignedIpv6 = None
    assignedIpIds = []
    bridgeName = "vmbr0"
    ipv4Gateway = None
    ipv6Gateway = None
    networkDns = None
    if vps.get('networkid'):
        netType = vps.get('network_type', 'proxmox')

        # Get network to check ipv4/ipv6 flags
        netTable = "proxmox_networks" if netType == 'proxmox' else "docker_networks"
        with db.getconnection() as conn:
            net = conn.execute(f"SELECT * FROM {netTable} WHERE id = ?", (vps['networkid'],)).fetchone()
        net = dict(net) if net else {}

        if net.get('name'):
            bridgeName = net['name']
        ipv4Gateway = net.get('ipv4_gateway')
        ipv6Gateway = net.get('ipv6_gateway') or net.get('gateway')
        if net.get('dns'):
            networkDns = net['dns']

        if net.get('ipv6'):
            availIpv6 = db.getavailableipbyversion(vps['networkid'], network_type=netType, version='ipv6')
            if availIpv6:
                assignedIpv6 = availIpv6['ip']
                assignedIpIds.append(availIpv6['id'])
                db.assignip(availIpv6['id'], vps['id'])

        if net.get('ipv4'):
            availIpv4 = db.getavailableipbyversion(vps['networkid'], network_type=netType, version='ipv4')
            if availIpv4:
                assignedIpv4 = availIpv4['ip']
                assignedIpIds.append(availIpv4['id'])
                db.assignip(availIpv4['id'], vps['id'])

    assignedIp = assignedIpv6 or assignedIpv4

    # Get Proxmox client
    pve = getproxmoxclient(node)

    # Get next VMID
    vmid = pveclient.nextvmid(pve)
    if not vmid:
        for ipId in assignedIpIds:
            db.unassignip(ipId)
        db.updatevps(vpsUuid, status='error')
        raise ValueError("Failed to get VMID")

    # Build LXC parameters
    ram = int(vps['ram'])
    cpu = int(vps['cpu'])
    disk_gb = max(1, int(vps.get('disk', 20)) // 1024)  # Convert MB to GB, min 1GB
    
    # Image: if it contains ":" use as-is (e.g. "custom:vztmpl/ubuntu-24.04.tar.zst")
    # Otherwise build from image's linked storage, or node's default storage, + filename
    template = vpsDetails.get('image_path', 'ubuntu-22.04-standard')
    if ':' not in template:
        storageName = vpsDetails.get('image_storage_name')
        if not storageName:
            imgStorage = db.getdefaultimagestorage(vps['nodeid'])
            storageName = imgStorage['name'] if imgStorage else 'local'
        if not template.endswith(('.tar.gz', '.tar.xz', '.tar.zst')):
            template = f"{template}.tar.gz"
        template = f"{storageName}:vztmpl/{template}"

    # Get storage pool name for rootfs
    storagePool = "local-lvm"
    if vps.get('storagepoolid'):
        with db.getconnection() as conn:
            pool = conn.execute("SELECT name FROM storagepools WHERE id = ?", (vps['storagepoolid'],)).fetchone()
        if pool:
            storagePool = pool['name']

    lxc_params = {
        "hostname": vps['hostname'],
        "cores": cpu,
        "memory": ram,
        "rootfs": f"{storagePool}:{disk_gb}",
        "ostemplate": template,
        "password": vps['password'],
        "net0": f"name=eth0,bridge={bridgeName},ip=dhcp",
        "onboot": 1,
        "swap": int(vps.get('swap', 0)),
    }

    # Set DNS if configured on network
    if networkDns:
        lxc_params["nameserver"] = networkDns

    # If we have a specific IP, set it with gateway
    if assignedIpv6 and assignedIpv4:
        gw6 = f",gw6={ipv6Gateway}" if ipv6Gateway else ""
        gw4 = f",gw={ipv4Gateway}" if ipv4Gateway else ""
        lxc_params["net0"] = f"name=eth0,bridge={bridgeName},ip6={assignedIpv6}/64{gw6},ip={assignedIpv4}/24{gw4}"
    elif assignedIpv6:
        gw = f",gw6={ipv6Gateway}" if ipv6Gateway else ""
        lxc_params["net0"] = f"name=eth0,bridge={bridgeName},ip6={assignedIpv6}/64{gw},ip=dhcp"
    elif assignedIpv4:
        gw = f",gw={ipv4Gateway}" if ipv4Gateway else ""
        lxc_params["net0"] = f"name=eth0,bridge={bridgeName},ip={assignedIpv4}/24{gw}"

    # Create LXC
    try:
        pveclient.createlxc(pve, node_name, vmid, lxc_params)
    except Exception as e:
        for ipId in assignedIpIds:
            db.unassignip(ipId)
        db.updatevps(vpsUuid, status='error')
        raise ValueError(f"LXC creation failed: {e}")

    # Start LXC
    time.sleep(1)
    try:
        pveclient.startlxc(pve, node_name, vmid)
    except Exception as e:
        for ipId in assignedIpIds:
            db.unassignip(ipId)
        db.updatevps(vpsUuid, status='error')
        raise ValueError(f"LXC start failed: {e}")

    db.updatevps(vpsUuid, status='running', container=str(vmid), vmid=vmid, ipv4=assignedIpv4, ipv6=assignedIpv6)
    return {"containerId": str(vmid), "vmid": vmid, "status": "created"}

# VMID mapping - stored in vps.vmid column

def setvmidmapping(uuid, vmid):
    db.updatevps(uuid, vmid=vmid)

def getvmidmapping(uuid):
    vps = db.getvps(uuid)
    return vps.get('vmid') if vps else None

def removevmidmapping(uuid):
    db.updatevps(uuid, vmid=None)
