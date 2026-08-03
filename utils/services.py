import uuid
import secrets
import string
import math
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
    
    # session expiry stored as ISO; compare in validatesession with aware UTC
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
        where = "WHERE v.userid = ? AND v.status != 'deleted'"
        params = [userId]

        if search:
            where += " AND (v.hostname LIKE ? OR v.ipv6 LIKE ? OR v.status LIKE ?)"
            s = f"%{search}%"
            params.extend([s, s, s])

        totalRow = conn.execute(f"SELECT COUNT(*) AS cnt FROM vps v {where}", params).fetchone()
        total = totalRow["cnt"] if totalRow else 0

        query = f"""
            SELECT v.*, p.name as plan_name, p.price as plan_price, i.name as image_name, i.os_type
            FROM vps v
            JOIN plans p ON v.planid = p.id
            JOIN images i ON v.imageid = i.id
            {where}
            ORDER BY v.created DESC
            LIMIT ? OFFSET ?
        """
        rows = conn.execute(query, params + [perPage, offset]).fetchall()
        vpsList = [dict(r) for r in rows]
        for inst in vpsList:
            _annotate_billing(inst)
        return {
            "vps": vpsList,
            "totalCount": total,
            "currentPage": page,
            "perPage": perPage,
            "totalPages": math.ceil(total / perPage) if perPage else 1,
            "hasPrev": page > 1,
            "hasNext": (page * perPage) < total,
        }

def getvpsdetails(vpsId):
    """Gets full VPS info including node and plan details."""
    with db.getconnection() as conn:
        query = """
            SELECT v.*, p.name as plan_name, p.price as plan_price, p.netmbps, p.ipv4 as plan_ipv4, p.ipv6 as plan_ipv6, p.node_type as plan_node_type,
                   n.address as node_ip, n.name as node_name, n.url as node_url, n.apikey as node_apikey, n.type as node_type,
                   loc.name as location_name, loc.code as location_code, loc.flag as location_flag,
                   i.name as image_name, i.image as image_path, i.os_type,
                   ni.imagestorageid,
                   ist.name as image_storage_name
            FROM vps v
            JOIN plans p ON v.planid = p.id
            JOIN nodes n ON v.nodeid = n.id
            LEFT JOIN locations loc ON n.locationid = loc.id
            JOIN images i ON v.imageid = i.id
            LEFT JOIN node_images ni ON ni.imageid = i.id AND ni.nodeid = n.id
            LEFT JOIN imagestorage ist ON ni.imagestorageid = ist.id
            WHERE v.id = ?
        """
        row = conn.execute(query, (vpsId,)).fetchone()
        if not row:
            return None
        details = dict(row)
        _annotate_billing(details)
        return details


# Billing warning window before paid_until
BILLING_WARN_DAYS = 7


def _parse_paid_until(val):
    from core import timeutil
    return timeutil.parse_local(val)


def _annotate_billing(inst, warn_days=None):
    """
    Attach billing_due / free_renew / labels for UI.
    free_period_days = renew length only. warn_days = banner window (free + paid).
    """
    from core import timeutil

    if warn_days is None:
        try:
            from core import appconfig
            b = appconfig.load().get("billing") or {}
            warn_days = max(0, int(b.get("warn_days") if b.get("warn_days") is not None else BILLING_WARN_DAYS))
        except Exception:
            warn_days = BILLING_WARN_DAYS

    inst["billing_due"] = False
    inst["billing_overdue"] = False
    inst["billing_days_left"] = None
    inst["billing_days_text"] = None
    inst["billing_label"] = None
    inst["is_free_plan"] = False
    inst["can_renew_free"] = False
    inst["timezone"] = timeutil.get_tz_name()
    raw_until = inst.get("paid_until")
    inst["paid_until_display"] = (
        timeutil.format_local(raw_until, with_tz=True) if raw_until else None
    )
    try:
        price = float(inst.get("plan_price") or 0)
    except (TypeError, ValueError):
        price = 0
    inst["is_free_plan"] = price <= 0
    if inst.get("status") in ("pendingpayment", "deleted", "creating"):
        return inst

    until = _parse_paid_until(inst.get("paid_until"))

    if not until:
        if price > 0:
            inst["billing_due"] = True
            inst["billing_days_left"] = 0
            inst["billing_label"] = "Payment period unknown — contact support"
        else:
            inst["can_renew_free"] = True
        return inst

    now = timeutil.now()
    delta = until - now
    days_left = int(delta.total_seconds() // 86400)
    inst["billing_days_left"] = days_left
    if days_left < 0:
        d = abs(days_left)
        inst["billing_days_text"] = f"Expired {d} day{'s' if d != 1 else ''} ago"
    elif days_left == 0:
        inst["billing_days_text"] = "Ends today"
    else:
        inst["billing_days_text"] = f"Renews in {days_left} day{'s' if days_left != 1 else ''}"

    if price <= 0:
        inst["can_renew_free"] = True
        if days_left < 0:
            inst["billing_due"] = True
            inst["billing_overdue"] = True
            d = abs(days_left)
            inst["billing_label"] = f"Free period expired {d} day{'s' if d != 1 else ''} ago — renew now"
        elif days_left == 0:
            inst["billing_due"] = True
            inst["billing_label"] = "Free period ends today — renew now"
        elif days_left <= warn_days:
            inst["billing_due"] = True
            inst["billing_label"] = f"Free renewal due in {days_left} day{'s' if days_left != 1 else ''}"
        return inst

    if days_left < 0:
        inst["billing_due"] = True
        inst["billing_overdue"] = True
        d = abs(days_left)
        inst["billing_label"] = f"Payment overdue by {d} day{'s' if d != 1 else ''}"
    elif days_left == 0:
        inst["billing_due"] = True
        inst["billing_label"] = "Payment due today"
    elif days_left <= warn_days:
        inst["billing_due"] = True
        inst["billing_label"] = f"Payment due in {days_left} day{'s' if days_left != 1 else ''}"
    return inst


# Panel power states that should track Proxmox live status
_LIVE_SYNC_STATUSES = frozenset({"running", "stopped", "restarting", "error"})
# Keep these as-is even if Proxmox says something else
_NO_SYNC_STATUSES = frozenset({"creating", "pendingpayment", "deleted", "suspended"})

_PROXMOX_TO_PANEL = {
    "running": "running",
    "stopped": "stopped",
    "paused": "stopped",
    "suspended": "stopped",
}


def _vps_node_and_vmid(vps):
    """(node_dict, vmid) from a details/vps row, or (None, None)."""
    if not vps:
        return None, None
    vmid = vps.get("vmid") or getvmidmapping(vps.get("uuid"))
    if not vmid:
        return None, None
    with db.getconnection() as conn:
        node = conn.execute("SELECT * FROM nodes WHERE id = ?", (vps["nodeid"],)).fetchone()
    if not node:
        return None, None
    return dict(node), vmid


def getproxmoxlivestatus(vpsId, details=None):
    """Query Proxmox for LXC power state. Returns 'running'|'stopped'|None."""
    vps = details or getvpsdetails(vpsId)
    if not vps:
        return None
    node, vmid = _vps_node_and_vmid(vps)
    if not node or not vmid:
        return None
    try:
        pve = getproxmoxclient(node)
        node_name = node.get("proxmoxnode", "pve")
        cur = pveclient.getlxcstatus(pve, node_name, vmid)
        raw = (cur or {}).get("status") or ""
        return _PROXMOX_TO_PANEL.get(raw, raw if raw in ("running", "stopped") else None)
    except Exception:
        return None


def _metrics_from_lxc_status(status):
    """Build panel metrics dict from Proxmox status.current (no RRD)."""
    if not status or status.get("status") != "running":
        return None
    cpu_usage = status.get("cpu", 0) or 0
    mem_usage = status.get("mem", 0) or 0
    disk_usage = status.get("disk", 0) or 0
    disk_max = status.get("maxdisk", 0) or 0
    return {
        "cpu": f"{cpu_usage * 100:.1f}%",
        "ram": f"{mem_usage / (1024**2):.0f}MB",
        "disk": f"{(disk_usage / disk_max * 100):.1f}%" if disk_max > 0 else "0%",
        "diskUsed": f"{disk_usage / (1024**3):.1f}GB",
        "diskTotal": f"{disk_max / (1024**3):.1f}GB",
        "netIn": formatbytes(status.get("netin", 0)),
        "netOut": formatbytes(status.get("netout", 0)),
    }


def fetchlivevps(vpsId, details=None):
    """
    One Proxmox round-trip: sync power status + metrics.
    Returns (details_dict, metrics_or_none).
    """
    details = details or getvpsdetails(vpsId)
    if not details:
        return None, None

    db_status = details.get("status")
    if db_status in _NO_SYNC_STATUSES:
        return details, None

    node, vmid = _vps_node_and_vmid(details)
    if not node or not vmid:
        return details, None

    try:
        pve = getproxmoxclient(node)
        node_name = node.get("proxmoxnode", "pve")
        cur = pveclient.getlxcstatus(pve, node_name, vmid) or {}
    except Exception:
        return details, None

    raw = (cur.get("status") or "").lower()
    live = _PROXMOX_TO_PANEL.get(raw, raw if raw in ("running", "stopped") else None)
    if live and live != db_status and db_status in _LIVE_SYNC_STATUSES:
        db.updatevps(details["uuid"], status=live)
        details["status"] = live
    elif live and db_status in _LIVE_SYNC_STATUSES:
        details["status"] = live

    metrics = _metrics_from_lxc_status(cur)
    return details, metrics


def synclivestatus(vpsId, details=None):
    """
    Align DB status with Proxmox when safe.
    Skips creating/pendingpayment/deleted/suspended.
    Returns updated details dict (or original if no change / unreachable).
    """
    details, _ = fetchlivevps(vpsId, details=details)
    return details


def provisiononnode(vpsUuid):
    """Provision a VPS as LXC on Proxmox."""
    return provisiononproxmox(vpsUuid)


def setnoderunstatus(node, reachable):
    """Flip online/offline from live reachability. Leave maintenance alone."""
    current = node.get("status") or "offline"
    if current == "maintenance":
        return current
    new = "online" if reachable else "offline"
    if new != current and node.get("uuid"):
        db.updatenode(node["uuid"], status=new)
        node["status"] = new
    return new


def probenode(node, timeout=5):
    """Probe Proxmox node; update online/offline. Returns (reachable, stats_or_none)."""
    node = dict(node) if not isinstance(node, dict) else node
    try:
        pve = pveclient.getproxmoxclient(node, timeout=timeout)
        node_name = node.get("proxmoxnode", "pve")
        status = pve.nodes(node_name).status.get()
        if not status:
            setnoderunstatus(node, False)
            return False, None
        setnoderunstatus(node, True)
        return True, status
    except Exception:
        setnoderunstatus(node, False)
        return False, None

def performvpsaction(vpsId, action, actorUserId):
    """Sends a command (start, stop, restart) to Proxmox; status from live API after."""
    vps = getvpsdetails(vpsId)
    if not vps:
        raise ValueError("VPS not found")

    if vps.get("status") == "suspended":
        raise ValueError("VPS is suspended")

    # Reconcile before action so start works when panel was stale "running"
    synclivestatus(vpsId)
    vps = getvpsdetails(vpsId) or vps

    with db.getconnection() as conn:
        node = conn.execute("SELECT * FROM nodes WHERE id = ?", (vps['nodeid'],)).fetchone()

    if not node:
        raise ValueError("Node not found")
    
    node = dict(node)
    vmid = getvmidmapping(vps['uuid']) or vps.get("vmid")
    if not vmid:
        raise ValueError("VMID not found for this VPS")
    
    pve = getproxmoxclient(node)
    node_name = node.get('proxmoxnode', 'pve')

    # Live state before command
    try:
        cur = pveclient.getlxcstatus(pve, node_name, vmid) or {}
        live = (cur.get("status") or "").lower()
    except Exception as e:
        raise ValueError(f"Proxmox unreachable: {e}")

    try:
        if action == "start":
            if live != "running":
                pveclient.startlxc(pve, node_name, vmid)
        elif action == "stop":
            if live == "running":
                pveclient.stoplxc_wait(pve, node_name, vmid, timeout=90)
        elif action == "restart":
            if live == "running":
                pveclient.restartlxc(pve, node_name, vmid)
            else:
                pveclient.startlxc(pve, node_name, vmid)
        else:
            raise ValueError("Invalid action")
    except Exception as e:
        raise ValueError(f"Proxmox action failed: {e}")

    # Prefer actual Proxmox state after command (with short wait)
    newStatus = {"start": "running", "stop": "stopped", "restart": "running"}.get(action, "error")
    for _ in range(8):
        time.sleep(0.4)
        try:
            cur = pveclient.getlxcstatus(pve, node_name, vmid) or {}
            live = (cur.get("status") or "").lower()
            mapped = _PROXMOX_TO_PANEL.get(live)
            if mapped:
                if action == "start" and mapped == "running":
                    newStatus = "running"
                    break
                if action == "stop" and mapped == "stopped":
                    newStatus = "stopped"
                    break
                if action == "restart" and mapped == "running":
                    newStatus = "running"
                    break
                newStatus = mapped
        except Exception:
            break

    db.updatevps(vps['uuid'], status=newStatus)
    return {"status": newStatus}

def formatbytes(value):
    try:
        value = float(value or 0)
    except (TypeError, ValueError):
        return "0B"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f}{unit}" if unit != "B" else f"{int(value)}B"
        value /= 1024


def getlatestvpsmetric(vpsId, details=None):
    """Fetch live metrics from Proxmox (status.current only — no RRD)."""
    _, metrics = fetchlivevps(vpsId, details=details)
    return metrics

def listfirewallrulesforvps(vpsId):
    """Placeholder for firewall logic."""
    return []

def generaterandomhostname():
    suffix = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    return f"vps-{suffix}"

def generaterandompassword():
    return secrets.token_urlsafe(16)

def getproxmoxclient(node, timeout=10):
    """Create a ProxmoxAPI client from node config."""
    return pveclient.getproxmoxclient(node, timeout=timeout)

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

        with db.getconnection() as conn:
            net = conn.execute("SELECT * FROM proxmox_networks WHERE id = ?", (vps['networkid'],)).fetchone()
        net = dict(net) if net else {}

        if net.get('name'):
            bridgeName = net['name']
        ipv4Gateway = net.get('ipv4_gateway')
        ipv6Gateway = net.get('ipv6_gateway') or net.get('gateway')
        if net.get('dns'):
            networkDns = net['dns']

        needsIpv6 = bool(vpsDetails.get('plan_ipv6'))
        needsIpv4 = bool(vpsDetails.get('plan_ipv4'))
        if needsIpv6 and not net.get('ipv6'):
            raise ValueError("Plan requires IPv6 but network does not support it")
        if needsIpv4 and not net.get('ipv4'):
            raise ValueError("Plan requires IPv4 but network does not support it")

        held = db.getassignedipsforvps(vps['id'])
        if held.get('ipv6'):
            assignedIpv6 = held['ipv6']['ip']
            assignedIpIds.append((held['ipv6']['id'], 'ipv6'))
        if held.get('ipv4'):
            assignedIpv4 = held['ipv4']['ip']
            assignedIpIds.append((held['ipv4']['id'], 'ipv4'))

        if needsIpv6 and not assignedIpv6:
            availIpv6 = db.reserveipbyversion(vps['networkid'], network_type=netType, version='ipv6', vpsid=vps['id'])
            if not availIpv6:
                raise ValueError("No IPv6 addresses available for this network")
            assignedIpv6 = availIpv6['ip']
            assignedIpIds.append((availIpv6['id'], 'ipv6'))

        if needsIpv4 and not assignedIpv4:
            availIpv4 = db.reserveipbyversion(vps['networkid'], network_type=netType, version='ipv4', vpsid=vps['id'])
            if not availIpv4:
                for ipId, ipVersion in assignedIpIds:
                    db.unassignip(ipId, ipVersion)
                raise ValueError("No IPv4 addresses available for this network")
            assignedIpv4 = availIpv4['ip']
            assignedIpIds.append((availIpv4['id'], 'ipv4'))

    assignedIp = assignedIpv6 or assignedIpv4

    # Get Proxmox client
    pve = getproxmoxclient(node)

    # Get next VMID
    vmid = pveclient.nextvmid(pve)
    if not vmid:
        for ipId, ipVersion in assignedIpIds:
            db.unassignip(ipId, ipVersion)
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
        "net0": f"name=eth0,bridge={bridgeName}",
        "onboot": 1,
        "swap": int(vps.get('swap', 0)),
        "features": "nesting=1",
    }

    # Set DNS if configured on network
    if networkDns:
        lxc_params["nameserver"] = networkDns

    # Plan netmbps is Mbps; Proxmox net0 rate is MB/s
    netRateMbps = int(vpsDetails.get("netmbps") or 0)
    ratePart = f",rate={max(netRateMbps / 8.0, 0.001):.3f}" if netRateMbps > 0 else ""

    # If we have a specific IP, set it with gateway
    if assignedIpv6 and assignedIpv4:
        gw6 = f",gw6={ipv6Gateway}" if ipv6Gateway else ""
        gw4 = f",gw={ipv4Gateway}" if ipv4Gateway else ""
        lxc_params["net0"] = f"name=eth0,bridge={bridgeName},ip6={assignedIpv6}/64{gw6},ip={assignedIpv4}/24{gw4}{ratePart}"
    elif assignedIpv6:
        gw = f",gw6={ipv6Gateway}" if ipv6Gateway else ""
        lxc_params["net0"] = f"name=eth0,bridge={bridgeName},ip6={assignedIpv6}/64{gw}{ratePart}"
    elif assignedIpv4:
        gw = f",gw={ipv4Gateway}" if ipv4Gateway else ""
        lxc_params["net0"] = f"name=eth0,bridge={bridgeName},ip={assignedIpv4}/24{gw}{ratePart}"
    elif ratePart:
        lxc_params["net0"] = f"name=eth0,bridge={bridgeName}{ratePart}"

    # Create LXC
    try:
        pveclient.createlxc(pve, node_name, vmid, lxc_params)
    except Exception as e:
        for ipId, ipVersion in assignedIpIds:
            db.unassignip(ipId, ipVersion)
        db.updatevps(vpsUuid, status='error')
        raise ValueError(f"LXC creation failed: {e}")

    # Start LXC
    time.sleep(1)
    try:
        pveclient.startlxc(pve, node_name, vmid)
    except Exception as e:
        for ipId, ipVersion in assignedIpIds:
            db.unassignip(ipId, ipVersion)
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


def is_tun_enabled_for_lxc(node_id, vmid):
    """Checks if TUN is already enabled for a Proxmox LXC container."""
    node = db.getnodebyid(node_id)
    if not node:
        raise ValueError("Node not found")
    
    pve = getproxmoxclient(node)
    try:
        config = pve.nodes(node['proxmoxnode']).lxc(vmid).config.get()
        return "dev0" in config and "path=/dev/net/tun" in config.get("dev0", "")
    except Exception as e:
        raise Exception(f"Failed to check TUN status: {str(e)}")


def enable_tun_for_lxc(node_id, vmid):
    """Enables TUN device for a Proxmox LXC container using the `dev0` parameter (no confirmation)."""
    if is_tun_enabled_for_lxc(node_id, vmid):
        raise ValueError("TUN is already enabled for this VPS.")

    node = db.getnodebyid(node_id)
    if not node:
        raise ValueError("Node not found")

    pve = getproxmoxclient(node)
    try:
        pve.nodes(node['proxmoxnode']).lxc(vmid).status.stop.post()
        while True:
            status = pve.nodes(node['proxmoxnode']).lxc(vmid).status.current.get().get("status")
            if status == "stopped":
                break
            time.sleep(1)

        pve.nodes(node['proxmoxnode']).lxc(vmid).config.put(dev0="path=/dev/net/tun")
        pve.nodes(node['proxmoxnode']).lxc(vmid).status.start.post()
    except Exception as e:
        raise Exception(f"Failed to enable TUN: {str(e)}")
