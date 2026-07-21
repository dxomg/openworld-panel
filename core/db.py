import sqlite3
import math
import uuid
import random

def getconnection():
    conn = sqlite3.connect("database.db")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn

# --- USER FUNCTIONS ---

def adduser(uuid, username, password, discordid=None, email=None, role='user', status='active', verified=0):
    with getconnection() as conn:
        conn.execute(
            """INSERT INTO users (uuid, discordid, username, email, password, role, status, verified) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", 
            (uuid, discordid, username, email, password, role, status, verified)
        )

def getuser(uuid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM users WHERE uuid = ?", (uuid,)).fetchone()
        return dict(row) if row else None

def getuserbyid(userid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (userid,)).fetchone()
        return dict(row) if row else None

def getuserbyemail(email):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        return dict(row) if row else None

def getuserbydiscord(discordid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM users WHERE discordid = ?", (discordid,)).fetchone()
        return dict(row) if row else None

def updateuser(identifier, **kwargs):
    with getconnection() as conn:
        keys = [f"{k} = ?" for k in kwargs.keys()]
        values = list(kwargs.values()) + [identifier]
        
        # Check if the identifier is just numbers (an ID) or a string (a UUID)
        if str(identifier).isdigit():
            whereClause = "WHERE id = ?"
        else:
            whereClause = "WHERE uuid = ?"
            
        conn.execute(f"UPDATE users SET {', '.join(keys)}, updated = CURRENT_TIMESTAMP {whereClause}", values)

def removeuser(uuid):
    with getconnection() as conn:
        conn.execute("DELETE FROM users WHERE uuid = ?", (uuid,))

# --- BAN FUNCTIONS ---

def addban(uuid, userid, adminid, reason, expires=None):
    with getconnection() as conn:
        conn.execute("INSERT INTO bans (uuid, userid, adminid, reason, expires) VALUES (?, ?, ?, ?, ?)", 
                     (uuid, userid, adminid, reason, expires))

def getban(uuid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM bans WHERE uuid = ?", (uuid,)).fetchone()
        return dict(row) if row else None

def getbanbyuserid(userid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM bans WHERE userid = ? ORDER BY created DESC LIMIT 1", (userid,)).fetchone()
        return dict(row) if row else None

def removeban(uuid):
    with getconnection() as conn:
        conn.execute("DELETE FROM bans WHERE uuid = ?", (uuid,))

# --- PLAN FUNCTIONS ---

def addplan(uuid, name, cpu, ram, swap, disk, description=None, ipv4=0, ipv6=1, price=0.0, active=1, stock=-1, readbps=0, writebps=0):
    with getconnection() as conn:
        conn.execute(
            """INSERT INTO plans (uuid, name, cpu, ram, swap, disk, description, ipv4, ipv6, price, active, stock, readbps, writebps) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
            (uuid, name, cpu, ram, swap, disk, description, ipv4, ipv6, price, active, stock, readbps, writebps)
        )
        
def updateplan(uuid, name, cpu, ram, swap, disk, description=None, ipv4=0, ipv6=1, price=0.0, active=1, stock=-1, readbps=0, writebps=0):
    with getconnection() as conn:
        conn.execute(
            """UPDATE plans 
               SET name = ?, cpu = ?, ram = ?, swap = ?, disk = ?, 
                   description = ?, ipv4 = ?, ipv6 = ?, price = ?, 
                   active = ?, stock = ?, readbps = ?, writebps = ?,
                   updated = CURRENT_TIMESTAMP 
               WHERE uuid = ?""",
            (name, cpu, ram, swap, disk, description, ipv4, ipv6, price, active, stock, readbps, writebps, uuid)
        )
def getplan(uuid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM plans WHERE uuid = ?", (uuid,)).fetchone()
        return dict(row) if row else None

def listplans(active=None):
    with getconnection() as conn:
        if active is not None:
            rows = conn.execute("SELECT * FROM plans WHERE active = ?", (active,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM plans").fetchall()
        return [dict(r) for r in rows]
    
def removeplan(uuid):
    with getconnection() as conn:
        conn.execute("DELETE FROM plans WHERE uuid = ?", (uuid,))

def decrementplanstock(planid):
    """Decrements stock by 1. Returns True if stock was available, False if out of stock."""
    with getconnection() as conn:
        row = conn.execute("SELECT stock FROM plans WHERE id = ?", (planid,)).fetchone()
        if not row:
            return False
        stock = row['stock']
        if stock == 0:
            return False
        if stock > 0:
            conn.execute("UPDATE plans SET stock = stock - 1, updated = CURRENT_TIMESTAMP WHERE id = ?", (planid,))
        return True  # stock == -1 means unlimited

def userhasfreevps(userid):
    """Check if user already has a VPS on a free plan (price = 0)."""
    with getconnection() as conn:
        row = conn.execute("""
            SELECT COUNT(*) FROM vps v
            JOIN plans p ON v.planid = p.id
            WHERE v.userid = ? AND p.price = 0 AND v.status != 'deleted'
        """, (userid,)).fetchone()
        return row[0] > 0

# --- IMAGE FUNCTIONS ---

def addimage(uuid, name, image, description=None, active=1, node_type='docker'):
    with getconnection() as conn:
        conn.execute("INSERT INTO images (uuid, name, image, description, active, node_type) VALUES (?, ?, ?, ?, ?, ?)", 
                     (uuid, name, image, description, active, node_type))

def getimage(uuid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM images WHERE uuid = ?", (uuid,)).fetchone()
        return dict(row) if row else None

def getimagebyid(imageid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM images WHERE id = ?", (imageid,)).fetchone()
        return dict(row) if row else None

def listimages(active=None, node_type=None):
    with getconnection() as conn:
        if active is not None and node_type:
            rows = conn.execute("SELECT * FROM images WHERE active = ? AND node_type = ?", (active, node_type)).fetchall()
        elif active is not None:
            rows = conn.execute("SELECT * FROM images WHERE active = ?", (active,)).fetchall()
        elif node_type:
            rows = conn.execute("SELECT * FROM images WHERE node_type = ?", (node_type,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM images").fetchall()
        return [dict(r) for r in rows]

# --- NODE FUNCTIONS ---

def addnode(uuid, name, hostname, address, apikey, cpu, ram, disk, status, tier, url='', nodeType='docker',
            proxmoxhost=None, proxmoxuser=None, proxmoxpassword=None, proxmoxnode='pve', proxmoxport=8006, proxmoxssl=0):
    with getconnection() as conn:
        conn.execute("""
            INSERT INTO nodes (uuid, name, hostname, address, url, apikey, type, cpu, ram, disk, status, tier,
                               proxmoxhost, proxmoxuser, proxmoxpassword, proxmoxnode, proxmoxport, proxmoxssl)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (uuid, name, hostname, address, url, apikey, nodeType, cpu, ram, disk, status, tier,
              proxmoxhost, proxmoxuser, proxmoxpassword, proxmoxnode, proxmoxport, proxmoxssl))

def getnode(uuid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM nodes WHERE uuid = ?", (uuid,)).fetchone()
        return dict(row) if row else None

# --- NETWORK FUNCTIONS ---

def addstoragepool(uuid, nodeid, name, source=None, size=0, nodeType='proxmox'):
    with getconnection() as conn:
        conn.execute("""
            INSERT INTO storagepools (uuid, nodeid, name, source, size, node_type)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (uuid, nodeid, name, source, size, nodeType))

def getstoragepool(uuid):
    with getconnection() as conn:
        row = conn.execute("""
            SELECT sp.*, nd.name as node_name
            FROM storagepools sp
            JOIN nodes nd ON sp.nodeid = nd.id
            WHERE sp.uuid = ?
        """, (uuid,)).fetchone()
        return dict(row) if row else None

def removestoragepool(uuid):
    with getconnection() as conn:
        conn.execute("DELETE FROM storagepools WHERE uuid = ?", (uuid,))

def updatestoragepool(uuid, **kwargs):
    with getconnection() as conn:
        keys = [f"{k} = ?" for k in kwargs.keys()]
        values = list(kwargs.values()) + [uuid]
        conn.execute(f"UPDATE storagepools SET {', '.join(keys)}, updated = CURRENT_TIMESTAMP WHERE uuid = ?", values)

def liststoragepools(nodeid=None, nodeType=None):
    with getconnection() as conn:
        if nodeid:
            rows = conn.execute("""
                SELECT sp.*, nd.name as node_name
                FROM storagepools sp
                JOIN nodes nd ON sp.nodeid = nd.id
                WHERE sp.nodeid = ?
                ORDER BY sp.created DESC
            """, (nodeid,)).fetchall()
        elif nodeType:
            rows = conn.execute("""
                SELECT sp.*, nd.name as node_name
                FROM storagepools sp
                JOIN nodes nd ON sp.nodeid = nd.id
                WHERE sp.node_type = ?
                ORDER BY sp.created DESC
            """, (nodeType,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT sp.*, nd.name as node_name
                FROM storagepools sp
                JOIN nodes nd ON sp.nodeid = nd.id
                ORDER BY sp.created DESC
            """).fetchall()
        return [dict(r) for r in rows]

def liststoragepoolspaginated(page=1, perpage=12, search=None, nodeType=None):
    with getconnection() as conn:
        offset = (page - 1) * perpage
        where = ""
        params = []
        if nodeType:
            where = "WHERE sp.node_type = ?"
            params.append(nodeType)
        if search:
            where = ("WHERE " if not where else where + " AND ") + "(sp.name LIKE ? OR nd.name LIKE ?)"
            s = f"%{search}%"
            params.extend([s, s])
        total = conn.execute(f"""
            SELECT COUNT(*) FROM storagepools sp
            JOIN nodes nd ON sp.nodeid = nd.id
            {where}
        """, params).fetchone()[0]
        rows = conn.execute(f"""
            SELECT sp.*, nd.name as node_name
            FROM storagepools sp
            JOIN nodes nd ON sp.nodeid = nd.id
            {where}
            ORDER BY sp.created DESC
            LIMIT ? OFFSET ?
        """, params + [perpage, offset]).fetchall()
        return {
            "pools": [dict(r) for r in rows],
            "totalCount": total,
            "currentPage": page,
            "perPage": perpage,
            "totalPages": math.ceil(total / perpage) if perpage else 1,
            "hasPrev": page > 1,
            "hasNext": (page * perpage) < total,
        }

def getstoragepoolbyname(name):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM storagepools WHERE name = ?", (name,)).fetchone()
        return dict(row) if row else None

def getstoragepoolbyid(poolid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM storagepools WHERE id = ?", (poolid,)).fetchone()
        return dict(row) if row else None

def decreasestorageavailable(poolid, diskmb):
    """Decrease available storage when a VPS is created (diskmb in MB)."""
    with getconnection() as conn:
        conn.execute("UPDATE storagepools SET used = used + ?, updated = CURRENT_TIMESTAMP WHERE id = ?", (diskmb, poolid))

def increasestorageavailable(poolid, diskmb):
    """Increase available storage when a VPS is deleted (diskmb in MB)."""
    with getconnection() as conn:
        conn.execute("UPDATE storagepools SET used = MAX(0, used - ?), updated = CURRENT_TIMESTAMP WHERE id = ?", (diskmb, poolid))

# --- NETWORK FUNCTIONS ---

def _nettable(network_type):
    return "proxmox_networks" if network_type == "proxmox" else "docker_networks"

def addnetwork(uuid, nodeid, name, network_type='docker', subnet=None, gateway=None, ipv4=0, ipv6=1, ipv4_subnet=None, ipv4_gateway=None, dns='1.1.1.1,8.8.8.8,2606:4700:4700::1111,2001:4860:4860::8888'):
    table = _nettable(network_type)
    with getconnection() as conn:
        conn.execute(f"""
            INSERT INTO {table} (uuid, nodeid, name, subnet, gateway, ipv4, ipv6, ipv4_subnet, ipv4_gateway, dns)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (uuid, nodeid, name, subnet, gateway, ipv4, ipv6, ipv4_subnet, ipv4_gateway, dns))

def getnetwork(uuid, network_type='docker'):
    table = _nettable(network_type)
    with getconnection() as conn:
        row = conn.execute(f"""
            SELECT n.*, nd.name as node_name, nd.address as node_address
            FROM {table} n
            JOIN nodes nd ON n.nodeid = nd.id
            WHERE n.uuid = ?
        """, (uuid,)).fetchone()
        return dict(row) if row else None

def getnetworkbyid(networkid, network_type='docker'):
    table = _nettable(network_type)
    with getconnection() as conn:
        row = conn.execute(f"""
            SELECT n.*, nd.name as node_name, nd.address as node_address
            FROM {table} n
            JOIN nodes nd ON n.nodeid = nd.id
            WHERE n.id = ?
        """, (networkid,)).fetchone()
        return dict(row) if row else None

def removenetwork(uuid, network_type='docker'):
    table = _nettable(network_type)
    with getconnection() as conn:
        conn.execute(f"DELETE FROM {table} WHERE uuid = ?", (uuid,))

def listnetworks(nodeid=None, network_type=None):
    with getconnection() as conn:
        if network_type:
            table = _nettable(network_type)
            if nodeid:
                rows = conn.execute(f"""
                    SELECT n.*, nd.name as node_name
                    FROM {table} n
                    JOIN nodes nd ON n.nodeid = nd.id
                    WHERE n.nodeid = ?
                    ORDER BY n.created DESC
                """, (nodeid,)).fetchall()
            else:
                rows = conn.execute(f"""
                    SELECT n.*, nd.name as node_name
                    FROM {table} n
                    JOIN nodes nd ON n.nodeid = nd.id
                    ORDER BY n.created DESC
                """).fetchall()
            result = [dict(r) for r in rows]
            for r in result:
                r['network_type'] = network_type
        else:
            result = []
            for t in ('docker_networks', 'proxmox_networks'):
                ntype = 'proxmox' if 'proxmox' in t else 'docker'
                if nodeid:
                    r = conn.execute(f"""
                        SELECT n.*, nd.name as node_name
                        FROM {t} n
                        JOIN nodes nd ON n.nodeid = nd.id
                        WHERE n.nodeid = ?
                        ORDER BY n.created DESC
                    """, (nodeid,)).fetchall()
                else:
                    r = conn.execute(f"""
                        SELECT n.*, nd.name as node_name
                        FROM {t} n
                        JOIN nodes nd ON n.nodeid = nd.id
                        ORDER BY n.created DESC
                    """).fetchall()
                for row in r:
                    d = dict(row)
                    d['network_type'] = ntype
                    result.append(d)
            result.sort(key=lambda x: x['created'] if x['created'] else '', reverse=True)
        return result

def listnetworkspaginated(page=1, perpage=12, search=None, network_type=None):
    with getconnection() as conn:
        offset = (page - 1) * perpage
        if network_type:
            table = _nettable(network_type)
            where = ""
            params = []
            if search:
                where = "WHERE (n.name LIKE ? OR nd.name LIKE ? OR n.subnet LIKE ?)"
                s = f"%{search}%"
                params = [s, s, s]
            total = conn.execute(f"""
                SELECT COUNT(*) FROM {table} n
                JOIN nodes nd ON n.nodeid = nd.id
                {where}
            """, params).fetchone()[0]
            rows = conn.execute(f"""
                SELECT n.*, nd.name as node_name
                FROM {table} n
                JOIN nodes nd ON n.nodeid = nd.id
                {where}
                ORDER BY n.created DESC
                LIMIT ? OFFSET ?
            """, params + [perpage, offset]).fetchall()
            result = [dict(r) for r in rows]
            for r in result:
                r['network_type'] = network_type
        else:
            where = ""
            params = []
            if search:
                where = "WHERE (n.name LIKE ? OR nd.name LIKE ? OR n.subnet LIKE ?)"
                s = f"%{search}%"
                params = [s, s, s]
            total = 0
            result = []
            for t in ('docker_networks', 'proxmox_networks'):
                ntype = 'proxmox' if 'proxmox' in t else 'docker'
                cnt = conn.execute(f"""
                    SELECT COUNT(*) FROM {t} n
                    JOIN nodes nd ON n.nodeid = nd.id
                    {where}
                """, params).fetchone()[0]
                total += cnt
                r = conn.execute(f"""
                    SELECT n.*, nd.name as node_name
                    FROM {t} n
                    JOIN nodes nd ON n.nodeid = nd.id
                    {where}
                    ORDER BY n.created DESC
                    LIMIT ? OFFSET ?
                """, params + [perpage, offset]).fetchall()
                for row in r:
                    d = dict(row)
                    d['network_type'] = ntype
                    result.append(d)
            result.sort(key=lambda x: x['created'] if x['created'] else '', reverse=True)
            result = result[:perpage]
        return {
            "networks": result,
            "totalCount": total,
            "currentPage": page,
            "perPage": perpage,
            "totalPages": math.ceil(total / perpage) if perpage else 1,
            "hasPrev": page > 1,
            "hasNext": (page * perpage) < total,
        }

def getnetworkbynamenodeid(name, nodeid, network_type='docker'):
    table = _nettable(network_type)
    with getconnection() as conn:
        row = conn.execute(f"SELECT * FROM {table} WHERE name = ? AND nodeid = ?", (name, nodeid)).fetchone()
        return dict(row) if row else None

def countvpsbynetwork(networkid, network_type='docker'):
    with getconnection() as conn:
        row = conn.execute("SELECT COUNT(*) FROM vps WHERE networkid = ? AND network_type = ?", (networkid, network_type)).fetchone()
        return row[0] if row else 0

# --- NETWORK IP FUNCTIONS ---

def addnetworkip(uuid, networkid, ip, network_type='docker'):
    with getconnection() as conn:
        conn.execute("""
            INSERT INTO networkips (uuid, networkid, network_type, ip)
            VALUES (?, ?, ?, ?)
        """, (uuid, networkid, network_type, ip))

def getnetworkip(uuid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM networkips WHERE uuid = ?", (uuid,)).fetchone()
        return dict(row) if row else None

def removenetworkip(uuid):
    with getconnection() as conn:
        conn.execute("DELETE FROM networkips WHERE uuid = ?", (uuid,))

def listnetworkips(networkid, network_type='docker', page=1, perpage=50, search=None):
    with getconnection() as conn:
        offset = (page - 1) * perpage
        where = "WHERE ni.networkid = ? AND ni.network_type = ?"
        params = [networkid, network_type]
        if search:
            where += " AND ni.ip LIKE ?"
            params.append(f"%{search}%")
        total = conn.execute(f"SELECT COUNT(*) FROM networkips ni {where}", params).fetchone()[0]
        rows = conn.execute(f"""
            SELECT ni.*, v.hostname as vps_hostname
            FROM networkips ni
            LEFT JOIN vps v ON ni.vpsid = v.id
            {where}
            ORDER BY ni.ip ASC
            LIMIT ? OFFSET ?
        """, params + [perpage, offset]).fetchall()
        return {
            "ips": [dict(r) for r in rows],
            "totalCount": total,
            "currentPage": page,
            "perPage": perpage,
            "totalPages": math.ceil(total / perpage) if perpage else 1,
            "hasPrev": page > 1,
            "hasNext": (page * perpage) < total,
        }

def getavailableip(networkid, network_type='docker'):
    """Get the first available (unassigned) IP for a network."""
    with getconnection() as conn:
        row = conn.execute("""
            SELECT * FROM networkips
            WHERE networkid = ? AND network_type = ? AND assigned = 0
            ORDER BY ip ASC
            LIMIT 1
        """, (networkid, network_type)).fetchone()
        return dict(row) if row else None

def getavailableipbyversion(networkid, network_type='docker', version='ipv6'):
    """Get an available IP filtered by IPv4 or IPv6."""
    with getconnection() as conn:
        if version == 'ipv4':
            row = conn.execute("""
                SELECT * FROM networkips
                WHERE networkid = ? AND network_type = ? AND assigned = 0 AND ip NOT LIKE '%:%'
                ORDER BY ip ASC
                LIMIT 1
            """, (networkid, network_type)).fetchone()
        else:
            row = conn.execute("""
                SELECT * FROM networkips
                WHERE networkid = ? AND network_type = ? AND assigned = 0 AND ip LIKE '%:%'
                ORDER BY ip ASC
                LIMIT 1
            """, (networkid, network_type)).fetchone()
        return dict(row) if row else None

def assignip(ipid, vpsid):
    """Mark an IP as assigned to a VPS."""
    with getconnection() as conn:
        conn.execute("""
            UPDATE networkips SET assigned = 1, vpsid = ? WHERE id = ?
        """, (vpsid, ipid))

def unassignip(ipid):
    """Mark an IP as available again."""
    with getconnection() as conn:
        conn.execute("""
            UPDATE networkips SET assigned = 0, vpsid = NULL WHERE id = ?
        """, (ipid,))

def unassignipbyvpsid(vpsid):
    """Release IP when a VPS is deleted."""
    with getconnection() as conn:
        conn.execute("""
            UPDATE networkips SET assigned = 0, vpsid = NULL WHERE vpsid = ?
        """, (vpsid,))

def countips(networkid, network_type='docker'):
    with getconnection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM networkips WHERE networkid = ? AND network_type = ?", (networkid, network_type)).fetchone()[0]
        assigned = conn.execute("SELECT COUNT(*) FROM networkips WHERE networkid = ? AND network_type = ? AND assigned = 1", (networkid, network_type)).fetchone()[0]
        return {"total": total, "assigned": assigned, "available": total - assigned}

def generateipsfornetwork(networkid, baseip, count, network_type='docker', isipv6=False):
    """Generate a range of IPs for a network."""
    import ipaddress
    generated = []
    try:
        if isipv6:
            base = ipaddress.IPv6Address(baseip)
        else:
            base = ipaddress.IPv4Address(baseip)
    except ValueError:
        return generated

    with getconnection() as conn:
        for i in range(count):
            ip = str(base + i)
            ipuuid = str(uuid.uuid4())
            try:
                conn.execute("""
                    INSERT INTO networkips (uuid, networkid, network_type, ip)
                    VALUES (?, ?, ?, ?)
                """, (ipuuid, networkid, network_type, ip))
                generated.append(ip)
            except Exception:
                continue  # Skip duplicates
    return generated

# --- VPS FUNCTIONS ---

def addvps(uuid, userid, planid, imageid, nodeid, storageid, hostname, password, cpu, ram, swap, disk, status='creating', networkid=None, network_type='docker', storagepoolid=None):
    with getconnection() as conn:
        conn.execute(
            """INSERT INTO vps (uuid, userid, planid, imageid, nodeid, storageid, networkid, network_type, storagepoolid, hostname, password, cpu, ram, swap, disk, status) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
            (uuid, userid, planid, imageid, nodeid, storageid, networkid, network_type, storagepoolid, hostname, password, cpu, ram, swap, disk, status)
        )

def getvps(uuid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM vps WHERE uuid = ?", (uuid,)).fetchone()
        return dict(row) if row else None

def getallocatedresources():
    with getconnection() as conn:
        row = conn.execute("SELECT SUM(cpu), SUM(ram), SUM(disk) FROM vps").fetchone()
    return {
        "cpu": row[0] or 0,
        "ram_gb": round((row[1] or 0) / 1024, 1) or 0,
        "disk": round((row[2] or 0) / 1024, 1) or 0
    }

def countusers():
    with getconnection() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

def countvps(userid=None):
    with getconnection() as conn:
        if userid is not None:
            return conn.execute("SELECT COUNT(*) FROM vps WHERE userid = ?", (userid,)).fetchone()[0]
        return conn.execute("SELECT COUNT(*) FROM vps").fetchone()[0]

def updatevps(uuid, **kwargs):
    with getconnection() as conn:
        keys = [f"{k} = ?" for k in kwargs.keys()]
        values = list(kwargs.values()) + [uuid]
        conn.execute(f"UPDATE vps SET {', '.join(keys)}, updated = CURRENT_TIMESTAMP WHERE uuid = ?", values)

# --- SESSION FUNCTIONS ---

def addsession(uuid, userid, token, expires, ip=None, agent=None):
    with getconnection() as conn:
        conn.execute("INSERT INTO sessions (uuid, userid, token, expires, ip, agent) VALUES (?, ?, ?, ?, ?, ?)", 
                     (uuid, userid, token, expires, ip, agent))

def getsession(token):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()
        return dict(row) if row else None

def removesession(token):
    with getconnection() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))

def getnodebyid(nodeid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM nodes WHERE id = ?", (nodeid,)).fetchone()
        return dict(row) if row else None

def getvpsbyid(vpsid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM vps WHERE id = ?", (vpsid,)).fetchone()
        return dict(row) if row else None
    
#Web shit

def listuserspaginated(page=1, perpage=20, search=None):
    offset = (page - 1) * perpage
    where = ""
    params = []
    if search:
        where = "WHERE username LIKE ? OR email LIKE ? OR role LIKE ? OR status LIKE ?"
        s = f"%{search}%"
        params = [s, s, s, s]

    with getconnection() as conn:
        totalUsers = conn.execute(f"SELECT COUNT(*) FROM users {where}", params).fetchone()[0]
        cursor = conn.execute(
            f"""
            SELECT id, uuid, discordid, username, email, role, status, verified, created
            FROM users 
            {where}
            ORDER BY created DESC
            LIMIT ? OFFSET ?
            """, 
            params + [perpage, offset]
        )
        users = [dict(row) for row in cursor.fetchall()]

    for user in users:
        if user["status"] == "banned":
            user["active_ban"] = getbanbyuserid(user["id"])
        else:
            user["active_ban"] = None

    return {
        "users": users,
        "currentPage": page,
        "totalPages": math.ceil(totalUsers / perpage) if totalUsers else 1,
        "hasNext": page < math.ceil(totalUsers / perpage),
        "hasPrev": page > 1
    }
def listvpspaginated(page=1, perpage=20, userid=None, search=None):
    offset = (page - 1) * perpage
    
    with getconnection() as conn:
        baseCount = "SELECT COUNT(*) FROM vps v"
        dataQuery = """
            SELECT 
                v.*, 
                u.username as owner_name, 
                p.name as plan_name, 
                n.name as node_name, 
                i.name as image_name
            FROM vps v
            JOIN users u ON v.userid = u.id
            JOIN plans p ON v.planid = p.id
            JOIN nodes n ON v.nodeid = n.id
            JOIN images i ON v.imageid = i.id
        """
        
        params = []
        conditions = []
        joins = ""
        
        if userid:
            conditions.append("v.userid = ?")
            params.append(userid)
        
        if search:
            joins = " JOIN users u ON v.userid = u.id JOIN nodes n ON v.nodeid = n.id"
            conditions.append("(v.hostname LIKE ? OR v.ipv6 LIKE ? OR u.username LIKE ? OR v.status LIKE ? OR n.name LIKE ?)")
            s = f"%{search}%"
            params.extend([s, s, s, s, s])

        whereClause = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        
        totalVps = conn.execute(baseCount + joins + whereClause, params).fetchone()[0]
        
        finalQuery = dataQuery + whereClause + " ORDER BY v.created DESC LIMIT ? OFFSET ?"
        cursor = conn.execute(finalQuery, params + [perpage, offset])
        
        vpsList = [dict(row) for row in cursor.fetchall()]

    for vps in vpsList:
        if vps["status"] == "suspended":
            vps["suspension_details"] = getsuspensionbyvpsid(vps["id"])
        else:
            vps["suspension_details"] = None

    # Calculate total pages
    totalPages = math.ceil(totalVps / perpage) if totalVps > 0 else 1

    return {
        "vps": vpsList,
        "currentPage": page,
        "totalPages": totalPages,
        "totalCount": totalVps,
        "hasNext": page < totalPages,
        "hasPrev": page > 1
    }
def listallusers():
    """Returns a simple list of all users for dropdown selection."""
    with getconnection() as conn:
        rows = conn.execute("SELECT id, username FROM users ORDER BY username ASC").fetchall()
        return [dict(r) for r in rows]

def getsuspensionbyvpsid(vpsid):
    """Used by listvpspaginated to show suspension reasons."""
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM vpssuspensions WHERE vpsid = ? AND lifted IS NULL", (vpsid,)).fetchone()
        return dict(row) if row else None
    
def getplanbyid(planid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM plans WHERE id = ?", (planid,)).fetchone()
        return dict(row) if row else None
    
def listallnodes():
    with getconnection() as conn:
        # Join with a count of VPS instances currently on that node
        rows = conn.execute("""
            SELECT n.*, 
            (SELECT COUNT(*) FROM vps WHERE nodeid = n.id) as vps_count
            FROM nodes n
        """).fetchall()
        return [dict(r) for r in rows]

def updatenode(uuid, **kwargs):
    with getconnection() as conn:
        keys = [f"{k} = ?" for k in kwargs.keys()]
        values = list(kwargs.values()) + [uuid]
        conn.execute(f"UPDATE nodes SET {', '.join(keys)}, updated = CURRENT_TIMESTAMP WHERE uuid = ?", values)

def removenode(uuid):
    with getconnection() as conn:
        conn.execute("DELETE FROM nodes WHERE uuid = ?", (uuid,))

def addpaymentmethod(uuid, name, slug, active=1):
    with getconnection() as conn:
        conn.execute(
            """INSERT INTO paymentmethods (uuid, name, slug, active) 
               VALUES (?, ?, ?, ?)""",
            (uuid, name, slug, active)
        )


def listallpaymentmethods():
    with getconnection() as conn:
        rows = conn.execute(
            """SELECT p.*,
                      COUNT(t.id) AS transaction_count,
                      COALESCE(SUM(CASE WHEN t.status = 'completed' THEN t.amount ELSE 0 END), 0) AS total_amount
               FROM paymentmethods p
               LEFT JOIN transactions t ON t.paymentprocessorid = p.id
               GROUP BY p.id
               ORDER BY p.created DESC"""
        ).fetchall()
        return [dict(row) for row in rows]


def getpaymentmethods(processorUuid):
    with getconnection() as conn:
        row = conn.execute(
            "SELECT * FROM paymentmethods WHERE uuid = ?", (processorUuid,)
        ).fetchone()
        return dict(row) if row else None


def updatepaymentmethods(processorUuid, **fields):
    if not fields:
        return
    setClause = ", ".join(f"{key} = ?" for key in fields)
    values = list(fields.values()) + [processorUuid]
    with getconnection() as conn:
        conn.execute(
            f"UPDATE paymentmethods SET {setClause}, updated = CURRENT_TIMESTAMP WHERE uuid = ?",
            values
        )


def removepaymentmethods(processorUuid):
    with getconnection() as conn:
        conn.execute("DELETE FROM paymentmethods WHERE uuid = ?", (processorUuid,))


def countactivepaymentmethods():
    with getconnection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM paymentmethods WHERE active = 1"
        ).fetchone()
        return row["cnt"] if row else 0


def gettransactionstats():
    with getconnection() as conn:
        row = conn.execute(
            """SELECT COUNT(*) AS total_transactions,
                      COALESCE(SUM(CASE WHEN status = 'completed' THEN amount ELSE 0 END), 0) AS total_revenue
               FROM transactions"""
        ).fetchone()
        return dict(row) if row else {"total_transactions": 0, "total_revenue": 0}
    
def getallreceipts():
    with getconnection() as conn:
        return conn.execute("""
            SELECT receipts.*, users.username, transactions.transactionid AS txn_public_id
            FROM receipts
            JOIN users ON users.id = receipts.userid
            LEFT JOIN transactions ON transactions.id = receipts.transactionid
            ORDER BY receipts.created DESC
        """).fetchall()

def geteligibletransactions():
    with getconnection() as conn:
        return conn.execute("""
            SELECT transactions.id, transactions.uuid, transactions.transactionid, 
                   transactions.amount, transactions.currency, users.username
            FROM transactions
            JOIN users ON users.id = transactions.userid
            LEFT JOIN receipts ON receipts.transactionid = transactions.id
            WHERE transactions.status = 'completed' AND receipts.id IS NULL
            ORDER BY transactions.created DESC
        """).fetchall()

def listtransactionspaginated(page=1, perpage=12, search=None):
    with getconnection() as conn:
        offset = (page - 1) * perpage
        where = ""
        params = []
        if search:
            where = "WHERE t.transactionid LIKE ? OR u.username LIKE ? OR t.status LIKE ? OR t.amount LIKE ? OR pm.name LIKE ?"
            s = f"%{search}%"
            params = [s, s, s, s, s]
        totalRow = conn.execute(f"SELECT COUNT(*) AS cnt FROM transactions t JOIN users u ON u.id = t.userid LEFT JOIN paymentmethods pm ON pm.id = t.paymentprocessorid {where}", params).fetchone()
        total = totalRow["cnt"] if totalRow else 0
        rows = conn.execute(f"""
            SELECT t.*, u.username AS owner_name,
                   pm.name AS payment_method_name
            FROM transactions t
            JOIN users u ON u.id = t.userid
            LEFT JOIN paymentmethods pm ON pm.id = t.paymentprocessorid
            {where}
            ORDER BY t.created DESC
            LIMIT ? OFFSET ?
        """, params + [perpage, offset]).fetchall()
        return {
            "transactions": [dict(row) for row in rows],
            "totalCount": total,
            "currentPage": page,
            "perPage": perpage,
            "totalPages": math.ceil(total / perpage) if perpage else 1,
            "hasPrev": page > 1,
            "hasNext": (page * perpage) < total,
        }

def gettransaction(tid):
    with getconnection() as conn:
        row = conn.execute("SELECT id, userid, status FROM transactions WHERE id = ?", (tid,)).fetchone()
        return dict(row) if row else None

def gettransactionbyuuid(uuid):
    with getconnection() as conn:
        row = conn.execute("SELECT id, userid, status FROM transactions WHERE uuid = ?", (uuid,)).fetchone()
        return dict(row) if row else None

def gettransactionbytxnid(transactionid):
    with getconnection() as conn:
        row = conn.execute("SELECT id, userid, status FROM transactions WHERE transactionid = ?", (transactionid,)).fetchone()
        return dict(row) if row else None

def addtransaction(uuid, userid, transactionid, amount, currency, status, paymentprocessorid, vpsid=None, planid=None):
    with getconnection() as conn:
        cur = conn.execute("""
            INSERT INTO transactions (uuid, userid, transactionid, amount, currency, status, paymentprocessorid, vpsid, planid)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (uuid, userid, transactionid, amount, currency, status, paymentprocessorid, vpsid, planid))
        txnId = cur.lastrowid

        # Auto-generate receipt for completed transactions
        if status == "completed" and txnId:
            user = conn.execute("SELECT username, email FROM users WHERE id = ?", (userid,)).fetchone()
            receiptCount = conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
            receiptNumber = f"RCP-{(receiptCount + 1):06d}"
            conn.execute("""
                INSERT INTO receipts (uuid, receiptnumber, transactionid, userid, amount, currency,
                                    taxamount, billingname, billingemail, billingaddress, notes)
                VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, NULL, ?)
            """, (str(uuid.uuid4()), receiptNumber, txnId, userid, float(amount), currency,
                  user['username'] if user else None, user['email'] if user else None,
                  f"Auto-generated for transaction {transactionid}"))

def getpaymentmethodbyslug(slug):
    with getconnection() as conn:
        row = conn.execute("SELECT id FROM paymentmethods WHERE slug = ?", (slug,)).fetchone()
        return dict(row) if row else None

def getreceiptbytransaction(tid):
    with getconnection() as conn:
        return conn.execute("SELECT id FROM receipts WHERE transactionid = ?", (tid,)).fetchone()

def getreceipt(uuid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM receipts WHERE uuid = ?", (uuid,)).fetchone()
        return dict(row) if row else None

def addreceipt(data):
    with getconnection() as conn:
        conn.execute("""
            INSERT INTO receipts (uuid, receiptnumber, transactionid, userid, amount, currency, 
                                taxamount, billingname, billingemail, billingaddress, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (str(uuid.uuid4()), data['receiptnumber'], data['transactionid'], data['userid'],
              data['amount'], data['currency'], data['taxamount'], data['billingname'], 
              data['billingemail'], data['billingaddress'], data['notes']))

def updatereceipt(uuid, data):
    with getconnection() as conn:
        conn.execute("""
            UPDATE receipts SET receiptnumber=?, amount=?, currency=?, taxamount=?, billingname=?,
                               billingemail=?, billingaddress=?, notes=?, updated=CURRENT_TIMESTAMP
            WHERE uuid = ?
        """, (data['receiptnumber'], data['amount'], data['currency'], data['taxamount'], 
              data['billingname'], data['billingemail'], data['billingaddress'], data['notes'], uuid))

def deletereceipt(uuid):
    with getconnection() as conn:
        conn.execute("DELETE FROM receipts WHERE uuid = ?", (uuid,))

def generatereceiptnumber():
    with getconnection() as conn:
        row = conn.execute("SELECT COUNT(*) FROM receipts").fetchone()
        count = (row[0] if row else 0) + 1
        return f"RCP-{count:06d}"

def gettransactionfull(tid):
    with getconnection() as conn:
        row = conn.execute("""
            SELECT t.*, u.username, pm.name as payment_method_name
            FROM transactions t
            JOIN users u ON u.id = t.userid
            LEFT JOIN paymentmethods pm ON pm.id = t.paymentprocessorid
            WHERE t.id = ?
        """, (tid,)).fetchone()
        return dict(row) if row else None


def getsuitablenodeandstorage(planPrice, strategy='both'):
    requiredTier = 'paid' if planPrice > 0 else 'free'
    
    with getconnection() as conn:
        if strategy == 'random':
            nodes = conn.execute(
                "SELECT id FROM nodes WHERE tier = ? AND status = 'online'", 
                (requiredTier,)
            ).fetchall()
            if not nodes:
                return None, None
            node_id = random.choice(nodes)['id']

        elif strategy == 'least_vps':
            row = conn.execute("""
                SELECT n.id
                FROM nodes n
                LEFT JOIN vps v ON v.nodeid = n.id AND v.status NOT IN ('deleted', 'error')
                WHERE n.tier = ? AND n.status = 'online'
                GROUP BY n.id
                ORDER BY COUNT(v.id) ASC
                LIMIT 1
            """, (requiredTier,)).fetchone()
            if not row:
                return None, None
            node_id = row['id']

        elif strategy == 'resources':
            row = conn.execute("""
                SELECT n.id
                FROM nodes n
                LEFT JOIN vps v ON v.nodeid = n.id AND v.status NOT IN ('deleted', 'error')
                WHERE n.tier = ? AND n.status = 'online'
                GROUP BY n.id
                HAVING n.ram > COALESCE(SUM(v.ram), 0)
                ORDER BY (n.ram - COALESCE(SUM(v.ram), 0)) DESC
                LIMIT 1
            """, (requiredTier,)).fetchone()
            if not row:
                return None, None
            node_id = row['id']

        else:  # 'both' (default)
            row = conn.execute("""
                SELECT n.id,
                       n.ram as total_ram,
                       COALESCE(SUM(v.ram), 0) as used_ram,
                       COUNT(v.id) as vps_count
                FROM nodes n
                LEFT JOIN vps v ON v.nodeid = n.id AND v.status NOT IN ('deleted', 'error')
                WHERE n.tier = ? AND n.status = 'online'
                GROUP BY n.id
                HAVING n.ram > COALESCE(SUM(v.ram), 0)
                ORDER BY (n.ram - COALESCE(SUM(v.ram), 0)) DESC, vps_count ASC
                LIMIT 1
            """, (requiredTier,)).fetchone()
            if not row:
                return None, None
            node_id = row['id']

        storage = conn.execute(
            "SELECT id FROM storagepools WHERE nodeid = ?", 
            (node_id,)
        ).fetchone()
        
        return node_id, (storage['id'] if storage else None)
    
def listallimages():
    with getconnection() as conn:
        # Join with a count of VPS instances currently using that image
        rows = conn.execute("""
            SELECT i.*, 
            (SELECT COUNT(*) FROM vps WHERE imageid = i.id) as vps_count
            FROM images i
            ORDER BY i.created DESC
        """).fetchall()
        return [dict(r) for r in rows]


def updateimage(uuid, **kwargs):
    with getconnection() as conn:
        keys = [f"{k} = ?" for k in kwargs.keys()]
        values = list(kwargs.values()) + [uuid]
        conn.execute(f"UPDATE images SET {', '.join(keys)}, updated = CURRENT_TIMESTAMP WHERE uuid = ?", values)

def removeimage(uuid):
    with getconnection() as conn:
        conn.execute("DELETE FROM images WHERE uuid = ?", (uuid,))


# --- PAGINATED LIST FUNCTIONS ---

def listplanspaginated(page=1, perpage=12, search=None):
    with getconnection() as conn:
        offset = (page - 1) * perpage
        where = ""
        params = []
        if search:
            where = "WHERE name LIKE ? OR description LIKE ?"
            s = f"%{search}%"
            params = [s, s]
        total = conn.execute(f"SELECT COUNT(*) FROM plans {where}", params).fetchone()[0]
        rows = conn.execute(f"SELECT * FROM plans {where} ORDER BY created DESC LIMIT ? OFFSET ?", params + [perpage, offset]).fetchall()
        return {
            "plans": [dict(r) for r in rows],
            "totalCount": total,
            "currentPage": page,
            "perPage": perpage,
            "totalPages": math.ceil(total / perpage) if perpage else 1,
            "hasPrev": page > 1,
            "hasNext": (page * perpage) < total,
        }

def listimagespaginated(page=1, perpage=12, search=None, node_type=None):
    with getconnection() as conn:
        offset = (page - 1) * perpage
        where = ""
        params = []
        if node_type:
            where = "WHERE i.node_type = ?"
            params.append(node_type)
        if search:
            where = ("WHERE " if not where else where + " AND ") + "(i.name LIKE ? OR i.image LIKE ? OR i.description LIKE ?)"
            s = f"%{search}%"
            params.extend([s, s, s])
        total = conn.execute(f"SELECT COUNT(*) FROM images i {where}", params).fetchone()[0]
        rows = conn.execute(f"""
            SELECT i.*, 
            (SELECT COUNT(*) FROM vps WHERE imageid = i.id) as vps_count
            FROM images i
            {where}
            ORDER BY i.created DESC
            LIMIT ? OFFSET ?
        """, params + [perpage, offset]).fetchall()
        return {
            "images": [dict(r) for r in rows],
            "totalCount": total,
            "currentPage": page,
            "perPage": perpage,
            "totalPages": math.ceil(total / perpage) if perpage else 1,
            "hasPrev": page > 1,
            "hasNext": (page * perpage) < total,
        }

def listnodespaginated(page=1, perpage=12, search=None):
    with getconnection() as conn:
        offset = (page - 1) * perpage
        where = ""
        params = []
        if search:
            where = "WHERE n.name LIKE ? OR n.hostname LIKE ? OR n.address LIKE ? OR n.status LIKE ? OR n.tier LIKE ?"
            s = f"%{search}%"
            params = [s, s, s, s, s]
        total = conn.execute(f"SELECT COUNT(*) FROM nodes n {where}", params).fetchone()[0]
        rows = conn.execute(f"""
            SELECT n.*, 
            (SELECT COUNT(*) FROM vps WHERE nodeid = n.id) as vps_count
            FROM nodes n
            {where}
            ORDER BY n.created DESC
            LIMIT ? OFFSET ?
        """, params + [perpage, offset]).fetchall()
        return {
            "nodes": [dict(r) for r in rows],
            "totalCount": total,
            "currentPage": page,
            "perPage": perpage,
            "totalPages": math.ceil(total / perpage) if perpage else 1,
            "hasPrev": page > 1,
            "hasNext": (page * perpage) < total,
        }

def listpaymentmethodspaginated(page=1, perpage=12, search=None):
    with getconnection() as conn:
        offset = (page - 1) * perpage
        where = ""
        params = []
        if search:
            where = "WHERE p.name LIKE ? OR p.slug LIKE ?"
            s = f"%{search}%"
            params = [s, s]
        total = conn.execute(f"SELECT COUNT(*) FROM paymentmethods p {where}", params).fetchone()[0]
        rows = conn.execute(f"""
            SELECT p.*,
                   COUNT(t.id) AS transaction_count,
                   COALESCE(SUM(CASE WHEN t.status = 'completed' THEN t.amount ELSE 0 END), 0) AS total_amount
            FROM paymentmethods p
            LEFT JOIN transactions t ON t.paymentprocessorid = p.id
            {where}
            GROUP BY p.id
            ORDER BY p.created DESC
            LIMIT ? OFFSET ?
        """, params + [perpage, offset]).fetchall()
        return {
            "methods": [dict(r) for r in rows],
            "totalCount": total,
            "currentPage": page,
            "perPage": perpage,
            "totalPages": math.ceil(total / perpage) if perpage else 1,
            "hasPrev": page > 1,
            "hasNext": (page * perpage) < total,
        }


def listreceiptspaginated(page=1, perpage=12, search=None):
    with getconnection() as conn:
        offset = (page - 1) * perpage
        where = ""
        params = []
        if search:
            where = "WHERE receipts.receiptnumber LIKE ? OR receipts.billingname LIKE ? OR receipts.billingemail LIKE ? OR users.username LIKE ? OR receipts.currency LIKE ?"
            s = f"%{search}%"
            params = [s, s, s, s, s]
        total = conn.execute(f"""
            SELECT COUNT(*) FROM receipts
            JOIN users ON users.id = receipts.userid
            {where}
        """, params).fetchone()[0]
        rows = conn.execute(f"""
            SELECT receipts.*, users.username, transactions.transactionid AS txn_public_id
            FROM receipts
            JOIN users ON users.id = receipts.userid
            LEFT JOIN transactions ON transactions.id = receipts.transactionid
            {where}
            ORDER BY receipts.created DESC
            LIMIT ? OFFSET ?
        """, params + [perpage, offset]).fetchall()
        return {
            "receipts": [dict(r) for r in rows],
            "totalCount": total,
            "currentPage": page,
            "perPage": perpage,
            "totalPages": math.ceil(total / perpage) if perpage else 1,
            "hasPrev": page > 1,
            "hasNext": (page * perpage) < total,
        }