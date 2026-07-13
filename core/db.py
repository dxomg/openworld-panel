import sqlite3
import math

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
            where_clause = "WHERE id = ?"
        else:
            where_clause = "WHERE uuid = ?"
            
        conn.execute(f"UPDATE users SET {', '.join(keys)}, updated = CURRENT_TIMESTAMP {where_clause}", values)

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

def addplan(uuid, name, cpu, ram, swap, disk, description=None, ipv4=0, ipv6=1, price=0.0, active=1):
    with getconnection() as conn:
        conn.execute(
            """INSERT INTO plans (uuid, name, cpu, ram, swap, disk, description, ipv4, ipv6, price, active) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
            (uuid, name, cpu, ram, swap, disk, description, ipv4, ipv6, price, active)
        )
        
def updateplan(uuid, name, cpu, ram, swap, disk, description=None, ipv4=0, ipv6=1, price=0.0, active=1):
    """
    Updates an existing plan by its UUID.
    """
    with getconnection() as conn:
        conn.execute(
            """UPDATE plans 
               SET name = ?, cpu = ?, ram = ?, swap = ?, disk = ?, 
                   description = ?, ipv4 = ?, ipv6 = ?, price = ?, 
                   active = ?, updated = CURRENT_TIMESTAMP 
               WHERE uuid = ?""",
            (name, cpu, ram, swap, disk, description, ipv4, ipv6, price, active, uuid)
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

# --- IMAGE FUNCTIONS ---

def addimage(uuid, name, image, description=None, active=1):
    with getconnection() as conn:
        conn.execute("INSERT INTO images (uuid, name, image, description, active) VALUES (?, ?, ?, ?, ?)", 
                     (uuid, name, image, description, active))

def getimage(uuid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM images WHERE uuid = ?", (uuid,)).fetchone()
        return dict(row) if row else None

def listimages(active=None):
    with getconnection() as conn:
        if active is not None:
            rows = conn.execute("SELECT * FROM images WHERE active = ?", (active,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM images").fetchall()
        return [dict(r) for r in rows]

# --- NODE FUNCTIONS ---

def addnode(uuid, name, hostname, address, apikey, cpu, ram, disk, status='online'):
    with getconnection() as conn:
        conn.execute(
            """INSERT INTO nodes (uuid, name, hostname, address, apikey, cpu, ram, disk, status) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
            (uuid, name, hostname, address, apikey, cpu, ram, disk, status)
        )

def getnode(uuid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM nodes WHERE uuid = ?", (uuid,)).fetchone()
        return dict(row) if row else None

# --- VPS FUNCTIONS ---

def addvps(uuid, userid, planid, imageid, nodeid, storageid, hostname, password, cpu, ram, swap, disk, status='creating'):
    with getconnection() as conn:
        conn.execute(
            """INSERT INTO vps (uuid, userid, planid, imageid, nodeid, storageid, hostname, password, cpu, ram, swap, disk, status) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
            (uuid, userid, planid, imageid, nodeid, storageid, hostname, password, cpu, ram, swap, disk, status)
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

def listuserspaginated(page=1, perpage=20):
    offset = (page - 1) * perpage
    with getconnection() as conn:
        # Get the total count of users first
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        # Get the users for the current page
        cursor = conn.execute(
            """
            SELECT id, uuid, discordid, username, email, role, status, verified, created
            FROM users 
            ORDER BY created DESC
            LIMIT ? OFFSET ?
            """, 
            (perpage, offset)
        )
        users = [dict(row) for row in cursor.fetchall()]

    # Attach the most recent ban record for banned users
    for user in users:
        if user["status"] == "banned":
            user["active_ban"] = getbanbyuserid(user["id"])
        else:
            user["active_ban"] = None

    # Return everything the template needs
    return {
        "users": users,
        "current_page": page,
        "total_pages": math.ceil(total_users / perpage),
        "has_next": page < math.ceil(total_users / perpage),
        "has_prev": page > 1
    }