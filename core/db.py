import sqlite3
import math
import uuid

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

def addnode(uuid, name, hostname, address, apikey, cpu, ram, disk, status, tier):
    with getconnection() as conn:
        conn.execute("""
            INSERT INTO nodes (uuid, name, hostname, address, apikey, cpu, ram, disk, status, tier)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (uuid, name, hostname, address, apikey, cpu, ram, disk, status, tier))

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
def listvpspaginated(page=1, perpage=20, userid=None):
    """
    Lists VPS instances with pagination.
    Optional: pass a userid to list only VPSs belonging to a specific user.
    """
    offset = (page - 1) * perpage
    
    with getconnection() as conn:
        # 1. Build the base queries
        # We join with users, plans, nodes, and images to get readable names
        count_query = "SELECT COUNT(*) FROM vps"
        data_query = """
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
        where_clause = ""
        
        # 2. Handle optional filtering by User ID (useful for the user dashboard)
        if userid:
            where_clause = " WHERE v.userid = ?"
            params.append(userid)
        
        # 3. Get total count for pagination math
        total_vps = conn.execute(count_query + where_clause, params).fetchone()[0]
        
        # 4. Get the actual data
        final_query = data_query + where_clause + " ORDER BY v.created DESC LIMIT ? OFFSET ?"
        cursor = conn.execute(final_query, params + [perpage, offset])
        
        # Convert rows to dictionaries
        vps_list = [dict(row) for row in cursor.fetchall()]

    # 5. Attach suspension details if the status is 'suspended'
    for vps in vps_list:
        if vps["status"] == "suspended":
            # You would need a helper function similar to your getbanbyuserid
            vps["suspension_details"] = getsuspensionbyvpsid(vps["id"])
        else:
            vps["suspension_details"] = None

    # Calculate total pages
    total_pages = math.ceil(total_vps / perpage) if total_vps > 0 else 1

    return {
        "vps": vps_list,
        "current_page": page,
        "total_pages": total_pages,
        "total_count": total_vps,
        "has_next": page < total_pages,
        "has_prev": page > 1
    }
def listallusers():
    """Returns a simple list of all users for dropdown selection."""
    with getconnection() as conn:
        rows = conn.execute("SELECT id, username FROM users ORDER BY username ASC").fetchall()
        return [dict(r) for r in rows]

def listnodestorage():
    """Returns nodes joined with their storage paths for selection."""
    with getconnection() as conn:
        rows = conn.execute("""
            SELECT 
                n.id as nodeid, 
                n.name as nodename, 
                s.id as storageid, 
                s.name as storagename 
            FROM nodes n 
            JOIN nodestorage s ON n.id = s.nodeid
            WHERE n.status = 'online'
        """).fetchall()
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


def getpaymentmethods(processor_uuid):
    with getconnection() as conn:
        row = conn.execute(
            "SELECT * FROM paymentmethods WHERE uuid = ?", (processor_uuid,)
        ).fetchone()
        return dict(row) if row else None


def updatepaymentmethods(processor_uuid, **fields):
    if not fields:
        return
    set_clause = ", ".join(f"{key} = ?" for key in fields)
    values = list(fields.values()) + [processor_uuid]
    with getconnection() as conn:
        conn.execute(
            f"UPDATE paymentmethods SET {set_clause}, updated = CURRENT_TIMESTAMP WHERE uuid = ?",
            values
        )


def removepaymentmethods(processor_uuid):
    with getconnection() as conn:
        conn.execute("DELETE FROM paymentmethods WHERE uuid = ?", (processor_uuid,))


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

def gettransaction(tid):
    with getconnection() as conn:
        row = conn.execute("SELECT id, userid, status FROM transactions WHERE id = ?", (tid,)).fetchone()
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