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

# --- IMAGE FUNCTIONS ---

def addimage(uuid, name, image, description=None, active=1):
    with getconnection() as conn:
        conn.execute("INSERT INTO images (uuid, name, image, description, active) VALUES (?, ?, ?, ?, ?)", 
                     (uuid, name, image, description, active))

def getimage(uuid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM images WHERE uuid = ?", (uuid,)).fetchone()
        return dict(row) if row else None

def getimagebyid(imageid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM images WHERE id = ?", (imageid,)).fetchone()
        return dict(row) if row else None

def listimages(active=None):
    with getconnection() as conn:
        if active is not None:
            rows = conn.execute("SELECT * FROM images WHERE active = ?", (active,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM images").fetchall()
        return [dict(r) for r in rows]

# --- NODE FUNCTIONS ---

def addnode(uuid, name, hostname, address, apikey, cpu, ram, disk, status, tier, url=''):
    with getconnection() as conn:
        conn.execute("""
            INSERT INTO nodes (uuid, name, hostname, address, url, apikey, cpu, ram, disk, status, tier)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (uuid, name, hostname, address, url, apikey, cpu, ram, disk, status, tier))

def getnode(uuid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM nodes WHERE uuid = ?", (uuid,)).fetchone()
        return dict(row) if row else None

# --- NETWORK FUNCTIONS ---

def addnetwork(uuid, nodeid, name, subnet=None, gateway=None, ipv6=1):
    with getconnection() as conn:
        conn.execute("""
            INSERT INTO networks (uuid, nodeid, name, subnet, gateway, ipv6)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (uuid, nodeid, name, subnet, gateway, ipv6))

def getnetwork(uuid):
    with getconnection() as conn:
        row = conn.execute("""
            SELECT n.*, nd.name as node_name, nd.address as node_address
            FROM networks n
            JOIN nodes nd ON n.nodeid = nd.id
            WHERE n.uuid = ?
        """, (uuid,)).fetchone()
        return dict(row) if row else None

def removenetwork(uuid):
    with getconnection() as conn:
        conn.execute("DELETE FROM networks WHERE uuid = ?", (uuid,))

def listnetworks(nodeid=None):
    with getconnection() as conn:
        if nodeid:
            rows = conn.execute("""
                SELECT n.*, nd.name as node_name
                FROM networks n
                JOIN nodes nd ON n.nodeid = nd.id
                WHERE n.nodeid = ?
                ORDER BY n.created DESC
            """, (nodeid,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT n.*, nd.name as node_name
                FROM networks n
                JOIN nodes nd ON n.nodeid = nd.id
                ORDER BY n.created DESC
            """).fetchall()
        return [dict(r) for r in rows]

def listnetworkspaginated(page=1, perpage=12, search=None):
    with getconnection() as conn:
        offset = (page - 1) * perpage
        where = ""
        params = []
        if search:
            where = "WHERE n.name LIKE ? OR nd.name LIKE ? OR n.subnet LIKE ?"
            s = f"%{search}%"
            params = [s, s, s]
        total = conn.execute(f"""
            SELECT COUNT(*) FROM networks n
            JOIN nodes nd ON n.nodeid = nd.id
            {where}
        """, params).fetchone()[0]
        rows = conn.execute(f"""
            SELECT n.*, nd.name as node_name
            FROM networks n
            JOIN nodes nd ON n.nodeid = nd.id
            {where}
            ORDER BY n.created DESC
            LIMIT ? OFFSET ?
        """, params + [perpage, offset]).fetchall()
        return {
            "networks": [dict(r) for r in rows],
            "totalCount": total,
            "currentPage": page,
            "perPage": perpage,
            "totalPages": math.ceil(total / perpage) if perpage else 1,
            "hasPrev": page > 1,
            "hasNext": (page * perpage) < total,
        }

def getnetworkbynamenodeid(name, nodeid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM networks WHERE name = ? AND nodeid = ?", (name, nodeid)).fetchone()
        return dict(row) if row else None

def countvpsbynetwork(networkid):
    with getconnection() as conn:
        row = conn.execute("SELECT COUNT(*) FROM vps WHERE networkid = ?", (networkid,)).fetchone()
        return row[0] if row else 0

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


def addnodesstorage(uuid, nodeid, name, path, type, size):
    with getconnection() as conn:
        conn.execute("""
            INSERT INTO nodestorage (uuid, nodeid, name, path, type, size)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (uuid, nodeid, name, path, type, size))

def listallnodesstorage():
    with getconnection() as conn:
        rows = conn.execute("""
            SELECT s.*, n.name as node_name 
            FROM nodestorage s
            JOIN nodes n ON s.nodeid = n.id
        """).fetchall()
        return [dict(r) for r in rows]

def updatenodesstorage(uuid, **kwargs):
    with getconnection() as conn:
        keys = [f"{k} = ?" for k in kwargs.keys()]
        values = list(kwargs.values()) + [uuid]
        conn.execute(f"UPDATE nodestorage SET {', '.join(keys)}, updated = CURRENT_TIMESTAMP WHERE uuid = ?", values)

def removenodesstorage(uuid):
    with getconnection() as conn:
        conn.execute("DELETE FROM nodestorage WHERE uuid = ?", (uuid,))

def getsuitablenodeandstorage(planPrice):
    # Determine tier based on price
    requiredTier = 'paid' if planPrice > 0 else 'free'
    
    with getconnection() as conn:
        # Find nodes of the correct tier that are 'online'
        nodes = conn.execute(
            "SELECT id FROM nodes WHERE tier = ? AND status = 'online'", 
            (requiredTier,)
        ).fetchall()
        
        if not nodes:
            return None, None
            
        # Pick a random node from the available ones
        node = random.choice(nodes)
        
        # Find a storage unit on that node
        storage = conn.execute(
            "SELECT id FROM nodestorage WHERE nodeid = ?", 
            (node['id'],)
        ).fetchone()
        
        return node['id'], (storage['id'] if storage else None)
    
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

def addimage(uuid, name, image, description, active):
    with getconnection() as conn:
        conn.execute("""
            INSERT INTO images (uuid, name, image, description, active)
            VALUES (?, ?, ?, ?, ?)
        """, (uuid, name, image, description, active))

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

def listimagespaginated(page=1, perpage=12, search=None):
    with getconnection() as conn:
        offset = (page - 1) * perpage
        where = ""
        params = []
        if search:
            where = "WHERE i.name LIKE ? OR i.image LIKE ? OR i.description LIKE ?"
            s = f"%{search}%"
            params = [s, s, s]
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

def listnodesstoragepaginated(page=1, perpage=12, search=None):
    with getconnection() as conn:
        offset = (page - 1) * perpage
        where = ""
        params = []
        if search:
            where = "WHERE s.name LIKE ? OR s.path LIKE ? OR s.type LIKE ? OR n.name LIKE ?"
            s = f"%{search}%"
            params = [s, s, s, s]
        total = conn.execute(f"SELECT COUNT(*) FROM nodestorage s JOIN nodes n ON s.nodeid = n.id {where}", params).fetchone()[0]
        rows = conn.execute(f"""
            SELECT s.*, n.name as node_name 
            FROM nodestorage s
            JOIN nodes n ON s.nodeid = n.id
            {where}
            ORDER BY s.created DESC
            LIMIT ? OFFSET ?
        """, params + [perpage, offset]).fetchall()
        return {
            "storage": [dict(r) for r in rows],
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