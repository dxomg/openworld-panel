import math
import uuid
import random
import json
import sqlite3
from datetime import date, datetime
from decimal import Decimal

from core import dbconfig

try:
    import pymysql
    from pymysql.cursors import DictCursor
except ImportError:
    pymysql = None
    DictCursor = None


def _norm_value(v):
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(v, date):
        return v.strftime("%Y-%m-%d")
    if isinstance(v, Decimal):
        return float(v)
    if isinstance(v, bytes):
        return v.decode("utf-8", errors="replace")
    return v


def _norm_row(row):
    if row is None:
        return None
    if isinstance(row, dict):
        return {k: _norm_value(v) for k, v in row.items()}
    # sqlite3.Row
    return {k: _norm_value(row[k]) for k in row.keys()}


def _scalar(row, default=0):
    """First column value from a fetchone() row (dict or sequence)."""
    if row is None:
        return default
    if isinstance(row, dict):
        if not row:
            return default
        return next(iter(row.values()))
    try:
        return row[0]
    except (KeyError, IndexError, TypeError):
        return default


class _Cursor:
    def __init__(self, cur, engine):
        self._cur = cur
        self._engine = engine
        self.lastrowid = 0
        self.rowcount = -1

    def execute(self, sql, params=None):
        if params is None:
            params = ()
        if self._engine == "mysql":
            sql = sql.replace("?", "%s")
        self._cur.execute(sql, params)
        self.lastrowid = getattr(self._cur, "lastrowid", 0) or 0
        self.rowcount = getattr(self._cur, "rowcount", -1)
        return self

    def executemany(self, sql, seq):
        if self._engine == "mysql":
            sql = sql.replace("?", "%s")
        self._cur.executemany(sql, seq)
        self.rowcount = getattr(self._cur, "rowcount", -1)
        return self

    def fetchone(self):
        return _norm_row(self._cur.fetchone())

    def fetchall(self):
        rows = self._cur.fetchall() or []
        return [_norm_row(r) for r in rows]

    def close(self):
        self._cur.close()


class _Conn:
    def __init__(self, raw, engine):
        self._raw = raw
        self._engine = engine

    @property
    def engine(self):
        return self._engine

    def execute(self, sql, params=None):
        cur = _Cursor(self._raw.cursor(), self._engine)
        cur.execute(sql, params)
        return cur

    def executemany(self, sql, seq):
        cur = _Cursor(self._raw.cursor(), self._engine)
        cur.executemany(sql, seq)
        return cur

    def executescript(self, script):
        if self._engine == "sqlite":
            self._raw.executescript(script)
            return
        # MySQL: split on ; outside of naive multi-statement
        for stmt in script.split(";"):
            s = stmt.strip()
            if s:
                self.execute(s)

    def commit(self):
        self._raw.commit()

    def rollback(self):
        self._raw.rollback()

    def close(self):
        self._raw.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self._raw.commit()
            else:
                self._raw.rollback()
        finally:
            self._raw.close()
        return False


def getengine():
    return dbconfig.engine()


def is_mysql():
    return dbconfig.is_mysql()


def getconnection():
    cfg = dbconfig.load()
    if cfg["engine"] == "mysql":
        if pymysql is None:
            raise RuntimeError("PyMySQL not installed. pip install PyMySQL")
        m = cfg["mysql"]
        raw = pymysql.connect(
            host=m.get("host") or "127.0.0.1",
            port=int(m.get("port") or 3306),
            user=m.get("user") or "root",
            password=m.get("password") or "",
            database=m.get("database") or "openworld",
            charset=m.get("charset") or "utf8mb4",
            cursorclass=DictCursor,
            autocommit=False,
        )
        conn = _Conn(raw, "mysql")
        # Align MySQL session clock with app timezone (for CURRENT_TIMESTAMP defaults)
        try:
            from core import timeutil
            off = timeutil.to_mysql_offset()
            conn.execute(f"SET time_zone = '{off}'")
        except Exception:
            pass
        return conn

    path = dbconfig.sqlite_path()
    raw = sqlite3.connect(path)
    raw.execute("PRAGMA foreign_keys = ON")
    raw.row_factory = sqlite3.Row
    return _Conn(raw, "sqlite")


def begin_immediate(conn):
    if conn.engine == "mysql":
        conn.execute("START TRANSACTION")
    else:
        conn.execute("BEGIN IMMEDIATE")


def insert_ignore(conn, sql, params=None):
    """sql should be 'INSERT INTO ...' (no OR IGNORE)."""
    if conn.engine == "mysql":
        sql = sql.replace("INSERT INTO", "INSERT IGNORE INTO", 1)
    else:
        sql = sql.replace("INSERT INTO", "INSERT OR IGNORE INTO", 1)
    return conn.execute(sql, params)


def expired_before_expr(minutes):
    """
    Return (sql_placeholder_or_literal, params) for checkout soft-expire.
    Uses app timezone wall-clock so it matches general.timezone.
    """
    from datetime import timedelta
    from core import timeutil

    minutes = int(minutes)
    cutoff = timeutil.now() - timedelta(minutes=minutes)
    # Compare as string timestamps stored/coerced the same way
    return "?", (cutoff.strftime("%Y-%m-%d %H:%M:%S"),)


def table_columns(conn, table):
    if conn.engine == "mysql":
        rows = conn.execute(
            "SELECT COLUMN_NAME AS name FROM INFORMATION_SCHEMA.COLUMNS "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?",
            (table,),
        ).fetchall()
        return [r["name"] for r in rows]
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    # pragma returns cid, name, type, ... — after norm_row keys are indices? sqlite3.Row keys are names
    # With our wrapper, PRAGMA returns rows as dicts with numeric? Actually Row keys are column names: cid, name, type, notnull, dflt_value, pk
    out = []
    for r in rows:
        if isinstance(r, dict):
            out.append(r.get("name") if "name" in r else r.get(1))
        else:
            out.append(r[1])
    return out


def _iptable(version):
    return "networkipv4" if version == "ipv4" else "networkipv6"


def _ipversion(ip=None, version=None):
    if version in ("ipv4", "ipv6"):
        return version
    return "ipv6" if ip and ":" in ip else "ipv4"

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

# --- BAN FUNCTIONS ---

def addban(uuid, userid, adminid, reason, expires=None):
    with getconnection() as conn:
        conn.execute("INSERT INTO bans (uuid, userid, adminid, reason, expires) VALUES (?, ?, ?, ?, ?)", 
                     (uuid, userid, adminid, reason, expires))

def getbanbyuserid(userid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM bans WHERE userid = ? ORDER BY created DESC LIMIT 1", (userid,)).fetchone()
        return dict(row) if row else None

def removeban(uuid):
    with getconnection() as conn:
        conn.execute("DELETE FROM bans WHERE uuid = ?", (uuid,))

# --- PLAN FUNCTIONS ---

def addplan(uuid, name, cpu, ram, swap, disk, description=None, ipv4=0, ipv6=1, price=0.0, active=1, stock=-1, netmbps=0, node_type='proxmox'):
    with getconnection() as conn:
        conn.execute(
            """INSERT INTO plans (uuid, name, cpu, ram, swap, disk, description, ipv4, ipv6, price, active, stock, netmbps, node_type) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
            (uuid, name, cpu, ram, swap, disk, description, ipv4, ipv6, price, active, stock, netmbps, node_type)
        )
        
def updateplan(uuid, name, cpu, ram, swap, disk, description=None, ipv4=0, ipv6=1, price=0.0, active=1, stock=-1, netmbps=0, node_type='proxmox'):
    with getconnection() as conn:
        conn.execute(
            """UPDATE plans 
               SET name = ?, cpu = ?, ram = ?, swap = ?, disk = ?, 
                   description = ?, ipv4 = ?, ipv6 = ?, price = ?, 
                   active = ?, stock = ?, netmbps = ?, node_type = ?,
                   updated = CURRENT_TIMESTAMP 
               WHERE uuid = ?""",
            (name, cpu, ram, swap, disk, description, ipv4, ipv6, price, active, stock, netmbps, node_type, uuid)
        )
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


def _ensure_index(conn, name, table, columns):
    """Create index if missing. MySQL has no CREATE INDEX IF NOT EXISTS on many hosts."""
    try:
        if conn.engine == "mysql":
            rows = conn.execute(
                "SELECT 1 FROM INFORMATION_SCHEMA.STATISTICS "
                "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ? LIMIT 1",
                (table, name),
            ).fetchone()
            if rows:
                return
            conn.execute(f"CREATE INDEX {name} ON {table} ({columns})")
        else:
            conn.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({columns})")
    except Exception as e:
        msg = str(e).lower()
        if "duplicate" in msg or "already exists" in msg:
            return
        raise


def ensureplanassignmenttables():
    """Create plan_nodes / plan_storagepools if missing (live DB migrate)."""
    with getconnection() as conn:
        if conn.engine == "mysql":
            conn.execute("""
                CREATE TABLE IF NOT EXISTS plan_nodes (
                    id INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    planid INTEGER NOT NULL,
                    nodeid INTEGER NOT NULL,
                    created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(planid, nodeid),
                    FOREIGN KEY(planid) REFERENCES plans(id) ON DELETE CASCADE,
                    FOREIGN KEY(nodeid) REFERENCES nodes(id) ON DELETE CASCADE
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS plan_storagepools (
                    id INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    planid INTEGER NOT NULL,
                    storagepoolid INTEGER NOT NULL,
                    created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(planid, storagepoolid),
                    FOREIGN KEY(planid) REFERENCES plans(id) ON DELETE CASCADE,
                    FOREIGN KEY(storagepoolid) REFERENCES storagepools(id) ON DELETE CASCADE
                )
            """)
        else:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS plan_nodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    planid INTEGER NOT NULL,
                    nodeid INTEGER NOT NULL,
                    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(planid) REFERENCES plans(id) ON DELETE CASCADE,
                    FOREIGN KEY(nodeid) REFERENCES nodes(id) ON DELETE CASCADE,
                    UNIQUE(planid, nodeid)
                );
                CREATE TABLE IF NOT EXISTS plan_storagepools (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    planid INTEGER NOT NULL,
                    storagepoolid INTEGER NOT NULL,
                    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(planid) REFERENCES plans(id) ON DELETE CASCADE,
                    FOREIGN KEY(storagepoolid) REFERENCES storagepools(id) ON DELETE CASCADE,
                    UNIQUE(planid, storagepoolid)
                );
            """)
        _ensure_index(conn, "idxplannodesplan", "plan_nodes", "planid")
        _ensure_index(conn, "idxplannodesnode", "plan_nodes", "nodeid")
        _ensure_index(conn, "idxplanpoolsplan", "plan_storagepools", "planid")
        _ensure_index(conn, "idxplanpoolspool", "plan_storagepools", "storagepoolid")


def ensurejobssuspendtype():
    """Add 'suspend' to jobs.type CHECK if missing (SQLite rebuild only)."""
    with getconnection() as conn:
        if conn.engine == "mysql":
            # MySQL CHECK often not rewritten; jobs already include suspend on fresh create
            return
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='jobs'"
        ).fetchone()
        sqltext = (row or {}).get("sql") or (row or {}).get(0) if row else None
        if isinstance(row, dict) and "sql" not in row and 0 in row:
            sqltext = row[0]
        if row and not sqltext:
            # sqlite_master via wrapper: column name is sql
            sqltext = list(row.values())[0] if row else None
        if not row or not sqltext or "'suspend'" in str(sqltext):
            return
        conn.executescript("""
            CREATE TABLE jobs_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT UNIQUE NOT NULL,
                vpsid INTEGER,
                vpsuuid TEXT NOT NULL,
                userid INTEGER NOT NULL,
                type TEXT NOT NULL
                    CHECK(type IN ('create','delete','reinstall','start','stop','restart','provision','enable_tun','suspend')),
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending','running','completed','failed')),
                payload TEXT,
                result TEXT,
                created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(vpsid) REFERENCES vps(id) ON DELETE CASCADE,
                FOREIGN KEY(userid) REFERENCES users(id) ON DELETE CASCADE
            );
            INSERT INTO jobs_new (id, uuid, vpsid, vpsuuid, userid, type, status, payload, result, created, updated)
            SELECT id, uuid, vpsid, vpsuuid, userid, type, status, payload, result, created,
                   COALESCE(updated, created)
            FROM jobs;
            DROP TABLE jobs;
            ALTER TABLE jobs_new RENAME TO jobs;
            CREATE INDEX IF NOT EXISTS idxjobsuuid ON jobs(uuid);
            CREATE INDEX IF NOT EXISTS idxjobsvps ON jobs(vpsuuid);
            CREATE INDEX IF NOT EXISTS idxjobsstatus ON jobs(status);
        """)


def getplannodeids(planid):
    with getconnection() as conn:
        rows = conn.execute(
            "SELECT nodeid FROM plan_nodes WHERE planid = ?", (planid,)
        ).fetchall()
        return [r["nodeid"] for r in rows]


def getplanstoragepoolids(planid):
    with getconnection() as conn:
        rows = conn.execute(
            "SELECT storagepoolid FROM plan_storagepools WHERE planid = ?", (planid,)
        ).fetchall()
        return [r["storagepoolid"] for r in rows]


def listplannodes(planid):
    with getconnection() as conn:
        rows = conn.execute("""
            SELECT n.*
            FROM plan_nodes pn
            JOIN nodes n ON n.id = pn.nodeid
            WHERE pn.planid = ?
            ORDER BY n.name
        """, (planid,)).fetchall()
        return [dict(r) for r in rows]


def listplanstoragepools(planid):
    with getconnection() as conn:
        rows = conn.execute("""
            SELECT sp.*, nd.name as node_name, nd.id as node_id
            FROM plan_storagepools psp
            JOIN storagepools sp ON sp.id = psp.storagepoolid
            JOIN nodes nd ON nd.id = sp.nodeid
            WHERE psp.planid = ?
            ORDER BY nd.name, sp.name
        """, (planid,)).fetchall()
        return [dict(r) for r in rows]


def setplannodes(planid, nodeids):
    """Replace plan→node assignments. nodeids = list of int ids."""
    nodeids = [int(x) for x in nodeids if x is not None and str(x).strip() != ""]
    with getconnection() as conn:
        conn.execute("DELETE FROM plan_nodes WHERE planid = ?", (planid,))
        for nid in nodeids:
            insert_ignore(
                conn,
                "INSERT INTO plan_nodes (planid, nodeid) VALUES (?, ?)",
                (planid, nid),
            )


def setplanstoragepools(planid, poolids, nodeids=None):
    """Replace plan→storagepool assignments. Only pools on assigned nodes kept."""
    poolids = [int(x) for x in poolids if x is not None and str(x).strip() != ""]
    with getconnection() as conn:
        if nodeids is not None:
            nodeids = [int(x) for x in nodeids if x is not None and str(x).strip() != ""]
            if not nodeids:
                poolids = []
            else:
                placeholders = ",".join("?" * len(nodeids))
                valid = conn.execute(
                    f"SELECT id FROM storagepools WHERE nodeid IN ({placeholders})",
                    nodeids,
                ).fetchall()
                valid_ids = {r["id"] for r in valid}
                poolids = [p for p in poolids if p in valid_ids]
        conn.execute("DELETE FROM plan_storagepools WHERE planid = ?", (planid,))
        for pid in poolids:
            insert_ignore(
                conn,
                "INSERT INTO plan_storagepools (planid, storagepoolid) VALUES (?, ?)",
                (planid, pid),
            )


def getplanbyuuid(planuuid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM plans WHERE uuid = ?", (planuuid,)).fetchone()
        return dict(row) if row else None


def userhasfreevps(userid):
    """Check if user already has a VPS on a free plan (price = 0)."""
    with getconnection() as conn:
        row = conn.execute("""
            SELECT COUNT(*) FROM vps v
            JOIN plans p ON v.planid = p.id
            WHERE v.userid = ? AND p.price = 0 AND v.status != 'deleted'
        """, (userid,)).fetchone()
        return _scalar(row) > 0

def countpendingpaymentvps(userid):
    with getconnection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM vps WHERE userid = ? AND status = 'pendingpayment'",
            (userid,)
        ).fetchone()
        return _scalar(row)

def listexpiredpendingpaymentvps(maxageminutes=30):
    with getconnection() as conn:
        expr, params = expired_before_expr(maxageminutes)
        rows = conn.execute(f"""
            SELECT * FROM vps
            WHERE status = 'pendingpayment'
              AND COALESCE(updated, created) <= {expr}
        """, params).fetchall()
        return [dict(r) for r in rows]

def touchpendingpaymentvps(uuid):
    """Restart unpaid checkout expiry timer."""
    with getconnection() as conn:
        conn.execute(
            "UPDATE vps SET updated = CURRENT_TIMESTAMP WHERE uuid = ? AND status = 'pendingpayment'",
            (uuid,)
        )

# --- IMAGE FUNCTIONS ---

def addimage(uuid, name, image, description=None, active=1, node_type='proxmox', os_type='linux'):
    with getconnection() as conn:
        conn.execute("INSERT INTO images (uuid, name, image, os_type, description, active, node_type) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (uuid, name, image, os_type, description, active, node_type))

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

# --- NODE_IMAGES FUNCTIONS ---

def addimagetonode(nodeid, imageid, imagestorageid=None):
    with getconnection() as conn:
        result = conn.execute("""
            UPDATE node_images SET imagestorageid = ? WHERE nodeid = ? AND imageid = ?
        """, (imagestorageid, nodeid, imageid))
        if result.rowcount == 0:
            conn.execute("""
                INSERT INTO node_images (uuid, nodeid, imageid, imagestorageid)
                VALUES (?, ?, ?, ?)
            """, (str(__import__('uuid').uuid4()), nodeid, imageid, imagestorageid))

def removeimagefromnode(nodeid, imageid):
    with getconnection() as conn:
        conn.execute("DELETE FROM node_images WHERE nodeid = ? AND imageid = ?", (nodeid, imageid))

def getimagesfornode(nodeid, active=None):
    with getconnection() as conn:
        if active is not None:
            rows = conn.execute("""
                SELECT i.*, ni.imagestorageid, ist.name as storage_name
                FROM images i
                JOIN node_images ni ON ni.imageid = i.id
                LEFT JOIN imagestorage ist ON ni.imagestorageid = ist.id
                WHERE ni.nodeid = ? AND i.active = ?
                ORDER BY i.name
            """, (nodeid, active)).fetchall()
        else:
            rows = conn.execute("""
                SELECT i.*, ni.imagestorageid, ist.name as storage_name
                FROM images i
                JOIN node_images ni ON ni.imageid = i.id
                LEFT JOIN imagestorage ist ON ni.imagestorageid = ist.id
                WHERE ni.nodeid = ?
                ORDER BY i.name
            """, (nodeid,)).fetchall()
        return [dict(r) for r in rows]

def getnodesforimage(imageid):
    with getconnection() as conn:
        rows = conn.execute("""
            SELECT n.*, ni.imagestorageid
            FROM nodes n
            JOIN node_images ni ON ni.nodeid = n.id
            WHERE ni.imageid = ?
            ORDER BY n.name
        """, (imageid,)).fetchall()
        return [dict(r) for r in rows]

def getimagestorageforimage(imageid, nodeid):
    with getconnection() as conn:
        row = conn.execute("""
            SELECT ist.* FROM imagestorage ist
            JOIN node_images ni ON ni.imagestorageid = ist.id
            WHERE ni.imageid = ? AND ni.nodeid = ?
        """, (imageid, nodeid)).fetchone()
        return dict(row) if row else None

def isimageassignedtonode(imageid, nodeid):
    with getconnection() as conn:
        row = conn.execute("SELECT 1 FROM node_images WHERE imageid = ? AND nodeid = ?", (imageid, nodeid)).fetchone()
        return row is not None

# --- LOCATION FUNCTIONS ---

def ensurelocationstable():
    """Create locations table and ensure nodes.locationid exists."""
    with getconnection() as conn:
        if conn.engine == "mysql":
            conn.execute("""
                CREATE TABLE IF NOT EXISTS locations (
                    id INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    uuid VARCHAR(191) NOT NULL UNIQUE,
                    name VARCHAR(255) NOT NULL,
                    code VARCHAR(191) NOT NULL UNIQUE,
                    flag VARCHAR(50) DEFAULT '',
                    description TEXT,
                    created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
        else:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS locations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    uuid TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    code TEXT UNIQUE NOT NULL,
                    flag TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
            """)
        node_cols = set(table_columns(conn, "nodes") or [])
        if node_cols and "locationid" not in node_cols:
            try:
                conn.execute("ALTER TABLE nodes ADD COLUMN locationid INTEGER NULL")
            except Exception:
                pass
        if node_cols and "max_vps" not in node_cols:
            try:
                conn.execute("ALTER TABLE nodes ADD COLUMN max_vps INTEGER NOT NULL DEFAULT 0")
            except Exception:
                pass

def addlocation(uuid, name, code, flag='', description=''):
    ensurelocationstable()
    with getconnection() as conn:
        conn.execute("""
            INSERT INTO locations (uuid, name, code, flag, description)
            VALUES (?, ?, ?, ?, ?)
        """, (uuid, name, code, flag, description))

def getlocation(uuid):
    ensurelocationstable()
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM locations WHERE uuid = ?", (uuid,)).fetchone()
        return dict(row) if row else None

def getlocationbyid(loc_id):
    ensurelocationstable()
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM locations WHERE id = ?", (loc_id,)).fetchone()
        return dict(row) if row else None

def listalllocations():
    ensurelocationstable()
    with getconnection() as conn:
        rows = conn.execute("""
            SELECT l.*,
            (SELECT COUNT(*) FROM nodes WHERE locationid = l.id) as node_count,
            (SELECT COUNT(*) FROM vps v JOIN nodes n ON v.nodeid = n.id WHERE n.locationid = l.id AND v.status NOT IN ('deleted', 'error')) as vps_count
            FROM locations l
            ORDER BY l.name ASC
        """).fetchall()
        return [dict(r) for r in rows]

def countlocations():
    ensurelocationstable()
    with getconnection() as conn:
        return _scalar(conn.execute("SELECT COUNT(*) FROM locations").fetchone())

def listlocationspaginated(page=1, perpage=12, search=None):
    ensurelocationstable()
    with getconnection() as conn:
        offset = (page - 1) * perpage
        where = ""
        params = []
        if search:
            where = "WHERE l.name LIKE ? OR l.code LIKE ? OR l.description LIKE ?"
            s = f"%{search}%"
            params = [s, s, s]
        total = _scalar(conn.execute(f"SELECT COUNT(*) FROM locations l {where}", params).fetchone())
        rows = conn.execute(f"""
            SELECT l.*,
            (SELECT COUNT(*) FROM nodes WHERE locationid = l.id) as node_count,
            (SELECT COUNT(*) FROM vps v JOIN nodes n ON v.nodeid = n.id WHERE n.locationid = l.id AND v.status NOT IN ('deleted', 'error')) as vps_count
            FROM locations l
            {where}
            ORDER BY l.created DESC
            LIMIT ? OFFSET ?
        """, params + [perpage, offset]).fetchall()
        return {
            "locations": [dict(r) for r in rows],
            "totalCount": total,
            "currentPage": page,
            "perPage": perpage,
            "totalPages": math.ceil(total / perpage) if perpage else 1,
            "hasPrev": page > 1,
            "hasNext": (page * perpage) < total,
        }

def updatelocation(uuid, **kwargs):
    ensurelocationstable()
    with getconnection() as conn:
        keys = [f"{k} = ?" for k in kwargs.keys()]
        values = list(kwargs.values()) + [uuid]
        conn.execute(f"UPDATE locations SET {', '.join(keys)}, updated = CURRENT_TIMESTAMP WHERE uuid = ?", values)

def removelocation(uuid):
    ensurelocationstable()
    with getconnection() as conn:
        conn.execute("DELETE FROM locations WHERE uuid = ?", (uuid,))

def getlocationsforplan(planid):
    """
    Returns all locations with availability status for a plan.
    A location is available if at least one online assigned node for this plan has space
    (vps_count < max_vps or max_vps == 0).
    """
    ensurelocationstable()
    with getconnection() as conn:
        locations = conn.execute("""
            SELECT l.* FROM locations l ORDER BY l.name ASC
        """).fetchall()
        
        result = []
        for loc in locations:
            ldict = dict(loc)
            nodes = conn.execute("""
                SELECT n.id, n.status, n.max_vps,
                       (SELECT COUNT(*) FROM vps v WHERE v.nodeid = n.id AND v.status NOT IN ('deleted', 'error')) as vps_count
                FROM nodes n
                JOIN plan_nodes pn ON pn.nodeid = n.id
                WHERE n.locationid = ? AND pn.planid = ?
            """, (loc['id'], planid)).fetchall()

            if not nodes:
                ldict['available'] = False
                ldict['reason'] = "No nodes assigned"
                ldict['status_text'] = "Unavailable"
                ldict['vps_count'] = 0
            else:
                ldict['vps_count'] = sum(n['vps_count'] or 0 for n in nodes)
                has_available_node = False
                online_nodes = 0
                for n in nodes:
                    if n['status'] == 'online':
                        online_nodes += 1
                        vps_cnt = n['vps_count'] or 0
                        max_cnt = n['max_vps'] or 0
                        if max_cnt == 0 or vps_cnt < max_cnt:
                            has_available_node = True
                            break

                if has_available_node:
                    ldict['available'] = True
                    ldict['reason'] = None
                    ldict['status_text'] = "Available"
                elif online_nodes == 0:
                    ldict['available'] = False
                    ldict['reason'] = "Nodes offline"
                    ldict['status_text'] = "Offline"
                else:
                    ldict['available'] = False
                    ldict['reason'] = "Capacity reached"
                    ldict['status_text'] = "Capacity Reached"

            result.append(ldict)

        return result

# --- NODE FUNCTIONS ---

def addnode(uuid, name, hostname, address, apikey, cpu, ram, status, tier, url='', nodeType='proxmox',
            proxmoxhost=None, proxmoxuser=None, proxmoxpassword=None, proxmoxnode='pve', proxmoxport=8006, proxmoxssl=0, locationid=None, max_vps=0):
    ensurelocationstable()
    with getconnection() as conn:
        conn.execute("""
            INSERT INTO nodes (uuid, name, hostname, address, url, apikey, locationid, type, cpu, ram, max_vps, status, tier,
                               proxmoxhost, proxmoxuser, proxmoxpassword, proxmoxnode, proxmoxport, proxmoxssl)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (uuid, name, hostname, address, url, apikey, locationid, nodeType, cpu, ram, max_vps, status, tier,
              proxmoxhost, proxmoxuser, proxmoxpassword, proxmoxnode, proxmoxport, proxmoxssl))

def getnode(uuid):
    ensurelocationstable()
    with getconnection() as conn:
        row = conn.execute("""
            SELECT n.*, loc.name as location_name, loc.code as location_code, loc.flag as location_flag
            FROM nodes n
            LEFT JOIN locations loc ON n.locationid = loc.id
            WHERE n.uuid = ?
        """, (uuid,)).fetchone()
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
        total = _scalar(conn.execute(f"""
            SELECT COUNT(*) FROM storagepools sp
            JOIN nodes nd ON sp.nodeid = nd.id
            {where}
""", params).fetchone())
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

def decreasestorageavailable(poolid, diskinMB):
    """Decrease available storage when a VPS is created. VPS disk is in MB, pool used is in MB."""
    with getconnection() as conn:
        conn.execute("UPDATE storagepools SET used = used + ?, updated = CURRENT_TIMESTAMP WHERE id = ?", (diskinMB, poolid))

def increasestorageavailable(poolid, diskinMB):
    """Increase available storage when a VPS is deleted. VPS disk is in MB, pool used is in MB."""
    with getconnection() as conn:
        # MySQL: MAX() is aggregate-only in expressions → use GREATEST()
        if conn.engine == "mysql":
            conn.execute(
                "UPDATE storagepools SET used = GREATEST(0, used - ?), updated = CURRENT_TIMESTAMP WHERE id = ?",
                (diskinMB, poolid),
            )
        else:
            conn.execute(
                "UPDATE storagepools SET used = MAX(0, used - ?), updated = CURRENT_TIMESTAMP WHERE id = ?",
                (diskinMB, poolid),
            )

# --- IMAGE STORAGE FUNCTIONS ---

def addimagestorage(uuid, nodeid, name, description=None):
    with getconnection() as conn:
        conn.execute("""
            INSERT INTO imagestorage (uuid, nodeid, name, description)
            VALUES (?, ?, ?, ?)
        """, (uuid, nodeid, name, description))

def getimagestorage(uuid):
    with getconnection() as conn:
        row = conn.execute("""
            SELECT ist.*, nd.name as node_name
            FROM imagestorage ist
            JOIN nodes nd ON ist.nodeid = nd.id
            WHERE ist.uuid = ?
        """, (uuid,)).fetchone()
        return dict(row) if row else None

def getimagestoragebyid(storageid):
    with getconnection() as conn:
        row = conn.execute("""
            SELECT ist.*, nd.name as node_name
            FROM imagestorage ist
            JOIN nodes nd ON ist.nodeid = nd.id
            WHERE ist.id = ?
        """, (storageid,)).fetchone()
        return dict(row) if row else None

def removeimagestorage(uuid):
    with getconnection() as conn:
        conn.execute("DELETE FROM imagestorage WHERE uuid = ?", (uuid,))

def updateimagestorage(uuid, **kwargs):
    with getconnection() as conn:
        keys = [f"{k} = ?" for k in kwargs.keys()]
        values = list(kwargs.values()) + [uuid]
        conn.execute(f"UPDATE imagestorage SET {', '.join(keys)}, updated = CURRENT_TIMESTAMP WHERE uuid = ?", values)

def listimagestorage(nodeid=None):
    with getconnection() as conn:
        if nodeid:
            rows = conn.execute("""
                SELECT ist.*, nd.name as node_name
                FROM imagestorage ist
                JOIN nodes nd ON ist.nodeid = nd.id
                WHERE ist.nodeid = ?
                ORDER BY ist.created DESC
            """, (nodeid,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT ist.*, nd.name as node_name
                FROM imagestorage ist
                JOIN nodes nd ON ist.nodeid = nd.id
                ORDER BY nd.name, ist.created DESC
            """).fetchall()
        return [dict(r) for r in rows]

def getdefaultimagestorage(nodeid):
    """Get the first image storage for a node (used during provisioning)."""
    with getconnection() as conn:
        row = conn.execute("""
            SELECT * FROM imagestorage WHERE nodeid = ? ORDER BY id ASC LIMIT 1
        """, (nodeid,)).fetchone()
        return dict(row) if row else None

# --- NETWORK FUNCTIONS ---

def _nettable(network_type=None):
    return "proxmox_networks"

def addnetwork(uuid, nodeid, name, network_type='proxmox', subnet=None, gateway=None, ipv4=0, ipv6=1, ipv4_subnet=None, ipv4_gateway=None, dns='1.1.1.1,8.8.8.8,2606:4700:4700::1111,2001:4860:4860::8888'):
    table = _nettable(network_type)
    with getconnection() as conn:
        conn.execute(f"""
            INSERT INTO {table} (uuid, nodeid, name, subnet, gateway, ipv4, ipv6, ipv4_subnet, ipv4_gateway, dns)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (uuid, nodeid, name, subnet, gateway, ipv4, ipv6, ipv4_subnet, ipv4_gateway, dns))

def getnetwork(uuid, network_type='proxmox'):
    table = _nettable(network_type)
    with getconnection() as conn:
        row = conn.execute(f"""
            SELECT n.*, nd.name as node_name, nd.address as node_address
            FROM {table} n
            JOIN nodes nd ON n.nodeid = nd.id
            WHERE n.uuid = ?
        """, (uuid,)).fetchone()
        return dict(row) if row else None

def getnetworkbyid(networkid, network_type='proxmox'):
    table = _nettable(network_type)
    with getconnection() as conn:
        row = conn.execute(f"""
            SELECT n.*, nd.name as node_name, nd.address as node_address
            FROM {table} n
            JOIN nodes nd ON n.nodeid = nd.id
            WHERE n.id = ?
        """, (networkid,)).fetchone()
        return dict(row) if row else None

def updatenetwork(uuid, network_type='proxmox', **kwargs):
    table = _nettable(network_type)
    with getconnection() as conn:
        keys = [f"{k} = ?" for k in kwargs.keys()]
        values = list(kwargs.values()) + [uuid]
        conn.execute(f"UPDATE {table} SET {', '.join(keys)}, updated = CURRENT_TIMESTAMP WHERE uuid = ?", values)

def removenetwork(uuid, network_type='proxmox'):
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
            for t in ('proxmox_networks',):
                ntype = 'proxmox'
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
            total = _scalar(conn.execute(f"""
                SELECT COUNT(*) FROM {table} n
                JOIN nodes nd ON n.nodeid = nd.id
                {where}
""", params).fetchone())
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
            for t in ('proxmox_networks',):
                ntype = 'proxmox'
                cnt = _scalar(conn.execute(f"""
                    SELECT COUNT(*) FROM {t} n
                    JOIN nodes nd ON n.nodeid = nd.id
                    {where}
""", params).fetchone())
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

def getnetworkbynamenodeid(name, nodeid, network_type='proxmox'):
    table = _nettable(network_type)
    with getconnection() as conn:
        row = conn.execute(f"SELECT * FROM {table} WHERE name = ? AND nodeid = ?", (name, nodeid)).fetchone()
        return dict(row) if row else None

def countvpsbynetwork(networkid, network_type='proxmox'):
    with getconnection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM vps WHERE networkid = ? AND network_type = ? AND status != 'deleted'",
            (networkid, network_type)
        ).fetchone()
        return _scalar(row)

# --- NETWORK IP FUNCTIONS ---

def addnetworkip(uuid, networkid, ip, network_type='proxmox'):
    table = _iptable(_ipversion(ip=ip))
    with getconnection() as conn:
        conn.execute(f"""
            INSERT INTO {table} (uuid, networkid, network_type, ip)
            VALUES (?, ?, ?, ?)
        """, (uuid, networkid, network_type, ip))

def getnetworkip(uuid):
    with getconnection() as conn:
        for version in ("ipv4", "ipv6"):
            table = _iptable(version)
            row = conn.execute(f"SELECT *, ? as ip_version FROM {table} WHERE uuid = ?", (version, uuid)).fetchone()
            if row:
                return dict(row)
        return None

def removenetworkip(uuid):
    with getconnection() as conn:
        conn.execute("DELETE FROM networkipv4 WHERE uuid = ?", (uuid,))
        conn.execute("DELETE FROM networkipv6 WHERE uuid = ?", (uuid,))

def removenetworkips(uuids):
    """Delete unassigned IPs by uuid list. Returns count deleted."""
    uuids = [u for u in (uuids or []) if u]
    if not uuids:
        return 0
    deleted = 0
    placeholders = ",".join("?" * len(uuids))
    with getconnection() as conn:
        for table in ("networkipv4", "networkipv6"):
            result = conn.execute(
                f"DELETE FROM {table} WHERE uuid IN ({placeholders}) AND assigned = 0",
                uuids,
            )
            deleted += result.rowcount or 0
    return deleted

def listnetworkips(networkid, network_type='proxmox', page=1, perpage=50, search=None, version='ipv6'):
    table = _iptable(version)
    with getconnection() as conn:
        offset = (page - 1) * perpage
        where = "WHERE ni.networkid = ? AND ni.network_type = ?"
        params = [networkid, network_type]
        if search:
            where += " AND ni.ip LIKE ?"
            params.append(f"%{search}%")
        total = _scalar(conn.execute(f"SELECT COUNT(*) FROM {table} ni {where}", params).fetchone())
        rows = conn.execute(f"""
            SELECT ni.*, ? as ip_version, v.hostname as vps_hostname
            FROM {table} ni
            LEFT JOIN vps v ON ni.vpsid = v.id
            {where}
            ORDER BY ni.ip ASC
            LIMIT ? OFFSET ?
        """, [version] + params + [perpage, offset]).fetchall()
        return {
            "ips": [dict(r) for r in rows],
            "totalCount": total,
            "currentPage": page,
            "perPage": perpage,
            "totalPages": math.ceil(total / perpage) if perpage else 1,
            "hasPrev": page > 1,
            "hasNext": (page * perpage) < total,
        }

def getavailableipbyversion(networkid, network_type='proxmox', version='ipv6'):
    """Get an available IP filtered by IPv4 or IPv6."""
    table = _iptable(version)
    with getconnection() as conn:
        row = conn.execute(f"""
            SELECT *, ? as ip_version FROM {table}
            WHERE networkid = ? AND network_type = ? AND assigned = 0
            ORDER BY ip ASC
            LIMIT 1
        """, (version, networkid, network_type)).fetchone()
        return dict(row) if row else None

def planipavailabilityerror(plan, network, network_type='proxmox'):
    if plan.get('ipv6'):
        if not network.get('ipv6'):
            return "Plan requires IPv6 but selected network does not support it."
        if not getavailableipbyversion(network['id'], network_type=network_type, version='ipv6'):
            return "No IPv6 addresses available for this network."
    if plan.get('ipv4'):
        if not network.get('ipv4'):
            return "Plan requires IPv4 but selected network does not support it."
        if not getavailableipbyversion(network['id'], network_type=network_type, version='ipv4'):
            return "No IPv4 addresses available for this network."
    return None

def reserveipbyversion(networkid, network_type='proxmox', version='ipv6', vpsid=None):
    """Atomically reserve one available IP for a VPS."""
    table = _iptable(version)
    with getconnection() as conn:
        begin_immediate(conn)
        lock = " FOR UPDATE" if conn.engine == "mysql" else ""
        row = conn.execute(f"""
            SELECT *, ? as ip_version FROM {table}
            WHERE networkid = ? AND network_type = ? AND assigned = 0
            ORDER BY ip ASC
            LIMIT 1{lock}
        """, (version, networkid, network_type)).fetchone()
        if not row:
            return None
        result = conn.execute(f"""
            UPDATE {table} SET assigned = 1, vpsid = ?
            WHERE id = ? AND assigned = 0
        """, (vpsid, row["id"]))
        if result.rowcount != 1:
            return None
        return dict(row)

def unassignip(ipid, version='ipv6'):
    """Mark an IP as available again."""
    table = _iptable(version)
    with getconnection() as conn:
        conn.execute(f"""
            UPDATE {table} SET assigned = 0, vpsid = NULL WHERE id = ?
        """, (ipid,))

def unassignipbyvpsid(vpsid):
    """Release IP when a VPS is deleted."""
    with getconnection() as conn:
        conn.execute("UPDATE networkipv4 SET assigned = 0, vpsid = NULL WHERE vpsid = ?", (vpsid,))
        conn.execute("UPDATE networkipv6 SET assigned = 0, vpsid = NULL WHERE vpsid = ?", (vpsid,))

def getassignedipsforvps(vpsid):
    with getconnection() as conn:
        ipv4 = conn.execute(
            "SELECT *, 'ipv4' as ip_version FROM networkipv4 WHERE vpsid = ? AND assigned = 1 ORDER BY id ASC LIMIT 1",
            (vpsid,)
        ).fetchone()
        ipv6 = conn.execute(
            "SELECT *, 'ipv6' as ip_version FROM networkipv6 WHERE vpsid = ? AND assigned = 1 ORDER BY id ASC LIMIT 1",
            (vpsid,)
        ).fetchone()
        return {
            "ipv4": dict(ipv4) if ipv4 else None,
            "ipv6": dict(ipv6) if ipv6 else None,
        }

def reserveplanipsforvps(vps, plan, network_type='proxmox'):
    """Reserve required plan IPs for a VPS. Raises ValueError if unavailable."""
    assigned = {"ipv4": None, "ipv6": None}
    reserved = []
    try:
        if plan.get('ipv6'):
            ip6 = reserveipbyversion(vps['networkid'], network_type=network_type, version='ipv6', vpsid=vps['id'])
            if not ip6:
                raise ValueError("No IPv6 addresses available for this network")
            assigned['ipv6'] = ip6['ip']
            reserved.append((ip6['id'], 'ipv6'))
        if plan.get('ipv4'):
            ip4 = reserveipbyversion(vps['networkid'], network_type=network_type, version='ipv4', vpsid=vps['id'])
            if not ip4:
                raise ValueError("No IPv4 addresses available for this network")
            assigned['ipv4'] = ip4['ip']
            reserved.append((ip4['id'], 'ipv4'))
        updatevps(vps['uuid'], ipv4=assigned['ipv4'], ipv6=assigned['ipv6'])
        return assigned
    except Exception:
        for ipid, version in reserved:
            unassignip(ipid, version)
        raise

def countips(networkid, network_type='proxmox'):
    with getconnection() as conn:
        ipv4 = _scalar(conn.execute("SELECT COUNT(*) FROM networkipv4 WHERE networkid = ? AND network_type = ?", (networkid, network_type)).fetchone())
        ipv4assigned = _scalar(conn.execute("SELECT COUNT(*) FROM networkipv4 WHERE networkid = ? AND network_type = ? AND assigned = 1", (networkid, network_type)).fetchone())
        ipv6 = _scalar(conn.execute("SELECT COUNT(*) FROM networkipv6 WHERE networkid = ? AND network_type = ?", (networkid, network_type)).fetchone())
        ipv6assigned = _scalar(conn.execute("SELECT COUNT(*) FROM networkipv6 WHERE networkid = ? AND network_type = ? AND assigned = 1", (networkid, network_type)).fetchone())
        total = ipv4 + ipv6
        assigned = ipv4assigned + ipv6assigned
        return {
            "total": total, "assigned": assigned, "available": total - assigned,
            "ipv4": {"total": ipv4, "assigned": ipv4assigned, "available": ipv4 - ipv4assigned},
            "ipv6": {"total": ipv6, "assigned": ipv6assigned, "available": ipv6 - ipv6assigned},
        }

def generateipsfornetwork(networkid, baseip, count, network_type='proxmox', isipv6=False):
    """Generate a range of IPs for a network."""
    import ipaddress
    generated = []
    table = _iptable('ipv6' if isipv6 else 'ipv4')
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
                conn.execute(f"""
                    INSERT INTO {table} (uuid, networkid, network_type, ip)
                    VALUES (?, ?, ?, ?)
                """, (ipuuid, networkid, network_type, ip))
                generated.append(ip)
            except Exception:
                continue  # Skip duplicates
    return generated

# --- VPS FUNCTIONS ---

def addvps(uuid, userid, planid, imageid, nodeid, storageid, hostname, password, cpu, ram, swap, disk, status='creating', networkid=None, network_type='proxmox', storagepoolid=None):
    with getconnection() as conn:
        conn.execute(
            """INSERT INTO vps (uuid, userid, planid, imageid, nodeid, storageid, networkid, network_type, storagepoolid, hostname, password, cpu, ram, swap, disk, status) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
            (uuid, userid, planid, imageid, nodeid, storageid, networkid, network_type, storagepoolid, hostname, password, cpu, ram, swap, disk, status)
        )


def createvpswithjob(uuid, userid, plan, imageid, nodeid, storageid, networkid, network_type, storagepoolid, hostname, password, status, jobtype=None):
    with getconnection() as conn:
        begin_immediate(conn)
        lock = " FOR UPDATE" if conn.engine == "mysql" else ""
        stock = conn.execute(
            f"SELECT stock FROM plans WHERE id = ?{lock}", (plan['id'],)
        ).fetchone()
        if not stock:
            raise ValueError("Invalid plan selected.")
        if stock['stock'] == 0:
            raise ValueError("This plan is out of stock.")
        if stock['stock'] > 0:
            conn.execute("UPDATE plans SET stock = stock - 1, updated = CURRENT_TIMESTAMP WHERE id = ?", (plan['id'],))
        if storagepoolid:
            conn.execute("UPDATE storagepools SET used = used + ?, updated = CURRENT_TIMESTAMP WHERE id = ?", (plan['disk'], storagepoolid))
        cur = conn.execute(
            """INSERT INTO vps (uuid, userid, planid, imageid, nodeid, storageid, networkid, network_type, storagepoolid, hostname, password, cpu, ram, swap, disk, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (uuid, userid, plan['id'], imageid, nodeid, storageid, networkid, network_type, storagepoolid, hostname, password, plan['cpu'], plan['ram'], plan['swap'], plan['disk'], status)
        )
        vpsid = cur.lastrowid
        if jobtype:
            jobuuid = str(__import__('uuid').uuid4())
            conn.execute("""
                INSERT INTO jobs (uuid, vpsid, vpsuuid, userid, type, status, payload)
                VALUES (?, ?, ?, ?, ?, 'pending', NULL)
            """, (jobuuid, vpsid, uuid, userid, jobtype))
        return vpsid


def getvps(uuid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM vps WHERE uuid = ?", (uuid,)).fetchone()
        return dict(row) if row else None

def getallocatedresources():
    with getconnection() as conn:
        row = conn.execute(
            "SELECT SUM(cpu) AS cpu, SUM(ram) AS ram, SUM(disk) AS disk FROM vps WHERE status != 'deleted'"
        ).fetchone() or {}
    cpu = row.get("cpu") or 0
    ram = row.get("ram") or 0
    disk = row.get("disk") or 0
    return {
        "cpu": cpu,
        "ram_gb": round(ram / 1024, 1) or 0,
        "disk": round(disk / 1024, 1) or 0
    }

def countusers():
    with getconnection() as conn:
        return _scalar(conn.execute("SELECT COUNT(*) FROM users").fetchone())
def countvps(userid=None):
    with getconnection() as conn:
        if userid is not None:
            return _scalar(conn.execute(
                "SELECT COUNT(*) FROM vps WHERE userid = ? AND status != 'deleted'",
                (userid,)
            ).fetchone())
        return _scalar(conn.execute(
            "SELECT COUNT(*) FROM vps WHERE status != 'deleted'"
        ).fetchone())

def updatevps(uuid, **kwargs):
    with getconnection() as conn:
        keys = [f"{k} = ?" for k in kwargs.keys()]
        values = list(kwargs.values()) + [uuid]
        conn.execute(f"UPDATE vps SET {', '.join(keys)}, updated = CURRENT_TIMESTAMP WHERE uuid = ?", values)


def ensurevpspaiduntilcolumn():
    """Add vps.paid_until if missing (live migrate)."""
    with getconnection() as conn:
        cols = set(table_columns(conn, "vps") or [])
        if not cols or "paid_until" in cols:
            return
        try:
            if conn.engine == "mysql":
                conn.execute("ALTER TABLE vps ADD COLUMN paid_until DATETIME NULL")
            else:
                conn.execute("ALTER TABLE vps ADD COLUMN paid_until TEXT")
        except Exception:
            pass


def extendvpspaiduntil(uuid, days=30, from_now=True):
    """
    Set/extend paid_until by `days` in app timezone (general.timezone).
    from_now=True: max(now, current paid_until) + days (renewal-friendly).
    """
    ensurevpspaiduntilcolumn()
    from datetime import datetime, timedelta
    from core import timeutil

    now = timeutil.now()
    with getconnection() as conn:
        row = conn.execute("SELECT paid_until FROM vps WHERE uuid = ?", (uuid,)).fetchone()
        if not row:
            return None
        base = now
        cur = row.get("paid_until") if isinstance(row, dict) else None
        if cur:
            existing = timeutil.parse_local(cur)
            if existing and from_now and existing > now:
                base = existing
        until = base + timedelta(days=int(days))
        until_s = until.strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "UPDATE vps SET paid_until = ?, updated = CURRENT_TIMESTAMP WHERE uuid = ?",
            (until_s, uuid),
        )
        return until_s


def listoverduevps(include_free=True, include_paid=True):
    """
    Live VPS past paid_until (app timezone), not already suspended/deleted/pending.
    """
    ensurevpspaiduntilcolumn()
    from core import timeutil

    price_parts = []
    if include_paid:
        price_parts.append("p.price > 0")
    if include_free:
        price_parts.append("p.price <= 0")
    if not price_parts:
        return []
    price_sql = "(" + " OR ".join(price_parts) + ")"
    now_s = timeutil.now_str()
    with getconnection() as conn:
        rows = conn.execute(f"""
            SELECT v.*, p.price as plan_price, p.name as plan_name
            FROM vps v
            JOIN plans p ON p.id = v.planid
            WHERE {price_sql}
              AND v.paid_until IS NOT NULL
              AND v.paid_until < ?
              AND v.status NOT IN ('suspended', 'deleted', 'pendingpayment', 'creating')
        """, (now_s,)).fetchall()
        return [dict(r) for r in rows]


def listoverduepaidvps():
    """Backward-compatible: paid only."""
    return listoverduevps(include_free=False, include_paid=True)


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
        totalUsers = _scalar(conn.execute(f"SELECT COUNT(*) FROM users {where}", params).fetchone())
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
def listvpspaginated(page=1, perpage=20, userid=None, search=None, status=None):
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
        
        conditions.append("v.status != 'deleted'")

        if userid:
            conditions.append("v.userid = ?")
            params.append(userid)

        if status:
            conditions.append("v.status = ?")
            params.append(status)
        
        if search:
            joins = " JOIN users u ON v.userid = u.id JOIN nodes n ON v.nodeid = n.id"
            conditions.append("(v.hostname LIKE ? OR v.ipv6 LIKE ? OR u.username LIKE ? OR v.status LIKE ? OR n.name LIKE ?)")
            s = f"%{search}%"
            params.extend([s, s, s, s, s])

        whereClause = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        
        totalVps = _scalar(conn.execute(baseCount + joins + whereClause, params).fetchone())
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

def ensurevpssuspensioncolumns():
    """Add userid/lifted on vpssuspensions if missing (live migrate)."""
    with getconnection() as conn:
        cols = set(table_columns(conn, "vpssuspensions") or [])
        if not cols:
            return
        if "userid" not in cols:
            try:
                if conn.engine == "mysql":
                    conn.execute("ALTER TABLE vpssuspensions ADD COLUMN userid INTEGER NULL")
                else:
                    conn.execute("ALTER TABLE vpssuspensions ADD COLUMN userid INTEGER")
            except Exception:
                pass
        if "lifted" not in cols:
            try:
                if conn.engine == "mysql":
                    conn.execute("ALTER TABLE vpssuspensions ADD COLUMN lifted DATETIME NULL")
                else:
                    conn.execute("ALTER TABLE vpssuspensions ADD COLUMN lifted TEXT")
            except Exception:
                pass


def getsuspensionbyvpsid(vpsid):
    """Used by listvpspaginated to show suspension reasons."""
    ensurevpssuspensioncolumns()
    with getconnection() as conn:
        cols = set(table_columns(conn, "vpssuspensions") or [])
        if "lifted" in cols:
            row = conn.execute(
                "SELECT * FROM vpssuspensions WHERE vpsid = ? AND lifted IS NULL ORDER BY id DESC LIMIT 1",
                (vpsid,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM vpssuspensions WHERE vpsid = ? ORDER BY id DESC LIMIT 1",
                (vpsid,),
            ).fetchone()
        return dict(row) if row else None

def addvpssuspension(uuid, vpsid, userid, adminid, reason):
    ensurevpssuspensioncolumns()
    with getconnection() as conn:
        cols = set(table_columns(conn, "vpssuspensions") or [])
        if "userid" in cols:
            conn.execute("""
                INSERT INTO vpssuspensions (uuid, vpsid, userid, adminid, reason)
                VALUES (?, ?, ?, ?, ?)
            """, (uuid, vpsid, userid, adminid, reason))
        else:
            conn.execute("""
                INSERT INTO vpssuspensions (uuid, vpsid, adminid, reason)
                VALUES (?, ?, ?, ?)
            """, (uuid, vpsid, adminid, reason))

def liftvpssuspension(vpsid):
    ensurevpssuspensioncolumns()
    with getconnection() as conn:
        cols = set(table_columns(conn, "vpssuspensions") or [])
        if "lifted" in cols:
            conn.execute("""
                UPDATE vpssuspensions SET lifted = CURRENT_TIMESTAMP
                WHERE vpsid = ? AND lifted IS NULL
            """, (vpsid,))
        else:
            conn.execute("DELETE FROM vpssuspensions WHERE vpsid = ?", (vpsid,))
    
def getplanbyid(planid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM plans WHERE id = ?", (planid,)).fetchone()
        return dict(row) if row else None
    
def countnodes():
    with getconnection() as conn:
        return _scalar(conn.execute("SELECT COUNT(*) FROM nodes").fetchone())
def listallnodes():
    ensurelocationstable()
    with getconnection() as conn:
        # Join with a count of VPS instances currently on that node and location info
        rows = conn.execute("""
            SELECT n.*, 
            loc.name as location_name, loc.code as location_code, loc.flag as location_flag,
            (SELECT COUNT(*) FROM vps WHERE nodeid = n.id AND status != 'deleted') as vps_count
            FROM nodes n
            LEFT JOIN locations loc ON n.locationid = loc.id
            ORDER BY n.created DESC
        """).fetchall()
        return [dict(r) for r in rows]

def updatenode(uuid, **kwargs):
    ensurelocationstable()
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
            receiptCount = _scalar(conn.execute("SELECT COUNT(*) FROM receipts").fetchone())
            receiptNumber = f"RCP-{(receiptCount + 1):06d}"
            conn.execute("""
                INSERT INTO receipts (uuid, receiptnumber, transactionid, userid, amount, currency,
                                    taxamount, billingname, billingemail, billingaddress, notes)
                VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, NULL, ?)
            """, (str(__import__('uuid').uuid4()), receiptNumber, txnId, userid, float(amount), currency,
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
        count = _scalar(row) + 1
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


def getsuitablenodeandstorage(planid, strategy='both', node_type='proxmox', imageid=None, disk_mb=0, locationid=None):
    """Pick node+storage from plan assignments (not free/paid tier).

    Returns (node_id, storagepool_id).
    """
    imageFilter = "AND EXISTS (SELECT 1 FROM node_images ni WHERE ni.nodeid = n.id AND ni.imageid = ?)" if imageid else ""
    imageParams = [imageid] if imageid else []
    
    locFilter = "AND n.locationid = ?" if locationid else ""
    locParams = [locationid] if locationid else []

    capacityFilter = "AND (n.max_vps = 0 OR (SELECT COUNT(*) FROM vps v WHERE v.nodeid = n.id AND v.status NOT IN ('deleted', 'error')) < n.max_vps)"

    # Only nodes assigned to this plan
    planNodeFilter = "AND EXISTS (SELECT 1 FROM plan_nodes pn WHERE pn.nodeid = n.id AND pn.planid = ?)"
    baseWhere = f"n.status = 'online' AND n.type = ? {planNodeFilter} {imageFilter} {locFilter} {capacityFilter}"
    baseParams = [node_type, planid] + imageParams + locParams

    with getconnection() as conn:
        if strategy == 'random':
            nodes = conn.execute(
                f"SELECT n.id FROM nodes n WHERE {baseWhere}",
                baseParams
            ).fetchall()
            if not nodes:
                return None, None
            node_id = random.choice(nodes)['id']

        elif strategy == 'least_vps':
            row = conn.execute(f"""
                SELECT n.id
                FROM nodes n
                LEFT JOIN vps v ON v.nodeid = n.id AND v.status NOT IN ('deleted', 'error')
                WHERE {baseWhere}
                GROUP BY n.id
                ORDER BY COUNT(v.id) ASC
                LIMIT 1
            """, baseParams).fetchone()
            if not row:
                return None, None
            node_id = row['id']

        elif strategy == 'resources':
            row = conn.execute(f"""
                SELECT n.id
                FROM nodes n
                LEFT JOIN vps v ON v.nodeid = n.id AND v.status NOT IN ('deleted', 'error')
                WHERE {baseWhere}
                GROUP BY n.id
                HAVING n.ram > COALESCE(SUM(v.ram), 0)
                ORDER BY (n.ram - COALESCE(SUM(v.ram), 0)) DESC
                LIMIT 1
            """, baseParams).fetchone()
            if not row:
                return None, None
            node_id = row['id']

        else:  # 'both' (default)
            row = conn.execute(f"""
                SELECT n.id,
                       n.ram as total_ram,
                       COALESCE(SUM(v.ram), 0) as used_ram,
                       COUNT(v.id) as vps_count
                FROM nodes n
                LEFT JOIN vps v ON v.nodeid = n.id AND v.status NOT IN ('deleted', 'error')
                WHERE {baseWhere}
                GROUP BY n.id
                HAVING n.ram > COALESCE(SUM(v.ram), 0)
                ORDER BY (n.ram - COALESCE(SUM(v.ram), 0)) DESC, vps_count ASC
                LIMIT 1
            """, baseParams).fetchone()
            if not row:
                return None, None
            node_id = row['id']

        # Storage: prefer pools assigned to plan on this node; fall back none
        storage = conn.execute("""
            SELECT sp.id
            FROM storagepools sp
            JOIN plan_storagepools psp ON psp.storagepoolid = sp.id
            WHERE psp.planid = ? AND sp.nodeid = ?
              AND (sp.size <= 0 OR (sp.size * 1024 - sp.used) >= ?)
            ORDER BY (CASE WHEN sp.size > 0 THEN (sp.size * 1024 - sp.used) ELSE 999999999 END) DESC
            LIMIT 1
        """, (planid, node_id, disk_mb or 0)).fetchone()

        if not storage:
            storage = conn.execute("""
                SELECT sp.id
                FROM storagepools sp
                JOIN plan_storagepools psp ON psp.storagepoolid = sp.id
                WHERE psp.planid = ? AND sp.nodeid = ?
                ORDER BY sp.created DESC
                LIMIT 1
            """, (planid, node_id)).fetchone()

        return node_id, (storage['id'] if storage else None)
    
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
        total = _scalar(conn.execute(f"SELECT COUNT(*) FROM plans {where}", params).fetchone())
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
        total = _scalar(conn.execute(f"SELECT COUNT(*) FROM images i {where}", params).fetchone())
        rows = conn.execute(f"""
            SELECT i.*,
            (SELECT COUNT(*) FROM vps WHERE imageid = i.id AND status != 'deleted') as vps_count,
            (SELECT COUNT(*) FROM node_images WHERE imageid = i.id) as node_count
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
    ensurelocationstable()
    with getconnection() as conn:
        offset = (page - 1) * perpage
        where = ""
        params = []
        if search:
            where = "WHERE n.name LIKE ? OR n.hostname LIKE ? OR n.address LIKE ? OR loc.name LIKE ? OR loc.code LIKE ? OR n.status LIKE ? OR n.tier LIKE ?"
            s = f"%{search}%"
            params = [s, s, s, s, s, s, s]
        total = _scalar(conn.execute(f"SELECT COUNT(*) FROM nodes n LEFT JOIN locations loc ON n.locationid = loc.id {where}", params).fetchone())
        rows = conn.execute(f"""
            SELECT n.*, 
            loc.name as location_name, loc.code as location_code, loc.flag as location_flag,
            (SELECT COUNT(*) FROM vps WHERE nodeid = n.id AND status != 'deleted') as vps_count
            FROM nodes n
            LEFT JOIN locations loc ON n.locationid = loc.id
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
        total = _scalar(conn.execute(f"SELECT COUNT(*) FROM paymentmethods p {where}", params).fetchone())
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
        total = _scalar(conn.execute(f"""
            SELECT COUNT(*) FROM receipts
            JOIN users ON users.id = receipts.userid
            {where}
""", params).fetchone())
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

# --- AUDIT LOG FUNCTIONS ---

def addauditlog(uuid, userid, username, role, action, target_type=None, target_id=None, details=None, ip=None):
    with getconnection() as conn:
        conn.execute("""
            INSERT INTO auditlog (uuid, userid, username, role, action, target_type, target_id, details, ip)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (uuid, userid, username, role, action, target_type, target_id, details, ip))

def getlastfreerenewtime(vpsuuid):
    """Returns the datetime of the latest free renewal audit log for a VPS, or None."""
    with getconnection() as conn:
        row = conn.execute("""
            SELECT created FROM auditlog
            WHERE action = 'vps.free_renew' AND target_id = ?
            ORDER BY created DESC LIMIT 1
        """, (vpsuuid,)).fetchone()
        if row and row.get("created"):
            from core import timeutil
            return timeutil.parse_local(row["created"])
        return None

def listauditlogspaginated(page=1, perpage=25, search=None, action_filter=None, user_filter=None):
    with getconnection() as conn:
        offset = (page - 1) * perpage
        where = ""
        params = []

        if action_filter:
            where = "WHERE al.action LIKE ?"
            params.append(f"%{action_filter}%")
        if user_filter:
            where = ("WHERE " if not where else where + " AND ") + "al.username LIKE ?"
            params.append(f"%{user_filter}%")
        if search:
            where = ("WHERE " if not where else where + " AND ") + "(al.action LIKE ? OR al.username LIKE ? OR al.details LIKE ? OR al.target_type LIKE ? OR al.target_id LIKE ?)"
            s = f"%{search}%"
            params.extend([s, s, s, s, s])

        total = _scalar(conn.execute(f"SELECT COUNT(*) FROM auditlog al {where}", params).fetchone())
        rows = conn.execute(f"""
            SELECT al.*
            FROM auditlog al
            {where}
            ORDER BY al.created DESC
            LIMIT ? OFFSET ?
        """, params + [perpage, offset]).fetchall()
        return {
            "logs": [dict(r) for r in rows],
            "totalCount": total,
            "currentPage": page,
            "perPage": perpage,
            "totalPages": math.ceil(total / perpage) if perpage else 1,
            "hasPrev": page > 1,
            "hasNext": (page * perpage) < total,
        }

def getauditlogactions():
    """Get distinct action types for filter dropdown."""
    with getconnection() as conn:
        rows = conn.execute("SELECT DISTINCT action FROM auditlog ORDER BY action").fetchall()
        return [r['action'] for r in rows]

# --- SETTINGS FUNCTIONS ---

def getsetting(key, default=None):
    with getconnection() as conn:
        col = "`key`" if conn.engine == "mysql" else "key"
        row = conn.execute(f"SELECT value FROM settings WHERE {col} = ?", (key,)).fetchone()
        if row:
            try:
                return json.loads(row['value'])
            except (json.JSONDecodeError, TypeError):
                return row['value']
        return default

def setsetting(key, value, description=None):
    with getconnection() as conn:
        # Always JSON-encode so strings stay strings (e.g. numeric Discord client IDs)
        serialized = json.dumps(value)
        if conn.engine == "mysql":
            conn.execute("""
                INSERT INTO settings (`key`, value, description, updated)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON DUPLICATE KEY UPDATE
                    value = VALUES(value),
                    description = COALESCE(VALUES(description), settings.description),
                    updated = CURRENT_TIMESTAMP
            """, (key, serialized, description))
        else:
            conn.execute("""
                INSERT INTO settings (key, value, description, updated)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    description = COALESCE(excluded.description, settings.description),
                    updated = CURRENT_TIMESTAMP
            """, (key, serialized, description))

def getallsettings():
    with getconnection() as conn:
        col = "`key`" if conn.engine == "mysql" else "key"
        rows = conn.execute(
            f"SELECT {col} AS k, value, description FROM settings ORDER BY {col}"
        ).fetchall()
        result = {}
        for r in rows:
            try:
                result[r['k']] = json.loads(r['value'])
            except (json.JSONDecodeError, TypeError):
                result[r['k']] = r['value']
        return result

def removesetting(key):
    with getconnection() as conn:
        col = "`key`" if conn.engine == "mysql" else "key"
        conn.execute(f"DELETE FROM settings WHERE {col} = ?", (key,))

# --- JOB QUEUE FUNCTIONS ---

def addjob(uuid, vpsid, vpsuuid, userid, jobtype, payload=None):
    with getconnection() as conn:
        conn.execute("""
            INSERT INTO jobs (uuid, vpsid, vpsuuid, userid, type, status, payload)
            VALUES (?, ?, ?, ?, ?, 'pending', ?)
        """, (uuid, vpsid, vpsuuid, userid, jobtype, payload))

def getjob(uuid):
    with getconnection() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE uuid = ?", (uuid,)).fetchone()
        return dict(row) if row else None

def getnextpendingjob():
    """
    Atomically claim one pending job → running.
    MySQL: FOR UPDATE SKIP LOCKED when available (multi-worker safe).
    """
    with getconnection() as conn:
        begin_immediate(conn)
        row = None
        if conn.engine == "mysql":
            for lock in (" FOR UPDATE SKIP LOCKED", " FOR UPDATE", ""):
                try:
                    row = conn.execute(
                        f"SELECT * FROM jobs WHERE status = 'pending' ORDER BY id ASC LIMIT 1{lock}"
                    ).fetchone()
                    break
                except Exception:
                    row = None
                    continue
        else:
            row = conn.execute(
                "SELECT * FROM jobs WHERE status = 'pending' ORDER BY id ASC LIMIT 1"
            ).fetchone()
        if not row:
            return None
        columns = table_columns(conn, "jobs")
        if "updated" in columns:
            conn.execute(
                "UPDATE jobs SET status = 'running', updated = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'",
                (row["id"],),
            )
        else:
            conn.execute(
                "UPDATE jobs SET status = 'running' WHERE id = ? AND status = 'pending'",
                (row["id"],),
            )
        # re-read in case lost race
        claimed = conn.execute("SELECT * FROM jobs WHERE id = ?", (row["id"],)).fetchone()
        if not claimed or claimed.get("status") != "running":
            return None
        return dict(claimed)

def updatejob(uuid, **kwargs):
    with getconnection() as conn:
        keys = [f"{k} = ?" for k in kwargs.keys()]
        columns = table_columns(conn, "jobs")
        if "updated" in columns:
            keys.append("updated = CURRENT_TIMESTAMP")
        values = list(kwargs.values()) + [uuid]
        conn.execute(f"UPDATE jobs SET {', '.join(keys)} WHERE uuid = ?", values)


def reclaimstalejobs(stale_minutes=45):
    """
    Jobs left 'running' after crash/deploy → pending again.
    Returns number reclaimed.
    """
    from core import timeutil
    from datetime import timedelta

    stale_minutes = max(5, int(stale_minutes or 45))
    cutoff = (timeutil.now() - timedelta(minutes=stale_minutes)).strftime("%Y-%m-%d %H:%M:%S")
    with getconnection() as conn:
        columns = table_columns(conn, "jobs")
        if "updated" not in columns:
            return 0
        cur = conn.execute(
            """
            UPDATE jobs
            SET status = 'pending', updated = CURRENT_TIMESTAMP,
                result = COALESCE(result, 'reclaimed: stale running job')
            WHERE status = 'running'
              AND COALESCE(updated, created) < ?
            """,
            (cutoff,),
        )
        return max(0, cur.rowcount or 0)


def countjobsbystatus():
    with getconnection() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) AS c FROM jobs GROUP BY status"
        ).fetchall()
        out = {"pending": 0, "running": 0, "completed": 0, "failed": 0}
        for r in rows:
            out[r.get("status") or "?"] = int(r.get("c") or 0)
        return out

def getactivejobforvps(vpsuuid):
    """Get the most recent non-completed job for a VPS."""
    with getconnection() as conn:
        row = conn.execute("""
            SELECT * FROM jobs WHERE vpsuuid = ? AND status IN ('pending', 'running')
            ORDER BY id DESC LIMIT 1
        """, (vpsuuid,)).fetchone()
        return dict(row) if row else None

def getrecentjobsforvps(vpsuuid, limit=5):
    with getconnection() as conn:
        rows = conn.execute("""
            SELECT * FROM jobs WHERE vpsuuid = ? ORDER BY id DESC LIMIT ?
        """, (vpsuuid, limit)).fetchall()
        return [dict(r) for r in rows]

def haspendingjobs(vpsuuid):
    with getconnection() as conn:
        row = conn.execute("""
            SELECT COUNT(*) FROM jobs WHERE vpsuuid = ? AND status IN ('pending', 'running')
        """, (vpsuuid,)).fetchone()
        return _scalar(row) > 0


def deletevpsrecord(vpsid):
    with getconnection() as conn:
        conn.execute("UPDATE networkipv4 SET assigned = 0, vpsid = NULL WHERE vpsid = ?", (vpsid,))
        conn.execute("UPDATE networkipv6 SET assigned = 0, vpsid = NULL WHERE vpsid = ?", (vpsid,))
        conn.execute("UPDATE transactions SET vpsid = NULL WHERE vpsid = ?", (vpsid,))
        conn.execute("UPDATE jobs SET vpsid = NULL WHERE vpsid = ?", (vpsid,))
        conn.execute("DELETE FROM vpssuspensions WHERE vpsid = ?", (vpsid,))
        conn.execute("DELETE FROM vps WHERE id = ?", (vpsid,))


def listdeletedvpsneedingpurge(limit=20):
    """
    VPS marked deleted that still need node purge (had a CT) and no active delete job.
    Skips checkout soft-deletes (no vmid) so late PayPal can still revive them.
    """
    with getconnection() as conn:
        rows = conn.execute("""
            SELECT v.*
            FROM vps v
            WHERE v.status = 'deleted'
              AND v.vmid IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1 FROM jobs j
                  WHERE j.vpsuuid = v.uuid
                    AND j.type = 'delete'
                    AND j.status IN ('pending', 'running')
              )
            ORDER BY v.updated ASC
            LIMIT ?
        """, (int(limit),)).fetchall()
        return [dict(r) for r in rows]


def listimagesfornode(nodeid):
    """List images assigned to a given node."""
    with getconnection() as conn:
        rows = conn.execute("""
            SELECT i.*, ni.imagestorageid, ist.name as storage_name
            FROM images i
            JOIN node_images ni ON ni.imageid = i.id
            LEFT JOIN imagestorage ist ON ni.imagestorageid = ist.id
            WHERE ni.nodeid = ?
            ORDER BY i.created DESC
        """, (nodeid,)).fetchall()
        return [dict(r) for r in rows]

def countvpsfornode(nodeid):
    """Count active VPS instances on a specific node."""
    with getconnection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM vps WHERE nodeid = ? AND status != 'deleted'",
            (nodeid,)
        ).fetchone()
        return _scalar(row)

def getnodediskcapacity(nodeid):
    """Sum of all storage pool sizes for a node (in GB)."""
    with getconnection() as conn:
        row = conn.execute("SELECT COALESCE(SUM(size), 0) FROM storagepools WHERE nodeid = ?", (nodeid,)).fetchone()
        return _scalar(row)
# ===== TICKETING SYSTEM =====

def createticket(uuid, userid, subject, priority='normal'):
    """Create a new support ticket."""
    with getconnection() as conn:
        conn.execute("""
            INSERT INTO tickets (uuid, userid, subject, priority, status)
            VALUES (?, ?, ?, ?, 'open')
        """, (uuid, userid, subject, priority))
        return conn.execute("SELECT * FROM tickets WHERE uuid = ?", (uuid,)).fetchone()

def getticket(ticket_uuid):
    """Get ticket by UUID."""
    with getconnection() as conn:
        ticket = conn.execute("""
            SELECT t.*, u.username, u.email
            FROM tickets t
            JOIN users u ON t.userid = u.id
            WHERE t.uuid = ?
        """, (ticket_uuid,)).fetchone()
        return dict(ticket) if ticket else None

def listtickets(userid=None, status=None, page=1, per_page=20):
    """List tickets with pagination. If userid is None, returns all tickets (admin view)."""
    with getconnection() as conn:
        conditions = []
        params = []
        
        if userid:
            conditions.append("t.userid = ?")
            params.append(userid)
        
        if status:
            conditions.append("t.status = ?")
            params.append(status)
        
        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
        
        # Get total count
        count_query = f"SELECT COUNT(*) FROM tickets t {where_clause}"
        total = _scalar(conn.execute(count_query, params).fetchone())
        # Get paginated tickets
        offset = (page - 1) * per_page
        params.extend([per_page, offset])
        
        query = f"""
            SELECT t.*, u.username, u.email,
                   (SELECT COUNT(*) FROM ticket_messages WHERE ticketid = t.id) as message_count
            FROM tickets t
            JOIN users u ON t.userid = u.id
            {where_clause}
            ORDER BY t.updated DESC, t.created DESC
            LIMIT ? OFFSET ?
        """
        
        tickets = conn.execute(query, params).fetchall()
        
        return {
            'tickets': [dict(t) for t in tickets],
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        }

def addticketmessage(ticketid, userid, message, is_staff=0):
    """Add a message to a ticket and update ticket status/timestamp."""
    with getconnection() as conn:
        # Add message
        conn.execute("""
            INSERT INTO ticket_messages (ticketid, userid, message, is_staff)
            VALUES (?, ?, ?, ?)
        """, (ticketid, userid, message, is_staff))
        
        # Update ticket status and timestamp
        new_status = 'replied' if is_staff else 'open'
        conn.execute("""
            UPDATE tickets 
            SET status = ?, updated = CURRENT_TIMESTAMP 
            WHERE id = ?
        """, (new_status, ticketid))
        
        return True

def getticketmessages(ticketid):
    """Get all messages for a ticket."""
    with getconnection() as conn:
        messages = conn.execute("""
            SELECT tm.*, u.username, u.email, u.role
            FROM ticket_messages tm
            JOIN users u ON tm.userid = u.id
            WHERE tm.ticketid = ?
            ORDER BY tm.created ASC
        """, (ticketid,)).fetchall()
        return [dict(m) for m in messages]

def updateticketstatus(ticket_uuid, status):
    """Update ticket status (open, replied, closed)."""
    with getconnection() as conn:
        conn.execute("""
            UPDATE tickets 
            SET status = ?, updated = CURRENT_TIMESTAMP 
            WHERE uuid = ?
        """, (status, ticket_uuid))
        return True

def counttickets(userid=None, status=None):
    """Count tickets. If userid is None, counts all tickets (admin view)."""
    with getconnection() as conn:
        conditions = []
        params = []
        
        if userid:
            conditions.append("userid = ?")
            params.append(userid)
        
        if status:
            conditions.append("status = ?")
            params.append(status)
        
        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
        
        query = f"SELECT COUNT(*) FROM tickets {where_clause}"
        row = conn.execute(query, params).fetchone()
        return _scalar(row)

def getticketbyid(ticketid):
    """Get ticket by internal ID."""
    with getconnection() as conn:
        ticket = conn.execute("""
            SELECT t.*, u.username, u.email
            FROM tickets t
            JOIN users u ON t.userid = u.id
            WHERE t.id = ?
        """, (ticketid,)).fetchone()
        return dict(ticket) if ticket else None
