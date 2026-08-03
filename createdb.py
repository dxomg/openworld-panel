"""Create schema for configured engine (sqlite or mysql)."""
import os
import sys

# allow running from client/ or repo root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import dbconfig
from core.db import getconnection

SCHEMA_SQLITE = open(os.path.join(os.path.dirname(__file__), "schema_sqlite.sql"), encoding="utf-8").read() if False else None

# Inline schema (from previous createdb) — dual convert at runtime
_SCHEMA = r"""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    discordid TEXT UNIQUE,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
        CHECK(role IN ('user','admin')),
    status TEXT NOT NULL DEFAULT 'active'
        CHECK(status IN ('active','suspended','banned')),
    verified INTEGER NOT NULL DEFAULT 0
        CHECK(verified IN (0,1)),
    theme TEXT DEFAULT NULL,
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    userid INTEGER NOT NULL,
    adminid INTEGER,
    reason TEXT NOT NULL,
    expires TEXT,
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(userid) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(adminid) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    address TEXT NOT NULL,
    url TEXT NOT NULL DEFAULT '',
    apikey TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'proxmox'
        CHECK(type IN ('proxmox')),
    status TEXT NOT NULL DEFAULT 'online'
        CHECK(status IN ('online','offline','maintenance')),
    tier TEXT NOT NULL DEFAULT 'free'
        CHECK(tier IN ('free', 'paid')),
    cpu INTEGER NOT NULL,
    ram INTEGER NOT NULL,
    proxmoxhost TEXT,
    proxmoxuser TEXT,
    proxmoxpassword TEXT,
    proxmoxnode TEXT DEFAULT 'pve',
    proxmoxport INTEGER DEFAULT 8006,
    proxmoxssl INTEGER DEFAULT 0
        CHECK(proxmoxssl IN (0,1)),
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    cpu INTEGER NOT NULL,
    ram INTEGER NOT NULL,
    swap INTEGER NOT NULL,
    disk INTEGER NOT NULL,
    netmbps INTEGER NOT NULL DEFAULT 0,
    ipv4 INTEGER NOT NULL DEFAULT 0,
    ipv6 INTEGER NOT NULL DEFAULT 1,
    price REAL NOT NULL DEFAULT 0,
    stock INTEGER NOT NULL DEFAULT -1,
    node_type TEXT NOT NULL DEFAULT 'proxmox'
        CHECK(node_type IN ('proxmox')),
    active INTEGER NOT NULL DEFAULT 1
        CHECK(active IN (0,1)),
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS storagepools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    nodeid INTEGER NOT NULL,
    name TEXT NOT NULL,
    source TEXT,
    size INTEGER NOT NULL DEFAULT 0,
    used INTEGER NOT NULL DEFAULT 0,
    node_type TEXT NOT NULL DEFAULT 'proxmox'
        CHECK(node_type IN ('proxmox')),
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(nodeid) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS imagestorage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    nodeid INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(nodeid) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    image TEXT NOT NULL,
    os_type TEXT NOT NULL DEFAULT 'linux',
    description TEXT,
    node_type TEXT NOT NULL DEFAULT 'proxmox'
        CHECK(node_type IN ('proxmox')),
    active INTEGER NOT NULL DEFAULT 1
        CHECK(active IN (0,1)),
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

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

CREATE TABLE IF NOT EXISTS node_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    nodeid INTEGER NOT NULL,
    imageid INTEGER NOT NULL,
    imagestorageid INTEGER,
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(nodeid) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY(imageid) REFERENCES images(id) ON DELETE CASCADE,
    FOREIGN KEY(imagestorageid) REFERENCES imagestorage(id) ON DELETE SET NULL,
    UNIQUE(nodeid, imageid)
);

CREATE TABLE IF NOT EXISTS proxmox_networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    nodeid INTEGER NOT NULL,
    name TEXT NOT NULL,
    subnet TEXT,
    gateway TEXT,
    ipv4 INTEGER NOT NULL DEFAULT 0
        CHECK(ipv4 IN (0,1)),
    ipv6 INTEGER NOT NULL DEFAULT 1
        CHECK(ipv6 IN (0,1)),
    ipv4_subnet TEXT,
    ipv4_gateway TEXT,
    dns TEXT DEFAULT '1.1.1.1,8.8.8.8,2606:4700:4700::1111,2001:4860:4860::8888',
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(nodeid) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    userid INTEGER NOT NULL,
    planid INTEGER NOT NULL,
    imageid INTEGER NOT NULL,
    nodeid INTEGER NOT NULL,
    storageid INTEGER,
    networkid INTEGER,
    network_type TEXT DEFAULT 'proxmox'
        CHECK(network_type IN ('proxmox')),
    storagepoolid INTEGER,
    hostname TEXT NOT NULL,
    password TEXT NOT NULL,
    container TEXT,
    vmid INTEGER,
    status TEXT NOT NULL DEFAULT 'creating'
        CHECK(status IN (
            'creating','running','stopped','restarting','suspended',
            'pendingpayment','deleted','error'
        )),
    cpu INTEGER NOT NULL,
    ram INTEGER NOT NULL,
    swap INTEGER NOT NULL,
    disk INTEGER NOT NULL,
    ipv4 TEXT,
    ipv6 TEXT,
    paid_until TEXT,
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(userid) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(planid) REFERENCES plans(id) ON DELETE RESTRICT,
    FOREIGN KEY(imageid) REFERENCES images(id) ON DELETE RESTRICT,
    FOREIGN KEY(nodeid) REFERENCES nodes(id) ON DELETE RESTRICT,
    FOREIGN KEY(storagepoolid) REFERENCES storagepools(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS networkipv4 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    networkid INTEGER NOT NULL,
    network_type TEXT NOT NULL DEFAULT 'proxmox'
        CHECK(network_type IN ('proxmox')),
    ip TEXT NOT NULL,
    assigned INTEGER NOT NULL DEFAULT 0
        CHECK(assigned IN (0,1)),
    vpsid INTEGER,
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(vpsid) REFERENCES vps(id) ON DELETE SET NULL,
    UNIQUE(networkid, network_type, ip)
);

CREATE TABLE IF NOT EXISTS networkipv6 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    networkid INTEGER NOT NULL,
    network_type TEXT NOT NULL DEFAULT 'proxmox'
        CHECK(network_type IN ('proxmox')),
    ip TEXT NOT NULL,
    assigned INTEGER NOT NULL DEFAULT 0
        CHECK(assigned IN (0,1)),
    vpsid INTEGER,
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(vpsid) REFERENCES vps(id) ON DELETE SET NULL,
    UNIQUE(networkid, network_type, ip)
);

CREATE TABLE IF NOT EXISTS vpssuspensions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    vpsid INTEGER NOT NULL,
    userid INTEGER,
    reason TEXT NOT NULL,
    adminid INTEGER,
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lifted TEXT,
    FOREIGN KEY(vpsid) REFERENCES vps(id) ON DELETE CASCADE,
    FOREIGN KEY(userid) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY(adminid) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS paymentmethods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL DEFAULT 'manual',
    config TEXT,
    active INTEGER NOT NULL DEFAULT 1
        CHECK(active IN (0,1)),
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    transactionid TEXT UNIQUE,
    userid INTEGER NOT NULL,
    vpsid INTEGER,
    planid INTEGER,
    paymentprocessorid INTEGER,
    amount REAL NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT 'USD',
    status TEXT NOT NULL DEFAULT 'pending',
    raw TEXT,
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(userid) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(vpsid) REFERENCES vps(id) ON DELETE SET NULL,
    FOREIGN KEY(planid) REFERENCES plans(id) ON DELETE SET NULL,
    FOREIGN KEY(paymentprocessorid) REFERENCES paymentmethods(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    receiptnumber TEXT UNIQUE NOT NULL,
    transactionid INTEGER,
    userid INTEGER NOT NULL,
    amount REAL NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT 'USD',
    taxamount REAL NOT NULL DEFAULT 0,
    billingname TEXT,
    billingemail TEXT,
    billingaddress TEXT,
    notes TEXT,
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(transactionid) REFERENCES transactions(id) ON DELETE SET NULL,
    FOREIGN KEY(userid) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    userid INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires TEXT NOT NULL,
    ip TEXT,
    agent TEXT,
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(userid) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auditlog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    userid INTEGER,
    username TEXT,
    role TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    details TEXT,
    ip TEXT,
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(userid) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS jobs (
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

CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    userid INTEGER NOT NULL,
    subject TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open'
        CHECK(status IN ('open','replied','closed')),
    priority TEXT NOT NULL DEFAULT 'normal'
        CHECK(priority IN ('low','normal','high')),
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(userid) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ticket_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticketid INTEGER NOT NULL,
    userid INTEGER NOT NULL,
    message TEXT NOT NULL,
    is_staff INTEGER NOT NULL DEFAULT 0
        CHECK(is_staff IN (0,1)),
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(ticketid) REFERENCES tickets(id) ON DELETE CASCADE,
    FOREIGN KEY(userid) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idxproxnetuuid ON proxmox_networks(uuid);
CREATE INDEX IF NOT EXISTS idxproxnetnode ON proxmox_networks(nodeid);
CREATE INDEX IF NOT EXISTS idxnetworkipv4uuid ON networkipv4(uuid);
CREATE INDEX IF NOT EXISTS idxnetworkipv4net ON networkipv4(networkid, network_type);
CREATE INDEX IF NOT EXISTS idxnetworkipv6uuid ON networkipv6(uuid);
CREATE INDEX IF NOT EXISTS idxnetworkipv6net ON networkipv6(networkid, network_type);
CREATE INDEX IF NOT EXISTS idxvpsuuid ON vps(uuid);
CREATE INDEX IF NOT EXISTS idxvpsuser ON vps(userid);
CREATE INDEX IF NOT EXISTS idxvpsplan ON vps(planid);
CREATE INDEX IF NOT EXISTS idxvpsimage ON vps(imageid);
CREATE INDEX IF NOT EXISTS idxvpsnode ON vps(nodeid);
CREATE INDEX IF NOT EXISTS idxvpsstorage ON vps(storageid);
CREATE INDEX IF NOT EXISTS idxsuspensionvps ON vpssuspensions(vpsid);
CREATE INDEX IF NOT EXISTS idxpaymentmethodsuuid ON paymentmethods(uuid);
CREATE INDEX IF NOT EXISTS idxpaymentmethodsslug ON paymentmethods(slug);
CREATE INDEX IF NOT EXISTS idxtransactionsuuid ON transactions(uuid);
CREATE INDEX IF NOT EXISTS idxtransactionsid ON transactions(transactionid);
CREATE INDEX IF NOT EXISTS idxtransactionsuser ON transactions(userid);
CREATE INDEX IF NOT EXISTS idxtransactionsvps ON transactions(vpsid);
CREATE INDEX IF NOT EXISTS idxtransactionsplan ON transactions(planid);
CREATE INDEX IF NOT EXISTS idxtransactionsprocessor ON transactions(paymentprocessorid);
CREATE INDEX IF NOT EXISTS idxreceiptsuuid ON receipts(uuid);
CREATE INDEX IF NOT EXISTS idxreceiptsnumber ON receipts(receiptnumber);
CREATE INDEX IF NOT EXISTS idxreceiptstransaction ON receipts(transactionid);
CREATE INDEX IF NOT EXISTS idxreceiptsuser ON receipts(userid);
CREATE INDEX IF NOT EXISTS idxsessionuser ON sessions(userid);
CREATE INDEX IF NOT EXISTS idxsessiontoken ON sessions(token);
CREATE INDEX IF NOT EXISTS idxauditloguuid ON auditlog(uuid);
CREATE INDEX IF NOT EXISTS idxauditloguser ON auditlog(userid);
CREATE INDEX IF NOT EXISTS idxauditlogaction ON auditlog(action);
CREATE INDEX IF NOT EXISTS idxauditlogcreated ON auditlog(created);
CREATE INDEX IF NOT EXISTS idxjobsuuid ON jobs(uuid);
CREATE INDEX IF NOT EXISTS idxjobsvps ON jobs(vpsuuid);
CREATE INDEX IF NOT EXISTS idxjobsstatus ON jobs(status);
CREATE INDEX IF NOT EXISTS idxticketsuuid ON tickets(uuid);
CREATE INDEX IF NOT EXISTS idxticketsuser ON tickets(userid);
CREATE INDEX IF NOT EXISTS idxticketsstatus ON tickets(status);
CREATE INDEX IF NOT EXISTS idxticketmsgticket ON ticket_messages(ticketid);
CREATE INDEX IF NOT EXISTS idxplannodesplan ON plan_nodes(planid);
CREATE INDEX IF NOT EXISTS idxplannodesnode ON plan_nodes(nodeid);
CREATE INDEX IF NOT EXISTS idxplanpoolsplan ON plan_storagepools(planid);
CREATE INDEX IF NOT EXISTS idxplanpoolspool ON plan_storagepools(storagepoolid);
"""


def _to_mysql(schema: str) -> str:
    """Convert SQLite DDL to MySQL-safe types (no DEFAULT on TEXT/BLOB)."""
    import re

    s = schema
    s = s.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY")
    s = s.replace("REAL ", "DOUBLE ")
    # MySQL < 8.0 / many hosts: no CREATE INDEX IF NOT EXISTS
    s = s.replace("CREATE INDEX IF NOT EXISTS ", "CREATE INDEX ")

    # timestamps as DATETIME (VARCHAR DEFAULT CURRENT_TIMESTAMP often rejected)
    s = s.replace(
        "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP",
        "DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
    )
    s = s.replace(
        "TEXT DEFAULT CURRENT_TIMESTAMP",
        "DATETIME DEFAULT CURRENT_TIMESTAMP",
    )

    # settings.key reserved word + PK length
    s = s.replace(
        "CREATE TABLE IF NOT EXISTS settings (\n    key TEXT PRIMARY KEY,",
        "CREATE TABLE IF NOT EXISTS settings (\n    `key` VARCHAR(191) PRIMARY KEY,",
    )

    # UNIQUE TEXT needs a length for InnoDB indexes.
    # token_urlsafe(64) ≈ 86 chars — use 191 (safe utf8mb4 index limit)
    s = re.sub(r"\bTEXT UNIQUE NOT NULL\b", "VARCHAR(191) UNIQUE NOT NULL", s)
    s = re.sub(r"\bTEXT UNIQUE\b", "VARCHAR(191) UNIQUE", s)

    # Any remaining TEXT ... DEFAULT ...  → VARCHAR (MySQL rejects DEFAULT on TEXT)
    def _text_default(m):
        rest = m.group(1)
        # long DNS default etc.
        size = 512 if len(rest) > 40 else 191
        return f"VARCHAR({size}){rest}"

    s = re.sub(r"\bTEXT( NOT NULL DEFAULT [^,\n]+)", _text_default, s)
    s = re.sub(r"\bTEXT( DEFAULT [^,\n]+)", _text_default, s)

    # leftover bare TEXT columns (nullable free-form) stay TEXT — fine without DEFAULT
    # but uuid-like NOT NULL without UNIQUE already handled; convert common short fields
    short_cols = (
        "role", "status", "tier", "type", "node_type", "network_type", "os_type",
        "currency", "priority", "hostname", "address", "name", "slug", "token",
        "ip", "ipv4", "ipv6", "container", "action", "target_type", "target_id",
        "username", "email", "discordid", "proxmoxhost", "proxmoxuser",
        "proxmoxnode", "proxmoxpassword", "url", "apikey", "password", "source",
        "image", "expires", "subnet", "gateway", "ipv4_subnet", "ipv4_gateway",
        "dns", "subject", "receiptnumber", "transactionid", "billingname",
        "billingemail", "theme", "vpsuuid", "agent",
    )
    for col in short_cols:
        s = re.sub(
            rf"\b{col} TEXT\b",
            f"{col} VARCHAR(255)",
            s,
        )

    # free-form long text stay as TEXT: description, reason, config, raw, notes,
    # message, details, payload, result, billingaddress, value
    return s


def createschema():
    cfg = dbconfig.load()
    engine = cfg["engine"]
    schema = _SCHEMA if engine == "sqlite" else _to_mysql(_SCHEMA)
    if engine == "mysql":
        import pymysql
        from pymysql.err import OperationalError

        m = cfg["mysql"]
        # try create database; free hosts often deny CREATE DATABASE — ignore
        try:
            raw = pymysql.connect(
                host=m.get("host") or "127.0.0.1",
                port=int(m.get("port") or 3306),
                user=m.get("user") or "root",
                password=m.get("password") or "",
                charset=m.get("charset") or "utf8mb4",
                autocommit=True,
            )
            try:
                with raw.cursor() as cur:
                    cur.execute(
                        f"CREATE DATABASE IF NOT EXISTS `{m.get('database') or 'openworld'}` "
                        "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
                    )
            finally:
                raw.close()
        except OperationalError as e:
            print(f"Note: could not CREATE DATABASE (ok on shared hosts): {e}")

    conn = getconnection()
    try:
        if engine == "mysql":
            conn.execute("SET FOREIGN_KEY_CHECKS=0")
        for stmt in schema.split(";"):
            s = stmt.strip()
            if not s:
                continue
            try:
                conn.execute(s)
            except Exception as e:
                msg = str(e).lower()
                # table/index already there, or duplicate key name
                if (
                    "already exists" in msg
                    or "duplicate key name" in msg
                    or "duplicate column" in msg
                ):
                    continue
                raise
        if engine == "mysql":
            conn.execute("SET FOREIGN_KEY_CHECKS=1")
        conn.commit()
    finally:
        conn.close()
    return engine


if __name__ == "__main__":
    eng = createschema()
    print(f"Schema created successfully ({eng}).")
