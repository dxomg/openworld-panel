import sqlite3

conn = sqlite3.connect("database.db")
conn.execute("PRAGMA foreign_keys = ON")
cursor = conn.cursor()

cursor.executescript("""

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

CREATE TABLE IF NOT EXISTS plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,

    name TEXT NOT NULL,
    description TEXT,

    cpu INTEGER NOT NULL,
    ram INTEGER NOT NULL,
    swap INTEGER NOT NULL,
    disk INTEGER NOT NULL,

    ipv4 INTEGER NOT NULL DEFAULT 0,
    ipv6 INTEGER NOT NULL DEFAULT 1,

    price REAL NOT NULL DEFAULT 0,

    stock INTEGER NOT NULL DEFAULT -1,

    active INTEGER NOT NULL DEFAULT 1
        CHECK(active IN (0,1)),

    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,

    name TEXT NOT NULL,
    image TEXT NOT NULL,
    description TEXT,

    active INTEGER NOT NULL DEFAULT 1
        CHECK(active IN (0,1)),

    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,

    name TEXT NOT NULL,

    hostname TEXT NOT NULL,
    address TEXT NOT NULL,

    apikey TEXT NOT NULL,

    status TEXT NOT NULL DEFAULT 'online'
        CHECK(status IN ('online','offline','maintenance')),

    -- NEW COLUMN ADDED HERE
    tier TEXT NOT NULL DEFAULT 'free'
        CHECK(tier IN ('free', 'paid')),

    cpu INTEGER NOT NULL,
    ram INTEGER NOT NULL,
    disk INTEGER NOT NULL,

    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS nodestorage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,

    nodeid INTEGER NOT NULL,

    name TEXT NOT NULL,
    path TEXT NOT NULL,

    type TEXT NOT NULL
        CHECK(type IN ('ssd','nvme','hdd')),

    size INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,

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
    storageid INTEGER NOT NULL,

    hostname TEXT NOT NULL,
    password TEXT NOT NULL,

    container TEXT,

    status TEXT NOT NULL DEFAULT 'creating'
        CHECK(status IN (
            'creating',
            'running',
            'stopped',
            'restarting',
            'suspended',
            'pendingpayment',
            'deleted',
            'error'
        )),

    cpu INTEGER NOT NULL,
    ram INTEGER NOT NULL,
    swap INTEGER NOT NULL,
    disk INTEGER NOT NULL,

    ipv6 TEXT,

    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(userid) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(planid) REFERENCES plans(id) ON DELETE RESTRICT,
    FOREIGN KEY(imageid) REFERENCES images(id) ON DELETE RESTRICT,
    FOREIGN KEY(nodeid) REFERENCES nodes(id) ON DELETE RESTRICT,
    FOREIGN KEY(storageid) REFERENCES nodestorage(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS vpssuspensions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,

    vpsid INTEGER NOT NULL,
    userid INTEGER NOT NULL,
    adminid INTEGER,

    reason TEXT NOT NULL,

    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lifted TEXT,

    FOREIGN KEY(vpsid) REFERENCES vps(id) ON DELETE CASCADE,
    FOREIGN KEY(userid) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(adminid) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS paymentmethods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,

    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,

    active INTEGER NOT NULL DEFAULT 1
        CHECK(active IN (0,1)),

    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,

    transactionid TEXT UNIQUE NOT NULL,

    userid INTEGER NOT NULL,
    vpsid INTEGER,
    planid INTEGER,
    paymentprocessorid INTEGER NOT NULL,

    amount REAL NOT NULL,
    currency TEXT NOT NULL DEFAULT 'USD',

    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','completed','failed','refunded','cancelled')),

    details TEXT,

    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(userid) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(vpsid) REFERENCES vps(id) ON DELETE SET NULL,
    FOREIGN KEY(planid) REFERENCES plans(id) ON DELETE SET NULL,
    FOREIGN KEY(paymentprocessorid) REFERENCES paymentmethods(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,

    receiptnumber TEXT UNIQUE NOT NULL,

    transactionid INTEGER NOT NULL UNIQUE,
    userid INTEGER NOT NULL,

    amount REAL NOT NULL,
    currency TEXT NOT NULL DEFAULT 'USD',

    taxamount REAL NOT NULL DEFAULT 0,

    billingname TEXT,
    billingemail TEXT,
    billingaddress TEXT,

    notes TEXT,

    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(transactionid) REFERENCES transactions(id) ON DELETE CASCADE,
    FOREIGN KEY(userid) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,

    userid INTEGER NOT NULL,

    token TEXT NOT NULL UNIQUE,

    ip TEXT,
    agent TEXT,

    expires TEXT NOT NULL,

    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(userid) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,

    userid INTEGER,

    action TEXT NOT NULL,
    target TEXT,
    targetuuid TEXT,

    details TEXT,
    ip TEXT,

    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(userid) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idxusersuuid ON users(uuid);
CREATE INDEX IF NOT EXISTS idxusersdiscord ON users(discordid);

CREATE INDEX IF NOT EXISTS idxbansuser ON bans(userid);

CREATE INDEX IF NOT EXISTS idxplansuuid ON plans(uuid);

CREATE INDEX IF NOT EXISTS idximagesuuid ON images(uuid);

CREATE INDEX IF NOT EXISTS idxnodesuuid ON nodes(uuid);
CREATE INDEX IF NOT EXISTS idxnodestier ON nodes(tier); -- NEW INDEX

CREATE INDEX IF NOT EXISTS idxstorageuuid ON nodestorage(uuid);
CREATE INDEX IF NOT EXISTS idxstoragenode ON nodestorage(nodeid);

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

CREATE INDEX IF NOT EXISTS idxlogsuser ON logs(userid);
CREATE INDEX IF NOT EXISTS idxlogstarget ON logs(target);

""")

# Migrations: add columns to existing tables if missing
try:
    cursor.execute("ALTER TABLE plans ADD COLUMN stock INTEGER NOT NULL DEFAULT -1")
except sqlite3.OperationalError:
    pass  # column already exists

conn.commit()
conn.close()

print("database.db created successfully with node tiers.")