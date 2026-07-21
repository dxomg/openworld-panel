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

    readbps INTEGER NOT NULL DEFAULT 0,
    writebps INTEGER NOT NULL DEFAULT 0,

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

    node_type TEXT NOT NULL DEFAULT 'docker'
        CHECK(node_type IN ('docker', 'proxmox')),

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
    url TEXT NOT NULL DEFAULT '',

    apikey TEXT NOT NULL,

    type TEXT NOT NULL DEFAULT 'docker'
        CHECK(type IN ('docker', 'proxmox')),

    status TEXT NOT NULL DEFAULT 'online'
        CHECK(status IN ('online','offline','maintenance')),

    tier TEXT NOT NULL DEFAULT 'free'
        CHECK(tier IN ('free', 'paid')),

    cpu INTEGER NOT NULL,
    ram INTEGER NOT NULL,
    disk INTEGER NOT NULL,

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

CREATE TABLE IF NOT EXISTS storagepools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,

    nodeid INTEGER NOT NULL,
    name TEXT NOT NULL,
    source TEXT,
    size INTEGER NOT NULL DEFAULT 0,
    used INTEGER NOT NULL DEFAULT 0,

    node_type TEXT NOT NULL DEFAULT 'proxmox'
        CHECK(node_type IN ('docker', 'proxmox')),

    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(nodeid) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS docker_networks (
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

CREATE TABLE IF NOT EXISTS networkips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,

    networkid INTEGER NOT NULL,
    network_type TEXT NOT NULL DEFAULT 'docker'
        CHECK(network_type IN ('docker', 'proxmox')),

    ip TEXT NOT NULL,

    assigned INTEGER NOT NULL DEFAULT 0
        CHECK(assigned IN (0,1)),

    vpsid INTEGER,

    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(vpsid) REFERENCES vps(id) ON DELETE SET NULL,
    UNIQUE(networkid, network_type, ip)
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
    network_type TEXT DEFAULT 'docker'
        CHECK(network_type IN ('docker', 'proxmox')),
    storagepoolid INTEGER,

    hostname TEXT NOT NULL,
    password TEXT NOT NULL,

    container TEXT,
    vmid INTEGER,

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

    ipv4 TEXT,
    ipv6 TEXT,

    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(userid) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(planid) REFERENCES plans(id) ON DELETE RESTRICT,
    FOREIGN KEY(imageid) REFERENCES images(id) ON DELETE RESTRICT,
    FOREIGN KEY(nodeid) REFERENCES nodes(id) ON DELETE RESTRICT,
    FOREIGN KEY(storageid) REFERENCES storagepools(id) ON DELETE SET NULL
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

CREATE INDEX IF NOT EXISTS idxusersuuid ON users(uuid);
CREATE INDEX IF NOT EXISTS idxusersdiscord ON users(discordid);

CREATE INDEX IF NOT EXISTS idxbansuser ON bans(userid);

CREATE INDEX IF NOT EXISTS idxplansuuid ON plans(uuid);

CREATE INDEX IF NOT EXISTS idximagesuuid ON images(uuid);

CREATE INDEX IF NOT EXISTS idxnodesuuid ON nodes(uuid);
CREATE INDEX IF NOT EXISTS idxnodestier ON nodes(tier);

CREATE INDEX IF NOT EXISTS idxdockernetuuid ON docker_networks(uuid);
CREATE INDEX IF NOT EXISTS idxdockernetnode ON docker_networks(nodeid);

CREATE INDEX IF NOT EXISTS idxproxnetuuid ON proxmox_networks(uuid);
CREATE INDEX IF NOT EXISTS idxproxnetnode ON proxmox_networks(nodeid);

CREATE INDEX IF NOT EXISTS idxnetworkipuuid ON networkips(uuid);
CREATE INDEX IF NOT EXISTS idxnetworkipnet ON networkips(networkid, network_type);

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

""")

conn.commit()
conn.close()

print("database.db created successfully.")
