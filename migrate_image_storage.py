import sqlite3
import toml
import os
import uuid as uuid_mod

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.toml")

conn = sqlite3.connect("database.db")
conn.execute("PRAGMA foreign_keys = ON")
cursor = conn.cursor()

# 1. Create imagestorage table
cursor.execute("""
    CREATE TABLE IF NOT EXISTS imagestorage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT UNIQUE NOT NULL,
        nodeid INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(nodeid) REFERENCES nodes(id) ON DELETE CASCADE
    )
""")
print("Created imagestorage table.")

cursor.execute("CREATE INDEX IF NOT EXISTS idximagestorageuuid ON imagestorage(uuid)")
cursor.execute("CREATE INDEX IF NOT EXISTS idximagestoragenode ON imagestorage(nodeid)")
print("Created indexes.")

# 2. Migrate image_storage from nodes
try:
    rows = cursor.execute("SELECT id, image_storage FROM nodes WHERE image_storage IS NOT NULL AND image_storage != ''").fetchall()
    for node_id, storage_name in rows:
        cursor.execute(
            "INSERT OR IGNORE INTO imagestorage (uuid, nodeid, name) VALUES (?, ?, ?)",
            (str(uuid_mod.uuid4()), node_id, storage_name)
        )
    if rows:
        print(f"Migrated {len(rows)} image storage record(s) from nodes.")
    else:
        print("No existing image_storage data to migrate.")
except sqlite3.OperationalError:
    print("No image_storage column on nodes (fresh install).")

try:
    cursor.execute("ALTER TABLE nodes DROP COLUMN image_storage")
    print("Removed image_storage column from nodes table.")
except sqlite3.OperationalError:
    print("image_storage column already removed or not present.")

try:
    cursor.execute("ALTER TABLE images ADD COLUMN imagestorageid INTEGER REFERENCES imagestorage(id) ON DELETE SET NULL")
    print("Added imagestorageid column to images table.")
except sqlite3.OperationalError:
    print("imagestorageid column already exists on images.")

# 3. Create auditlog table
cursor.execute("""
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
    )
""")
print("Created auditlog table.")

cursor.execute("CREATE INDEX IF NOT EXISTS idxauditloguuid ON auditlog(uuid)")
cursor.execute("CREATE INDEX IF NOT EXISTS idxauditloguser ON auditlog(userid)")
cursor.execute("CREATE INDEX IF NOT EXISTS idxauditlogaction ON auditlog(action)")
cursor.execute("CREATE INDEX IF NOT EXISTS idxauditlogcreated ON auditlog(created)")
print("Created auditlog indexes.")

# 4. Create settings table
cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        description TEXT,
        updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
""")
print("Created settings table.")

# 5. Add theme column to users
try:
    cursor.execute("ALTER TABLE users ADD COLUMN theme TEXT DEFAULT NULL")
    print("Added theme column to users table.")
except sqlite3.OperationalError:
    print("theme column already exists on users.")

# 6. Create jobs table
cursor.execute("""
    CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT UNIQUE NOT NULL,
        vpsid INTEGER,
        vpsuuid TEXT NOT NULL,
        userid INTEGER NOT NULL,
        type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        payload TEXT,
        result TEXT,
        created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(vpsid) REFERENCES vps(id) ON DELETE CASCADE,
        FOREIGN KEY(userid) REFERENCES users(id) ON DELETE CASCADE
    )
""")
print("Created jobs table.")

cursor.execute("CREATE INDEX IF NOT EXISTS idxjobsuuid ON jobs(uuid)")
cursor.execute("CREATE INDEX IF NOT EXISTS idxjobsvps ON jobs(vpsuuid)")
cursor.execute("CREATE INDEX IF NOT EXISTS idxjobsstatus ON jobs(status)")
print("Created jobs indexes.")

# 5. Migrate config.toml to DB
cursor.execute("SELECT COUNT(*) FROM settings")
count = cursor.fetchone()[0]

if count == 0:
    DEFAULT_CONFIG = {
        "general": {
            "projectname": "Openworld",
            "passwordlength": 24,
            "cookielength": 128,
            "defaultcookiettl": 7,
            "favicon": "/static/favicon.ico",
            "logo": "/static/logo.png",
            "discord": "https://discord.gg/ZJrg5sGr5R",
            "theme": "catppuccin",
        },
        "server": {
            "host": "0.0.0.0",
            "port": 5000,
            "debug": True,
        },
        "paypal": {
            "email": "example@example.com",
            "sandbox": True,
            "base_url": "http://localhost:5000",
        },
        "discord": {
            "clientid": "changeme",
            "clientsecret": "changeme",
            "redirecturl": "http://localhost:5000/discord-callback",
            "discordbaseurl": "https://discord.com/api",
        },
        "loadbalancing": {
            "strategy": "both",
        },
        "console": {
            "timeout": 10,
            "metrics": "dynamic",
        },
    }

    cfg = DEFAULT_CONFIG
    if os.path.exists(CONFIG_PATH):
        try:
            cfg = toml.load(CONFIG_PATH)
            print("Loaded config.toml for migration.")
        except Exception:
            print("Failed to parse config.toml, using defaults.")

    for section, values in DEFAULT_CONFIG.items():
        if isinstance(values, dict):
            for key, defaultval in values.items():
                flatkey = f"{section}.{key}"
                actual = cfg.get(section, {}).get(key, defaultval)
                if isinstance(actual, (dict, list, bool)):
                    serialized = str(actual).replace("'", '"')
                else:
                    serialized = str(actual)
                cursor.execute(
                    "INSERT OR IGNORE INTO settings (key, value, description) VALUES (?, ?, ?)",
                    (flatkey, serialized, f"{section} -> {key}")
                )
        else:
            cursor.execute(
                "INSERT OR IGNORE INTO settings (key, value, description) VALUES (?, ?, ?)",
                (section, str(values), section)
            )
    print("Migrated config to database.")
else:
    print(f"Settings table already has {count} rows, skipping migration.")

conn.commit()
conn.close()
print("Migration complete.")
