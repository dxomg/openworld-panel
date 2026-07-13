import uuid
import time
import hashlib
import sqlite3
from datetime import datetime

# Default user
userid = "1149791430307491880"

# Connect to SQLite database (creates if not exists)
conn = sqlite3.connect('database.db')

# Create a cursor object to execute SQL queries
cursor = conn.cursor()


# Default plan
plan_uuid = str(uuid.uuid4())

cursor.execute("""
INSERT INTO plans (
    uuid, name, description, cpu, ram, swap, disk, iptype
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
""", (
    plan_uuid,
    "Free VPS",
    "Default free VPS plan",
    "1",
    "1024",
    "2048",
    "5120",
    "6"
))


# Default image
image_uuid = str(uuid.uuid4())

cursor.execute("""
INSERT INTO images (
    uuid, name, imagename
) VALUES (?, ?, ?)
""", (
    image_uuid,
    "Debian 12",
    "debian-12"
))


# Default node
node_uuid = str(uuid.uuid4())

cursor.execute("""
INSERT INTO nodes (
    uuid, name, description, apiurl, apikey
) VALUES (?, ?, ?, ?, ?)
""", (
    node_uuid,
    "node-1",
    "Default VPS node",
    "http://127.0.0.1:5001",
    "example-api-key"
))


# Default disk
disk_uuid = str(uuid.uuid4())

cursor.execute("""
INSERT INTO nodedisks (
    uuid, diskpath, description
) VALUES (?, ?, ?)
""", (
    disk_uuid,
    "/var/lib/vps",
    "Main VPS storage"
))


# Default VPS assigned to userid
vps_uuid = str(uuid.uuid4())

cursor.execute("""
INSERT INTO vps (
    userid,
    uuid,
    nodeuuid,
    hostname,
    password,
    cpu,
    ram,
    swap,
    disk,
    network,
    ip,
    dns,
    image,
    diskpath,
    planuuid
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""", (
    userid,
    vps_uuid,
    node_uuid,
    "example-vps",
    "changeme",
    "1",
    "1024",
    "2048",
    "5120",
    "10",
    "2001:db8::10",
    "2606:4700:4700::1111",
    image_uuid,
    "/var/lib/vps/example-vps",
    plan_uuid
))


# Default suspension entry (empty example)
cursor.execute("""
INSERT INTO suspendedservers (
    serveruuid,
    userid,
    suspendreason,
    date,
    punisheruserid
) VALUES (?, ?, ?, ?, ?)
""", (
    vps_uuid,
    userid,
    "Example suspension reason",
    datetime.now().isoformat(),
    "0"
))


# Commit the transaction
conn.commit()

# Close the database connection
conn.close()