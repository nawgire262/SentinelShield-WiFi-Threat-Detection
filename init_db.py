import sqlite3

conn = sqlite3.connect("wifi_profiles.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS wifi_profiles (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    ssid TEXT,
    bssid TEXT UNIQUE,

    security TEXT,
    channel INTEGER,

    avg_rssi REAL,
    min_rssi INTEGER,
    max_rssi INTEGER,
    rssi_variance REAL,
    rssi_std REAL,
    signal_range INTEGER,

    ap_count INTEGER,
    bssid_count INTEGER,

    signal_trend TEXT,
    signal_stability TEXT,

    first_seen TEXT,
    last_seen TEXT,

    observation_count INTEGER DEFAULT 1
)
""")

conn.commit()
conn.close()

print("Database Created Successfully")