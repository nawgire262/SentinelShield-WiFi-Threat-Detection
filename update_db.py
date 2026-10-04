import sqlite3

conn = sqlite3.connect("wifi_profiles.db")
cursor = conn.cursor()

try:
    cursor.execute("""
    ALTER TABLE wifi_profiles
    ADD COLUMN rssi_history TEXT
    """)
    print("✅ RSSI history column added.")
except sqlite3.OperationalError as e:
    print(f"ℹ️ {e}")

conn.commit()
conn.close()