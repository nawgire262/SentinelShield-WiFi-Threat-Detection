import sqlite3
import json
import numpy as np
from datetime import datetime


class WiFiFingerprintEngine:

    def __init__(self, db_name="wifi_profiles.db"):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()

    # -----------------------------------------
    # Get WiFi Profile
    # -----------------------------------------
    def get_profile(self, bssid):

        self.cursor.execute(
            "SELECT * FROM wifi_profiles WHERE bssid=?",
            (bssid,)
        )

        return self.cursor.fetchone()

    # -----------------------------------------
    # Create New WiFi Profile
    # -----------------------------------------
    def create_profile(
            self,
            ssid,
            bssid,
            security,
            channel,
            rssi,
            ap_count,
            bssid_count):

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        history = [rssi]

        self.cursor.execute("""

        INSERT INTO wifi_profiles(

        ssid,
        bssid,

        security,
        channel,

        avg_rssi,
        min_rssi,
        max_rssi,

        rssi_variance,
        rssi_std,
        signal_range,

        ap_count,
        bssid_count,

        signal_trend,
        signal_stability,

        first_seen,
        last_seen,

        observation_count,
        rssi_history

        )

        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)

        """, (

            ssid,
            bssid,

            security,
            channel,

            rssi,
            rssi,
            rssi,

            0,
            0,
            0,

            ap_count,
            bssid_count,

            "Stable",
            "High",

            now,
            now,

            1,
            json.dumps(history)

        ))

        self.conn.commit()

    # -----------------------------------------
    # Update Existing WiFi Profile
    # -----------------------------------------
    def update_profile(
            self,
            bssid,
            rssi,
            security,
            channel,
            ap_count,
            bssid_count):

        self.cursor.execute("""

        SELECT
        rssi_history,
        observation_count

        FROM wifi_profiles

        WHERE bssid=?

        """, (bssid,))

        row = self.cursor.fetchone()

        if row is None:
            return

        history = json.loads(row[0]) if row[0] else []

        history.append(rssi)

        # Keep last 20 observations
        history = history[-20:]

        avg = round(float(np.mean(history)), 2)
        var = round(float(np.var(history)), 2)
        std = round(float(np.std(history)), 2)

        minimum = min(history)
        maximum = max(history)

        signal_range = maximum - minimum

        # ------------------------
        # Trend Detection
        # ------------------------

        if len(history) >= 3:

            if history[-1] > history[-2]:
                trend = "Increasing"

            elif history[-1] < history[-2]:
                trend = "Decreasing"

            else:
                trend = "Stable"

        else:

            trend = "Stable"

        # ------------------------
        # Stability Detection
        # ------------------------

        if var < 5:
            stability = "High"

        elif var < 15:
            stability = "Medium"

        else:
            stability = "Low"

        observations = row[1] + 1

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.cursor.execute("""

        UPDATE wifi_profiles

        SET

        security=?,
        channel=?,

        avg_rssi=?,
        min_rssi=?,
        max_rssi=?,

        rssi_variance=?,
        rssi_std=?,
        signal_range=?,

        ap_count=?,
        bssid_count=?,

        signal_trend=?,
        signal_stability=?,

        last_seen=?,

        observation_count=?,

        rssi_history=?

        WHERE bssid=?

        """, (

            security,
            channel,

            avg,
            minimum,
            maximum,

            var,
            std,
            signal_range,

            ap_count,
            bssid_count,

            trend,
            stability,

            now,

            observations,

            json.dumps(history),

            bssid

        ))

        self.conn.commit()

    # -----------------------------------------
    # Close Database
    # -----------------------------------------
    def close(self):
        self.conn.close()