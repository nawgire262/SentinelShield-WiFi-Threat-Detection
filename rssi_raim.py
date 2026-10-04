"""
rssi_raim.py

RAIM-inspired WiFi signal validation utilities
for SentinelShield.

Provides:
1. RSSI -> Distance estimation
2. Temporal RSSI stability detection
3. RAIM-style consistency check
"""

import math
import statistics


# -------------------------------------------------
# RSSI TO DISTANCE
# -------------------------------------------------

def rssi_to_distance(rssi, tx_power=-40, path_loss_exponent=2.4):
    """
    Estimate distance from RSSI using
    the log-distance path loss model.

    Parameters
    ----------
    rssi : int
        Received Signal Strength (dBm)

    tx_power : int
        Expected RSSI at 1 meter

    path_loss_exponent : float
        Indoor propagation factor

    Returns
    -------
    float
        Estimated distance (meters)
    """

    try:
        distance = 10 ** ((tx_power - rssi) /
                          (10 * path_loss_exponent))
        return round(distance, 2)

    except Exception:
        return 0.0


# -------------------------------------------------
# TEMPORAL STABILITY
# -------------------------------------------------

def is_temporally_unstable(history,
                           std_threshold=8,
                           range_threshold=15):
    """
    Determine whether RSSI is unstable
    over repeated scans.
    """

    if history is None:
        return False

    if len(history) < 3:
        return False

    try:

        signal_range = max(history) - min(history)

        std = statistics.stdev(history)

        if signal_range > range_threshold:
            return True

        if std > std_threshold:
            return True

        return False

    except Exception:
        return False


# -------------------------------------------------
# RAIM CONSISTENCY CHECK
# -------------------------------------------------

def raim_consistency_check(per_bssid_histories):
    """
    Compare all BSSIDs broadcasting
    the same SSID.

    Returns dictionary:

    {
        bssid:{
            flagged,
            distance,
            rogue_votes,
            benign_votes
        }
    }
    """

    results = {}

    if not per_bssid_histories:
        return results

    distances = {}

    for bssid, history in per_bssid_histories.items():

        if len(history) == 0:
            continue

        avg = sum(history) / len(history)

        distances[bssid] = rssi_to_distance(avg)

    if len(distances) == 0:
        return results

    median_distance = statistics.median(
        distances.values()
    )

    for bssid, distance in distances.items():

        difference = abs(distance - median_distance)

        flagged = difference > 6

        results[bssid] = {

            "flagged": flagged,

            "distance": round(distance, 2),

            "rogue_votes": 1 if flagged else 0,

            "benign_votes": 0 if flagged else 1

        }

    return results


# -------------------------------------------------
# OPTIONAL HELPERS
# -------------------------------------------------

def calculate_signal_variance(history):
    """
    Return RSSI variance.
    """

    if len(history) < 2:
        return 0

    return round(statistics.variance(history), 2)


def calculate_signal_std(history):
    """
    Return RSSI standard deviation.
    """

    if len(history) < 2:
        return 0

    return round(statistics.stdev(history), 2)


def signal_quality(rssi):
    """
    Human readable signal quality.
    """

    if rssi >= -50:
        return "Excellent"

    if rssi >= -60:
        return "Very Good"

    if rssi >= -70:
        return "Good"

    if rssi >= -80:
        return "Fair"

    return "Poor"


# -------------------------------------------------
# TEST
# -------------------------------------------------

if __name__ == "__main__":

    history = [-45, -47, -46, -44, -60]

    print("Distance:",
          rssi_to_distance(-45))

    print("Unstable:",
          is_temporally_unstable(history))

    sample = {

        "AA:BB:CC:11": [-44, -45, -46],

        "AA:BB:CC:22": [-46, -45, -47],

        "AA:BB:CC:33": [-72, -74, -73]

    }

    print(raim_consistency_check(sample))
