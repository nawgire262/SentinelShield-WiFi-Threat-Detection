# Firebase Cloud Threat Intelligence Setup

1. Create a Firebase project and enable **Cloud Firestore** in production or test mode.
2. In **Project settings → Service accounts**, generate a new private key.
3. Save it as `firebase_credentials.json` beside `background_scanner.py`, or set the `FIREBASE_CREDENTIALS` environment variable to its path.
4. Install the optional dependency:

   ```powershell
   pip install firebase-admin
   ```

The scanner uses the Firestore collection `global_threat_intel`. Each document is keyed by normalized BSSID and includes `ssid`, `bssid`, `risk_score`, `detection_time`, and `threat_type`.

Cloud sync is attempted at the start of each scan but is rate-limited to every 300 seconds. HIGH and CRITICAL scan results are uploaded automatically. Without the SDK, credentials, or network access SentinelShield runs in offline mode with no change to its local RSSI, ML, and adaptive-threshold detection.

Do not commit `firebase_credentials.json`; it grants administrative access to your Firebase project.
