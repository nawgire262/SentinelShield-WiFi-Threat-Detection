# xai_explain.py (Excerpt of the rendering definitions)
BASE_FEATURES = ["RSSI", "Channel", "Security_enc", "AP_Count", "Signal_Var"]
FEATURE_LABELS = {
    "RSSI": "RSSI Signal Spike",
    "Channel": "Channel Congestion",
    "Security_enc": "Open Network Risk",
    "AP_Count": "Multi AP MAC Density",
    "Signal_Var": "Temporal Signal Variance",
}
