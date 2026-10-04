import os
import pandas as pd
import streamlit as st

from scanner import scan_wifi


SCAN_FILE = "current_scan.csv"


# ============================================================
# SAVE SCAN
# ============================================================

def save_scan(findings):

    if not findings:
        return

    rows = []

    for item in findings:

        rows.append({

            "SSID": item["SSID"],

            "BSSID": item["BSSID"],

            "RSSI": item["RSSI"],

            "Channel": item["Channel"],

            "Security": item["Security"],

            "Threat_Score": item["Threat_Score"],

            "Combined_Risk": item["Combined_Risk"],

            "Threat_Level": item["Threat_Level"],

            "Signal_History": str(
                item["Signal_History"]
            ),

            "BSSID_Count": item["BSSID_Count"],

            "Reasons": ", ".join(
                item["Reasons"]
            ),

        })

    df = pd.DataFrame(rows)

    df.to_csv(
        SCAN_FILE,
        index=False
    )


# ============================================================
# LOAD SAVED DATA
# ============================================================

def load_saved_scan():

    if not os.path.exists(SCAN_FILE):

        return pd.DataFrame()

    try:

        return pd.read_csv(
            SCAN_FILE
        )

    except Exception:

        return pd.DataFrame()


# ============================================================
# LIVE SCAN PAGE
# ============================================================

def show_live_scan():

    st.markdown(
        """
        <h1 style="color:#00d9ff;">
            📡 Live WiFi Scan
        </h1>
        """,
        unsafe_allow_html=True
    )

    st.caption(
        "Real-time wireless network monitoring and Evil Twin risk analysis"
    )

    # --------------------------------------------------------
    # Buttons
    # --------------------------------------------------------

    col1, col2, col3 = st.columns(
        [1, 1, 4]
    )

    with col1:

        start_scan = st.button(
            "🔍 Start Scan",
            use_container_width=True
        )

    with col2:

        refresh = st.button(
            "🔄 Refresh Results",
            use_container_width=True
        )

    # --------------------------------------------------------
    # Run real scanner
    # --------------------------------------------------------

    if start_scan:

        with st.spinner(
            "📡 Scanning nearby WiFi networks..."
        ):

            try:

                findings = scan_wifi(
                    rounds=3
                )

                if findings:

                    save_scan(findings)

                    st.session_state[
                        "scanner_status"
                    ] = "Available"

                    st.session_state[
                        "scan_error"
                    ] = None

                    st.success(
                        f"✅ Scan completed. "
                        f"{len(findings)} networks detected."
                    )

                else:

                    st.session_state[
                        "scanner_status"
                    ] = "Unavailable"

                    st.session_state[
                        "scan_error"
                    ] = (
                        "No WiFi networks detected "
                        "or adapter unavailable."
                    )

            except Exception as e:

                st.session_state[
                    "scanner_status"
                ] = "Error"

                st.session_state[
                    "scan_error"
                ] = str(e)

    # --------------------------------------------------------
    # Refresh
    # --------------------------------------------------------

    if refresh:

        st.rerun()

    # --------------------------------------------------------
    # Status
    # --------------------------------------------------------

    status = st.session_state.get(
        "scanner_status",
        "Ready"
    )

    scan_error = st.session_state.get(
        "scan_error"
    )

    if status == "Available":

        st.success(
            "🟢 Scanner Available"
        )

    elif status == "Error":

        st.error(
            f"🔴 Scanner Error: {scan_error}"
        )

    elif status == "Unavailable":

        st.warning(
            f"🟠 Scanner Unavailable: {scan_error}"
        )

    else:

        st.info(
            "🔵 Scanner Ready — click Start Scan."
        )

    # --------------------------------------------------------
    # Load data
    # --------------------------------------------------------

    df = load_saved_scan()

    if df.empty:

        st.info(
            "No scan results available. "
            "Click **Start Scan**."
        )

        return

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    total = len(df)

    safe = len(
        df[
            df["Combined_Risk"] < 40
        ]
    )

    medium = len(
        df[
            (df["Combined_Risk"] >= 40)
            &
            (df["Combined_Risk"] < 70)
        ]
    )

    high = len(
        df[
            df["Combined_Risk"] >= 70
        ]
    )

    st.divider()

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "📡 Networks",
        total
    )

    c2.metric(
        "🟢 Safe",
        safe
    )

    c3.metric(
        "🟠 Medium",
        medium
    )

    c4.metric(
        "🔴 High Risk",
        high
    )

    st.divider()

    # --------------------------------------------------------
    # Network Table
    # --------------------------------------------------------

    st.subheader(
        "📊 Detected WiFi Networks"
    )

    display_columns = [

        "SSID",
        "BSSID",
        "RSSI",
        "Channel",
        "Security",
        "Threat_Score",
        "Combined_Risk",
        "Threat_Level"

    ]

    available_columns = [

        column
        for column in display_columns
        if column in df.columns

    ]

    st.dataframe(

        df[available_columns],

        use_container_width=True,

        hide_index=True

    )

    # --------------------------------------------------------
    # Detailed network analysis
    # --------------------------------------------------------

    st.divider()

    st.subheader(
        "🔎 Network Details"
    )

    for _, row in df.iterrows():

        risk = float(
            row["Combined_Risk"]
        )

        if risk >= 70:

            icon = "🔴"

        elif risk >= 40:

            icon = "🟠"

        else:

            icon = "🟢"

        with st.expander(

            f"{icon} {row['SSID']} — "
            f"{row['Threat_Level']} "
            f"({risk:.0f}%)"

        ):

            col1, col2 = st.columns(2)

            with col1:

                st.write(
                    f"**BSSID:** {row['BSSID']}"
                )

                st.write(
                    f"**RSSI:** {row['RSSI']} dBm"
                )

                st.write(
                    f"**Channel:** {row['Channel']}"
                )

                st.write(
                    f"**Security:** {row['Security']}"
                )

            with col2:

                st.metric(
                    "Threat Score",
                    f"{row['Threat_Score']}%"
                )

                st.metric(
                    "Combined Risk",
                    f"{risk:.0f}%"
                )

                st.write(
                    f"**Threat Level:** "
                    f"{row['Threat_Level']}"
                )

            # ------------------------------------------------
            # Risk progress
            # ------------------------------------------------

            st.progress(
                min(max(risk / 100, 0), 1)
            )

            # ------------------------------------------------
            # Reasons
            # ------------------------------------------------

            if (
                "Reasons" in row
                and str(row["Reasons"]).strip()
            ):

                st.warning(
                    f"⚠️ {row['Reasons']}"
                )

            # ------------------------------------------------
            # Signal history
            # ------------------------------------------------

            if (
                "Signal_History" in row
                and str(row["Signal_History"]).strip()
            ):

                st.write(
                    "**Signal History:**"
                )

                st.code(
                    str(row["Signal_History"])
                )