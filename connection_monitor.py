import subprocess


def get_connected_wifi():

    try:
        output = subprocess.check_output(
            "netsh wlan show interfaces",
            shell=True,
            text=True,
            encoding="utf-8"
        )

        connected = False
        ssid = None

        for line in output.splitlines():

            line = line.strip()

            if line.startswith("State"):

                if "connected" in line.lower():
                    connected = True

            elif line.startswith("SSID") and "BSSID" not in line:

                ssid = line.split(":")[1].strip()

        if connected:
            return ssid

        return None

    except Exception:
        return None