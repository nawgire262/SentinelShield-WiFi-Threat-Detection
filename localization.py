import math
from typing import Dict, List

from rssi_raim import rssi_to_distance


class SignalLocalizer:
    def __init__(self, width: int = 900, height: int = 520):
        self.width = width
        self.height = height
        self.sensor_positions = {
            "central": (self.width * 0.5, self.height * 0.5)
        }
        self.max_distance_m = 80.0

    def normalize_distance(self, distance_m: float) -> float:
        return min(0.45, max(0.08, distance_m / self.max_distance_m))

    def _angle_for_bssid(self, bssid: str) -> float:
        if not bssid:
            return math.pi / 4
        numeric = sum(int(byte, 16) for byte in bssid.split(":") if byte)
        return (numeric % 360) * math.pi / 180.0

    def estimate_position(self, bssid: str, rssi: float, risk_score: float = 50.0) -> Dict:
        distance_m = rssi_to_distance(float(rssi)) if rssi is not None else self.max_distance_m
        normalized = self.normalize_distance(distance_m)
        angle = self._angle_for_bssid(bssid)

        cx, cy = self.sensor_positions["central"]
        x = int(cx + math.cos(angle) * normalized * self.width * 0.45)
        y = int(cy + math.sin(angle) * normalized * self.height * 0.45)

        intensity = float(min(100.0, max(10.0, (100.0 - distance_m) * 0.8 + (risk_score * 0.2))))
        distance_label = f"{distance_m:.1f}m"

        return {
            "bssid": bssid,
            "x": max(0, min(self.width, x)),
            "y": max(0, min(self.height, y)),
            "value": intensity,
            "distance_m": distance_m,
            "label": f"{bssid[-8:]} ({distance_label})",
            "risk": risk_score,
        }

    def build_heatmap_data(self, network_records: List[Dict]) -> List[Dict]:
        points = []
        for rec in network_records:
            rssi = rec.get("RSSI")
            if rssi is None:
                continue
            try:
                rssi_val = float(rssi)
            except Exception:
                continue
            points.append(self.estimate_position(
                rec.get("BSSID", "unknown"),
                rssi_val,
                float(rec.get("Combined_Risk", rec.get("Threat_Score", 35))) if rec.get("Combined_Risk") is not None else 35.0,
            ))
        return points

    def render_heatmap_html(self, points: List[Dict]) -> str:
        safe_points = [p for p in points if p.get("x") is not None and p.get("y") is not None]
        point_data = ",\n".join([
            '{{x: {x}, y: {y}, value: {value}, label: "{label}"}}'.format(
                x=p["x"],
                y=p["y"],
                value=p["value"],
                label=p["label"].replace('"', '\\"'),
            )
            for p in safe_points
        ])

        html = """
        <div style='width:{width}px; height:{height}px; position: relative; background: #03030a; border: 1px solid #222; border-radius: 16px; overflow:hidden;'>
            <div id='heatmapContainer' style='width:100%; height:100%; position:absolute; top:0; left:0;'></div>
            <div style='position:absolute; left:16px; top:16px; color:#ffffff; font-family:monospace; z-index:2;'>
                <div style='font-size:18px; font-weight:bold; color:#d0d0ff;'>Tactical Signal Heatmap</div>
                <div style='font-size:12px; color:#aaa;'>Threat source intensity and proximity overlay</div>
            </div>
        </div>
        <script src='https://cdnjs.cloudflare.com/ajax/libs/heatmap.js/2.0.5/heatmap.min.js'></script>
        <script>
            const container = document.querySelector('#heatmapContainer');
            if (typeof h337 === 'undefined') {
                container.innerHTML = '<div style="color:#f0f0f0;font-family:monospace;padding:20px;">Heatmap library failed to load.</div>';
            } else {
                const heatmapInstance = h337.create({
                    container: container,
                    radius: 70,
                    maxOpacity: 0.85,
                    minOpacity: 0.12,
                    blur: 0.80,
                    gradient: {0.4: 'blue', 0.6: 'purple', 0.8: 'magenta', 1.0: 'red'},
                });
                heatmapInstance.setData({
                    max: 100,
                    data: [
                        {point_data}
                    ]
                });
                const labels = [
                    {
                        x: 30,
                        y: 470,
                        value: 0,
                        label: 'Command Station',
                    }
                ];
            }
        </script>
        """.format(width=self.width, height=self.height, point_data=point_data)
        return html
