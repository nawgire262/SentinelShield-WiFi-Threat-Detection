"""alert_ws_server.py – optional WebSocket push-alert sidecar for SentinelShield.

Runs alongside ``streamlit run dashboard.py`` and broadcasts real-time JSON
alert payloads to connected browser/mobile clients whenever a new CRITICAL or
HIGH threat is detected.

Usage
-----
    # Terminal 1 – Streamlit dashboard
    streamlit run dashboard.py

    # Terminal 2 – WebSocket sidecar (optional)
    python alert_ws_server.py

Clients connect to  ws://localhost:8765/alerts  and receive a JSON object:
    {
        "type": "alert",
        "level": "CRITICAL",
        "ssid": "HomeNetwork",
        "bssid": "AA:BB:CC:DD:EE:FF",
        "risk": 91.0,
        "reason": "RAIM inconsistency; open security; cloud reputation hit",
        "timestamp": "2026-10-04T21:00:00+00:00"
    }

Requirements
------------
    pip install websockets          # WebSocket server
    pip install watchdog            # (optional) faster file-change detection

The sidecar tails the ``alert_history.csv`` written by the Streamlit dashboard
and broadcasts new rows.  No Wi-Fi scanning is performed here.
"""
from __future__ import annotations

import asyncio
import csv
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Set

LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [WS-ALERT] %(message)s")

HOST = os.getenv("SENTINELSHIELD_WS_HOST", "localhost")
PORT = int(os.getenv("SENTINELSHIELD_WS_PORT", "8765"))
ALERT_FILE = Path(os.getenv("SENTINELSHIELD_ALERT_FILE", "alert_history.csv"))
POLL_INTERVAL = float(os.getenv("SENTINELSHIELD_WS_POLL_SECONDS", "0.5"))
MIN_RISK_BROADCAST = float(os.getenv("SENTINELSHIELD_WS_MIN_RISK", "50.0"))

try:
    import websockets
    from websockets.server import WebSocketServerProtocol
    _WS_OK = True
except ImportError:
    _WS_OK = False


# ---------------------------------------------------------------------------
# Alert tailer – polls alert_history.csv for new rows
# ---------------------------------------------------------------------------

class AlertTailer:
    """Yield new alert rows appended to ``ALERT_FILE`` since last call."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._last_pos: int = 0
        self._header: list[str] = []

    def poll(self) -> list[dict[str, Any]]:
        if not self._path.exists():
            return []
        try:
            size = self._path.stat().st_size
            if size < self._last_pos:
                # File was truncated or rotated
                self._last_pos = 0
                self._header = []

            if size <= self._last_pos:
                return []

            with self._path.open("r", newline="", encoding="utf-8", errors="replace") as fh:
                if not self._header:
                    header_line = fh.readline()
                    if header_line:
                        self._header = [h.strip() for h in next(csv.reader([header_line]))]
                    if self._last_pos == 0:
                        self._last_pos = size
                        return []

                fh.seek(self._last_pos)
                new_lines = fh.readlines()
                self._last_pos = fh.tell()

            if not new_lines or not self._header:
                return []

            reader = csv.DictReader(new_lines, fieldnames=self._header)
            return [dict(row) for row in reader]
        except (OSError, csv.Error) as exc:
            LOGGER.warning("Alert tailer read error: %s", exc)
            return []


# ---------------------------------------------------------------------------
# WebSocket server
# ---------------------------------------------------------------------------

_clients: Set[Any] = set()
_tailer = AlertTailer(ALERT_FILE)


async def _broadcast(payload: dict[str, Any]) -> None:
    """Send *payload* as JSON to all connected clients."""
    if not _clients:
        return
    message = json.dumps(payload, ensure_ascii=False, default=str)
    dead: Set[Any] = set()
    for ws in list(_clients):
        try:
            await ws.send(message)
        except Exception:
            dead.add(ws)
    _clients.difference_update(dead)


async def _handler(websocket: Any) -> None:
    """Accept a client connection and keep it alive until disconnected."""
    _clients.add(websocket)
    LOGGER.info("Client connected from %s (total: %d)", websocket.remote_address, len(_clients))
    try:
        # Send a handshake so the client knows it's connected
        await websocket.send(json.dumps({
            "type": "connected",
            "message": "SentinelShield WebSocket alert feed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))
        await websocket.wait_closed()
    finally:
        _clients.discard(websocket)
        LOGGER.info("Client disconnected (total: %d)", len(_clients))


async def _poll_loop() -> None:
    """Continuously poll the alert CSV and broadcast new HIGH/CRITICAL rows."""
    LOGGER.info("Alert tailer watching %s (poll every %.1fs)", ALERT_FILE.resolve(), POLL_INTERVAL)
    while True:
        try:
            new_rows = _tailer.poll()
            for row in new_rows:
                try:
                    risk = float(row.get("Risk", 0) or 0)
                except (TypeError, ValueError):
                    risk = 0.0
                if risk < MIN_RISK_BROADCAST:
                    continue
                payload: dict[str, Any] = {
                    "type": "alert",
                    "level": str(row.get("Level", "HIGH")).upper(),
                    "ssid": row.get("SSID", "Unknown"),
                    "bssid": row.get("BSSID", "Unknown"),
                    "risk": round(risk, 1),
                    "reason": str(row.get("Reason", ""))[:300],
                    "timestamp": row.get("Time", datetime.now(timezone.utc).isoformat()),
                }
                LOGGER.info(
                    "Broadcasting alert: %s — %s (risk %.0f%%)",
                    payload["ssid"], payload["level"], payload["risk"],
                )
                await _broadcast(payload)
        except Exception as exc:
            LOGGER.exception("Poll loop error: %s", exc)
        await asyncio.sleep(POLL_INTERVAL)


async def _serve() -> None:
    async with websockets.serve(_handler, HOST, PORT):
        LOGGER.info(
            "SentinelShield WebSocket alert server listening on ws://%s:%d/alerts", HOST, PORT
        )
        await _poll_loop()


def run_ws_server() -> None:
    """Entry point – blocks until the server is stopped (Ctrl-C)."""
    if not _WS_OK:
        raise SystemExit(
            "The 'websockets' package is required to run the WebSocket alert server.\n"
            "Install it with:  pip install websockets"
        )
    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        LOGGER.info("WebSocket alert server stopped.")


if __name__ == "__main__":
    run_ws_server()
