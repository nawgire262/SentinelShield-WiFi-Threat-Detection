"""layer2_monitor.py – unified deauth/jamming/sequence-anomaly detector.

Wraps the existing ``scapy_capture`` and ``packet_sniffer`` modules into a
pipeline-friendly API that ``scan_controller.py`` can call to produce a
numeric evidence score (0–100) and a list of human-readable reasons.

The monitor is *optional*: if Scapy is not installed the score is simply
omitted from evidence fusion, which is already coded to exclude absent
components from its weighted denominator.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Any

LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional Scapy import
# ---------------------------------------------------------------------------
try:
    from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Disas, RadioTap
    _SCAPY_OK = True
except ImportError:
    sniff = Dot11 = Dot11Deauth = Dot11Disas = RadioTap = None  # type: ignore[assignment]
    _SCAPY_OK = False


def is_available() -> bool:
    """Return True when Scapy is installed and monitor mode may be attempted."""
    return _SCAPY_OK


# ---------------------------------------------------------------------------
# Internal packet accumulator (thread-safe, bounded ring buffer)
# ---------------------------------------------------------------------------

class _PacketAccumulator:
    """Collects raw frame statistics in a background thread."""

    # Deauth/disassoc burst threshold per rolling window
    _DEAUTH_BURST = 25
    # Beacon sequence-number jump considered anomalous
    _SEQ_JUMP_MAX = 50
    _SEQ_JUMP_MIN = 1  # ignore normal small steps
    _SEQ_WRAP = 4096

    def __init__(self, interface: str, window_seconds: float = 20.0) -> None:
        self.interface = interface
        self.window_seconds = max(2.0, float(window_seconds))
        # per-BSSID deauth timestamps
        self._deauth_times: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=500))
        # per-BSSID previous sequence number
        self._seq_tracker: dict[str, int] = {}
        # flagged events: list of {"bssid", "event", "detail"}
        self._events: list[dict[str, str]] = []
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # ------------------------------------------------------------------
    def start(self) -> None:
        if not _SCAPY_OK:
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="sentinel-layer2-monitor", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------
    def _run(self) -> None:
        try:
            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
                timeout=self.window_seconds + 2,
            )
        except Exception as exc:
            LOGGER.debug("Layer-2 monitor sniff error on %s: %s", self.interface, exc)

    # ------------------------------------------------------------------
    def _handle_packet(self, packet: Any) -> None:
        if not packet.haslayer(Dot11):
            return
        dot11 = packet.getlayer(Dot11)
        bssid = str(getattr(dot11, "addr3", "") or "").upper()
        now = time.monotonic()

        # ── Feature 1: deauth / disassoc flood (Paper 5) ────────────────
        if packet.haslayer(Dot11Deauth) or packet.haslayer(Dot11Disas):
            src = str(getattr(dot11, "addr2", "") or "").upper()
            key = src or bssid
            q = self._deauth_times[key]
            q.append(now)
            # count events within window
            cutoff = now - self.window_seconds
            burst = sum(1 for t in q if t >= cutoff)
            if burst >= self._DEAUTH_BURST:
                with self._lock:
                    self._events.append({
                        "bssid": key,
                        "event": "deauth_flood",
                        "detail": (
                            f"Deauth/disassoc burst: {burst} frames in "
                            f"{self.window_seconds:.0f}s window from {key}"
                        ),
                    })
            return

        # ── Feature 2: beacon sequence-number anomaly (Paper 6) ─────────
        if getattr(dot11, "type", -1) == 0 and getattr(dot11, "subtype", -1) == 8:
            # beacon frame
            seq_raw = getattr(dot11, "SC", 0) or 0
            seq = (seq_raw >> 4) & 0xFFF
            if bssid and bssid in self._seq_tracker:
                prev = self._seq_tracker[bssid]
                delta = (seq - prev) & (self._SEQ_WRAP - 1)
                if self._SEQ_JUMP_MIN < delta < self._SEQ_JUMP_MAX:
                    pass  # normal increment
                elif delta == 0:
                    pass  # retransmit or same frame
                else:
                    with self._lock:
                        self._events.append({
                            "bssid": bssid,
                            "event": "sequence_anomaly",
                            "detail": (
                                f"Beacon sequence jump on {bssid}: "
                                f"prev={prev} curr={seq} delta={delta} "
                                "(possible rogue AP injection)"
                            ),
                        })
            self._seq_tracker[bssid] = seq

    # ------------------------------------------------------------------
    def drain_events(self) -> list[dict[str, str]]:
        """Return and clear accumulated events."""
        with self._lock:
            events, self._events = self._events, []
        return events


# ---------------------------------------------------------------------------
# Module-level singleton accumulator – lazily started
# ---------------------------------------------------------------------------
_accumulator: _PacketAccumulator | None = None
_acc_lock = threading.Lock()


def _get_accumulator(interface: str, window_seconds: float = 20.0) -> _PacketAccumulator:
    global _accumulator
    with _acc_lock:
        if _accumulator is None or _accumulator.interface != interface:
            if _accumulator:
                _accumulator.stop()
            _accumulator = _PacketAccumulator(interface, window_seconds)
            _accumulator.start()
    return _accumulator


# ---------------------------------------------------------------------------
# Public API – called by scan_controller
# ---------------------------------------------------------------------------

def layer2_evidence(
    observation: dict[str, Any],
    interface: str = "wlan0mon",
    window_seconds: float = 20.0,
) -> dict[str, Any] | None:
    """Return a Layer-2 evidence dict ``{score, reasons}`` or ``None`` if unavailable.

    Parameters
    ----------
    observation:
        The current AP observation dict (used to correlate BSSID).
    interface:
        Monitor-mode interface name.  Must already be in monitor mode.
    window_seconds:
        Rolling time window used to assess deauth burst rates.
    """
    if not _SCAPY_OK:
        return None
    try:
        acc = _get_accumulator(interface, window_seconds)
        events = acc.drain_events()
    except Exception as exc:
        LOGGER.debug("layer2_evidence: accumulator error: %s", exc)
        return None

    obs_bssid = str(observation.get("bssid") or "").upper()
    score = 0.0
    reasons: list[str] = []

    for ev in events:
        ev_bssid = str(ev.get("bssid", "")).upper()
        # Always surface events that match this specific AP; also surface
        # global deauth floods even if BSSID does not match (jamming context).
        if ev["event"] == "deauth_flood":
            score = min(100.0, score + 60.0)
            reasons.append(ev["detail"])
        elif ev["event"] == "sequence_anomaly":
            if ev_bssid == obs_bssid or not obs_bssid:
                score = min(100.0, score + 40.0)
                reasons.append(ev["detail"])

    if not reasons:
        return None  # omit from fusion when nothing was detected
    return {"score": round(score, 2), "reasons": reasons}


def start_monitor(interface: str = "wlan0mon", window_seconds: float = 20.0) -> bool:
    """Explicitly (re-)start the background monitor on *interface*.

    Returns True if Scapy is available and the thread was started.
    """
    if not _SCAPY_OK:
        LOGGER.info("layer2_monitor: Scapy not installed – monitor unavailable")
        return False
    _get_accumulator(interface, window_seconds)
    return True


def stop_monitor() -> None:
    """Stop the background sniffer thread gracefully."""
    global _accumulator
    with _acc_lock:
        if _accumulator:
            _accumulator.stop()
            _accumulator = None
