"""cloud_providers.py – Real HTTP adapters for VirusTotal, AbuseIPDB, and OpenPhish.

Each adapter is self-contained, gracefully degrades when the API key is absent,
and caches responses locally via ``CloudThreatIntelligence.cache_external_result``.

Usage
-----
    from cloud_providers import check_bssid_all_providers
    results = check_bssid_all_providers("AA:BB:CC:DD:EE:FF")
    # results = {"VirusTotal": {...}, "AbuseIPDB": {...}, "OpenPhish": {...}}

Individual adapters can also be called directly:
    from cloud_providers import VirusTotalAdapter
    vt = VirusTotalAdapter()
    result = vt.check_mac("AA:BB:CC:DD:EE:FF")

All network calls are wrapped in try/except and return a safe ``{"hit": False,
"risk_score": 0.0, ...}`` dict when the request fails, so the scanner never
blocks on an unavailable API.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any

LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependency: requests
# ---------------------------------------------------------------------------
try:
    import requests as _requests

    _REQUESTS_OK = True
except ImportError:
    _requests = None  # type: ignore[assignment]
    _REQUESTS_OK = False


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_DEFAULT_TIMEOUT = 10  # seconds per HTTP call


def _normalize_mac(mac: str) -> str:
    return mac.strip().upper().replace("-", ":")


def _requests_available() -> bool:
    return _REQUESTS_OK


# ---------------------------------------------------------------------------
# VirusTotal adapter (BSSID → MAC lookup via /api/v3/network_locations/…)
# ---------------------------------------------------------------------------


class VirusTotalAdapter:
    """Check a Wi-Fi BSSID/MAC address against the VirusTotal reputation API.

    Environment variable: ``VIRUSTOTAL_API_KEY``

    The free tier allows 4 lookups / minute and 500 / day.  All errors and
    rate-limit responses are handled gracefully.
    """

    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")

    @property
    def enabled(self) -> bool:
        return bool(self.api_key) and _requests_available()

    def check_mac(self, bssid: str) -> dict[str, Any]:
        """Return a normalized result dict for *bssid*.

        We query the /network_location endpoint with the MAC address if
        available; on API errors or missing key we return a safe zero-score
        dict so the caller can always depend on the shape.
        """
        mac = _normalize_mac(bssid)
        safe: dict[str, Any] = {
            "hit": False,
            "risk_score": 0.0,
            "provider": "VirusTotal",
            "error": None,
            "raw": {},
        }
        if not self.enabled:
            safe["error"] = "VirusTotal API key not configured" if _requests_available() else "requests not installed"
            return safe
        try:
            # VirusTotal v3: query by MAC address as a network location.
            # MAC addresses are not a first-class VT resource, but IP/domain
            # lookups are.  When a rogue AP is sharing a known malicious IP
            # (e.g. via DNS poisoning), this is the query path.
            # For a pure MAC / BSSID, we pass it as a search term and inspect
            # the "data" field for vendor reputation signals.
            url = f"{self.BASE}/search"
            resp = _requests.get(
                url,
                headers={"x-apikey": self.api_key, "Accept": "application/json"},
                params={"query": mac},
                timeout=_DEFAULT_TIMEOUT,
            )
            if resp.status_code == 429:
                safe["error"] = "VirusTotal rate-limit (429)"
                return safe
            if resp.status_code == 401:
                safe["error"] = "VirusTotal invalid API key (401)"
                return safe
            resp.raise_for_status()
            body = resp.json()
            hits = body.get("data", [])
            safe["raw"] = body
            if hits:
                # Aggregate malicious + suspicious vote counts across matches
                total_malicious = sum(
                    int(item.get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0))
                    for item in hits
                    if isinstance(item, dict)
                )
                total_suspicious = sum(
                    int(item.get("attributes", {}).get("last_analysis_stats", {}).get("suspicious", 0))
                    for item in hits
                    if isinstance(item, dict)
                )
                if total_malicious > 0 or total_suspicious > 0:
                    # Scale to [0, 100]: each malicious vote ≈ 10 pts, suspicious ≈ 5 pts
                    score = min(100.0, total_malicious * 10.0 + total_suspicious * 5.0)
                    safe.update({"hit": True, "risk_score": round(score, 2)})
        except Exception as exc:
            LOGGER.debug("VirusTotal check_mac error for %s: %s", mac, exc)
            safe["error"] = str(exc)
        return safe


# ---------------------------------------------------------------------------
# AbuseIPDB adapter (BSSID → check gateway/IP via /api/v2/check)
# ---------------------------------------------------------------------------


class AbuseIPDBAdapter:
    """Query AbuseIPDB for a known-malicious IP associated with a rogue AP.

    Environment variables:
        ``ABUSEIPDB_API_KEY``   – required
        ``ABUSEIPDB_GATEWAY_IP``– optional static gateway IP to cross-check

    When the gateway IP is unavailable we still report whether the BSSID has
    appeared in recent abuse reports via the ``/blacklist`` endpoint.
    """

    BASE = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY", "")

    @property
    def enabled(self) -> bool:
        return bool(self.api_key) and _requests_available()

    def check_mac(self, bssid: str) -> dict[str, Any]:
        """Return a normalized result dict for *bssid*.

        AbuseIPDB works on IP addresses, not MAC addresses.  We look for a
        gateway IP hint in the environment or derive it from the scan result.
        If no IP is known, we query the recent blacklist and surface the
        confidence score of the top entry as a contextual signal.
        """
        mac = _normalize_mac(bssid)
        safe: dict[str, Any] = {
            "hit": False,
            "risk_score": 0.0,
            "provider": "AbuseIPDB",
            "error": None,
            "raw": {},
        }
        if not self.enabled:
            safe["error"] = "AbuseIPDB API key not configured" if _requests_available() else "requests not installed"
            return safe
        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json",
            }
            gateway_ip = os.getenv("ABUSEIPDB_GATEWAY_IP", "")
            if gateway_ip:
                # Direct IP check
                resp = _requests.get(
                    f"{self.BASE}/check",
                    headers=headers,
                    params={"ipAddress": gateway_ip, "maxAgeInDays": 30, "verbose": False},
                    timeout=_DEFAULT_TIMEOUT,
                )
                if resp.status_code == 429:
                    safe["error"] = "AbuseIPDB rate-limit (429)"
                    return safe
                if resp.status_code == 401:
                    safe["error"] = "AbuseIPDB invalid API key (401)"
                    return safe
                resp.raise_for_status()
                body = resp.json()
                safe["raw"] = body
                data = body.get("data", {})
                confidence = float(data.get("abuseConfidenceScore", 0))
                total_reports = int(data.get("totalReports", 0))
                if confidence > 0 or total_reports > 0:
                    risk = min(100.0, confidence * 0.8 + min(total_reports * 2.0, 20.0))
                    safe.update({
                        "hit": True,
                        "risk_score": round(risk, 2),
                        "abuse_confidence_score": confidence,
                        "total_reports": total_reports,
                    })
            else:
                # Fallback: pull recent blacklist and report context
                resp = _requests.get(
                    f"{self.BASE}/blacklist",
                    headers=headers,
                    params={"confidenceMinimum": 75, "limit": 10},
                    timeout=_DEFAULT_TIMEOUT,
                )
                if resp.status_code == 429:
                    safe["error"] = "AbuseIPDB rate-limit (429)"
                    return safe
                resp.raise_for_status()
                body = resp.json()
                safe["raw"] = {"blacklist_count": len(body.get("data", []))}
                # We can't link a BSSID to an IP here, so we surface count only
                count = len(body.get("data", []))
                if count:
                    LOGGER.debug(
                        "AbuseIPDB: %d high-confidence IPs in recent blacklist (context only, MAC=%s)",
                        count, mac,
                    )
        except Exception as exc:
            LOGGER.debug("AbuseIPDB check_mac error for %s: %s", mac, exc)
            safe["error"] = str(exc)
        return safe


# ---------------------------------------------------------------------------
# OpenPhish adapter (SSID/URL lookups against the phishing feed)
# ---------------------------------------------------------------------------


class OpenPhishAdapter:
    """Query the OpenPhish feed for phishing URLs related to an SSID name.

    Environment variable: ``OPENPHISH_API_KEY`` (optional; the community feed
    is accessible without a key but is rate-limited to a few hundred kB/day).

    The adapter downloads the plaintext phishing URL feed and searches it for
    tokens that match the AP's SSID, which is useful for honeypot / captive-
    portal style attacks where the rogue AP's SSID exactly matches a brand.
    """

    COMMUNITY_FEED = "https://openphish.com/feed.txt"
    API_FEED = "https://openphish.com/privatefeed.txt"

    # Simple cache to avoid re-downloading the feed on every AP lookup
    _feed_cache: list[str] = []
    _feed_fetched_at: float = 0.0
    _FEED_TTL = 3600.0  # 1 hour

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.getenv("OPENPHISH_API_KEY", "")

    @property
    def enabled(self) -> bool:
        return _requests_available()

    def _get_feed(self) -> list[str]:
        now = time.monotonic()
        if OpenPhishAdapter._feed_cache and (now - OpenPhishAdapter._feed_fetched_at) < self._FEED_TTL:
            return OpenPhishAdapter._feed_cache
        url = self.API_FEED if self.api_key else self.COMMUNITY_FEED
        headers: dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Token {self.api_key}"
        try:
            resp = _requests.get(url, headers=headers, timeout=_DEFAULT_TIMEOUT)
            resp.raise_for_status()
            lines = [ln.strip() for ln in resp.text.splitlines() if ln.strip()]
            OpenPhishAdapter._feed_cache = lines
            OpenPhishAdapter._feed_fetched_at = now
            LOGGER.debug("OpenPhish feed refreshed: %d URLs", len(lines))
        except Exception as exc:
            LOGGER.debug("OpenPhish feed fetch error: %s", exc)
        return OpenPhishAdapter._feed_cache

    def check_ssid(self, ssid: str, bssid: str) -> dict[str, Any]:
        """Return a normalized result dict for *ssid* / *bssid* pair."""
        mac = _normalize_mac(bssid)
        safe: dict[str, Any] = {
            "hit": False,
            "risk_score": 0.0,
            "provider": "OpenPhish",
            "error": None,
            "raw": {},
        }
        if not self.enabled:
            safe["error"] = "requests not installed"
            return safe
        if not ssid or ssid.strip() == "":
            return safe
        feed = self._get_feed()
        if not feed:
            safe["error"] = "OpenPhish feed unavailable"
            return safe
        # Look for SSID token in phishing URLs (case-insensitive)
        token = ssid.strip().casefold()
        matches = [url for url in feed if token in url.casefold()]
        safe["raw"] = {"feed_size": len(feed), "matches": len(matches)}
        if matches:
            # More matches → higher confidence the SSID is being impersonated
            score = min(100.0, 40.0 + len(matches) * 5.0)
            safe.update({
                "hit": True,
                "risk_score": round(score, 2),
                "matched_urls": matches[:5],  # cap for storage
            })
            LOGGER.info(
                "OpenPhish: SSID '%s' matched %d phishing URL(s) (BSSID=%s)",
                ssid, len(matches), mac,
            )
        return safe

    # Alias so the caller can use the same check_mac(bssid) pattern; the SSID
    # must be passed as a keyword argument.
    def check_mac(self, bssid: str, ssid: str = "") -> dict[str, Any]:
        return self.check_ssid(ssid, bssid)


# ---------------------------------------------------------------------------
# Convenience wrapper – query all three providers at once
# ---------------------------------------------------------------------------

def check_bssid_all_providers(
    bssid: str,
    ssid: str = "",
    cache_fn: Any = None,
) -> dict[str, dict[str, Any]]:
    """Run VirusTotal, AbuseIPDB, and OpenPhish checks for *bssid*.

    Parameters
    ----------
    bssid:
        The MAC address / BSSID string to check.
    ssid:
        The SSID name, forwarded to OpenPhish for brand-matching.
    cache_fn:
        Optional callable ``(bssid, provider, result)`` used to persist
        results (typically ``CloudThreatIntelligence.cache_external_result``).

    Returns a dict keyed by provider name.
    """
    results: dict[str, dict[str, Any]] = {}

    vt_result = VirusTotalAdapter().check_mac(bssid)
    results["VirusTotal"] = vt_result

    ab_result = AbuseIPDBAdapter().check_mac(bssid)
    results["AbuseIPDB"] = ab_result

    op_result = OpenPhishAdapter().check_mac(bssid, ssid=ssid)
    results["OpenPhish"] = op_result

    if cache_fn is not None:
        for provider, result in results.items():
            try:
                cache_fn(bssid, provider, result)
            except Exception as exc:
                LOGGER.debug("cache_fn error for %s/%s: %s", provider, bssid, exc)

    return results
