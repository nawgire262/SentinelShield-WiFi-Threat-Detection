"""Background scan orchestration, adaptive verification, evidence fusion and persistence."""
from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

from bluetooth_context import BluetoothContext
from evidence_fusion import EvidenceFusion
from fast_wifi_scanner import FastWiFiScanner, ScanBatch
from location_context import LocationContext
from ml_evidence import ExistingModelEvidence
from runtime_config import load_runtime_config
from temporal_analyzer import TemporalAnalyzer
from wifi_fingerprint import WiFiFingerprintStore, canonical_bssid
from evidence_integrity import receipt
from incident_assistant import explain
from sensor_mesh import mesh_context
from wired_correlation import correlate
from wifi_sensing import summarize as sensing_summary

LOGGER = logging.getLogger(__name__)


class ScanController:
    """One controller per dashboard session; only one run may be active at once."""

    MODES = {"fast", "balanced", "deep", "auto"}

    def __init__(self, scanner: FastWiFiScanner | None = None, config: dict[str, Any] | None = None, fingerprint_store: WiFiFingerprintStore | None = None, temporal: TemporalAnalyzer | None = None, fusion: EvidenceFusion | None = None, ml_models: ExistingModelEvidence | None = None, database: bool = True) -> None:
        self.config = config or load_runtime_config()
        self.scanner = scanner or FastWiFiScanner(config=self.config)
        self.fingerprints = fingerprint_store or WiFiFingerprintStore(config=self.config)
        self.temporal = temporal or TemporalAnalyzer(config=self.config)
        self.fusion = fusion or EvidenceFusion(config=self.config)
        self.ml_models = ml_models or ExistingModelEvidence()
        context_cfg = self.config["optional_context"]
        self.bluetooth = BluetoothContext(enabled=bool(context_cfg["bluetooth_enabled"]))
        self.location = LocationContext(enabled=bool(context_cfg["location_enabled"]))
        self.use_database = database
        self._lock = threading.RLock()
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None
        self._status: dict[str, Any] = {"status": "idle", "progress": 0, "error": None, "mode": None}
        self._latest: dict[str, Any] | None = None
        # Read-only first-pass output for the dashboard while verification runs.
        self._preliminary: dict[str, Any] | None = None
        self._metrics: deque[dict[str, float]] = deque(maxlen=100)
        for record in self.fingerprints.all_records():
            self.temporal.seed(record.get("bssid", ""), record.get("rssi_history", []))

    def start(self, mode: str = "auto") -> bool:
        normalized = str(mode).casefold()
        if normalized not in self.MODES:
            raise ValueError(f"mode must be one of {sorted(self.MODES)}")
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._cancel.clear()
            self._preliminary = None
            self._status = {"status": "queued", "progress": 1, "error": None, "mode": normalized, "started_at": _now()}
            self._thread = threading.Thread(target=self._worker, args=(normalized,), name="sentinel-scan-controller", daemon=True)
            self._thread.start()
            return True

    def stop(self) -> bool:
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                return False
            self._cancel.set()
            self._status = {**self._status, "status": "stopping", "message": "Waiting for in-flight driver scan to return safely."}
            return True

    def status(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._status)

    def latest(self) -> dict[str, Any] | None:
        with self._lock:
            return dict(self._latest) if self._latest else None

    def preliminary(self) -> dict[str, Any] | None:
        """Return first-pass findings only while a scan is still being verified."""
        with self._lock:
            return dict(self._preliminary) if self._preliminary else None

    def performance_summary(self) -> dict[str, Any]:
        with self._lock:
            rows = list(self._metrics)
        if not rows:
            return {"samples": 0, "average_scan_ms": None, "median_scan_ms": None, "p95_scan_ms": None, "average_detection_latency_ms": None, "average_aps": None}
        scans = sorted(row["scan_duration_ms"] for row in rows)
        latencies = sorted(row["detection_latency_ms"] for row in rows)
        def percentile(values: list[float], q: float) -> float:
            return values[min(len(values) - 1, max(0, round((len(values) - 1) * q)))]
        return {
            "samples": len(rows),
            "average_scan_ms": sum(scans) / len(scans),
            "median_scan_ms": percentile(scans, 0.5),
            "p95_scan_ms": percentile(scans, 0.95),
            "average_detection_latency_ms": sum(latencies) / len(latencies),
            "average_aps": sum(row["aps_discovered"] for row in rows) / len(rows),
        }

    def _set_status(self, **values: Any) -> None:
        with self._lock:
            self._status.update(values)

    def _worker(self, requested_mode: str) -> None:
        started_clock = time.perf_counter()
        try:
            adapters = self.scanner.discover_adapters()
            self._set_status(status="scanning", progress=10, adapters=[adapter.public_dict() for adapter in adapters], adapter_count=len(adapters), adapter_mode="multi-adapter" if len(adapters) > 1 else "single-adapter" if adapters else "unavailable")
            if self._cancel.is_set():
                self._set_status(status="cancelled", progress=0)
                return
            known = self.fingerprints.all_records()
            has_baseline = bool(known)
            mode = requested_mode
            if mode == "auto":
                mode = "fast" if has_baseline else "balanced"
            first_batch = self.scanner.scan(mode=mode, cancel_event=self._cancel, adapters=adapters)
            if self._cancel.is_set():
                self._set_status(status="cancelled", progress=0, message="Scan cancelled after the current driver operation.")
                return
            batches = [first_batch]
            preliminary = self._analyze_observations(first_batch.observations, update_state=False)
            with self._lock:
                self._preliminary = {
                    "scan_id": first_batch.scan_id,
                    "results": preliminary,
                    "adapters": first_batch.adapters,
                    "adapter_count": len(first_batch.adapters),
                    "adapter_mode": "multi-adapter" if len(first_batch.adapters) > 1 else "single-adapter" if first_batch.adapters else "unavailable",
                    "aps_discovered": len(preliminary),
                    "scan_duration_ms": first_batch.scan_duration_ms,
                }
                self._status.update(preliminary_available=True, preliminary_aps=len(preliminary), progress=45)
            if requested_mode == "deep":
                verification_count = int(self.config["fast_scanning"]["verification_samples"]) - 1
            elif requested_mode == "auto" and self.config["fast_scanning"]["adaptive_deep_scan"] and self._requires_verification(preliminary, known):
                verification_count = int(self.config["fast_scanning"]["verification_samples"]) - 1
            else:
                verification_count = 0
            for verification_index in range(max(0, verification_count)):
                if self._cancel.is_set():
                    break
                self._set_status(status="deep-verification", progress=55 + verification_index * 10)
                verification = self.scanner.scan(mode="deep", cancel_event=self._cancel, adapters=adapters)
                if not self._cancel.is_set():
                    batches.append(verification)
            if self._cancel.is_set():
                self._set_status(status="cancelled", progress=0, message="Verification cancelled; partial results were not committed.")
                return
            observations = self._merge_batches(batches)
            self._set_status(status="analyzing", progress=70)
            context = self._collect_context()
            results = self._analyze_observations(observations, update_state=True, context=context)
            completed_clock = time.perf_counter()
            scan_duration = sum(batch.scan_duration_ms for batch in batches)
            wall_duration = (completed_clock - started_clock) * 1000.0
            for row in results:
                row["scan_id"] = first_batch.scan_id
                row["scan_duration_ms"] = round(scan_duration, 2)
                row["detection_latency_ms"] = round(wall_duration, 2)
            batch_public = first_batch.public_dict()
            result = {
                **batch_public,
                "scan_id": first_batch.scan_id,
                "started_at": first_batch.started_at,
                "completed_at": _now(),
                "scan_duration_ms": round(scan_duration, 2),
                "processing_time_ms": round(max(0.0, wall_duration - scan_duration), 2),
                "detection_latency_ms": round(wall_duration, 2),
                "scan_mode": "deep-verification" if len(batches) > 1 else requested_mode,
                "adapters": first_batch.adapters,
                "adapter_count": len(first_batch.adapters),
                "adapter_mode": "multi-adapter" if len(first_batch.adapters) > 1 else "single-adapter" if first_batch.adapters else "unavailable",
                "aps_discovered": len(results),
                "unique_bssids": len({row["bssid"] for row in results if row.get("bssid")}),
                "results": results,
                "observations": observations,
                "errors": [error for batch in batches for error in batch.errors],
                "verification_performed": len(batches) > 1,
                "context": context,
            }
            integrity_cfg = self.config["evidence_integrity"]
            if integrity_cfg["enabled"]:
                result["integrity_receipt"] = receipt(
                    {"scan_id": result["scan_id"], "results": results}, integrity_cfg["hmac_key_env"]
                )
            result["incident_summaries"] = [explain(row) for row in results]
            self._persist(result)
            with self._lock:
                self._latest = result
                self._preliminary = None
                self._metrics.append({"scan_duration_ms": result["scan_duration_ms"], "detection_latency_ms": result["detection_latency_ms"], "aps_discovered": float(result["aps_discovered"])})
                self._status = {"status": "completed" if results else "empty", "progress": 100, "error": None, "mode": result["scan_mode"], "scan_id": result["scan_id"], "aps_discovered": result["aps_discovered"], "adapter_mode": result["adapter_mode"], "adapter_count": result["adapter_count"], "adapters": result["adapters"], "scan_duration_ms": result["scan_duration_ms"], "detection_latency_ms": result["detection_latency_ms"], "verification_performed": result["verification_performed"], "errors": result["errors"], "completed_at": result["completed_at"]}
        except Exception as exc:
            LOGGER.exception("Scan controller failed")
            self._set_status(status="error", progress=0, error=f"{type(exc).__name__}: {exc}")

    @staticmethod
    def _merge_batches(batches: list[ScanBatch]) -> list[dict[str, Any]]:
        combined: dict[tuple[str, str], dict[str, Any]] = {}
        for batch in batches:
            for observation in batch.observations:
                key = (str(observation.get("ssid", "")), canonical_bssid(observation.get("bssid")))
                if key not in combined:
                    combined[key] = {**observation, "rssi_samples_dbm": [], "adapter_ids": []}
                row = combined[key]
                if observation.get("rssi_dbm") is not None:
                    row["rssi_samples_dbm"].append(float(observation["rssi_dbm"]))
                row["adapter_ids"] = list(dict.fromkeys(row["adapter_ids"] + observation.get("adapter_ids", [observation.get("adapter_id")]) ))
                row["scan_duration_ms"] = max(float(row.get("scan_duration_ms") or 0), float(observation.get("scan_duration_ms") or 0))
        for row in combined.values():
            samples = row["rssi_samples_dbm"]
            if samples:
                row["rssi_dbm"] = sorted(samples)[len(samples) // 2]
            row["verification_observations"] = len(samples)
        return list(combined.values())

    def _requires_verification(self, preliminary: list[dict[str, Any]], known: list[dict[str, Any]]) -> bool:
        if not preliminary:
            return False
        trusted_by_ssid: dict[str, list[dict[str, Any]]] = defaultdict(list)
        known_bssids = {canonical_bssid(row.get("bssid")) for row in known}
        for record in known:
            if record.get("trusted"):
                trusted_by_ssid[str(record.get("ssid", "")).casefold()].append(record)
        min_samples = int(self.config["temporal_analysis"]["minimum_samples"])
        for row in preliminary:
            if row.get("bssid") not in known_bssids:
                return True
            if row.get("threat_level") in {"HIGH", "CRITICAL"}:
                return True
            if row.get("temporal", {}).get("sample_count", 0) >= min_samples and row.get("temporal", {}).get("rssi_delta", 0) >= self.config["fast_scanning"]["rssi_change_trigger_db"]:
                return True
            if trusted_by_ssid.get(str(row.get("ssid", "")).casefold()):
                security_evidence = row.get("evidence_scores", {}).get("security", {})
                security_score = security_evidence.get("score", 0.0) if isinstance(security_evidence, dict) else security_evidence
                if float(security_score or 0.0) > 0:
                    return True
        return False

    def _analyze_observations(self, observations: list[dict[str, Any]], update_state: bool, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        by_ssid: dict[str, set[str]] = defaultdict(set)
        bssid_to_ssids: dict[str, set[str]] = defaultdict(set)
        for item in observations:
            bssid = canonical_bssid(item.get("bssid"))
            ssid = str(item.get("ssid", ""))
            if bssid:
                by_ssid[ssid.casefold()].add(bssid)
                bssid_to_ssids[bssid].add(ssid.casefold())
        all_records = self.fingerprints.all_records()
        by_bssid = {canonical_bssid(record.get("bssid")): record for record in all_records}
        trusted_by_ssid: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in all_records:
            if record.get("trusted"):
                trusted_by_ssid[str(record.get("ssid", "")).casefold()].append(record)
        prepared: list[tuple[dict[str, Any], str, dict[str, Any] | None, dict[str, Any], dict[str, Any]]] = []
        for observation in observations:
            bssid = canonical_bssid(observation.get("bssid"))
            baseline = by_bssid.get(bssid)
            temporal = self.temporal.observe(observation) if update_state else self.temporal.preview(observation)
            density = self._density_evidence(observation, by_ssid, bssid_to_ssids, trusted_by_ssid)
            prepared.append((observation, bssid, baseline, temporal, density))

        if update_state and self.ml_models.available:
            ml_results = self.ml_models.predict_many(
                [item[0] for item in prepared],
                [len(by_ssid[str(item[0].get("ssid", "")).casefold()]) for item in prepared],
                [float(item[3].get("rssi_variance") or 0) for item in prepared],
            )
        else:
            ml_results = [None] * len(prepared)

        output: list[dict[str, Any]] = []
        for (observation, bssid, baseline, temporal, density), ml in zip(prepared, ml_results):
            ssid_key = str(observation.get("ssid", "")).casefold()
            row_context = dict(context or {})
            wired_cfg = self.config["wired_correlation"]
            if wired_cfg["enabled"]:
                row_context["wired"] = correlate(observation, wired_cfg["inventory_file"])
                row_context.setdefault("reasons", []).extend(row_context["wired"].get("reasons", []))
            mesh_cfg = self.config["sensor_mesh"]
            if mesh_cfg["enabled"]:
                row_context["sensor_mesh"] = mesh_context(observation, mesh_cfg["inbox_dir"], mesh_cfg["max_age_seconds"])
                row_context.setdefault("reasons", []).extend(row_context["sensor_mesh"].get("reasons", []))
            fused = self.fusion.score_observation(
                observation, baseline, trusted_by_ssid.get(ssid_key, []),
                temporal, density=density, context=row_context or None, ml_score=ml.get("risk_score") if ml else None,
            )
            record = self.fingerprints.observe(observation) if update_state else baseline
            if update_state and record and fused["threat_level"] in {"HIGH", "CRITICAL"}:
                self.fingerprints.mark_suspicious(bssid, True)
            output.append({
                **observation,
                "bssid": bssid,
                "vendor": (record or baseline or {}).get("vendor") or observation.get("vendor"),
                "fingerprint_hash": (record or baseline or {}).get("fingerprint_hash"),
                "confidence": (record or baseline or {}).get("confidence", "UNKNOWN"),
                "fingerprint_similarity": max(0.0, 100.0 - float(fused["scores"].get("fingerprint") or 0.0)) if baseline else None,
                "temporal": temporal,
                "density": density,
                "ml": ml,
                "context": row_context or None,
                "RF_Prediction": ml.get("rf_fake_probability") if ml else None,
                "KNN_Prediction": ml.get("knn_fake_probability") if ml else None,
                "Isolation_Forest": ml.get("isolation_anomaly_score") if ml else None,
                "ML_Risk": ml.get("risk_score") if ml else None,
                "risk_score": fused["risk_score"],
                "threat_level": fused["threat_level"],
                "evidence_scores": fused["evidence_scores"],
                "reasons": fused["reasons"],
                "detection_reason": "; ".join(fused["reasons"]) or "No high-risk evidence",
            })
        return sorted(output, key=lambda row: row["risk_score"], reverse=True)

    def _density_evidence(self, observation: dict[str, Any], by_ssid: dict[str, set[str]], bssid_to_ssids: dict[str, set[str]], trusted_by_ssid: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
        ssid_key = str(observation.get("ssid", "")).casefold()
        current_bssids = by_ssid.get(ssid_key, set())
        baseline_count = max(1, len(trusted_by_ssid.get(ssid_key, [])))
        reference = int(self.config["evidence_fusion"]["density_reference_count"])
        unexpected = max(0, len(current_bssids) - max(baseline_count, reference))
        score = min(100.0, unexpected * float(self.config["evidence_fusion"]["density_unexpected_bssid_score"]))
        reasons = []
        if unexpected:
            reasons.append(f"Unexpected BSSID density for SSID ({len(current_bssids)} observed; reference {max(baseline_count, reference)})")
        other_ssids = bssid_to_ssids.get(canonical_bssid(observation.get("bssid")), set()) - {ssid_key}
        if other_ssids:
            score = min(100.0, score + 25.0)
            reasons.append("Same BSSID observed advertising multiple SSIDs")
        return {"score": score, "reasons": reasons, "ssid_bssid_count": len(current_bssids), "bssid_ssid_count": len(other_ssids) + 1}

    def _collect_context(self) -> dict[str, Any] | None:
        configs = self.config["optional_context"]
        if not configs["bluetooth_enabled"] and not configs["location_enabled"] and not self.config["wired_correlation"]["enabled"] and not self.config["sensor_mesh"]["enabled"] and not self.config["wifi_sensing"]["enabled"]:
            return None
        context: dict[str, Any] = {"score": 0.0, "reasons": []}
        if configs["bluetooth_enabled"]:
            context["bluetooth"] = self.bluetooth.collect()
            context["reasons"].extend(context["bluetooth"].get("reasons", []))
        if configs["location_enabled"]:
            context["location"] = self.location.collect()
            context["reasons"].extend(context["location"].get("reasons", []))
        sensing_cfg = self.config["wifi_sensing"]
        if sensing_cfg["enabled"]:
            context["wifi_sensing"] = sensing_summary([], enabled=True, consent=(not sensing_cfg["consent_required"] or sensing_cfg["consent_granted"]))
            context["reasons"].extend(context["wifi_sensing"].get("reasons", []))
        return context

    def _persist(self, result: dict[str, Any]) -> None:
        if not self.use_database:
            return
        try:
            import database_manager
            database_manager.save_wifi_scan(result)
        except Exception as exc:
            LOGGER.warning("Optional SQLite scan persistence failed: %s", exc)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
