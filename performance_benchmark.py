"""Compare canonical legacy and fast scanners on the attached hardware.

The two scans run sequentially on purpose to avoid competing for the same radio.
No speedup is asserted: inspect measured scan and discovery figures in the JSON.
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
import tracemalloc
from typing import Any, Callable

from fast_wifi_scanner import FastWiFiScanner
from scanner import scan_wifi


def _canonical_bssid(value: Any) -> str:
    return "".join(character for character in str(value or "").upper() if character in "0123456789ABCDEF")


def _percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round((len(ordered) - 1) * q))]


def _run_samples(fn: Callable[[], Any], runs: int) -> dict[str, Any]:
    durations: list[float] = []
    cpu: list[float] = []
    counts: list[int] = []
    bssid_union: set[str] = set()
    memory_peaks: list[int] = []
    errors: list[str] = []
    for _ in range(runs):
        current_before = tracemalloc.get_traced_memory()[0] if tracemalloc.is_tracing() else 0
        if tracemalloc.is_tracing():
            tracemalloc.reset_peak()
        cpu_start, start = time.process_time(), time.perf_counter()
        try:
            result = fn()
            if hasattr(result, "public_dict"):
                payload = result.public_dict()
                counts.append(int(payload.get("aps_discovered", 0)))
                bssid_union.update(_canonical_bssid(item.get("bssid")) for item in payload.get("observations", []) if _canonical_bssid(item.get("bssid")))
            else:
                counts.append(len(result or []))
                bssid_union.update(_canonical_bssid(item.get("bssid", item.get("BSSID", ""))) for item in (result or []) if _canonical_bssid(item.get("bssid", item.get("BSSID", ""))))
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
            counts.append(0)
        durations.append((time.perf_counter() - start) * 1000.0)
        cpu.append((time.process_time() - cpu_start) * 1000.0)
        if tracemalloc.is_tracing():
            memory_peaks.append(max(0, tracemalloc.get_traced_memory()[1] - current_before))
    return {
        "runs": runs,
        "average_ms": round(statistics.mean(durations), 2),
        "median_ms": round(statistics.median(durations), 2),
        "p95_ms": round(_percentile(durations, 0.95) or 0.0, 2),
        "average_cpu_ms": round(statistics.mean(cpu), 2),
        "peak_python_heap_bytes": max(memory_peaks, default=0),
        "average_aps_discovered": round(statistics.mean(counts), 2),
        "aps_per_second": round(statistics.mean(counts) / max(statistics.mean(durations) / 1000, 0.001), 2),
        "bssids": sorted(bssid_union),
        "errors": errors,
    }


def benchmark(runs: int = 3, old_rounds: int = 1) -> dict[str, Any]:
    runs = max(1, min(20, int(runs)))
    tracemalloc.start()
    fast_scanner = FastWiFiScanner()
    old_samples: list[dict[str, Any]] = []
    fast_samples: list[dict[str, Any]] = []
    overlaps: list[float] = []
    for _ in range(runs):
        # Alternate on the same machine to reduce time-of-day/channel-load bias.
        old_result = _run_samples(lambda: scan_wifi(rounds=old_rounds), 1)
        fast_result = _run_samples(lambda: fast_scanner.scan(mode="fast"), 1)
        old_samples.append(old_result)
        fast_samples.append(fast_result)
        old_set, fast_set = set(old_result["bssids"]), set(fast_result["bssids"])
        union = old_set | fast_set
        overlaps.append(len(old_set & fast_set) / len(union) if union else 0.0)
    tracemalloc.stop()
    def aggregate(samples: list[dict[str, Any]]) -> dict[str, Any]:
        durations = [item["average_ms"] for item in samples]
        cpus = [item["average_cpu_ms"] for item in samples]
        counts = [item["average_aps_discovered"] for item in samples]
        return {
            "runs": len(samples),
            "average_ms": round(statistics.mean(durations), 2),
            "median_ms": round(statistics.median(durations), 2),
            "p95_ms": round(_percentile(durations, 0.95) or 0.0, 2),
            "average_cpu_ms": round(statistics.mean(cpus), 2),
            "peak_python_heap_bytes": max(item["peak_python_heap_bytes"] for item in samples),
            "average_aps_discovered": round(statistics.mean(counts), 2),
            "aps_per_second": round(statistics.mean(counts) / max(statistics.mean(durations) / 1000, 0.001), 2),
            "errors": [error for item in samples for error in item["errors"]],
        }
    old = aggregate(old_samples)
    fast = aggregate(fast_samples)
    comparable = old["average_aps_discovered"] > 0 and fast["average_aps_discovered"] > 0 and statistics.mean(overlaps) >= 0.5
    improvement = None
    if comparable and old["average_ms"] > 0:
        improvement = round((old["average_ms"] - fast["average_ms"]) / old["average_ms"] * 100, 2)
    return {
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "hardware_available": bool(old["average_aps_discovered"] or fast["average_aps_discovered"]),
        "runs": runs,
        "old_scanner": old,
        "fast_scanner": fast,
        "average_bssid_jaccard_overlap": round(statistics.mean(overlaps), 3) if overlaps else 0.0,
        "comparison_comparable": comparable,
        "average_scan_time_change_percent": improvement,
        "notes": [
            "Scans execute sequentially to avoid radio contention.",
            "The legacy scanner's per-round delay is fixed in scanner.py; its reported time is end-to-end wall time.",
            "BSSID overlap normalizes case and punctuation. The legacy scanner emits one representative BSSID per SSID, while the fast scanner preserves per-BSSID observations; this can lower overlap when one SSID uses multiple APs.",
            "PyWiFi exposes full-band scans, not reliable channel partitions. Multi-adapter parallelism is measured only if multiple adapters are actually present.",
            "A speed improvement is published only when both scanners find APs and mean paired BSSID Jaccard overlap is at least 0.5.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--old-rounds", type=int, default=1)
    parser.add_argument("--output", default="performance_benchmark.json")
    args = parser.parse_args()
    report = benchmark(args.runs, args.old_rounds)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
