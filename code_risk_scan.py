#!/usr/bin/env python3
"""
Novelty #2 - Real-Time CI/CD Integrated Security Detection (CLI entrypoint).

Runs the full multi-dimensional code risk engine against a path and
exits non-zero if the project risk score crosses a threshold, so it
can gate a CI/CD pipeline (PR checks, pre-merge, pre-deploy) instead
of only surfacing issues after deployment.

Usage:
    python code_risk_scan.py                          # scan cwd, threshold=70
    python code_risk_scan.py --path . --threshold 60
    python code_risk_scan.py --json report.json        # machine-readable output
    python code_risk_scan.py --prompt-file prompts.json  # Feature #3 correlation
    python code_risk_scan.py --fail-on high             # gate on severity instead of score

Exit codes:
    0  -> risk below threshold, pipeline may proceed
    1  -> risk at/above threshold, pipeline should fail
    2  -> scan itself errored
"""

import argparse
import json
import sys
import time

from code_risk_analyzer.engine import CodeRiskEngine

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def main():
    parser = argparse.ArgumentParser(description="CI/CD-integrated AI code risk scanner")
    parser.add_argument("--path", default=".", help="Project path to scan (default: cwd)")
    parser.add_argument("--threshold", type=float, default=70.0,
                         help="Fail the pipeline if the project composite score >= this value (0-100)")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], default=None,
                         help="Alternatively, fail if the project grade reaches this severity")
    parser.add_argument("--json", metavar="FILE", default=None,
                         help="Write the full JSON report to FILE")
    parser.add_argument("--prompt-file", metavar="FILE", default=None,
                         help="JSON file mapping relative file paths -> the prompt used to generate them")
    parser.add_argument("--db-path", default=None, help="Custom sqlite path (defaults to <path>/code_risk.db)")
    parser.add_argument("--quiet", action="store_true", help="Only print the final verdict line")
    args = parser.parse_args()

    prompt_map = None
    if args.prompt_file:
        try:
            with open(args.prompt_file, "r", encoding="utf-8") as f:
                prompt_map = json.load(f)
        except Exception as e:
            print(f"::error::Could not read --prompt-file {args.prompt_file}: {e}")
            return 2

    try:
        engine = CodeRiskEngine(args.path, db_path=args.db_path)
        result = engine.scan_project(prompt_map=prompt_map)
    except Exception as e:
        print(f"::error::Code risk scan failed: {e}")
        return 2

    pf = result["project_fingerprint"]
    prop = result["propagation"]

    if not args.quiet:
        print("=" * 64)
        print(" SentinelShield :: AI Code Risk Analyzer  (CI/CD mode)")
        print("=" * 64)
        print(f" Files scanned      : {pf['files_scanned']}")
        print(f" Total findings     : {result['total_findings']}")
        print(f" Composite score    : {pf['composite_score']} / 100  ({pf['grade'].upper()})")
        print(f"   structural       : {pf['dimensions']['structural']}")
        print(f"   behavioral       : {pf['dimensions']['behavioral']}")
        print(f"   dependency       : {pf['dimensions']['dependency']}")
        print(f"   contextual       : {pf['dimensions']['contextual']}")
        print(f" Propagation clusters: {prop['clusters']} (files affected: {prop['files_affected']})")
        if pf["worst_files"]:
            print("\n Worst files:")
            for w in pf["worst_files"][:5]:
                print(f"   - {w['file']:<50} {w['composite_score']:>6} {w['grade']}")
        print("=" * 64)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)
        if not args.quiet:
            print(f" Full report written to {args.json}")

    score_fail = pf["composite_score"] >= args.threshold
    severity_fail = args.fail_on is not None and SEVERITY_ORDER[pf["grade"]] >= SEVERITY_ORDER[args.fail_on]

    if score_fail or severity_fail:
        reason = f"score {pf['composite_score']} >= threshold {args.threshold}" if score_fail else \
                 f"grade {pf['grade']} reached --fail-on {args.fail_on}"
        print(f"\n❌ FAIL: {reason}. Blocking pipeline.")
        return 1

    print(f"\n✅ PASS: composite score {pf['composite_score']} below threshold {args.threshold}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
