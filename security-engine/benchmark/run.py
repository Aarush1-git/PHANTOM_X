"""
CLI Entrypoint for the PHANTOM-X Security Benchmark Harness.

Usage:
    python -m benchmark.run [--manifest PATH] [--base-url URL] [--out DIR]
                            [--rps N] [--replays N] [--skip-stateful] [--fail-on-targets]
                            [--allow-insecure-http]
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

# Ensure security-engine and repo root are in sys.path
_current_file = Path(__file__).resolve()
_security_engine_dir = _current_file.parent.parent
_repo_root = _security_engine_dir.parent

if str(_security_engine_dir) not in sys.path:
    sys.path.insert(0, str(_security_engine_dir))
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from benchmark.metrics import compute_metrics, evaluate_targets, PROPOSED_TARGETS_DISCLAIMER
from benchmark.report import write_report
from benchmark.runner import run_benchmark
from benchmark.schema import load_manifest
from benchmark.security import is_loopback_host
from benchmark.server import start_mock_server


def _fmt_pct(val: float | None) -> str:
    return f"{val * 100:.1f}%" if val is not None else "n/a"


def main() -> int:
    default_manifest = _security_engine_dir / "benchmark" / "ground_truth" / "phantom_mock_v1.json"
    default_out = _security_engine_dir / "benchmark_results" / "latest"

    parser = argparse.ArgumentParser(
        description="PHANTOM-X Security Benchmark and Ground-Truth Evaluation"
    )
    parser.add_argument(
        "--manifest",
        type=str,
        default=str(default_manifest),
        help=f"Path to benchmark manifest JSON (default: {default_manifest})",
    )
    parser.add_argument(
        "--base-url",
        type=str,
        default=None,
        help="Optional external target base URL (skips internal mock server)",
    )
    parser.add_argument(
        "--out",
        type=str,
        default=str(default_out),
        help=f"Output directory for report and results.json (default: {default_out})",
    )
    parser.add_argument(
        "--rps",
        type=int,
        default=50,
        help="Rate limit (requests/sec) for central safety policy (default: 50)",
    )
    parser.add_argument(
        "--replays",
        type=int,
        default=3,
        help="Verification replay count for proof engine (default: 3)",
    )
    parser.add_argument(
        "--skip-stateful",
        action="store_true",
        help="Skip stateful/intermittent test cases",
    )
    parser.add_argument(
        "--allow-insecure-http",
        action="store_true",
        help="Allow sending credentials over cleartext HTTP to a NON-loopback host. "
             "Only for isolated lab networks (e.g. docker compose); default is to refuse.",
    )
    parser.add_argument(
        "--fail-on-targets",
        action="store_true",
        help="Exit with non-zero code if any proposed target fails",
    )

    args = parser.parse_args()

    manifest_path = Path(args.manifest).resolve()
    manifest, manifest_sha256 = load_manifest(manifest_path)

    base_url = args.base_url
    stop_fn = None
    reset_fn = None

    if base_url:
        from urllib.parse import urlparse
        _p = urlparse(base_url)
        if (_p.scheme.lower() != "https" and not is_loopback_host(_p.hostname or "")
                and not args.allow_insecure_http):
            print(
                "[ERROR] Refusing to send credentials over cleartext HTTP to a non-loopback host. "
                "Use an https:// --base-url, or pass --allow-insecure-http for an isolated lab network.",
                file=sys.stderr,
            )
            return 2
        print("[WARNING] External --base-url specified. Stateful cases may be unreliable without counter resets.")
    else:
        print("[INFO] Starting internal mock server on 127.0.0.1...")
        base_url, stop_fn, reset_fn = start_mock_server()
        print(f"[INFO] Mock application active at: {base_url}")

    try:
        run = asyncio.run(run_benchmark(
            manifest=manifest,
            base_url=base_url,
            rps=args.rps,
            replays=args.replays,
            reset=reset_fn,
            skip_stateful=args.skip_stateful,
            manifest_sha256=manifest_sha256,
            allow_insecure_http=args.allow_insecure_http,
        ))
    finally:
        if stop_fn is not None:
            stop_fn()
            print("[INFO] Mock application server stopped.")

    metrics = compute_metrics(
        results=run.results,
        request_log=run.request_log,
        plan_scenarios=manifest.plan_scenarios,
    )
    targets = evaluate_targets(metrics)

    out_dir = Path(args.out).resolve()
    results_json, report_md = write_report(run, metrics, targets, out_dir)

    # Print compact console summary
    print("\n" + "=" * 62)
    print("                 PHANTOM-X BENCHMARK SUMMARY")
    print("=" * 62)
    print(f"Total Cases:         {len(run.results)} (Accuracy: {_fmt_pct(metrics.get('outcome_accuracy'))})")
    print(f"Precision:           {_fmt_pct(metrics.get('precision'))} (Verified) | {_fmt_pct(metrics.get('raw_precision'))} (Raw)")
    print(f"Recall (Auto):       {_fmt_pct(metrics.get('recall_auto_confirmed'))} ({metrics.get('tp', 0)} confirmed)")
    print(f"Recall (+Review):    {_fmt_pct(metrics.get('recall_incl_human_review'))}")
    print(f"False Positive Rate: {_fmt_pct(metrics.get('false_positive_rate'))} (FP: {metrics.get('fp', 0)}) | Engine Removed: {metrics.get('false_positives_removed_by_proof_engine', 0)} FP")
    print(f"Safety Block Rate:   {_fmt_pct(metrics.get('safety_block_rate'))}")
    print(f"Safety Compliance:   {_fmt_pct(metrics.get('safety_compliance'))}")
    print(f"Execution Errors:    {metrics.get('error_cases', 0)}")
    print(f"Total HTTP Requests: {metrics.get('total_requests', 0)} across {metrics.get('total_duration_ms', 0):.0f} ms")
    print("-" * 62)
    print("Proposed Engineering Targets:")
    all_targets_passed = True
    for t in targets:
        badge = "PASS" if t["passed"] else "FAIL"
        if not t["passed"]:
            all_targets_passed = False
        print(f"  [{badge}] {t['name']}: {t['value']} ({t['target_text']})")
    print(f"Note: {PROPOSED_TARGETS_DISCLAIMER}")
    print("-" * 62)
    print(f"Report:   {report_md}")
    print(f"Results:  {results_json}")
    print("=" * 62 + "\n")

    if args.fail_on_targets and not all_targets_passed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())