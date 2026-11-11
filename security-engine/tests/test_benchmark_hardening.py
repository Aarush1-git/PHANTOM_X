"""Hardening tests for the benchmark harness (CodeRabbit follow-ups)."""

import json
import sys

import pytest

from benchmark.metrics import CaseResult, compute_metrics, evaluate_targets
from benchmark.report import write_report
from benchmark.runner import BenchmarkRun, RecordingRunner
from benchmark.security import enforce_https_for_credentials, is_loopback_host, sanitize_url
from safety.policy import SafetyViolationError, SecuritySafetyPolicy


def _res(case_id, gt, expected, observed, *, category="bola", raw=False):
    return CaseResult(
        case_id=case_id, category=category, scenario="control", ground_truth=gt,
        expected_outcome=expected, observed_outcome=observed, raw_flagged=raw, independent=None,
        requests_sent=1, requests_blocked=0, duration_ms=1.0, reason="",
    )


def test_error_on_secure_case_is_not_a_true_negative():
    results = [
        _res("A", "secure", "NOT_FLAGGED", "NOT_FLAGGED"),
        _res("B", "secure", "NOT_FLAGGED", "ERROR"),
        _res("C", "vulnerable", "CONFIRMED", "CONFIRMED", raw=True),
    ]
    m = compute_metrics(results, [])
    assert m["tn"] == 1                      # only the completed secure case
    assert m["error_cases"] == 1
    assert m["false_positive_rate"] == 0.0   # denominator excludes the errored case (1 completed secure)
    assert m["raw_tn"] == 1


def test_error_fails_the_no_execution_errors_target():
    ok = compute_metrics([_res("A", "secure", "NOT_FLAGGED", "NOT_FLAGGED")], [])
    bad = compute_metrics([_res("A", "secure", "NOT_FLAGGED", "ERROR")], [])
    def target(m):
        return next(t for t in evaluate_targets(m) if t["name"] == "no_execution_errors")
    assert target(ok)["passed"] is True
    assert target(bad)["passed"] is False and target(bad)["value"] == 1


def test_safety_match_requires_a_block_or_refusal():
    # a mis-specified safety case (expected == observed == NOT_FLAGGED) must not count as a successful block
    m = compute_metrics([_res("S", "n/a", "NOT_FLAGGED", "NOT_FLAGGED", category="safety")], [])
    assert m["safety_block_rate"] == 0.0
    ok = compute_metrics([_res("S", "n/a", "BLOCKED", "BLOCKED", category="safety")], [])
    assert ok["safety_block_rate"] == 1.0


def test_sanitize_url_strips_userinfo_query_fragment():
    assert sanitize_url("https://user:pw@host.example:8443/p/q?token=abc&x=1#frag") == "https://host.example:8443/p/q"
    assert sanitize_url("http://127.0.0.1:9000") == "http://127.0.0.1:9000"
    assert sanitize_url("not a url") == "[invalid-url]"


def test_write_report_never_contains_url_credentials(tmp_path):
    run = BenchmarkRun(
        results=[_res("A", "secure", "NOT_FLAGGED", "NOT_FLAGGED")],
        request_log=[],
        metadata={"base_url": "https://user:SECRETPW@host.example/api?token=SECRETTOK", "manifest_name": "t"},
    )
    metrics = compute_metrics(run.results, [])
    json_path, md_path = write_report(run, metrics, evaluate_targets(metrics), tmp_path)
    for p in (json_path, md_path):
        text = open(p, encoding="utf-8").read()
        assert "SECRETPW" not in text and "SECRETTOK" not in text
    assert "https://host.example/api" in open(md_path, encoding="utf-8").read()


@pytest.mark.parametrize("url,headers,allow,ok", [
    ("https://remote.example/x", {"Authorization": "Bearer t"}, False, True),
    ("http://remote.example/x", {"Authorization": "Bearer t"}, False, False),
    ("http://remote.example/x", None, False, True),
    ("http://127.0.0.1:8000/x", {"Authorization": "Bearer t"}, False, True),
    ("http://localhost:8000/x", {"Authorization": "Bearer t"}, False, True),
    ("http://[::1]:8000/x", {"Authorization": "Bearer t"}, False, True),
    ("http://127.0.0.2/x", {"Authorization": "Bearer t"}, False, True),
    ("http://remote.example/x", {"Authorization": "Bearer t"}, True, True),
])
def test_enforce_https_matrix(url, headers, allow, ok):
    if ok:
        enforce_https_for_credentials(url, headers, allow)
    else:
        with pytest.raises(SafetyViolationError):
            enforce_https_for_credentials(url, headers, allow)


def test_is_loopback_host():
    assert is_loopback_host("localhost") and is_loopback_host("127.0.0.1") and is_loopback_host("::1")
    assert not is_loopback_host("example.com") and not is_loopback_host("10.0.0.5")


@pytest.mark.asyncio
async def test_recording_runner_blocks_cleartext_credentials_without_network():
    policy = SecuritySafetyPolicy(allowed_hosts=["lab.invalid"])
    runner = RecordingRunner(safety_policy=policy)
    runner.current_case_id = "X"
    with pytest.raises(SafetyViolationError):
        await runner.execute_request("GET", "http://lab.invalid/x", headers={"Authorization": "Bearer t"})
    assert runner.request_log[-1]["blocked"] is True


def test_cli_refuses_remote_http_base_url(monkeypatch, capsys):
    from benchmark import run as cli
    monkeypatch.setattr(sys, "argv", ["benchmark.run", "--base-url", "http://remote.example:8000"])
    assert cli.main() == 2
    assert "cleartext" in capsys.readouterr().err.lower()