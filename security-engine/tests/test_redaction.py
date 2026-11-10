"""Tests for evidence/redact.py and its use in the BOLA check + pipeline."""

import json

import pytest

from checks.authorization.bola_check import BOLAOwnershipCheck
from checks.base import SecurityCheckContext
from evidence.collector import EvidenceCollector
from evidence.redact import build_response_dump, redact_body, redact_headers, redact_text
from execution.http_runner import ControlledHttpRunner
from safety.policy import SecuritySafetyPolicy
from verification.pipeline import verify_and_package
from verification.proof_engine import SelfChallengingProofEngine

SECRETS = ["SECRET-TOKEN-XYZ", "SECRET-COOKIE-123", "tokA", "tokB"]


def test_redact_headers_hides_credentials_only():
    out = redact_headers({"Set-Cookie": "sid=abc; Path=/", "X-Auth-Token": "t", "Content-Type": "application/json"})
    assert out["Set-Cookie"] == "[REDACTED]"
    assert out["X-Auth-Token"] == "[REDACTED]"
    assert out["Content-Type"] == "application/json"


def test_redact_body_json_keeps_business_data():
    out = json.loads(redact_body('{"id": 101, "destination": "Paris", "access_token": "abc", "nested": {"password": "p"}}'))
    assert out["destination"] == "Paris" and out["id"] == 101
    assert out["access_token"] == "[REDACTED]"
    assert out["nested"]["password"] == "[REDACTED]"


def test_redact_text_catches_bearer_jwt_and_pairs():
    text = "Authorization: Bearer abcdef123456\njwt=eyJhbGciOi.eyJzdWIiOiIx.sig api_key=XYZ123 ok=1"
    out = redact_text(text)
    assert "abcdef123456" not in out and "XYZ123" not in out and "eyJzdWIiOiIx" not in out
    assert "ok=1" in out


def test_build_response_dump_redacts_before_truncating():
    body = json.dumps({"pad": "x" * 1990, "access_token": "SECRET-TOKEN-XYZ"})
    dump = build_response_dump(200, {"Set-Cookie": "session=SECRET-COOKIE-123"}, body)
    assert "SECRET-TOKEN-XYZ" not in dump and "SECRET-COOKIE-123" not in dump


@pytest.mark.asyncio
async def test_leaky_endpoint_evidence_has_no_credentials(live_server):
    runner = ControlledHttpRunner(safety_policy=SecuritySafetyPolicy(allowed_hosts=["127.0.0.1", "localhost"]))
    ctx = SecurityCheckContext(
        test_id="redact-001", target_url=live_server, endpoint_path="/leaky/bookings/101", http_method="GET",
        auth_headers={"Authorization": "Bearer tokA"}, secondary_auth_headers={"Authorization": "Bearer tokB"},
    )
    result = await BOLAOwnershipCheck(runner=runner).run(ctx)
    assert result.is_vulnerable
    assert "Paris" in result.evidence_response  # business data (the proof) is kept

    package = await verify_and_package(result, ctx, SelfChallengingProofEngine(runner=runner), EvidenceCollector())
    assert package is not None
    blob = json.dumps(package.model_dump(), default=str) + result.evidence_request + result.evidence_response
    for secret in SECRETS:
        assert secret not in blob, f"{secret} leaked into evidence"


# ── CodeRabbit follow-ups ────────────────────────────────────────────────────

def test_quoted_value_with_spaces_fully_redacted_in_two_passes():
    text = 'Error body: "authToken": "alpha bravo charlie" trailing'
    once = redact_text(text)
    twice = redact_text(once)
    for out in (once, twice):
        assert "alpha" not in out and "bravo" not in out and "charlie" not in out
        assert "trailing" in out


def test_short_bearer_token_redacted():
    out = redact_text("Authorization: Bearer abc")
    assert "abc" not in out
    assert "abc" not in redact_text("see Bearer xy here")


def test_digest_authorization_fully_redacted():
    out = redact_text('Authorization: Digest username=x, response=abcdef123, nonce=zzz\nnext=line')
    assert "abcdef123" not in out and "nonce" not in out
    assert "next=line" in out
    assert "abcdef123" not in redact_text(out)


@pytest.mark.asyncio
async def test_engine_reports_safe_reason_when_baseline_unavailable(live_server):
    runner = ControlledHttpRunner(safety_policy=SecuritySafetyPolicy(allowed_hosts=["127.0.0.1", "localhost"]))
    engine = SelfChallengingProofEngine(runner=runner)
    base = {"attacker_headers": {"Authorization": "Bearer tokB"}, "baseline_body": ""}

    blocked = await engine.verify_finding("x", {**base, "attack_url": "http://example.com/x",
                                                "victim_headers": {"Authorization": "Bearer tokA"}})
    assert not blocked.is_confirmed and "safety policy" in blocked.counter_evidence

    denied = await engine.verify_finding("x", {**base, "attack_url": f"{live_server}/vuln/bookings/101",
                                               "victim_headers": {"Authorization": "Bearer wrong"}})
    assert not denied.is_confirmed and "HTTP 401" in denied.counter_evidence
    assert "wrong" not in denied.counter_evidence

    none = await engine.verify_finding("x", {**base, "attack_url": f"{live_server}/vuln/bookings/101"})
    assert not none.is_confirmed and "no owner credentials" in none.counter_evidence


def test_redaction_is_idempotent():
    text = 'Authorization: Bearer abc\n"authToken": "a b c" session=zzz'
    once = redact_text(text)
    assert redact_text(once) == once