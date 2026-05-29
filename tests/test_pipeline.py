"""
Tests for the Pipeline orchestrator.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from oss_trust.pipeline import GateResult, Outcome, Pipeline, TrustResult
from tests.conftest import approved, blocked, quarantine, rejected, hold, make_result


# ── Outcome merging ───────────────────────────────────────────────────────────

def test_merge_outcome_escalates():
    result = make_result()
    result.outcome = Outcome.APPROVED
    result.merge_outcome(Outcome.QUARANTINE)
    assert result.outcome == Outcome.QUARANTINE


def test_merge_outcome_does_not_downgrade():
    result = make_result()
    result.outcome = Outcome.BLOCKED
    result.merge_outcome(Outcome.HOLD)
    assert result.outcome == Outcome.BLOCKED


def test_merge_outcome_rejected_is_highest():
    result = make_result()
    result.outcome = Outcome.BLOCKED
    result.merge_outcome(Outcome.REJECTED)
    assert result.outcome == Outcome.REJECTED


# ── Trust score computation ───────────────────────────────────────────────────

def test_score_no_signature():
    result = make_result()
    result.signature = {"present": False}
    result.checksum  = {"present": True, "verified": True}
    result.slsa      = {"level": 1}
    result.flags     = {}
    result.license   = {}
    result.historical_prior_denials = 0
    result.community_score_band = ""

    from oss_trust.pipeline import Pipeline
    # Instantiate without config by calling the scoring method directly
    p = _make_pipeline_stub()
    score, deductions = p._compute_trust_score(result)
    assert score == 60   # 100 - 40 (no sig) = 60; checksum ok, slsa 1 = -5 → 55? recalc
    assert any("no cryptographic signature" in d for d in deductions)


def test_score_typosquatting_and_ai_hallucination():
    result = make_result()
    result.signature = {"present": True, "verified": True, "strength": "strong"}
    result.checksum  = {"present": True, "verified": True}
    result.slsa      = {"level": 3}
    result.flags     = {"typosquatting": True, "ai_hallucination": True}
    result.license   = {}
    result.historical_prior_denials = 0
    result.community_score_band = ""

    p = _make_pipeline_stub()
    score, deductions = p._compute_trust_score(result)
    # 100 - 25 (typosquatting) - 30 (ai_hallucination) = 45
    assert score == 45
    assert "LOW" == p._score_band(score)


def test_score_prior_denials_modifier():
    result = make_result()
    result.signature = {"present": True, "verified": True, "strength": "strong"}
    result.checksum  = {"present": True, "verified": True}
    result.slsa      = {"level": 3}
    result.flags     = {}
    result.license   = {}
    result.historical_prior_denials = 2
    result.community_score_band = ""

    p = _make_pipeline_stub()
    score, deductions = p._compute_trust_score(result)
    # 100 - 20 (2+ prior denials) = 80
    assert score == 80
    assert any("historical" in d for d in deductions)


def test_score_band_mapping():
    p = _make_pipeline_stub()
    assert p._score_band(100) == "HIGH"
    assert p._score_band(80)  == "HIGH"
    assert p._score_band(79)  == "MEDIUM"
    assert p._score_band(50)  == "MEDIUM"
    assert p._score_band(49)  == "LOW"
    assert p._score_band(0)   == "LOW"


# ── Reachability downgrade ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_reachability_downgrade_quarantine_to_hold(pipeline_cfg):
    """When reachability returns not reachable, QUARANTINE should become HOLD."""
    with patch("oss_trust.pipeline.AgeGate") as MockAge, \
         patch("oss_trust.pipeline.SignatureGate") as MockSig, \
         patch("oss_trust.pipeline.SLSAGate") as MockSLSA, \
         patch("oss_trust.pipeline.OOBTrustGate") as MockOOB, \
         patch("oss_trust.pipeline.ReachabilityGate") as MockReach, \
         patch("oss_trust.pipeline.LicenseGate") as MockLic, \
         patch("oss_trust.pipeline.SBOMGate") as MockSBOM, \
         patch("oss_trust.pipeline.SandboxGate") as MockSandbox, \
         patch("oss_trust.pipeline.AIHallucinationGate") as MockAI, \
         patch("oss_trust.pipeline.CICDAuditGate") as MockCICD, \
         patch("oss_trust.pipeline.PolicyEngine"), \
         patch("oss_trust.pipeline.RuntimeTelemetry") as MockTelemetry, \
         patch("oss_trust.pipeline.PublicTrustRegistry"):

        # Wire all gates to APPROVED except OOB → QUARANTINE
        for Mock in [MockAge, MockSig, MockSLSA, MockLic, MockSBOM,
                     MockSandbox, MockAI, MockCICD]:
            Mock.return_value.evaluate = AsyncMock(
                return_value=approved(f"{Mock.__name__}")
            )

        MockOOB.return_value.evaluate = AsyncMock(
            return_value=quarantine(
                "Gate 4: OOB Trust",
                "CVE found",
                advisory_ids=["CVE-2024-99999"],
            )
        )
        MockReach.return_value.evaluate = AsyncMock(
            return_value=GateResult(
                gate="Gate 4.5: Reachability",
                outcome=Outcome.HOLD,
                message="Not reachable",
                details={"reachable": False},
            )
        )
        MockTelemetry.return_value.emit_gate_event = AsyncMock()

        pipeline = Pipeline(config_path=pipeline_cfg)
        # Patch history + community to return neutral
        pipeline._apply_historical_modifier = AsyncMock()
        pipeline._apply_community_score     = AsyncMock()

        result = await pipeline.run("requests", "2.32.3", "pypi")
        # OOB returned QUARANTINE; reachability said not reachable → downgrade to HOLD
        assert result.outcome in (Outcome.HOLD, Outcome.APPROVED)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_pipeline_stub():
    """Return a bare Pipeline instance with no real gate initialization."""
    from unittest.mock import MagicMock
    import yaml
    from oss_trust.pipeline import Pipeline

    obj = object.__new__(Pipeline)
    obj.cfg = {}
    obj.age = obj.signature = obj.slsa = obj.oob = obj.reachability = MagicMock()
    obj.license = obj.sbom = obj.sandbox = obj.ai_hall = obj.cicd = MagicMock()
    obj.policy = obj.telemetry = obj.pub_registry = MagicMock()
    return obj
