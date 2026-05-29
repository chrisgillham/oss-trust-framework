"""Tests for Gate 8 — AI Hallucination Detection."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from oss_trust.ai_hallucination import AIHallucinationGate
from oss_trust.pipeline import Outcome

CFG = {
    "enabled": True,
    "hallucination_registry_url": "https://api.oss-trust.dev/hallucinations",
    "registry_cache_ttl_hours": 6,
    "similarity_threshold": 0.85,
    "new_package_age_days": 90,
    "min_download_count": 100,
    "on_confirmed_hallucination": "block",
    "on_suspected": "quarantine",
}


def _gate():
    return AIHallucinationGate(CFG)


@pytest.mark.asyncio
async def test_confirmed_hallucination_blocked():
    gate = _gate()
    with patch.object(gate, "_load_registry", AsyncMock(return_value=["react-moduel"])), \
         patch.object(gate, "_fetch_package_stats", AsyncMock(return_value=None)):
        r = await gate.evaluate("react-moduel", "1.0.0", "npm")
    assert r.outcome == Outcome.BLOCKED
    assert r.details["confirmed"] is True


@pytest.mark.asyncio
async def test_clean_popular_package_approved():
    gate = _gate()
    with patch.object(gate, "_load_registry", AsyncMock(return_value=[])), \
         patch.object(gate, "_fetch_package_stats", AsyncMock(return_value={
             "age_days": 1000, "total_downloads": 50_000_000
         })):
        r = await gate.evaluate("requests", "2.32.3", "pypi")
    assert r.outcome == Outcome.APPROVED
    assert r.details["hallucination_detected"] is False


@pytest.mark.asyncio
async def test_typosquat_similarity_quarantined():
    gate = _gate()
    # "reqeusts" is 94% similar to "requests"
    with patch.object(gate, "_load_registry", AsyncMock(return_value=[])), \
         patch.object(gate, "_fetch_package_stats", AsyncMock(return_value={
             "age_days": 10, "total_downloads": 5
         })):
        r = await gate.evaluate("reqeusts", "1.0.0", "pypi")
    # Should trigger similarity or age+download heuristic
    assert r.outcome in (Outcome.QUARANTINE, Outcome.BLOCKED)


@pytest.mark.asyncio
async def test_disabled_gate_approves():
    gate = AIHallucinationGate({**CFG, "enabled": False})
    r = await gate.evaluate("anything", "1.0.0", "npm")
    assert r.outcome == Outcome.APPROVED
    assert r.details["skipped"] is True


@pytest.mark.asyncio
async def test_registry_fetch_failure_does_not_crash():
    gate = _gate()
    with patch.object(gate, "_load_registry", AsyncMock(side_effect=Exception("network error"))), \
         patch.object(gate, "_fetch_package_stats", AsyncMock(return_value=None)):
        # Should not raise — registry failure → empty list → other checks still run
        try:
            r = await gate.evaluate("some-pkg", "1.0.0", "npm")
            assert r.outcome in (Outcome.APPROVED, Outcome.QUARANTINE, Outcome.BLOCKED)
        except Exception as e:
            pytest.fail(f"Gate raised unexpected exception: {e}")
