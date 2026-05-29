"""Tests for the Zero-Day Expedited Lane."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from oss_trust.zeroday import ZeroDayLane

CFG = {
    "required_approvers":   2,
    "token_ttl_hours":      6,
    "max_exceptions_per_24h": 3,
    "require_ticket":       False,
    "cve_sources_required": 2,
}


def _lane(tmp_path):
    import os
    # Point state file to tmp
    from oss_trust import zeroday as zd_mod
    zd_mod.STATE_PATH = tmp_path / "zeroday-state.json"
    return ZeroDayLane(CFG)


@pytest.mark.asyncio
async def test_exception_approved_when_cve_validated(tmp_path):
    lane = _lane(tmp_path)
    with patch.object(lane, "_validate_cve", AsyncMock(return_value={
        "valid": True,
        "confirmed_by": ["NVD", "OSV"],
    })):
        result = await lane.request_exception(
            "CVE-2024-12345", "requests", "2.32.4", "security@org.com"
        )
    assert result["approved"] is True
    assert result["token"] is not None
    assert "CVE-2024-12345" in result["cve_id"]


@pytest.mark.asyncio
async def test_exception_denied_when_cve_not_confirmed(tmp_path):
    lane = _lane(tmp_path)
    with patch.object(lane, "_validate_cve", AsyncMock(return_value={
        "valid": False,
        "confirmed_by": ["NVD"],   # Only 1 of 2 required
    })):
        result = await lane.request_exception(
            "CVE-2024-99999", "requests", "2.32.4", "security@org.com"
        )
    assert result["approved"] is False
    assert "not confirmed" in result["message"].lower()


@pytest.mark.asyncio
async def test_circuit_breaker_global_limit(tmp_path):
    lane = _lane(tmp_path)

    # Exhaust the 24h limit
    from datetime import datetime, timezone
    for _ in range(3):
        lane._state.setdefault("requests_24h", []).append({
            "requester": "someone@org.com",
            "issued_at": datetime.now(timezone.utc).isoformat(),
        })
    lane._save_state()

    with patch.object(lane, "_validate_cve", AsyncMock(return_value={
        "valid": True, "confirmed_by": ["NVD", "OSV"]
    })):
        result = await lane.request_exception(
            "CVE-2024-11111", "pkg", "1.0.0", "security@org.com"
        )
    assert result["approved"] is False
    assert "circuit breaker" in result["message"].lower()


@pytest.mark.asyncio
async def test_valid_token_accepted(tmp_path):
    lane = _lane(tmp_path)
    with patch.object(lane, "_validate_cve", AsyncMock(return_value={
        "valid": True, "confirmed_by": ["NVD", "OSV"],
    })):
        issued = await lane.request_exception(
            "CVE-2024-12345", "requests", "2.32.4", "s@org.com"
        )
    token = issued["token"]
    valid = await lane.validate_token(token, "requests")
    assert valid is True


@pytest.mark.asyncio
async def test_wrong_package_token_rejected(tmp_path):
    lane = _lane(tmp_path)
    with patch.object(lane, "_validate_cve", AsyncMock(return_value={
        "valid": True, "confirmed_by": ["NVD", "OSV"],
    })):
        issued = await lane.request_exception(
            "CVE-2024-12345", "requests", "2.32.4", "s@org.com"
        )
    token = issued["token"]
    valid = await lane.validate_token(token, "different-package")
    assert valid is False
