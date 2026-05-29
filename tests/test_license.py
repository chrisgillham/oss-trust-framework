"""Tests for Gate 5 — License Compliance."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from oss_trust.license import LicenseGate
from oss_trust.pipeline import Outcome

CFG = {
    "allowlist": ["MIT", "Apache-2.0", "BSD-2-Clause", "ISC"],
    "block_copyleft": True,
    "block_commercial_restrict": True,
    "on_unlicensed": "block",
    "on_allowlist_violation": "quarantine",
    "warn_on_change": True,
}


def _gate():
    return LicenseGate(CFG)


@pytest.mark.asyncio
async def test_approved_mit():
    gate = _gate()
    with patch.object(gate, "_fetch_licenses", AsyncMock(return_value=("MIT", "MIT"))):
        r = await gate.evaluate("pkg", "2.0.0", "pypi")
    assert r.outcome == Outcome.APPROVED


@pytest.mark.asyncio
async def test_blocked_gpl():
    gate = _gate()
    with patch.object(gate, "_fetch_licenses", AsyncMock(return_value=("GPL-3.0", "MIT"))):
        r = await gate.evaluate("pkg", "2.0.0", "pypi")
    assert r.outcome == Outcome.BLOCKED
    assert "copyleft" in r.message.lower()


@pytest.mark.asyncio
async def test_blocked_unlicensed():
    gate = _gate()
    with patch.object(gate, "_fetch_licenses", AsyncMock(return_value=("UNKNOWN", ""))):
        r = await gate.evaluate("pkg", "2.0.0", "pypi")
    assert r.outcome == Outcome.BLOCKED


@pytest.mark.asyncio
async def test_hold_on_license_change():
    gate = _gate()
    # MIT → Apache-2.0: both on allowlist but changed
    with patch.object(gate, "_fetch_licenses", AsyncMock(return_value=("Apache-2.0", "MIT"))):
        r = await gate.evaluate("pkg", "2.0.0", "pypi")
    assert r.outcome == Outcome.HOLD
    assert r.details["license_changed"] is True


@pytest.mark.asyncio
async def test_quarantine_non_allowlist():
    gate = _gate()
    with patch.object(gate, "_fetch_licenses", AsyncMock(return_value=("OSL-3.0", "OSL-3.0"))):
        r = await gate.evaluate("pkg", "2.0.0", "pypi")
    # OSL-3.0 not in allowlist but is copyleft — blocked
    assert r.outcome == Outcome.BLOCKED


@pytest.mark.asyncio
async def test_commercial_restriction_blocked():
    gate = _gate()
    with patch.object(gate, "_fetch_licenses", AsyncMock(return_value=("SSPL-1.0", "MIT"))):
        r = await gate.evaluate("pkg", "2.0.0", "pypi")
    assert r.outcome == Outcome.BLOCKED
    assert "commercial" in r.message.lower()
