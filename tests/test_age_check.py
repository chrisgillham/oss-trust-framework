"""Tests for Gate 1 — Age Check."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from oss_trust.age_check import AgeGate
from oss_trust.pipeline import Outcome


CFG_DEFAULT = {"hard_block_hours": 24, "hold_hours": 72}


def _gate(cfg=None):
    return AgeGate(cfg or CFG_DEFAULT)


@pytest.mark.asyncio
async def test_age_blocks_new_package():
    gate = _gate()
    now  = datetime.now(timezone.utc)
    recent = now - timedelta(hours=6)

    with patch.object(gate, "_fetch_publish_time", AsyncMock(return_value=recent)):
        result = await gate.evaluate("newpkg", "1.0.0", "pypi")

    assert result.outcome == Outcome.BLOCKED
    assert "6.0h" in result.message or "6" in result.message


@pytest.mark.asyncio
async def test_age_holds_within_window():
    gate = _gate()
    now  = datetime.now(timezone.utc)
    mid_window = now - timedelta(hours=48)

    with patch.object(gate, "_fetch_publish_time", AsyncMock(return_value=mid_window)):
        result = await gate.evaluate("pkg", "1.0.0", "pypi")

    assert result.outcome == Outcome.HOLD


@pytest.mark.asyncio
async def test_age_approves_old_package():
    gate = _gate()
    now  = datetime.now(timezone.utc)
    old  = now - timedelta(hours=200)

    with patch.object(gate, "_fetch_publish_time", AsyncMock(return_value=old)):
        result = await gate.evaluate("pkg", "1.0.0", "pypi")

    assert result.outcome == Outcome.APPROVED


@pytest.mark.asyncio
async def test_age_holds_on_fetch_error():
    gate = _gate()

    with patch.object(gate, "_fetch_publish_time", AsyncMock(side_effect=Exception("timeout"))):
        result = await gate.evaluate("pkg", "1.0.0", "pypi")

    assert result.outcome == Outcome.HOLD
    assert "unavailable" in result.message.lower()
