"""Tests for Gate 1 — release age validation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest
import respx
import httpx

from oss_trust_framework.age_check.checker import (
    AgeDecision,
    check_release_age,
)

NOW = datetime.now(timezone.utc)


def _pypi_response(release_time: datetime) -> dict:
    return {
        "urls": [
            {"upload_time_iso_8601": release_time.isoformat().replace("+00:00", "Z")}
        ]
    }


@pytest.mark.asyncio
@respx.mock
async def test_age_gate_blocks_new_release():
    """Releases < 24 h old must be blocked."""
    release_time = NOW - timedelta(hours=12)
    respx.get("https://pypi.org/pypi/requests/2.32.3/json").mock(
        return_value=httpx.Response(200, json=_pypi_response(release_time))
    )

    async with httpx.AsyncClient() as client:
        result = await check_release_age("requests", "2.32.3", "PyPI", http_client=client)

    assert result.decision == AgeDecision.BLOCK
    assert result.age_hours < 24


@pytest.mark.asyncio
@respx.mock
async def test_age_gate_holds_24_to_72h_release():
    """Releases 24–72 h old must enter the hold state."""
    release_time = NOW - timedelta(hours=36)
    respx.get("https://pypi.org/pypi/requests/2.32.3/json").mock(
        return_value=httpx.Response(200, json=_pypi_response(release_time))
    )

    async with httpx.AsyncClient() as client:
        result = await check_release_age("requests", "2.32.3", "PyPI", http_client=client)

    assert result.decision == AgeDecision.HOLD
    assert 24 <= result.age_hours < 72


@pytest.mark.asyncio
@respx.mock
async def test_age_gate_passes_old_release():
    """Releases > 72 h old must pass the age gate."""
    release_time = NOW - timedelta(hours=120)
    respx.get("https://pypi.org/pypi/requests/2.32.3/json").mock(
        return_value=httpx.Response(200, json=_pypi_response(release_time))
    )

    async with httpx.AsyncClient() as client:
        result = await check_release_age("requests", "2.32.3", "PyPI", http_client=client)

    assert result.decision == AgeDecision.PASS
    assert result.age_hours >= 72


@pytest.mark.asyncio
@respx.mock
async def test_custom_thresholds():
    """Custom hard_block and hold thresholds must be respected."""
    release_time = NOW - timedelta(hours=6)
    respx.get("https://pypi.org/pypi/requests/2.32.3/json").mock(
        return_value=httpx.Response(200, json=_pypi_response(release_time))
    )

    async with httpx.AsyncClient() as client:
        result = await check_release_age(
            "requests", "2.32.3", "PyPI",
            hard_block_hours=4, hold_hours=12,
            http_client=client,
        )

    assert result.decision == AgeDecision.HOLD  # 6h is between 4 and 12


@pytest.mark.asyncio
@respx.mock
async def test_registry_error_raises():
    """A registry API error must propagate as an exception."""
    respx.get("https://pypi.org/pypi/requests/2.32.3/json").mock(
        return_value=httpx.Response(404)
    )

    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await check_release_age("requests", "2.32.3", "PyPI", http_client=client)
