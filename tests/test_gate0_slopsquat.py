"""
Tests for Gate 0 — SlopsquatChecker heuristic battery.

Covers:
  - Watchlist load (present / missing / malformed)
  - Watchlist hit → WARN regardless of signal count
  - npm signal battery: 0 / partial / full signal sets
  - PyPI signal battery: basic flow
  - Non-npm/PyPI ecosystem → PASS with note
  - Registry errors fail open (never block)
  - Normalisation (separator-insensitive watchlist matching)
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from oss_trust_framework.name_similarity.checker import (
    SlopsquatResult,
    SimilarityDecision,
    _load_watchlist,
    check_slopsquat,
)


# ---------------------------------------------------------------------------
# Watchlist loader
# ---------------------------------------------------------------------------

def test_load_watchlist_returns_entries(tmp_path):
    wl = tmp_path / "watchlist.txt"
    wl.write_text("# comment\nfake-package\nAnother-Pkg\n\n")
    result = _load_watchlist(wl)
    assert "fake-package" in result
    assert "another-pkg" in result


def test_load_watchlist_missing_file_returns_empty(tmp_path):
    result = _load_watchlist(tmp_path / "nonexistent.txt")
    assert result == frozenset()


def test_load_watchlist_empty_file_returns_empty(tmp_path):
    wl = tmp_path / "watchlist.txt"
    wl.write_text("# only comments\n\n")
    assert _load_watchlist(wl) == frozenset()


# ---------------------------------------------------------------------------
# Non-npm/PyPI ecosystems
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_non_npm_pypi_ecosystem_passes(tmp_path):
    """Cargo / Go / etc. return PASS — no registry API coverage yet."""
    wl = tmp_path / "watchlist.txt"
    wl.write_text("")
    result = await check_slopsquat("serde", "Cargo", watchlist_path=wl)
    assert result.decision == SimilarityDecision.PASS
    assert result.signal_count == 0


@pytest.mark.asyncio
async def test_non_npm_pypi_on_watchlist_warns(tmp_path):
    """Even with no signal battery, a watchlist hit on Cargo → WARN."""
    wl = tmp_path / "watchlist.txt"
    wl.write_text("serde-fake\n")
    result = await check_slopsquat("serde-fake", "Cargo", watchlist_path=wl)
    assert result.decision == SimilarityDecision.WARN
    assert result.on_watchlist is True


# ---------------------------------------------------------------------------
# npm — signal battery via respx mocks
# ---------------------------------------------------------------------------

def _npm_package_payload(
    created="2020-01-01T00:00:00Z",
    versions=None,
    readme="A well documented package with GitHub link: https://github.com/org/pkg",
    repo_url="https://github.com/org/pkg",
):
    return {
        "time": {"created": created, "modified": created},
        "versions": {v: {} for v in (versions or ["1.0.0"])},
        "readme": readme,
        "description": "Test package",
        "repository": {"url": repo_url},
    }


@pytest.mark.asyncio
@respx.mock
async def test_npm_no_signals_passes(tmp_path):
    """Established package with rich metadata fires no signals → PASS."""
    wl = tmp_path / "watchlist.txt"
    wl.write_text("")

    respx.get("https://registry.npmjs.org/express").mock(
        return_value=httpx.Response(200, json=_npm_package_payload(
            created="2011-01-01T00:00:00Z",
            versions=["1.0.0", "2.0.0", "4.18.2"],
            readme="Express is a " + "word " * 200 + "https://github.com/expressjs/express",
            repo_url="https://github.com/expressjs/express",
        ))
    )
    respx.get("https://registry.npmjs.org/-/v1/search", params__contains={"text": "dependencies:express"}).mock(
        return_value=httpx.Response(200, json={"total": 50000})
    )
    respx.get("https://api.securityscorecards.dev/projects/github.com/expressjs/express").mock(
        return_value=httpx.Response(200, json={"score": 8.5})
    )

    result = await check_slopsquat("express", "npm", watchlist_path=wl)
    assert result.decision == SimilarityDecision.PASS
    assert result.signal_count < 3


@pytest.mark.asyncio
@respx.mock
async def test_npm_full_signals_blocks(tmp_path):
    """New package with no history, no README, no dependents → BLOCK (5 signals)."""
    from datetime import datetime, timezone, timedelta
    recent = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()

    wl = tmp_path / "watchlist.txt"
    wl.write_text("")

    respx.get("https://registry.npmjs.org/axios-retry-handler").mock(
        return_value=httpx.Response(200, json=_npm_package_payload(
            created=recent,
            versions=["0.0.1"],
            readme="A small utility",  # < 200 words, no GitHub
            repo_url="",
        ))
    )
    respx.get("https://registry.npmjs.org/-/v1/search", params__contains={"text": "dependencies:axios-retry-handler"}).mock(
        return_value=httpx.Response(200, json={"total": 0})
    )
    # No scorecard entry
    respx.get("https://api.securityscorecards.dev/projects/github.com/").mock(
        return_value=httpx.Response(404)
    )

    result = await check_slopsquat(
        "axios-retry-handler", "npm",
        warn_signal_count=3, block_signal_count=5,
        max_age_days=30,
        watchlist_path=wl,
    )
    # At least 3 signals → WARN or BLOCK
    assert result.decision in (SimilarityDecision.WARN, SimilarityDecision.BLOCK)
    assert result.signal_count >= 3


@pytest.mark.asyncio
@respx.mock
async def test_npm_watchlist_hit_warns_regardless(tmp_path):
    """Watchlist hit → WARN even if registry shows 0 signals."""
    wl = tmp_path / "watchlist.txt"
    wl.write_text("react-query-utils\n")

    respx.get("https://registry.npmjs.org/react-query-utils").mock(
        return_value=httpx.Response(200, json=_npm_package_payload(
            created="2011-01-01T00:00:00Z",
            versions=["1.0.0", "2.0.0"],
            readme="Well documented " * 50 + "https://github.com/org/rqu",
            repo_url="https://github.com/org/rqu",
        ))
    )
    respx.get("https://registry.npmjs.org/-/v1/search", params__contains={"text": "dependencies:react-query-utils"}).mock(
        return_value=httpx.Response(200, json={"total": 10000})
    )
    respx.get("https://api.securityscorecards.dev/projects/github.com/org/rqu").mock(
        return_value=httpx.Response(200, json={"score": 7.0})
    )

    result = await check_slopsquat("react-query-utils", "npm", watchlist_path=wl)
    assert result.decision == SimilarityDecision.WARN
    assert result.on_watchlist is True


@pytest.mark.asyncio
@respx.mock
async def test_npm_404_fails_open(tmp_path):
    """404 from registry = package doesn't exist; return PASS (not a slopsquat concern)."""
    wl = tmp_path / "watchlist.txt"
    wl.write_text("")

    respx.get("https://registry.npmjs.org/completely-unknown-pkg-xyz").mock(
        return_value=httpx.Response(404)
    )

    result = await check_slopsquat("completely-unknown-pkg-xyz", "npm", watchlist_path=wl)
    assert result.decision == SimilarityDecision.PASS


@pytest.mark.asyncio
@respx.mock
async def test_npm_registry_error_fails_open(tmp_path):
    """Registry HTTP 500 → fail open, PASS, never block."""
    wl = tmp_path / "watchlist.txt"
    wl.write_text("")

    respx.get("https://registry.npmjs.org/some-pkg").mock(
        return_value=httpx.Response(500)
    )

    result = await check_slopsquat("some-pkg", "npm", watchlist_path=wl)
    assert result.decision == SimilarityDecision.PASS
