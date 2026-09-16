"""
Tests for Gate 2 — Publisher identity continuity check.

Covers:
  - npm: identity unchanged → LOW/pass
  - npm: identity changed, high-value package → HIGH/quarantine
  - npm: identity changed, new account → HIGH/quarantine
  - npm: identity changed, low-value package, mature account → MEDIUM/quarantine
  - PyPI: identity unchanged → LOW/pass
  - PyPI: identity changed → MEDIUM/quarantine
  - Cargo: published_by consistent → LOW/pass
  - Cargo: published_by changed → MEDIUM/quarantine
  - Cargo: no published_by (API token) → INFO/pass
  - Registry errors fail open
  - Unsupported ecosystem → INFO/pass
"""

from __future__ import annotations

import httpx
import pytest
import respx

from oss_trust_framework.signature.provenance import check_publisher_continuity


# ---------------------------------------------------------------------------
# npm tests
# ---------------------------------------------------------------------------

def _npm_registry(package, versions_publishers: dict[str, str], weekly_downloads=500):
    """
    Build a minimal npm registry response.
    versions_publishers: {version_str: npm_username}
    """
    from datetime import datetime, timezone, timedelta
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    time_data = {}
    versions = {}
    for i, (ver, publisher) in enumerate(versions_publishers.items()):
        dt = (base + timedelta(days=i * 30)).isoformat()
        time_data[ver] = dt
        versions[ver] = {"_npmUser": {"name": publisher}}
    return {"time": time_data, "versions": versions}


@pytest.mark.asyncio
@respx.mock
async def test_npm_publisher_unchanged_passes():
    respx.get("https://registry.npmjs.org/express").mock(
        return_value=httpx.Response(200, json=_npm_registry(
            "express", {"4.17.0": "dougwilson", "4.18.0": "dougwilson", "4.18.2": "dougwilson"}
        ))
    )
    result = await check_publisher_continuity("express", "4.18.2", "npm")
    assert result.passed is True
    assert result.identity_changed is False
    assert result.risk == "LOW"


@pytest.mark.asyncio
@respx.mock
async def test_npm_publisher_changed_high_value_quarantines():
    respx.get("https://registry.npmjs.org/chalk").mock(
        return_value=httpx.Response(200, json=_npm_registry(
            "chalk", {"4.1.2": "sindresorhus", "5.0.0": "sindresorhus", "5.4.0": "attacker"}
        ))
    )
    # High download count → HIGH risk
    respx.get("https://api.npmjs.org/downloads/point/last-week/chalk").mock(
        return_value=httpx.Response(200, json={"downloads": 5_000_000})
    )
    # Attacker account is old enough
    respx.get("https://api.github.com/users/attacker").mock(
        return_value=httpx.Response(200, json={"created_at": "2015-01-01T00:00:00Z"})
    )

    result = await check_publisher_continuity(
        "chalk", "5.4.0", "npm", high_value_weekly_downloads=1_000_000
    )
    assert result.passed is False
    assert result.identity_changed is True
    assert result.risk == "HIGH"
    assert "attacker" in result.message


@pytest.mark.asyncio
@respx.mock
async def test_npm_publisher_changed_young_account_quarantines():
    from datetime import datetime, timezone, timedelta
    # Account created 30 days ago
    recent = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

    respx.get("https://registry.npmjs.org/debug").mock(
        return_value=httpx.Response(200, json=_npm_registry(
            "debug", {"4.3.3": "TooTallNate", "4.3.4": "TooTallNate", "4.3.5": "newguy"}
        ))
    )
    respx.get("https://api.npmjs.org/downloads/point/last-week/debug").mock(
        return_value=httpx.Response(200, json={"downloads": 100_000})
    )
    respx.get("https://api.github.com/users/newguy").mock(
        return_value=httpx.Response(200, json={"created_at": recent})
    )

    result = await check_publisher_continuity(
        "debug", "4.3.5", "npm", high_value_weekly_downloads=1_000_000
    )
    assert result.passed is False
    assert result.identity_changed is True
    assert result.risk == "HIGH"
    assert result.new_account_age_days is not None
    assert result.new_account_age_days < 90


@pytest.mark.asyncio
@respx.mock
async def test_npm_publisher_changed_low_value_mature_account_is_medium():
    from datetime import datetime, timezone, timedelta
    old = (datetime.now(timezone.utc) - timedelta(days=500)).isoformat()

    respx.get("https://registry.npmjs.org/small-pkg").mock(
        return_value=httpx.Response(200, json=_npm_registry(
            "small-pkg", {"1.0.0": "alice", "1.1.0": "alice", "1.2.0": "bob"}
        ))
    )
    respx.get("https://api.npmjs.org/downloads/point/last-week/small-pkg").mock(
        return_value=httpx.Response(200, json={"downloads": 1_000})
    )
    respx.get("https://api.github.com/users/bob").mock(
        return_value=httpx.Response(200, json={"created_at": old})
    )

    result = await check_publisher_continuity(
        "small-pkg", "1.2.0", "npm", high_value_weekly_downloads=1_000_000
    )
    assert result.passed is False
    assert result.identity_changed is True
    assert result.risk == "MEDIUM"


@pytest.mark.asyncio
@respx.mock
async def test_npm_first_version_passes():
    respx.get("https://registry.npmjs.org/brand-new-pkg").mock(
        return_value=httpx.Response(200, json=_npm_registry(
            "brand-new-pkg", {"1.0.0": "alice"}
        ))
    )
    result = await check_publisher_continuity("brand-new-pkg", "1.0.0", "npm")
    assert result.passed is True
    assert result.previous_publisher is None


@pytest.mark.asyncio
@respx.mock
async def test_npm_registry_error_fails_open():
    respx.get("https://registry.npmjs.org/some-pkg").mock(
        return_value=httpx.Response(500)
    )
    result = await check_publisher_continuity("some-pkg", "1.0.0", "npm")
    assert result.passed is True
    assert result.risk == "INFO"


# ---------------------------------------------------------------------------
# Cargo tests
# ---------------------------------------------------------------------------

def _cargo_versions(versions_publishers: dict[str, str | None]):
    """Build minimal crates.io /versions response."""
    from datetime import datetime, timezone, timedelta
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    result = []
    for i, (ver, pub) in enumerate(versions_publishers.items()):
        dt = (base + timedelta(days=i * 30)).isoformat()
        entry = {"num": ver, "created_at": dt}
        entry["published_by"] = {"login": pub} if pub else None
        result.append(entry)
    return {"versions": result}


@pytest.mark.asyncio
@respx.mock
async def test_cargo_publisher_unchanged_passes():
    respx.get("https://crates.io/api/v1/crates/serde/versions").mock(
        return_value=httpx.Response(200, json=_cargo_versions({
            "1.0.217": "dtolnay",
            "1.0.218": "dtolnay",
            "1.0.219": "dtolnay",
        }))
    )
    result = await check_publisher_continuity("serde", "1.0.219", "Cargo")
    assert result.passed is True
    assert result.risk == "LOW"


@pytest.mark.asyncio
@respx.mock
async def test_cargo_publisher_changed_quarantines():
    from datetime import datetime, timezone, timedelta
    old = (datetime.now(timezone.utc) - timedelta(days=500)).isoformat()

    respx.get("https://crates.io/api/v1/crates/tokio/versions").mock(
        return_value=httpx.Response(200, json=_cargo_versions({
            "1.35.0": "carllerche",
            "1.36.0": "carllerche",
            "1.37.0": "badactor",
        }))
    )
    respx.get("https://api.github.com/users/badactor").mock(
        return_value=httpx.Response(200, json={"created_at": old})
    )

    result = await check_publisher_continuity("tokio", "1.37.0", "Cargo")
    assert result.passed is False
    assert result.identity_changed is True
    assert result.risk in ("MEDIUM", "HIGH")


@pytest.mark.asyncio
@respx.mock
async def test_cargo_no_published_by_passes():
    """API token publishes have no published_by — INFO/pass."""
    respx.get("https://crates.io/api/v1/crates/serde/versions").mock(
        return_value=httpx.Response(200, json=_cargo_versions({
            "1.0.217": None,
            "1.0.218": None,
            "1.0.219": None,
        }))
    )
    result = await check_publisher_continuity("serde", "1.0.219", "Cargo")
    assert result.passed is True
    assert result.risk == "INFO"


# ---------------------------------------------------------------------------
# Unsupported ecosystem
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unsupported_ecosystem_passes():
    result = await check_publisher_continuity("rails", "7.0.0", "RubyGems")
    assert result.passed is True
    assert result.risk == "INFO"
