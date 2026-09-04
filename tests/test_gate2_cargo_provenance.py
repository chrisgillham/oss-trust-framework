"""
Tests for Gate 2 -- Cargo (crates.io) provenance via Trusted Publishing.

Covers:
  - Repo match on valid trustpub_data      -> PASS / LOW
  - Repo mismatch on valid trustpub_data   -> BLOCK / CRITICAL (Miasma pattern)
  - Missing trustpub_data, not required    -> PASS / INFO
  - Missing trustpub_data, required        -> HOLD / HIGH
  - Registry lookup failure                -> PASS / INFO (fail open, never block)
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import httpx
import pytest
import respx

from oss_trust_framework.signature.provenance import verify_provenance_attestation

CRATES_BASE = "https://crates.io/api/v1/crates"


def _version_payload(trustpub_data=None):
    return {
        "version": {
            "crate": "example-crate",
            "num": "1.2.3",
            "repository": "https://github.com/some-org/example-crate",
            "trustpub_data": trustpub_data,
        }
    }


@pytest.mark.asyncio
@respx.mock
async def test_cargo_trustpub_repo_match_passes():
    """trustpub_data.repository matching the allowlist -> LOW risk, passed."""
    respx.get(f"{CRATES_BASE}/example-crate/1.2.3").mock(
        return_value=httpx.Response(
            200,
            json=_version_payload({
                "provider": "github",
                "repository": "some-org/example-crate",
                "run_id": "123456",
                "sha": "deadbeef",
            }),
        )
    )

    result = await verify_provenance_attestation(
        package="example-crate",
        version="1.2.3",
        ecosystem="Cargo",
        trusted_publishers={"example-crate": "some-org/example-crate"},
    )

    assert result.passed is True
    assert result.attestation_found is True
    assert result.repo_match is True
    assert result.risk == "LOW"
    assert result.source_repo == "some-org/example-crate"


@pytest.mark.asyncio
@respx.mock
async def test_cargo_trustpub_repo_mismatch_blocks():
    """trustpub_data.repository pointing at an unexpected repo -> CRITICAL block."""
    respx.get(f"{CRATES_BASE}/example-crate/1.2.3").mock(
        return_value=httpx.Response(
            200,
            json=_version_payload({
                "provider": "github",
                "repository": "attacker-fork/example-crate",
                "run_id": "999999",
                "sha": "cafebabe",
            }),
        )
    )

    result = await verify_provenance_attestation(
        package="example-crate",
        version="1.2.3",
        ecosystem="Cargo",
        trusted_publishers={"example-crate": "some-org/example-crate"},
    )

    assert result.passed is False
    assert result.repo_match is False
    assert result.risk == "CRITICAL"
    assert "Miasma" in result.message


@pytest.mark.asyncio
@respx.mock
async def test_cargo_no_trustpub_not_required_passes():
    """No trustpub_data (long-lived token) and not in require_attestation -> INFO/pass."""
    respx.get(f"{CRATES_BASE}/example-crate/1.2.3").mock(
        return_value=httpx.Response(200, json=_version_payload(None))
    )

    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = await verify_provenance_attestation(
            package="example-crate",
            version="1.2.3",
            ecosystem="Cargo",
            trusted_publishers={"example-crate": "some-org/example-crate"},
        )

    assert result.passed is True
    assert result.attestation_found is False
    assert result.risk == "INFO"


@pytest.mark.asyncio
@respx.mock
async def test_cargo_no_trustpub_required_holds():
    """No trustpub_data but package IS in require_attestation -> HIGH, not passed."""
    respx.get(f"{CRATES_BASE}/example-crate/1.2.3").mock(
        return_value=httpx.Response(200, json=_version_payload(None))
    )

    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = await verify_provenance_attestation(
            package="example-crate",
            version="1.2.3",
            ecosystem="Cargo",
            trusted_publishers={"example-crate": "some-org/example-crate"},
            require_attestation=["example-crate"],
        )

    assert result.passed is False
    assert result.risk == "HIGH"
    assert "REQUIRED by policy" in result.message


@pytest.mark.asyncio
@respx.mock
async def test_cargo_no_trustpub_appends_advisory_vet_note():
    """A cargo-vet audit hit is surfaced as an advisory note, not a pass/fail signal."""
    respx.get(f"{CRATES_BASE}/example-crate/1.2.3").mock(
        return_value=httpx.Response(200, json=_version_payload(None))
    )

    fake_completed = subprocess.CompletedProcess(args=[], returncode=0)
    with patch("subprocess.run", return_value=fake_completed):
        result = await verify_provenance_attestation(
            package="example-crate",
            version="1.2.3",
            ecosystem="Cargo",
            trusted_publishers={"example-crate": "some-org/example-crate"},
        )

    # Still INFO/pass on its own -- cargo-vet never flips the gate outcome.
    assert result.passed is True
    assert result.risk == "INFO"
    assert "cargo-vet" in result.message


@pytest.mark.asyncio
@respx.mock
async def test_cargo_registry_lookup_failure_fails_open():
    """A non-200 from crates.io must never block -- fail open to INFO/pass."""
    respx.get(f"{CRATES_BASE}/example-crate/1.2.3").mock(
        return_value=httpx.Response(500)
    )

    result = await verify_provenance_attestation(
        package="example-crate",
        version="1.2.3",
        ecosystem="Cargo",
        trusted_publishers={"example-crate": "some-org/example-crate"},
    )

    assert result.passed is True
    assert result.risk == "INFO"
