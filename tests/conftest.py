"""
Shared pytest fixtures for OSS Trust Framework test suite.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from oss_trust.pipeline import TrustResult, GateResult, Outcome


# ── Config fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def pipeline_cfg(tmp_path):
    """Minimal pipeline config for testing."""
    import yaml
    cfg = {
        "age_gate":       {"hard_block_hours": 24, "hold_hours": 72},
        "trust_scoring":  {"min_score": 60, "require_zero_vulns": True},
        "slsa":           {"default_min_level": 1, "on_missing_attestation": "quarantine"},
        "reachability":   {"enabled": False},
        "license":        {"allowlist": ["MIT", "Apache-2.0"], "block_copyleft": True},
        "sbom":           {"recursive": False},
        "sandbox":        {"runtime": "none"},
        "ai_hallucination": {"enabled": True, "similarity_threshold": 0.85},
        "cicd_audit":     {"enabled": False},
        "zero_day":       {"required_approvers": 2, "max_exceptions_per_24h": 3},
        "runtime":        {},
        "public_registry": {"enabled": False},
        "out_of_band_trust": {"sources": []},
    }
    p = tmp_path / "pipeline.yaml"
    p.write_text(yaml.dump(cfg))
    return str(p)


@pytest.fixture
def pkg():
    """Default test package identity."""
    return {"package": "requests", "version": "2.32.3", "ecosystem": "pypi"}


# ── GateResult helpers ────────────────────────────────────────────────────────

def approved(gate: str, message: str = "Passed", **details) -> GateResult:
    return GateResult(gate=gate, outcome=Outcome.APPROVED, message=message, details=details)


def hold(gate: str, message: str = "Advisory", **details) -> GateResult:
    return GateResult(gate=gate, outcome=Outcome.HOLD, message=message, details=details)


def quarantine(gate: str, message: str = "Flagged", **details) -> GateResult:
    return GateResult(gate=gate, outcome=Outcome.QUARANTINE, message=message, details=details)


def blocked(gate: str, message: str = "Blocked", **details) -> GateResult:
    return GateResult(gate=gate, outcome=Outcome.BLOCKED, message=message, details=details)


def rejected(gate: str, message: str = "Rejected", **details) -> GateResult:
    return GateResult(gate=gate, outcome=Outcome.REJECTED, message=message, details=details)


# ── Trust result factory ──────────────────────────────────────────────────────

def make_result(**kwargs) -> TrustResult:
    defaults = {
        "package":   "test-pkg",
        "version":   "1.0.0",
        "ecosystem": "pypi",
    }
    defaults.update(kwargs)
    return TrustResult(**defaults)
