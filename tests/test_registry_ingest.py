"""Tests for scripts/registry_ingest.py"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import registry_ingest as ri


# ── Valid payload fixture ─────────────────────────────────────────────────────

def valid_payload(**overrides) -> dict:
    base = {
        "schema_version":   "1.0",
        "package":          "lodash",
        "version":          "4.17.21",
        "ecosystem":        "npm",
        "evaluated_at":     "2026-05-28T14:00:00Z",
        "trust_band":       "MEDIUM",
        "slsa_level":       1,
        "verdict":          "APPROVED",
        "signals_fired": {
            "typosquatting":       False,
            "behavior_change":     True,
            "author_reputation":   False,
            "provenance_activity": False,
            "ai_hallucination":    False,
            "no_signature":        False,
            "weak_signature":      True,
            "no_checksum":         False,
        },
        "contribution_id":  "a" * 64,
        "framework_version": "2.0.0",
    }
    base.update(overrides)
    return base


# ── Validation ────────────────────────────────────────────────────────────────

def test_valid_payload_passes():
    errors = ri.validate(valid_payload())
    assert errors == []


def test_wrong_schema_version():
    errors = ri.validate(valid_payload(schema_version="2.0"))
    assert any("schema_version" in e for e in errors)


def test_invalid_ecosystem():
    errors = ri.validate(valid_payload(ecosystem="cargo-ng"))
    assert any("ecosystem" in e for e in errors)


def test_invalid_trust_band():
    errors = ri.validate(valid_payload(trust_band="VERY_HIGH"))
    assert any("trust_band" in e for e in errors)


def test_invalid_verdict():
    errors = ri.validate(valid_payload(verdict="PENDING"))
    assert any("verdict" in e for e in errors)


def test_invalid_slsa_level():
    errors = ri.validate(valid_payload(slsa_level=5))
    assert any("slsa_level" in e for e in errors)


def test_invalid_contribution_id():
    errors = ri.validate(valid_payload(contribution_id="not-a-sha256"))
    assert any("contribution_id" in e for e in errors)


def test_extra_signal_key_rejected():
    payload = valid_payload()
    payload["signals_fired"]["unknown_signal"] = True
    errors = ri.validate(payload)
    assert any("Unknown signal" in e for e in errors)


def test_non_bool_signal_rejected():
    payload = valid_payload()
    payload["signals_fired"]["typosquatting"] = "yes"
    errors = ri.validate(payload)
    assert any("boolean" in e for e in errors)


def test_email_pii_rejected():
    errors = ri.validate(valid_payload(package="alice@example.com"))
    assert any("PII" in e for e in errors)


def test_ipv4_pii_rejected():
    payload = valid_payload()
    payload["framework_version"] = "2.0.0 from 192.168.1.1"
    errors = ri.validate(payload)
    assert any("PII" in e for e in errors)


# ── Merge logic ───────────────────────────────────────────────────────────────

def test_merge_increments_approved_count():
    pkg = ri.load_package_file.__wrapped__("npm", "lodash") if hasattr(ri.load_package_file, "__wrapped__") \
          else {
              "package": "lodash", "ecosystem": "npm", "updated_at": "", "contribution_count": 0,
              "aggregate": {
                  "approved_count": 0, "denied_count": 0, "expired_count": 0,
                  "band_votes": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
                  "community_band": "", "slsa_levels_observed": [],
                  "signal_fire_counts": {s: 0 for s in ri.VALID_SIGNALS},
              },
              "versions": {},
          }
    result = ri.merge_contribution(pkg, valid_payload(verdict="APPROVED"))
    assert result["aggregate"]["approved_count"] == 1
    assert result["contribution_count"] == 1


def test_merge_denied_increments_denied():
    pkg = {
        "package": "lodash", "ecosystem": "npm", "updated_at": "", "contribution_count": 0,
        "aggregate": {
            "approved_count": 0, "denied_count": 0, "expired_count": 0,
            "band_votes": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "community_band": "", "slsa_levels_observed": [],
            "signal_fire_counts": {s: 0 for s in ri.VALID_SIGNALS},
        },
        "versions": {},
    }
    result = ri.merge_contribution(pkg, valid_payload(verdict="DENIED", trust_band="LOW"))
    assert result["aggregate"]["denied_count"] == 1
    assert result["aggregate"]["band_votes"]["LOW"] == 1


def test_merge_version_record_created():
    pkg = {
        "package": "lodash", "ecosystem": "npm", "updated_at": "", "contribution_count": 0,
        "aggregate": {
            "approved_count": 0, "denied_count": 0, "expired_count": 0,
            "band_votes": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "community_band": "", "slsa_levels_observed": [],
            "signal_fire_counts": {s: 0 for s in ri.VALID_SIGNALS},
        },
        "versions": {},
    }
    result = ri.merge_contribution(pkg, valid_payload(version="4.17.21"))
    assert "4.17.21" in result["versions"]
    assert result["versions"]["4.17.21"]["approved_count"] == 1


def test_merge_slsa_level_recorded():
    pkg = {
        "package": "lodash", "ecosystem": "npm", "updated_at": "", "contribution_count": 0,
        "aggregate": {
            "approved_count": 0, "denied_count": 0, "expired_count": 0,
            "band_votes": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "community_band": "", "slsa_levels_observed": [],
            "signal_fire_counts": {s: 0 for s in ri.VALID_SIGNALS},
        },
        "versions": {},
    }
    result = ri.merge_contribution(pkg, valid_payload(slsa_level=2))
    assert 2 in result["aggregate"]["slsa_levels_observed"]


# ── Community band ────────────────────────────────────────────────────────────

def test_community_band_majority_denied_is_low():
    band = ri.compute_community_band(10, 6, {"HIGH": 4, "MEDIUM": 0, "LOW": 6})
    assert band == "LOW"


def test_community_band_majority_low_votes():
    band = ri.compute_community_band(10, 2, {"HIGH": 1, "MEDIUM": 3, "LOW": 6})
    assert band == "LOW"


def test_community_band_some_low_is_medium():
    band = ri.compute_community_band(10, 1, {"HIGH": 6, "MEDIUM": 1, "LOW": 3})
    assert band == "MEDIUM"


def test_community_band_mostly_high():
    band = ri.compute_community_band(10, 0, {"HIGH": 9, "MEDIUM": 1, "LOW": 0})
    assert band == "HIGH"


def test_community_band_empty():
    band = ri.compute_community_band(0, 0, {"HIGH": 0, "MEDIUM": 0, "LOW": 0})
    assert band == ""


# ── Filename sanitization ─────────────────────────────────────────────────────

def test_scoped_npm_package_filename():
    name = ri.package_filename("@scope/package")
    assert "@" not in name
    assert "/" not in name
    assert name.endswith(".json")


def test_regular_package_filename():
    assert ri.package_filename("lodash") == "lodash.json"
    assert ri.package_filename("my-pkg") == "my-pkg.json"
