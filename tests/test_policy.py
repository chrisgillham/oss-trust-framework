"""Tests for the Policy Engine."""
from __future__ import annotations

import os
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from oss_trust.policy import PolicyEngine
from tests.conftest import make_result


def _engine(rules: dict, tmp_path: Path) -> PolicyEngine:
    cfg = {"quorum_policy": rules}
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.dump(cfg))
    return PolicyEngine(policy_path=str(p))


def test_default_rule_when_no_match(tmp_path):
    engine = _engine({
        "default": {"threshold": 0.5, "deadline_hours": 24},
    }, tmp_path)
    result = make_result()
    result.trust_score = 90
    result.flags = {}
    result.slsa  = {}
    result.historical_prior_denials = 0

    decision = engine.evaluate(result)
    assert decision.rule_name == "default"
    assert decision.threshold == 0.5


def test_low_trust_rule_matches(tmp_path):
    engine = _engine({
        "default": {"threshold": 0.5, "deadline_hours": 24},
        "low_trust_override": {
            "condition": "trust_score < 30",
            "threshold": 0.75,
            "deadline_hours": 12,
        },
    }, tmp_path)
    result = make_result()
    result.trust_score = 25
    result.flags = {}
    result.slsa  = {}
    result.historical_prior_denials = 0

    decision = engine.evaluate(result)
    assert decision.rule_name == "low_trust_override"
    assert decision.threshold == 0.75
    assert decision.deadline_hours == 12


def test_ai_hallucination_rule(tmp_path):
    engine = _engine({
        "default": {"threshold": 0.5, "deadline_hours": 24},
        "ai_hallucination_override": {
            "condition": "flag_ai_hallucination == true",
            "threshold": 1.0,
            "deadline_hours": 4,
        },
    }, tmp_path)
    result = make_result()
    result.trust_score = 70
    result.flags = {"ai_hallucination": True}
    result.slsa  = {}
    result.historical_prior_denials = 0

    decision = engine.evaluate(result)
    assert decision.rule_name == "ai_hallucination_override"
    assert decision.threshold == 1.0


def test_and_condition(tmp_path):
    engine = _engine({
        "default": {"threshold": 0.5, "deadline_hours": 24},
        "combined": {
            "condition": "trust_score < 50 AND flag_typosquatting == true",
            "threshold": 0.9,
            "deadline_hours": 4,
        },
    }, tmp_path)

    result = make_result()
    result.trust_score = 30
    result.flags = {"typosquatting": True}
    result.slsa  = {}
    result.historical_prior_denials = 0

    decision = engine.evaluate(result)
    assert decision.rule_name == "combined"

    # If only one condition is true, should fall through to default
    result2 = make_result()
    result2.trust_score = 30
    result2.flags = {"typosquatting": False}
    result2.slsa  = {}
    result2.historical_prior_denials = 0

    decision2 = engine.evaluate(result2)
    assert decision2.rule_name == "default"


def test_env_var_resolution(tmp_path, monkeypatch):
    monkeypatch.setenv("CISO_DISCORD_ID", "999888777666555444")
    engine = _engine({
        "default": {"threshold": 0.5, "deadline_hours": 24},
        "escalation": {
            "condition": "trust_score < 30",
            "threshold": 1.0,
            "deadline_hours": 4,
            "require_members": ["${CISO_DISCORD_ID}"],
        },
    }, tmp_path)

    result = make_result()
    result.trust_score = 10
    result.flags = {}
    result.slsa  = {}
    result.historical_prior_denials = 0

    decision = engine.evaluate(result)
    assert "999888777666555444" in decision.require_members
