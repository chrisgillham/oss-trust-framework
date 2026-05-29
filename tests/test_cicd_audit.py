"""Tests for Gate 9 — CI/CD Pipeline Self-Audit."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from oss_trust.cicd_audit import CICDAuditGate
from oss_trust.pipeline import Outcome


def _gate(tmp_path: Path, extra_cfg: dict | None = None) -> CICDAuditGate:
    inventory = tmp_path / "approved-actions.json"
    inventory.write_text(json.dumps({
        "approved": [
            {
                "action": "actions/checkout",
                "sha":    "11bd71901bbe5b1630ceea73d27597364c9af683",
                "approved_by": "security-team",
                "approved_at": "2026-01-15",
            }
        ]
    }))
    cfg = {
        "enabled": True,
        "require_sha_pinning": True,
        "new_action_action": "hold",
        "approved_action_inventory": str(inventory),
        "flag_pull_request_target": True,
        "flag_script_injection": True,
    }
    cfg.update(extra_cfg or {})
    return CICDAuditGate(cfg)


def _write_workflow(tmp_path: Path, content: str) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / "test.yml").write_text(content)


@pytest.mark.asyncio
async def test_sha_pinned_approved_action(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_workflow(tmp_path, """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
""")
    gate = _gate(tmp_path)
    r = await gate.evaluate()
    assert r.outcome == Outcome.APPROVED


@pytest.mark.asyncio
async def test_tag_pinned_action_quarantined(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_workflow(tmp_path, """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""")
    gate = _gate(tmp_path)
    r = await gate.evaluate()
    assert r.outcome == Outcome.QUARANTINE
    assert any("SHA" in f["message"] for f in r.details["findings"])


@pytest.mark.asyncio
async def test_pull_request_target_with_write_blocked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_workflow(tmp_path, """
on:
  pull_request_target:
permissions:
  contents: write
  pull-requests: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
""")
    gate = _gate(tmp_path)
    r = await gate.evaluate()
    assert r.outcome == Outcome.BLOCKED
    assert any("pull_request_target" in f["message"] for f in r.details["findings"])


@pytest.mark.asyncio
async def test_script_injection_quarantined(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_workflow(tmp_path, """
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: echo ${{ github.event.pull_request.title }}
""")
    gate = _gate(tmp_path)
    r = await gate.evaluate()
    assert r.outcome == Outcome.QUARANTINE
    assert any("injection" in f["message"].lower() for f in r.details["findings"])


@pytest.mark.asyncio
async def test_new_unapproved_action_hold(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_workflow(tmp_path, """
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: some-org/new-action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
""")
    gate = _gate(tmp_path)
    r = await gate.evaluate()
    assert r.outcome == Outcome.HOLD
    assert any("unapproved" in f["message"].lower() for f in r.details["findings"])


@pytest.mark.asyncio
async def test_disabled_gate_skipped(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    gate = CICDAuditGate({"enabled": False})
    r = await gate.evaluate()
    assert r.outcome == Outcome.APPROVED
    assert r.details.get("skipped") is True
