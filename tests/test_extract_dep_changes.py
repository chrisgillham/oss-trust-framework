"""Tests for scripts/extract_dep_changes.py lock file parsers."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from extract_dep_changes import (
    parse_package_lock,
    parse_requirements_txt,
    parse_go_sum,
    parse_gemfile_lock,
    dedup,
)


# ── package-lock.json ─────────────────────────────────────────────────────────

LOCK_BEFORE = json.dumps({
    "lockfileVersion": 3,
    "packages": {
        "node_modules/lodash": {"version": "4.17.19"},
        "node_modules/express": {"version": "4.18.2"},
    }
})

LOCK_AFTER = json.dumps({
    "lockfileVersion": 3,
    "packages": {
        "node_modules/lodash":  {"version": "4.17.21"},   # bumped
        "node_modules/express": {"version": "4.18.2"},    # unchanged
        "node_modules/qs":      {"version": "6.11.2"},    # new
    }
})


def test_package_lock_detects_bump():
    changes = parse_package_lock(LOCK_BEFORE, LOCK_AFTER)
    names = [c["package"] for c in changes]
    assert "lodash" in names
    assert "express" not in names


def test_package_lock_detects_new_package():
    changes = parse_package_lock(LOCK_BEFORE, LOCK_AFTER)
    names = [c["package"] for c in changes]
    assert "qs" in names


def test_package_lock_empty_before():
    changes = parse_package_lock("", LOCK_AFTER)
    assert len(changes) >= 3   # all packages are "new"


# ── requirements.txt ─────────────────────────────────────────────────────────

REQ_BEFORE = "requests==2.31.0\nnumpy==1.26.0\n"
REQ_AFTER  = "requests==2.32.3\nnumpy==1.26.0\nflask==3.0.2\n"


def test_requirements_detects_bump():
    changes = parse_requirements_txt(REQ_BEFORE, REQ_AFTER)
    names = [c["package"] for c in changes]
    assert "requests" in names
    assert "numpy" not in names


def test_requirements_detects_new():
    changes = parse_requirements_txt(REQ_BEFORE, REQ_AFTER)
    names = [c["package"] for c in changes]
    assert "flask" in names


def test_requirements_ecosystem():
    changes = parse_requirements_txt(REQ_BEFORE, REQ_AFTER)
    for c in changes:
        assert c["ecosystem"] == "pypi"


# ── go.sum ────────────────────────────────────────────────────────────────────

GO_BEFORE = (
    "github.com/gin-gonic/gin v1.9.0 h1:abc123\n"
    "github.com/stretchr/testify v1.8.4 h1:def456\n"
)
GO_AFTER = (
    "github.com/gin-gonic/gin v1.9.1 h1:newsha\n"   # version bumped
    "github.com/stretchr/testify v1.8.4 h1:def456\n"
    "github.com/pkg/errors v0.9.1 h1:newpkg\n"       # new
)


def test_go_sum_detects_bump():
    changes = parse_go_sum(GO_BEFORE, GO_AFTER)
    mods = [c["package"] for c in changes]
    assert "github.com/gin-gonic/gin" in mods


def test_go_sum_detects_new_module():
    changes = parse_go_sum(GO_BEFORE, GO_AFTER)
    mods = [c["package"] for c in changes]
    assert "github.com/pkg/errors" in mods


def test_go_sum_unchanged_excluded():
    changes = parse_go_sum(GO_BEFORE, GO_AFTER)
    mods = [c["package"] for c in changes]
    assert "github.com/stretchr/testify" not in mods


# ── Gemfile.lock ──────────────────────────────────────────────────────────────

GEM_BEFORE = """GEM
  remote: https://rubygems.org/
  specs:
    rails (7.1.2)
    rack (3.0.8)
"""

GEM_AFTER = """GEM
  remote: https://rubygems.org/
  specs:
    rails (7.1.3)
    rack (3.0.8)
    nokogiri (1.16.2)
"""


def test_gemfile_detects_bump():
    changes = parse_gemfile_lock(GEM_BEFORE, GEM_AFTER)
    names = [c["package"] for c in changes]
    assert "rails" in names
    assert "rack" not in names


def test_gemfile_detects_new_gem():
    changes = parse_gemfile_lock(GEM_BEFORE, GEM_AFTER)
    names = [c["package"] for c in changes]
    assert "nokogiri" in names


# ── Deduplication ─────────────────────────────────────────────────────────────

def test_dedup_removes_duplicates():
    pkgs = [
        {"package": "lodash", "version": "4.17.21", "ecosystem": "npm"},
        {"package": "lodash", "version": "4.17.21", "ecosystem": "npm"},
        {"package": "express", "version": "4.18.2", "ecosystem": "npm"},
    ]
    result = dedup(pkgs)
    assert len(result) == 2
    names = [p["package"] for p in result]
    assert names.count("lodash") == 1
