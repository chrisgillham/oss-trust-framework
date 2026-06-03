"""
Tests for Gate 2.5 — CI/CD audit controls.

Covers:
  - Orphan commit detection (2.5a)
  - Workflow permission auditing (2.5b)
  - PR provenance verification (2.5c)
"""

from __future__ import annotations

import json
import pytest
import respx
import httpx

from oss_trust_framework.cicd_audit.orphan_commits import detect_orphan_commits
from oss_trust_framework.cicd_audit.workflow_permissions import (
    WorkflowFinding,
    _analyse_workflow,
    audit_publishing_workflows,
)
from oss_trust_framework.cicd_audit.pr_provenance import verify_pr_provenance


OWNER = "RedHatInsights"
REPO = "frontend-components"
TOKEN = "ghp_test_token"
BASE = "https://api.github.com"


# ---------------------------------------------------------------------------
# Orphan commit tests
# ---------------------------------------------------------------------------

def _mock_github_base(owner=OWNER, repo=REPO):
    """Register common GitHub API mocks."""
    respx.get(f"{BASE}/repos/{owner}/{repo}").mock(
        return_value=httpx.Response(200, json={"default_branch": "main"})
    )
    respx.get(f"{BASE}/repos/{owner}/{repo}/branches/main").mock(
        return_value=httpx.Response(200, json={"commit": {"sha": "aaa111"}})
    )


@pytest.mark.asyncio
@respx.mock
async def test_orphan_commit_detected():
    """A tag commit not reachable from main must be flagged as orphan."""
    _mock_github_base()

    # Commit graph: aaa111 -> bbb222 (main history)
    respx.get(f"{BASE}/repos/{OWNER}/{REPO}/commits/aaa111").mock(
        return_value=httpx.Response(200, json={"parents": [{"sha": "bbb222"}]})
    )
    respx.get(f"{BASE}/repos/{OWNER}/{REPO}/commits/bbb222").mock(
        return_value=httpx.Response(200, json={"parents": []})
    )

    # Tag points to ccc333 — NOT in the graph above
    respx.get(f"{BASE}/repos/{OWNER}/{REPO}/tags").mock(
        return_value=httpx.Response(200, json=[
            {"name": "v1.2.3", "commit": {"sha": "ccc333"}}
        ])
    )
    # ccc333 is a lightweight tag (commit object), not annotated
    respx.get(f"{BASE}/repos/{OWNER}/{REPO}/git/tags/ccc333").mock(
        return_value=httpx.Response(404)
    )
    # Fetch the commit itself (part of graph walk fallback)
    respx.get(f"{BASE}/repos/{OWNER}/{REPO}/commits/ccc333").mock(
        return_value=httpx.Response(200, json={"parents": []})
    )

    async with httpx.AsyncClient() as client:
        result = await detect_orphan_commits(OWNER, REPO, TOKEN, http_client=client)

    assert not result.passed
    assert result.orphans_found == 1
    assert result.findings[0].tag == "v1.2.3"
    assert "ORPHAN" in result.findings[0].reason


@pytest.mark.asyncio
@respx.mock
async def test_no_orphan_when_tag_reachable():
    """A tag commit reachable from main must pass."""
    _mock_github_base()

    respx.get(f"{BASE}/repos/{OWNER}/{REPO}/commits/aaa111").mock(
        return_value=httpx.Response(200, json={"parents": [{"sha": "bbb222"}]})
    )
    respx.get(f"{BASE}/repos/{OWNER}/{REPO}/commits/bbb222").mock(
        return_value=httpx.Response(200, json={"parents": []})
    )

    # Tag points to bbb222 — reachable from aaa111
    respx.get(f"{BASE}/repos/{OWNER}/{REPO}/tags").mock(
        return_value=httpx.Response(200, json=[
            {"name": "v1.2.2", "commit": {"sha": "bbb222"}}
        ])
    )
    respx.get(f"{BASE}/repos/{OWNER}/{REPO}/git/tags/bbb222").mock(
        return_value=httpx.Response(404)
    )

    async with httpx.AsyncClient() as client:
        result = await detect_orphan_commits(OWNER, REPO, TOKEN, http_client=client)

    assert result.passed
    assert result.orphans_found == 0


# ---------------------------------------------------------------------------
# Workflow permission tests
# ---------------------------------------------------------------------------

DANGEROUS_WORKFLOW_YAML = """
name: Publish
on: push
permissions:
  id-token: write
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
"""

SAFE_WORKFLOW_YAML = """
name: Test
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
"""

NON_PUBLISHING_WORKFLOW = """
name: Lint
on: push
permissions:
  id-token: write
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: eslint .
"""


def test_dangerous_permission_detected_in_publishing_workflow():
    findings = _analyse_workflow("publish.yml", DANGEROUS_WORKFLOW_YAML)
    assert len(findings) == 1
    assert findings[0].permission == "id-token: write"
    assert findings[0].severity == "CRITICAL"


def test_safe_workflow_has_no_findings():
    findings = _analyse_workflow("test.yml", SAFE_WORKFLOW_YAML)
    assert len(findings) == 0


def test_dangerous_permission_ignored_for_non_publishing_workflow():
    """id-token:write in a lint workflow with no publish step is not flagged."""
    findings = _analyse_workflow("lint.yml", NON_PUBLISHING_WORKFLOW)
    assert len(findings) == 0


def test_write_all_permissions_flagged():
    workflow = """
name: Release
on: push
permissions: write-all
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
"""
    findings = _analyse_workflow("release.yml", workflow)
    # write-all grants id-token:write among others
    assert any(f.permission == "id-token: write" for f in findings)


# ---------------------------------------------------------------------------
# PR provenance tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@respx.mock
async def test_pr_provenance_passes_for_reviewed_merged_pr():
    version = "1.2.3"

    respx.get(f"{BASE}/repos/{OWNER}/{REPO}/git/refs/tags/v{version}").mock(
        return_value=httpx.Response(200, json={"object": {"sha": "abc123", "type": "commit"}})
    )
    # Commit -> pulls association
    respx.get(f"{BASE}/repos/{OWNER}/{REPO}/commits/abc123/pulls").mock(
        return_value=httpx.Response(200, json=[
            {"number": 42, "merged_at": "2024-01-01T00:00:00Z", "user": {"login": "maintainer"}}
        ])
    )
    # PR reviews — one approval
    respx.get(f"{BASE}/repos/{OWNER}/{REPO}/pulls/42/reviews").mock(
        return_value=httpx.Response(200, json=[
            {"state": "APPROVED", "user": {"login": "reviewer1"}}
        ])
    )

    async with httpx.AsyncClient() as client:
        result = await verify_pr_provenance(OWNER, REPO, version, TOKEN, http_client=client)

    assert result.passed
    assert result.pr_number == 42
    assert result.reviewer_count == 1
    assert result.risk == "LOW"


@pytest.mark.asyncio
@respx.mock
async def test_direct_push_tag_blocked():
    """A tag with no associated merged PR must be flagged as DIRECT_PUSH."""
    version = "1.2.4"

    respx.get(f"{BASE}/repos/{OWNER}/{REPO}/git/refs/tags/v{version}").mock(
        return_value=httpx.Response(200, json={"object": {"sha": "dead000", "type": "commit"}})
    )
    # No PRs associated with this commit
    respx.get(f"{BASE}/repos/{OWNER}/{REPO}/commits/dead000/pulls").mock(
        return_value=httpx.Response(200, json=[])
    )
    # Search also returns nothing
    respx.get("https://api.github.com/search/issues").mock(
        return_value=httpx.Response(200, json={"items": []})
    )

    async with httpx.AsyncClient() as client:
        result = await verify_pr_provenance(OWNER, REPO, version, TOKEN, http_client=client)

    assert not result.passed
    assert result.provenance == "DIRECT_PUSH"
    assert result.risk == "CRITICAL"


@pytest.mark.asyncio
@respx.mock
async def test_no_tag_returns_high_risk():
    version = "9.9.9"

    respx.get(f"{BASE}/repos/{OWNER}/{REPO}/git/refs/tags/v{version}").mock(
        return_value=httpx.Response(404)
    )
    respx.get(f"{BASE}/repos/{OWNER}/{REPO}/git/refs/tags/{version}").mock(
        return_value=httpx.Response(404)
    )

    async with httpx.AsyncClient() as client:
        result = await verify_pr_provenance(OWNER, REPO, version, TOKEN, http_client=client)

    assert not result.passed
    assert result.provenance == "NO_TAG"
    assert result.risk == "HIGH"
