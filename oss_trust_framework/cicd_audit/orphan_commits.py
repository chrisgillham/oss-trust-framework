"""
Gate 2.5a — Orphan commit detection.

The Miasma / Shai-Hulud attack pattern uses a compromised employee GitHub
account to push "orphan commits" — commits with no parent in the default
branch history — directly to a repository, bypassing pull request review.
The CI/CD pipeline then publishes these commits as legitimate releases.

This module walks the commit graph from the default branch tip and flags any
release tag whose backing commit is unreachable from normal branch history.

Fix applied 2026-06-06: added version-targeted checking and age filtering to
eliminate false positives from historical tags that predate modern branch
protection (e.g. cryptography 46.x tags, httpx 1.0.0.beta0).

An orphan commit is not proof of compromise on its own (some release workflows
use detached HEAD builds), but combined with a fresh release timestamp it is a
high-confidence indicator of account takeover.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

GRAPH_WALK_DEPTH = 300   # Max commits to traverse; enough for active repos
RECENT_TAGS = 5          # Number of recent release tags to evaluate (after version match)
LOOKBACK_DAYS = 180      # Only flag orphan commits on tags newer than this many days


@dataclass
class OrphanFinding:
    tag: str
    sha: str
    reason: str          # Human-readable explanation
    risk: str            # HIGH | MEDIUM | INFO


@dataclass
class OrphanCommitResult:
    passed: bool
    orphans_found: int
    findings: list[OrphanFinding] = field(default_factory=list)
    reachable_commits_checked: int = 0
    message: str = ""


async def detect_orphan_commits(
    owner: str,
    repo: str,
    github_token: str,
    version: Optional[str] = None,
    recent_tags: int = RECENT_TAGS,
    graph_depth: int = GRAPH_WALK_DEPTH,
    lookback_days: int = LOOKBACK_DAYS,
    http_client: httpx.AsyncClient | None = None,
) -> OrphanCommitResult:
    """
    Walk the commit graph from the default branch tip and check whether the
    release tag for the specified version is reachable. Unreachable (orphan)
    commits indicate a direct push bypassing PR/merge flow.

    Key fix: only checks the tag matching `version` (if provided), plus recent
    tags within `lookback_days`. Historical tags from years ago are skipped —
    they predate modern branch protection and produce false positives for
    well-maintained libraries like cryptography and httpx.

    Args:
        owner:         GitHub org or user (e.g. "RedHatInsights").
        repo:          Repository name (e.g. "javascript-clients").
        github_token:  GitHub PAT or Actions token with repo:read scope.
        version:       The specific package version being validated. When
                       provided, the tag matching this version is always
                       checked regardless of age. Other tags are only checked
                       if they are within lookback_days.
        recent_tags:   Max additional recent tags to evaluate beyond the
                       version-matched tag.
        graph_depth:   Max commits to walk before giving up.
        lookback_days: Only flag orphan commits on tags whose commit date is
                       within this many days. Prevents false positives from
                       historical direct-push releases.
        http_client:   Optional pre-configured client (for testing).
    """
    own_client = http_client is None
    client = http_client or httpx.AsyncClient(
        timeout=20,
        headers={
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )

    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)

    try:
        # 1. Resolve default branch tip
        repo_resp = await client.get(f"https://api.github.com/repos/{owner}/{repo}")
        repo_resp.raise_for_status()
        default_branch = repo_resp.json()["default_branch"]

        branch_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/branches/{default_branch}"
        )
        branch_resp.raise_for_status()
        tip_sha = branch_resp.json()["commit"]["sha"]

        # 2. Walk commit graph; collect reachable SHAs
        reachable = await _walk_graph(client, owner, repo, tip_sha, graph_depth)
        logger.debug("orphan_check reachable=%d tip=%s", len(reachable), tip_sha[:8])

        # 3. Fetch recent tags (newest first) — get more than we need for filtering
        tags_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/tags",
            params={"per_page": 30},   # fetch 30, filter down by version/age
        )
        tags_resp.raise_for_status()
        all_tags = tags_resp.json()

        # 4. Select which tags to evaluate
        #    Priority 1: the tag matching the specific version being validated
        #    Priority 2: recent tags within lookback_days (up to recent_tags limit)
        tags_to_check = []
        version_tag = None

        if version:
            # Find the tag that matches this version — check common conventions
            version_variants = {
                version,
                f"v{version}",
                f"{version}.0",
                f"v{version}.0",
                version.replace(".", "_"),
            }
            for tag in all_tags:
                if tag["name"] in version_variants:
                    version_tag = tag
                    break

        if version_tag:
            tags_to_check.append(version_tag)

        # Add recent tags within lookback window (skip the version tag if already added)
        recent_count = 0
        for tag in all_tags:
            if recent_count >= recent_tags:
                break
            if version_tag and tag["name"] == version_tag["name"]:
                continue   # already included

            # Get commit date to check age
            tag_sha = tag["commit"]["sha"]
            resolved_sha = await _resolve_to_commit(client, owner, repo, tag_sha)
            commit_date = await _get_commit_date(client, owner, repo, resolved_sha)

            if commit_date and commit_date >= cutoff:
                tags_to_check.append(tag)
                recent_count += 1
            else:
                logger.debug(
                    "orphan_check skipping old tag %s (commit date: %s, cutoff: %s)",
                    tag["name"],
                    commit_date.isoformat() if commit_date else "unknown",
                    cutoff.isoformat(),
                )

        if not tags_to_check:
            return OrphanCommitResult(
                passed=True,
                orphans_found=0,
                reachable_commits_checked=len(reachable),
                message=(
                    f"No recent tags to evaluate for {owner}/{repo} "
                    f"(lookback: {lookback_days} days). "
                    f"Older tags skipped to prevent false positives."
                ),
            )

        # 5. Check each selected tag
        findings: list[OrphanFinding] = []

        for tag in tags_to_check:
            tag_name = tag["name"]
            tag_sha = tag["commit"]["sha"]

            resolved_sha = await _resolve_to_commit(client, owner, repo, tag_sha)

            if resolved_sha not in reachable:
                is_version_match = version_tag and tag_name == version_tag["name"]
                risk = "HIGH" if is_version_match else "MEDIUM"

                findings.append(
                    OrphanFinding(
                        tag=tag_name,
                        sha=resolved_sha,
                        reason=(
                            f"Commit {resolved_sha[:8]} backing tag '{tag_name}' is not "
                            f"reachable from {default_branch} tip ({tip_sha[:8]}). "
                            + (
                                "This is the EXACT VERSION being validated — high confidence indicator."
                                if is_version_match
                                else "Recent tag with orphan commit — possible direct push."
                            )
                        ),
                        risk=risk,
                    )
                )
                logger.warning(
                    "orphan_commit_found tag=%s sha=%s repo=%s/%s risk=%s",
                    tag_name,
                    resolved_sha[:8],
                    owner,
                    repo,
                    risk,
                )
            else:
                logger.debug(
                    "orphan_check tag=%s sha=%s REACHABLE repo=%s/%s",
                    tag_name,
                    resolved_sha[:8],
                    owner,
                    repo,
                )

    finally:
        if own_client:
            await client.aclose()

    # Only block on HIGH risk (version-matched orphan) or multiple MEDIUM findings
    high_risk = [f for f in findings if f.risk == "HIGH"]
    medium_risk = [f for f in findings if f.risk == "MEDIUM"]
    passed = len(high_risk) == 0 and len(medium_risk) < 2

    if not findings:
        message = f"No orphan commits found across {len(tags_to_check)} evaluated tags."
    elif passed:
        message = (
            f"{len(findings)} historical orphan commit(s) found but below block threshold "
            f"(no version-matched orphans, fewer than 2 recent orphans). "
            f"Tags: {[f.tag for f in findings]}"
        )
    else:
        message = (
            f"{len(findings)} orphan commit(s) detected — direct push bypassing PR review. "
            "This matches the Miasma/Shai-Hulud attack pattern."
        )

    return OrphanCommitResult(
        passed=passed,
        orphans_found=len(findings),
        findings=findings,
        reachable_commits_checked=len(reachable),
        message=message,
    )


async def _walk_graph(
    client: httpx.AsyncClient,
    owner: str,
    repo: str,
    start_sha: str,
    depth: int,
) -> set[str]:
    """BFS walk of the commit parent graph up to `depth` commits."""
    reachable: set[str] = set()
    queue = [start_sha]

    sem = asyncio.Semaphore(8)

    async def fetch_parents(sha: str) -> list[str]:
        async with sem:
            try:
                resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
                )
                if resp.status_code == 200:
                    return [p["sha"] for p in resp.json().get("parents", [])]
            except Exception as exc:
                logger.debug("commit fetch failed sha=%s: %s", sha[:8], exc)
        return []

    while queue and len(reachable) < depth:
        batch = queue[:16]
        queue = queue[16:]

        parent_lists = await asyncio.gather(*[fetch_parents(sha) for sha in batch])

        for sha, parents in zip(batch, parent_lists):
            reachable.add(sha)
            for p in parents:
                if p not in reachable:
                    queue.append(p)

    return reachable


async def _resolve_to_commit(
    client: httpx.AsyncClient, owner: str, repo: str, sha: str
) -> str:
    """Resolve an annotated tag object SHA to its underlying commit SHA."""
    resp = await client.get(
        f"https://api.github.com/repos/{owner}/{repo}/git/tags/{sha}"
    )
    if resp.status_code == 200:
        obj = resp.json().get("object", {})
        if obj.get("type") == "commit":
            return obj["sha"]
    return sha


async def _get_commit_date(
    client: httpx.AsyncClient, owner: str, repo: str, sha: str
) -> Optional[datetime]:
    """Fetch the commit date for a given SHA. Returns None on failure."""
    try:
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
        )
        if resp.status_code == 200:
            date_str = (
                resp.json()
                .get("commit", {})
                .get("committer", {})
                .get("date", "")
            )
            if date_str:
                return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except Exception as exc:
        logger.debug("commit date fetch failed sha=%s: %s", sha[:8], exc)
    return None