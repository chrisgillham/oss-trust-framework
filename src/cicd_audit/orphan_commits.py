"""
Gate 2.5a — Orphan commit detection.

The Miasma / Shai-Hulud attack pattern uses a compromised employee GitHub
account to push "orphan commits" — commits with no parent in the default
branch history — directly to a repository, bypassing pull request review.
The CI/CD pipeline then publishes these commits as legitimate releases.

This module walks the commit graph from the default branch tip and flags any
release tag whose backing commit is unreachable from normal branch history.

An orphan commit is not proof of compromise on its own (some release workflows
use detached HEAD builds), but combined with a fresh release timestamp it is a
high-confidence indicator of account takeover.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

GRAPH_WALK_DEPTH = 300   # Max commits to traverse; enough for active repos
RECENT_TAGS = 5          # Number of recent release tags to evaluate


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
    recent_tags: int = RECENT_TAGS,
    graph_depth: int = GRAPH_WALK_DEPTH,
    http_client: httpx.AsyncClient | None = None,
) -> OrphanCommitResult:
    """
    Walk the commit graph from the default branch tip and check whether recent
    release tag commits are reachable. Unreachable (orphan) commits indicate a
    direct push that bypassed the normal PR/merge flow.

    Args:
        owner:        GitHub org or user (e.g. "RedHatInsights").
        repo:         Repository name (e.g. "javascript-clients").
        github_token: GitHub PAT or Actions token with repo:read scope.
        recent_tags:  How many recent release tags to evaluate.
        graph_depth:  Max commits to walk before giving up (avoids timeout on huge repos).
        http_client:  Optional pre-configured client (for testing).
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

        # 3. Fetch recent tags (newest first)
        tags_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/tags",
            params={"per_page": recent_tags},
        )
        tags_resp.raise_for_status()
        tags = tags_resp.json()

        findings: list[OrphanFinding] = []

        for tag in tags:
            tag_name = tag["name"]
            tag_sha = tag["commit"]["sha"]

            # Lightweight tags point directly to a commit; annotated tags point
            # to a tag object — resolve to the underlying commit if needed.
            resolved_sha = await _resolve_to_commit(client, owner, repo, tag_sha)

            if resolved_sha not in reachable:
                findings.append(
                    OrphanFinding(
                        tag=tag_name,
                        sha=resolved_sha,
                        reason=(
                            f"Commit {resolved_sha[:8]} backing tag '{tag_name}' is not "
                            f"reachable from {default_branch} tip ({tip_sha[:8]}). "
                            "This is the signature of a direct push bypassing PR review."
                        ),
                        risk="HIGH",
                    )
                )
                logger.warning(
                    "orphan_commit_found tag=%s sha=%s repo=%s/%s",
                    tag_name,
                    resolved_sha[:8],
                    owner,
                    repo,
                )

    finally:
        if own_client:
            await client.aclose()

    passed = len(findings) == 0
    message = (
        f"No orphan commits found across {len(tags)} recent tags."
        if passed
        else (
            f"{len(findings)} orphan commit(s) detected — direct push bypassing PR review. "
            "This matches the Miasma/Shai-Hulud attack pattern."
        )
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

    # Run up to 8 concurrent requests to keep latency reasonable on deep graphs
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
    # Either a lightweight tag (already a commit SHA) or resolve failed — return as-is
    return sha
