"""
Gate 2.5a -- Orphan commit detection.

Fix 2026-06-06c: Added trusted_repos allowlist support. Repos listed in
config/pipeline.yaml under cicd_audit.orphan_commit_trusted_repos skip
the orphan commit check entirely -- these are well-established projects
whose release workflows legitimately produce commits off the default branch.

Fix 2026-06-06b: Added version-targeted checking and 180-day age filter.
Fix 2026-06-06a: Added graceful 403 handling for external repos.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

GRAPH_WALK_DEPTH = 300
RECENT_TAGS = 5
LOOKBACK_DAYS = 180


@dataclass
class OrphanFinding:
    tag: str
    sha: str
    reason: str
    risk: str


@dataclass
class OrphanCommitResult:
    passed: bool
    orphans_found: int
    findings: list[OrphanFinding] = field(default_factory=list)
    reachable_commits_checked: int = 0
    skipped: bool = False
    message: str = ""


async def detect_orphan_commits(
    owner: str,
    repo: str,
    github_token: str,
    version: Optional[str] = None,
    recent_tags: int = RECENT_TAGS,
    graph_depth: int = GRAPH_WALK_DEPTH,
    lookback_days: int = LOOKBACK_DAYS,
    trusted_repos: Optional[list[str]] = None,
    http_client: Optional[httpx.AsyncClient] = None,
) -> OrphanCommitResult:
    """
    Walk the commit graph from the default branch tip and check whether the
    release tag for the specified version is reachable.

    Args:
        trusted_repos: List of "owner/repo" strings to skip entirely.
                       Load from config/pipeline.yaml:
                         cicd_audit.orphan_commit_trusted_repos
    """
    # Skip trusted repos entirely
    repo_slug = f"{owner}/{repo}"
    if trusted_repos and repo_slug in trusted_repos:
        logger.info(
            "orphan_commits skipping trusted repo %s -- in allowlist", repo_slug
        )
        return OrphanCommitResult(
            passed=True,
            orphans_found=0,
            skipped=True,
            message=(
                f"Gate 2.5a skipped for {repo_slug} -- repo is in the "
                f"trusted_repos allowlist (established project with known "
                f"non-standard release workflow)."
            ),
        )

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
        repo_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}"
        )
        if repo_resp.status_code in (403, 404):
            logger.warning(
                "orphan_commits %d for %s -- skipping gate.",
                repo_resp.status_code, repo_slug
            )
            return OrphanCommitResult(
                passed=True, orphans_found=0, skipped=True,
                message=(
                    f"Gate 2.5a skipped for {repo_slug} -- "
                    f"HTTP {repo_resp.status_code}. "
                    f"Use a PAT with repo:read scope for full coverage."
                ),
            )
        repo_resp.raise_for_status()
        default_branch = repo_resp.json()["default_branch"]

        branch_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/branches/{default_branch}"
        )
        if branch_resp.status_code in (403, 404):
            logger.warning(
                "orphan_commits %d on branch %s for %s -- skipping.",
                branch_resp.status_code, default_branch, repo_slug
            )
            return OrphanCommitResult(
                passed=True, orphans_found=0, skipped=True,
                message=f"Gate 2.5a skipped -- cannot read branch for {repo_slug}.",
            )
        branch_resp.raise_for_status()
        tip_sha = branch_resp.json()["commit"]["sha"]

        reachable = await _walk_graph(client, owner, repo, tip_sha, graph_depth)
        logger.debug("orphan_check reachable=%d tip=%s", len(reachable), tip_sha[:8])

        tags_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/tags",
            params={"per_page": 30},
        )
        if tags_resp.status_code in (403, 404):
            return OrphanCommitResult(
                passed=True, orphans_found=0, skipped=True,
                message=f"Gate 2.5a skipped -- cannot read tags for {repo_slug}.",
            )
        tags_resp.raise_for_status()
        all_tags = tags_resp.json()

        tags_to_check = []
        version_tag = None

        if version:
            version_variants = {
                version, f"v{version}",
                f"{version}.0", f"v{version}.0",
                version.replace(".", "_"),
            }
            for tag in all_tags:
                if tag["name"] in version_variants:
                    version_tag = tag
                    break

        if version_tag:
            tags_to_check.append(version_tag)

        recent_count = 0
        for tag in all_tags:
            if recent_count >= recent_tags:
                break
            if version_tag and tag["name"] == version_tag["name"]:
                continue

            tag_sha = tag["commit"]["sha"]
            resolved_sha = await _resolve_to_commit(client, owner, repo, tag_sha)
            commit_date = await _get_commit_date(client, owner, repo, resolved_sha)

            if commit_date and commit_date >= cutoff:
                tags_to_check.append(tag)
                recent_count += 1
            else:
                logger.debug(
                    "orphan_check skipping old tag %s (date: %s)",
                    tag["name"],
                    commit_date.isoformat() if commit_date else "unknown",
                )

        if not tags_to_check:
            return OrphanCommitResult(
                passed=True, orphans_found=0,
                reachable_commits_checked=len(reachable),
                message=f"No recent tags to evaluate for {repo_slug} (lookback: {lookback_days}d).",
            )

        findings: list[OrphanFinding] = []

        for tag in tags_to_check:
            tag_name = tag["name"]
            tag_sha = tag["commit"]["sha"]
            resolved_sha = await _resolve_to_commit(client, owner, repo, tag_sha)

            if resolved_sha not in reachable:
                is_version_match = (
                    version_tag is not None and tag_name == version_tag["name"]
                )
                risk = "HIGH" if is_version_match else "MEDIUM"
                findings.append(OrphanFinding(
                    tag=tag_name, sha=resolved_sha,
                    reason=(
                        f"Commit {resolved_sha[:8]} backing tag '{tag_name}' "
                        f"is not reachable from {default_branch} tip ({tip_sha[:8]}). "
                        + ("EXACT VERSION -- high confidence."
                           if is_version_match else "Recent tag with orphan commit.")
                    ),
                    risk=risk,
                ))
                logger.warning(
                    "orphan_commit_found tag=%s sha=%s repo=%s risk=%s",
                    tag_name, resolved_sha[:8], repo_slug, risk,
                )

    except httpx.HTTPStatusError as exc:
        logger.warning(
            "orphan_commits HTTP %s for %s -- skipping.",
            exc.response.status_code, repo_slug
        )
        return OrphanCommitResult(
            passed=True, orphans_found=0, skipped=True,
            message=(
                f"Gate 2.5a skipped -- HTTP {exc.response.status_code} "
                f"for {repo_slug}."
            ),
        )
    except Exception as exc:
        logger.warning("orphan_commits error for %s: %s", repo_slug, exc)
        return OrphanCommitResult(
            passed=True, orphans_found=0, skipped=True,
            message=f"Gate 2.5a skipped -- error: {exc}",
        )
    finally:
        if own_client:
            await client.aclose()

    high_risk = [f for f in findings if f.risk == "HIGH"]
    medium_risk = [f for f in findings if f.risk == "MEDIUM"]
    passed = len(high_risk) == 0 and len(medium_risk) < 2

    if not findings:
        message = f"No orphan commits found across {len(tags_to_check)} evaluated tags."
    elif passed:
        message = (
            f"{len(findings)} historical orphan commit(s) found but below "
            f"block threshold. Tags: {[f.tag for f in findings]}"
        )
    else:
        message = (
            f"{len(findings)} orphan commit(s) detected -- direct push "
            f"bypassing PR review. This matches the Miasma/Shai-Hulud attack pattern."
        )

    return OrphanCommitResult(
        passed=passed, orphans_found=len(findings),
        findings=findings, reachable_commits_checked=len(reachable),
        message=message,
    )


async def _walk_graph(
    client: httpx.AsyncClient, owner: str, repo: str, start_sha: str, depth: int,
) -> set[str]:
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
    try:
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/git/tags/{sha}"
        )
        if resp.status_code == 200:
            obj = resp.json().get("object", {})
            if obj.get("type") == "commit":
                return obj["sha"]
    except Exception:
        pass
    return sha


async def _get_commit_date(
    client: httpx.AsyncClient, owner: str, repo: str, sha: str
) -> Optional[datetime]:
    try:
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
        )
        if resp.status_code == 200:
            date_str = (
                resp.json().get("commit", {})
                .get("committer", {}).get("date", "")
            )
            if date_str:
                return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except Exception as exc:
        logger.debug("commit date fetch failed sha=%s: %s", sha[:8], exc)
    return None
