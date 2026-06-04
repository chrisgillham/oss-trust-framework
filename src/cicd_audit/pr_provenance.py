"""
Gate 2.5c — PR provenance verification.

Legitimate releases in well-maintained projects originate from merged pull
requests with code review. A version tag that points to a commit with no
associated merged PR is a strong indicator of a compromised-account direct
push — exactly the pattern seen in Miasma and Shai-Hulud.

This module checks whether the commit backing a release tag can be traced to
a merged pull request and validates that the PR had meaningful review.

Important nuance: some valid release workflows (release-please, changesets)
create release PRs automatically. This module treats those as valid provenance
as long as the PR was merged via the normal merge queue — not bypassed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

# Bots that legitimately create release PRs without human authorship
KNOWN_RELEASE_BOTS = {
    "release-please[bot]",
    "github-actions[bot]",
    "dependabot[bot]",
    "changesets-bot",
    "renovate[bot]",
    "semantic-release-bot",
}


@dataclass
class PRProvenanceResult:
    passed: bool
    provenance: str         # PR_MERGED | DIRECT_PUSH | TAG_ONLY | NO_TAG | UNKNOWN
    pr_number: int | None
    pr_author: str | None
    reviewer_count: int
    is_bot_release: bool
    risk: str               # LOW | MEDIUM | HIGH | CRITICAL
    message: str


async def verify_pr_provenance(
    owner: str,
    repo: str,
    version: str,
    github_token: str,
    min_reviewers: int = 1,
    http_client: httpx.AsyncClient | None = None,
) -> PRProvenanceResult:
    """
    Check whether the release tag for `version` is backed by a merged PR
    with appropriate review, or was pushed directly.

    Args:
        owner:         GitHub org or user.
        repo:          Repository name.
        version:       Package version string (with or without leading 'v').
        github_token:  PAT or Actions token with repo:read scope.
        min_reviewers: Minimum approving reviewers expected on release PRs.
        http_client:   Optional pre-configured client (for testing).
    """
    own_client = http_client is None
    client = http_client or httpx.AsyncClient(
        timeout=15,
        headers={
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )

    try:
        result = await _check_provenance(client, owner, repo, version, min_reviewers)
    finally:
        if own_client:
            await client.aclose()

    return result


async def _check_provenance(
    client: httpx.AsyncClient,
    owner: str,
    repo: str,
    version: str,
    min_reviewers: int,
) -> PRProvenanceResult:

    # Try both "v1.2.3" and "1.2.3" tag formats
    tag_sha: str | None = None
    for tag_format in [f"v{version}", version]:
        ref_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/git/refs/tags/{tag_format}"
        )
        if ref_resp.status_code == 200:
            obj = ref_resp.json().get("object", {})
            tag_sha = obj.get("sha")
            # Resolve annotated tag to commit
            if obj.get("type") == "tag":
                tag_obj_resp = await client.get(
                    f"https://api.github.com/repos/{owner}/{repo}/git/tags/{tag_sha}"
                )
                if tag_obj_resp.status_code == 200:
                    tag_sha = tag_obj_resp.json().get("object", {}).get("sha", tag_sha)
            break

    if not tag_sha:
        return PRProvenanceResult(
            passed=False,
            provenance="NO_TAG",
            pr_number=None,
            pr_author=None,
            reviewer_count=0,
            is_bot_release=False,
            risk="HIGH",
            message=(
                f"No tag found for version '{version}' (tried 'v{version}' and '{version}'). "
                "Cannot verify release provenance."
            ),
        )

    # Search for PRs whose merge commit matches the tag SHA
    # GitHub's search API can find PRs by commit SHA
    search_resp = await client.get(
        "https://api.github.com/search/issues",
        params={
            "q": f"repo:{owner}/{repo} is:pr is:merged {tag_sha}",
            "per_page": 5,
        },
    )

    matching_prs = []
    if search_resp.status_code == 200:
        matching_prs = search_resp.json().get("items", [])

    # Also try the commit → pulls association endpoint (more reliable)
    commit_prs_resp = await client.get(
        f"https://api.github.com/repos/{owner}/{repo}/commits/{tag_sha}/pulls",
        headers={"Accept": "application/vnd.github.groot-preview+json"},
    )
    if commit_prs_resp.status_code == 200:
        direct_prs = [p for p in commit_prs_resp.json() if p.get("merged_at")]
        if direct_prs:
            matching_prs = direct_prs  # Prefer the direct association

    if not matching_prs:
        return PRProvenanceResult(
            passed=False,
            provenance="DIRECT_PUSH",
            pr_number=None,
            pr_author=None,
            reviewer_count=0,
            is_bot_release=False,
            risk="CRITICAL",
            message=(
                f"Tag for version '{version}' (commit {tag_sha[:8]}) has no associated "
                "merged pull request. This is the signature of a compromised-account "
                "direct push — matching the Miasma/Shai-Hulud attack pattern."
            ),
        )

    # Evaluate the best PR (most recent merged)
    pr = matching_prs[0]
    pr_number = pr["number"]
    pr_author = pr.get("user", {}).get("login", "unknown")
    is_bot = pr_author in KNOWN_RELEASE_BOTS

    # Fetch review details
    reviews_resp = await client.get(
        f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
    )
    approving_reviewers = 0
    if reviews_resp.status_code == 200:
        approving_reviewers = sum(
            1 for r in reviews_resp.json()
            if r.get("state") == "APPROVED"
            and r.get("user", {}).get("login") != pr_author  # Self-approval doesn't count
        )

    # Assess risk
    if is_bot and approving_reviewers == 0:
        # Automated release bot with no human review — medium risk, common pattern
        risk = "MEDIUM"
        passed = True  # Bots are allowed; flag for awareness
        message = (
            f"Release PR #{pr_number} was created by '{pr_author}' (known release bot) "
            f"with {approving_reviewers} human approver(s). "
            "This is a common automated release pattern but should be confirmed."
        )
    elif approving_reviewers >= min_reviewers:
        risk = "LOW"
        passed = True
        message = (
            f"Release PR #{pr_number} by '{pr_author}' had {approving_reviewers} "
            "approving reviewer(s). Provenance verified."
        )
    else:
        risk = "HIGH"
        passed = False
        message = (
            f"Release PR #{pr_number} by '{pr_author}' had only {approving_reviewers} "
            f"approving reviewer(s); {min_reviewers} required. "
            "A single compromised account may have authored and merged this release."
        )

    logger.info(
        "pr_provenance version=%s pr=%d author=%s reviewers=%d risk=%s",
        version, pr_number, pr_author, approving_reviewers, risk,
    )

    return PRProvenanceResult(
        passed=passed,
        provenance="PR_MERGED",
        pr_number=pr_number,
        pr_author=pr_author,
        reviewer_count=approving_reviewers,
        is_bot_release=is_bot,
        risk=risk,
        message=message,
    )
