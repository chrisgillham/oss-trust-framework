"""
Gate 2.5b — GitHub Actions workflow permission auditor.

The Miasma attack exploited a workflow with `id-token: write` permission.
This permission lets a workflow request a short-lived OIDC token from GitHub
and use it to authenticate with npm's trusted publishing endpoint — no stored
secret required. When an attacker controls the workflow (via a compromised
account), they inherit this capability.

This module inspects every publishing-capable workflow in a repository and
flags cases where dangerous permissions exist without adequate compensating
controls (required reviewers, environment protection rules, CODEOWNERS).

Dangerous permission combinations:
  - id-token: write  →  can publish to npm/PyPI via OIDC trusted publishing
  - contents: write  →  can push commits directly
  - packages: write  →  can publish GitHub Packages

Compensating controls required when any dangerous permission is present:
  - Branch protection with ≥1 required reviewer on the default branch
  - Environment protection rules on the publish environment (if defined)
  - CODEOWNERS file requiring approval for workflow file changes
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass, field

import httpx
import yaml  # PyYAML — already a framework dependency

logger = logging.getLogger(__name__)

# Permissions that allow a workflow to publish packages without a stored secret
DANGEROUS_PERMISSIONS: set[str] = {
    "id-token",   # OIDC — the Miasma vector
    "contents",   # Direct repo write
    "packages",   # GitHub Packages publish
}

PUBLISH_INDICATORS: set[str] = {
    # Commands / actions that indicate a workflow can publish to a registry
    "npm publish",
    "pip publish",
    "cargo publish",
    "twine upload",
    "actions/attest-build-provenance",
    "pypa/gh-action-pypi-publish",
    "JS-DevTools/npm-publish",
    "changesets/action",
}

MIN_REQUIRED_REVIEWERS = 1


@dataclass
class WorkflowFinding:
    workflow_file: str
    permission: str
    severity: str           # CRITICAL | HIGH | MEDIUM
    detail: str


@dataclass
class WorkflowAuditResult:
    passed: bool
    findings: list[WorkflowFinding] = field(default_factory=list)
    branch_protection_ok: bool = False
    required_reviewers: int = 0
    codeowners_present: bool = False
    environment_protection_found: bool = False
    message: str = ""


async def audit_publishing_workflows(
    owner: str,
    repo: str,
    github_token: str,
    min_required_reviewers: int = MIN_REQUIRED_REVIEWERS,
    http_client: httpx.AsyncClient | None = None,
) -> WorkflowAuditResult:
    """
    Inspect all GitHub Actions workflows for dangerous permission combinations
    and verify that adequate compensating controls are in place.

    Args:
        owner:                  GitHub org or user.
        repo:                   Repository name.
        github_token:           PAT or Actions token with repo:read scope.
        min_required_reviewers: Minimum required PR reviewers on default branch.
        http_client:            Optional pre-configured client (for testing).
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

    findings: list[WorkflowFinding] = []

    try:
        # 1. Fetch all workflow files from .github/workflows/
        wf_list_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/contents/.github/workflows"
        )
        if wf_list_resp.status_code == 404:
            return WorkflowAuditResult(
                passed=True,
                message="No .github/workflows directory found — no CI/CD workflows to audit.",
            )
        wf_list_resp.raise_for_status()

        workflow_files = [
            f for f in wf_list_resp.json()
            if f["name"].endswith((".yml", ".yaml"))
        ]

        # 2. Analyse each workflow file
        for wf_file in workflow_files:
            content_resp = await client.get(wf_file["url"])
            if content_resp.status_code != 200:
                continue
            raw = base64.b64decode(content_resp.json()["content"]).decode("utf-8")
            wf_findings = _analyse_workflow(wf_file["name"], raw)
            findings.extend(wf_findings)

        # 3. Check branch protection on default branch
        repo_resp = await client.get(f"https://api.github.com/repos/{owner}/{repo}")
        repo_resp.raise_for_status()
        default_branch = repo_resp.json()["default_branch"]

        bp_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/branches/{default_branch}/protection"
        )
        required_reviewers = 0
        if bp_resp.status_code == 200:
            required_reviewers = (
                bp_resp.json()
                .get("required_pull_request_reviews", {})
                .get("required_approving_review_count", 0)
            )

        branch_protection_ok = required_reviewers >= min_required_reviewers

        # 4. Check for CODEOWNERS
        codeowners_present = False
        for codeowners_path in [
            "CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"
        ]:
            co_resp = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/contents/{codeowners_path}"
            )
            if co_resp.status_code == 200:
                codeowners_present = True
                break

        # 5. Check for environment protection rules on any publish environment
        env_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/environments"
        )
        environment_protection_found = False
        if env_resp.status_code == 200:
            envs = env_resp.json().get("environments", [])
            for env in envs:
                if env.get("protection_rules"):
                    environment_protection_found = True
                    break

        # 6. Upgrade severity of workflow findings when compensating controls are absent
        if not branch_protection_ok:
            findings.append(WorkflowFinding(
                workflow_file="(repository)",
                permission="branch_protection",
                severity="HIGH",
                detail=(
                    f"Default branch '{default_branch}' has fewer than "
                    f"{min_required_reviewers} required reviewer(s). "
                    "A compromised account can merge workflow changes without review."
                ),
            ))

        if not codeowners_present:
            findings.append(WorkflowFinding(
                workflow_file="(repository)",
                permission="codeowners",
                severity="MEDIUM",
                detail=(
                    "No CODEOWNERS file found. Workflow file changes are not "
                    "subject to mandatory ownership-based review."
                ),
            ))

    finally:
        if own_client:
            await client.aclose()

    # CRITICAL findings always fail; HIGH+MEDIUM fail if no environment protection
    critical = [f for f in findings if f.severity == "CRITICAL"]
    high = [f for f in findings if f.severity == "HIGH"]
    passed = (
        len(critical) == 0
        and (len(high) == 0 or environment_protection_found)
    )

    message = (
        "Workflow permission audit passed — no dangerous permission combinations "
        "without compensating controls."
        if passed
        else (
            f"{len(critical)} critical and {len(high)} high-severity workflow "
            "permission finding(s). See findings for details."
        )
    )

    logger.info(
        "workflow_audit passed=%s findings=%d repo=%s/%s",
        passed, len(findings), owner, repo,
    )

    return WorkflowAuditResult(
        passed=passed,
        findings=findings,
        branch_protection_ok=branch_protection_ok,
        required_reviewers=required_reviewers,
        codeowners_present=codeowners_present,
        environment_protection_found=environment_protection_found,
        message=message,
    )


def _analyse_workflow(filename: str, raw_yaml: str) -> list[WorkflowFinding]:
    """
    Parse a workflow YAML and return findings for dangerous permission combinations.
    Returns an empty list if the workflow has no publish capability.
    """
    findings: list[WorkflowFinding] = []

    try:
        wf = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as exc:
        logger.warning("workflow parse failed file=%s: %s", filename, exc)
        return findings

    if not isinstance(wf, dict):
        return findings

    # Check whether this workflow can publish anything
    raw_lower = raw_yaml.lower()
    is_publishing = any(indicator in raw_lower for indicator in PUBLISH_INDICATORS)
    if not is_publishing:
        return findings

    # Collect all permission declarations (top-level and per-job)
    declared_permissions: dict[str, str] = {}  # permission_name -> write|read

    top_perms = wf.get("permissions", {})
    if isinstance(top_perms, dict):
        declared_permissions.update({k: v for k, v in top_perms.items()})
    elif top_perms == "write-all":
        # write-all grants every permission including id-token:write
        for perm in DANGEROUS_PERMISSIONS:
            declared_permissions[perm] = "write"

    for job in (wf.get("jobs") or {}).values():
        job_perms = job.get("permissions", {})
        if isinstance(job_perms, dict):
            declared_permissions.update({k: v for k, v in job_perms.items()})
        elif job_perms == "write-all":
            for perm in DANGEROUS_PERMISSIONS:
                declared_permissions[perm] = "write"

    # Flag dangerous write permissions in a publishing workflow
    for perm, value in declared_permissions.items():
        if perm in DANGEROUS_PERMISSIONS and str(value).lower() == "write":
            severity = "CRITICAL" if perm == "id-token" else "HIGH"
            findings.append(WorkflowFinding(
                workflow_file=filename,
                permission=f"{perm}: write",
                severity=severity,
                detail=(
                    f"Workflow '{filename}' has publish capability and "
                    f"'{perm}: write' permission. "
                    + (
                        "This is the exact permission exploited in Miasma/Shai-Hulud: "
                        "a compromised account can request an OIDC token and publish "
                        "to npm/PyPI without any stored secret."
                        if perm == "id-token"
                        else f"A compromised account can use this permission to push malicious artifacts."
                    )
                ),
            ))

    return findings
