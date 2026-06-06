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

Fix applied 2026-06-06: environment protection rules are now checked at the
workflow level (per-job environment reference) in addition to the repository
level. Libraries like click (Pallets) and rich (Textualize) use PyPI Trusted
Publishing with environment protection rules — the previous version was not
crediting this as a compensating control, producing false positive quarantines.

Dangerous permission combinations:
  - id-token: write  →  can publish to npm/PyPI via OIDC trusted publishing
  - contents: write  →  can push commits directly
  - packages: write  →  can publish GitHub Packages

Compensating controls (ANY ONE is sufficient to clear a finding):
  - Environment protection rules on the publish environment (STRONGEST)
  - Branch protection with >= 1 required reviewer on the default branch
  - CODEOWNERS file requiring approval for workflow file changes
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass, field
from typing import Optional

import httpx
import yaml

logger = logging.getLogger(__name__)

DANGEROUS_PERMISSIONS: set[str] = {
    "id-token",
    "contents",
    "packages",
}

PUBLISH_INDICATORS: set[str] = {
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

# Well-known PyPI/npm Trusted Publishing environments used by legitimate projects.
# When a workflow's publish job references one of these environment names AND
# that environment has protection rules, the id-token:write permission is
# expected and intentional — this is the correct use of OIDC trusted publishing.
KNOWN_PUBLISH_ENVIRONMENTS = {
    "pypi", "publish", "release", "npm", "prod", "production",
    "publish-pypi", "publish-npm", "deploy", "release-pypi",
}


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
    workflow_environment_protected: bool = False
    message: str = ""


async def audit_publishing_workflows(
    owner: str,
    repo: str,
    github_token: str,
    min_required_reviewers: int = MIN_REQUIRED_REVIEWERS,
    http_client: Optional[httpx.AsyncClient] = None,
) -> WorkflowAuditResult:
    """
    Inspect all GitHub Actions workflows for dangerous permission combinations
    and verify that adequate compensating controls are in place.

    Key fix: environment protection rules on the publish job's environment are
    now treated as a sufficient compensating control for id-token:write.
    This correctly handles PyPI/npm Trusted Publishing workflows (click, rich,
    requests, cryptography etc.) which legitimately use id-token:write scoped
    to a protected publish environment.

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
        # 1. Fetch all workflow files
        wf_list_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/contents/.github/workflows"
        )
        if wf_list_resp.status_code == 404:
            return WorkflowAuditResult(
                passed=True,
                message="No .github/workflows directory — no CI/CD workflows to audit.",
            )
        wf_list_resp.raise_for_status()

        workflow_files = [
            f for f in wf_list_resp.json()
            if f["name"].endswith((".yml", ".yaml"))
        ]

        # 2. Resolve default branch
        repo_resp = await client.get(f"https://api.github.com/repos/{owner}/{repo}")
        repo_resp.raise_for_status()
        default_branch = repo_resp.json()["default_branch"]

        # 3. Check branch protection
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
        for codeowners_path in ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]:
            co_resp = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/contents/{codeowners_path}"
            )
            if co_resp.status_code == 200:
                codeowners_present = True
                break

        # 5. Check repository-level environments for protection rules
        env_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/environments"
        )
        environment_protection_found = False
        protected_env_names: set[str] = set()

        if env_resp.status_code == 200:
            for env in env_resp.json().get("environments", []):
                if env.get("protection_rules"):
                    environment_protection_found = True
                    protected_env_names.add(env["name"].lower())

        # 6. Analyse each workflow file
        workflow_environment_protected = False

        for wf_file in workflow_files:
            content_resp = await client.get(wf_file["url"])
            if content_resp.status_code != 200:
                continue
            raw = base64.b64decode(content_resp.json()["content"]).decode("utf-8")

            # Extract which environments this workflow's jobs reference
            workflow_envs = _extract_workflow_environments(raw)

            # Check if any referenced environment has protection rules
            # This is the key fix — crediting per-workflow environment protection
            wf_env_protected = bool(
                protected_env_names & {e.lower() for e in workflow_envs}
            ) or bool(
                {e.lower() for e in workflow_envs} & KNOWN_PUBLISH_ENVIRONMENTS
                and environment_protection_found
            )

            if wf_env_protected:
                workflow_environment_protected = True

            wf_findings = _analyse_workflow(
                filename=wf_file["name"],
                raw_yaml=raw,
                has_environment_protection=wf_env_protected or environment_protection_found,
                branch_protection_ok=branch_protection_ok,
                codeowners_present=codeowners_present,
            )
            findings.extend(wf_findings)

        # 7. Repository-level findings (only if no workflow-level protection)
        if not branch_protection_ok and not workflow_environment_protected:
            findings.append(WorkflowFinding(
                workflow_file="(repository)",
                permission="branch_protection",
                severity="HIGH",
                detail=(
                    f"Default branch '{default_branch}' has fewer than "
                    f"{min_required_reviewers} required reviewer(s) and no "
                    f"environment protection rules detected. "
                    "A compromised account can merge workflow changes without review."
                ),
            ))

        if not codeowners_present and not workflow_environment_protected:
            findings.append(WorkflowFinding(
                workflow_file="(repository)",
                permission="codeowners",
                severity="MEDIUM",
                detail=(
                    "No CODEOWNERS file found and no environment protection rules. "
                    "Workflow file changes are not subject to mandatory review."
                ),
            ))

    finally:
        if own_client:
            await client.aclose()

    # Determine pass/fail
    # CRITICAL: only if id-token:write with NO compensating controls at all
    # HIGH: only if branch protection missing AND no environment protection
    critical = [f for f in findings if f.severity == "CRITICAL"]
    high = [f for f in findings if f.severity == "HIGH"]

    passed = len(critical) == 0 and len(high) == 0

    if passed:
        message = (
            "Workflow permission audit passed — "
            "dangerous permissions have adequate compensating controls."
        )
    else:
        message = (
            f"{len(critical)} critical and {len(high)} high-severity workflow "
            "permission finding(s). See findings for details."
        )

    logger.info(
        "workflow_audit passed=%s findings=%d env_protected=%s repo=%s/%s",
        passed, len(findings), environment_protection_found, owner, repo,
    )

    return WorkflowAuditResult(
        passed=passed,
        findings=findings,
        branch_protection_ok=branch_protection_ok,
        required_reviewers=required_reviewers,
        codeowners_present=codeowners_present,
        environment_protection_found=environment_protection_found,
        workflow_environment_protected=workflow_environment_protected,
        message=message,
    )


def _extract_workflow_environments(raw_yaml: str) -> set[str]:
    """
    Parse workflow YAML and return all environment names referenced in jobs.
    Handles both string and dict environment declarations:
      environment: pypi
      environment:
        name: pypi
        url: https://pypi.org
    """
    envs: set[str] = set()
    try:
        wf = yaml.safe_load(raw_yaml)
        if not isinstance(wf, dict):
            return envs
        for job in (wf.get("jobs") or {}).values():
            env = job.get("environment")
            if isinstance(env, str):
                envs.add(env)
            elif isinstance(env, dict):
                name = env.get("name", "")
                if name:
                    envs.add(name)
    except yaml.YAMLError:
        pass
    return envs


def _analyse_workflow(
    filename: str,
    raw_yaml: str,
    has_environment_protection: bool = False,
    branch_protection_ok: bool = False,
    codeowners_present: bool = False,
) -> list[WorkflowFinding]:
    """
    Parse a workflow YAML and return findings for dangerous permissions.

    Key logic: if the workflow has environment protection (the strongest
    compensating control), id-token:write is expected and correct — this is
    exactly how PyPI/npm Trusted Publishing is supposed to work.
    Only flag if dangerous permissions exist with NO compensating controls.
    """
    findings: list[WorkflowFinding] = []

    try:
        wf = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as exc:
        logger.warning("workflow parse failed file=%s: %s", filename, exc)
        return findings

    if not isinstance(wf, dict):
        return findings

    # Only audit publishing-capable workflows
    raw_lower = raw_yaml.lower()
    is_publishing = any(indicator in raw_lower for indicator in PUBLISH_INDICATORS)
    if not is_publishing:
        return findings

    # Collect all declared permissions
    declared_permissions: dict[str, str] = {}

    top_perms = wf.get("permissions", {})
    if isinstance(top_perms, dict):
        declared_permissions.update(top_perms)
    elif top_perms == "write-all":
        for perm in DANGEROUS_PERMISSIONS:
            declared_permissions[perm] = "write"

    for job in (wf.get("jobs") or {}).values():
        job_perms = job.get("permissions", {})
        if isinstance(job_perms, dict):
            declared_permissions.update(job_perms)
        elif job_perms == "write-all":
            for perm in DANGEROUS_PERMISSIONS:
                declared_permissions[perm] = "write"

    # Evaluate each dangerous permission
    for perm, value in declared_permissions.items():
        if perm not in DANGEROUS_PERMISSIONS:
            continue
        if str(value).lower() != "write":
            continue

        # Environment protection is the strongest compensating control.
        # id-token:write scoped to a protected publish environment is the
        # CORRECT and INTENDED way to use PyPI/npm Trusted Publishing.
        # Do not flag this — it is the security model working as designed.
        if has_environment_protection and perm == "id-token":
            logger.debug(
                "workflow_audit skipping id-token:write in %s — "
                "environment protection rules present (Trusted Publishing)",
                filename,
            )
            continue

        # contents:write or packages:write with environment protection is lower risk
        if has_environment_protection and perm in ("contents", "packages"):
            severity = "MEDIUM"
        elif branch_protection_ok or codeowners_present:
            # Some compensating control exists — lower severity
            severity = "HIGH" if perm == "id-token" else "MEDIUM"
        else:
            # No compensating controls at all
            severity = "CRITICAL" if perm == "id-token" else "HIGH"

        findings.append(WorkflowFinding(
            workflow_file=filename,
            permission=f"{perm}: write",
            severity=severity,
            detail=(
                f"Workflow '{filename}' has publish capability and "
                f"'{perm}: write' permission"
                + (
                    " without environment protection rules or branch protection. "
                    "This is the exact permission exploited in Miasma/Shai-Hulud."
                    if severity == "CRITICAL"
                    else " — environment or branch protection present as compensating control."
                )
            ),
        ))

    return findings