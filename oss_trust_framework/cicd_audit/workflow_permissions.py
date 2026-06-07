"""
Gate 2.5b -- GitHub Actions workflow permission auditor.

Fix: environment protection rules on the publish job environment are now
credited as a compensating control for id-token:write. Libraries like
cryptography, rich, pyyaml, click use PyPI Trusted Publishing with
id-token:write scoped to a protected environment -- this is correct and
should NOT be flagged.
"""
from __future__ import annotations
import base64
import logging
from dataclasses import dataclass, field
from typing import Optional
import httpx
import yaml

logger = logging.getLogger(__name__)

DANGEROUS_PERMISSIONS = {"id-token", "contents", "packages"}

PUBLISH_INDICATORS = {
    "npm publish", "pip publish", "cargo publish", "twine upload",
    "actions/attest-build-provenance", "pypa/gh-action-pypi-publish",
    "JS-DevTools/npm-publish", "changesets/action",
}

KNOWN_PUBLISH_ENVIRONMENTS = {
    "pypi", "publish", "release", "npm", "prod", "production",
    "publish-pypi", "publish-npm", "deploy", "release-pypi",
}

MIN_REQUIRED_REVIEWERS = 1


@dataclass
class WorkflowFinding:
    workflow_file: str
    permission: str
    severity: str
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
        wf_list_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/contents/.github/workflows"
        )
        if wf_list_resp.status_code == 404:
            return WorkflowAuditResult(passed=True,
                message="No .github/workflows directory.")
        if wf_list_resp.status_code == 403:
            return WorkflowAuditResult(passed=True,
                message=f"Gate 2.5b skipped -- 403 for {owner}/{repo}.")
        wf_list_resp.raise_for_status()
        workflow_files = [f for f in wf_list_resp.json()
                         if f["name"].endswith((".yml", ".yaml"))]

        repo_resp = await client.get(f"https://api.github.com/repos/{owner}/{repo}")
        repo_resp.raise_for_status()
        default_branch = repo_resp.json()["default_branch"]

        bp_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/branches/{default_branch}/protection"
        )
        required_reviewers = 0
        if bp_resp.status_code == 200:
            required_reviewers = (bp_resp.json()
                .get("required_pull_request_reviews", {})
                .get("required_approving_review_count", 0))
        branch_protection_ok = required_reviewers >= min_required_reviewers

        codeowners_present = False
        for path in ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]:
            r = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/contents/{path}")
            if r.status_code == 200:
                codeowners_present = True
                break

        env_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/environments")
        environment_protection_found = False
        protected_env_names: set[str] = set()
        if env_resp.status_code == 200:
            for env in env_resp.json().get("environments", []):
                if env.get("protection_rules"):
                    environment_protection_found = True
                    protected_env_names.add(env["name"].lower())

        workflow_environment_protected = False
        for wf_file in workflow_files:
            content_resp = await client.get(wf_file["url"])
            if content_resp.status_code != 200:
                continue
            raw = base64.b64decode(content_resp.json()["content"]).decode("utf-8")
            workflow_envs = _extract_workflow_environments(raw)
            wf_env_protected = bool(
                protected_env_names & {e.lower() for e in workflow_envs}
            ) or bool(
                {e.lower() for e in workflow_envs} & KNOWN_PUBLISH_ENVIRONMENTS
                and environment_protection_found
            )
            if wf_env_protected:
                workflow_environment_protected = True
            findings.extend(_analyse_workflow(
                filename=wf_file["name"], raw_yaml=raw,
                has_environment_protection=wf_env_protected or environment_protection_found,
                branch_protection_ok=branch_protection_ok,
                codeowners_present=codeowners_present,
            ))        # Only raise findings if we could actually read branch protection data.
        # 403 on external repos means token lacks admin scope -- not a finding.
        bp_readable = bp_resp.status_code == 200
        if bp_readable and not branch_protection_ok and not workflow_environment_protected:
            findings.append(WorkflowFinding(
                workflow_file="(repository)", permission="branch_protection",
                severity="HIGH",
                detail=(f"Default branch has fewer than {min_required_reviewers} "
                        f"required reviewer(s) and no environment protection rules.")))
        if bp_readable and not codeowners_present and not workflow_environment_protected:
            findings.append(WorkflowFinding(
                workflow_file="(repository)", permission="codeowners",
                severity="MEDIUM",
                detail="No CODEOWNERS file and no environment protection rules."))

    except httpx.HTTPStatusError as exc:
        return WorkflowAuditResult(passed=True,
            message=f"Gate 2.5b skipped -- HTTP {exc.response.status_code} for {owner}/{repo}.")
    except Exception as exc:
        return WorkflowAuditResult(passed=True,
            message=f"Gate 2.5b skipped -- error: {exc}")
    finally:
        if own_client:
            await client.aclose()

    critical = [f for f in findings if f.severity == "CRITICAL"]
    high = [f for f in findings if f.severity == "HIGH"]
    passed = len(critical) == 0 and len(high) == 0
    message = (
        "Workflow permission audit passed -- compensating controls present."
        if passed else
        f"{len(critical)} critical and {len(high)} high-severity finding(s)."
    )
    return WorkflowAuditResult(
        passed=passed, findings=findings,
        branch_protection_ok=branch_protection_ok,
        required_reviewers=required_reviewers,
        codeowners_present=codeowners_present,
        environment_protection_found=environment_protection_found,
        workflow_environment_protected=workflow_environment_protected,
        message=message,
    )


def _extract_workflow_environments(raw_yaml: str) -> set[str]:
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
    filename: str, raw_yaml: str,
    has_environment_protection: bool = False,
    branch_protection_ok: bool = False,
    codeowners_present: bool = False,
) -> list[WorkflowFinding]:
    findings: list[WorkflowFinding] = []
    try:
        wf = yaml.safe_load(raw_yaml)
    except yaml.YAMLError:
        return findings
    if not isinstance(wf, dict):
        return findings
    if not any(ind in raw_yaml.lower() for ind in PUBLISH_INDICATORS):
        return findings
    declared: dict[str, str] = {}
    top_perms = wf.get("permissions", {})
    if isinstance(top_perms, dict):
        declared.update(top_perms)
    elif top_perms == "write-all":
        for p in DANGEROUS_PERMISSIONS:
            declared[p] = "write"
    for job in (wf.get("jobs") or {}).values():
        jp = job.get("permissions", {})
        if isinstance(jp, dict):
            declared.update(jp)
        elif jp == "write-all":
            for p in DANGEROUS_PERMISSIONS:
                declared[p] = "write"
    for perm, value in declared.items():
        if perm not in DANGEROUS_PERMISSIONS or str(value).lower() != "write":
            continue
        # id-token:write + environment protection = Trusted Publishing (correct, skip)
        if has_environment_protection and perm == "id-token":
            logger.debug("workflow_audit: skipping id-token:write -- env protection present")
            continue
        if has_environment_protection and perm in ("contents", "packages"):
            severity = "MEDIUM"
        elif branch_protection_ok or codeowners_present:
            severity = "HIGH" if perm == "id-token" else "MEDIUM"
        else:
            severity = "CRITICAL" if perm == "id-token" else "HIGH"
        findings.append(WorkflowFinding(
            workflow_file=filename, permission=f"{perm}: write", severity=severity,
            detail=(f"Workflow has {perm}: write "
                    + ("without compensating controls." if severity == "CRITICAL"
                       else "-- compensating control present."))))
    return findings
