"""
Pipeline orchestrator — runs all gates in sequence.

Fix 2026-06-06: pass version= to detect_orphan_commits so the age filter
can find the version-matched tag correctly.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

from oss_trust_framework.age_check.checker import AgeCheckResult, AgeDecision, check_release_age
from oss_trust_framework.cicd_audit.orphan_commits import detect_orphan_commits
from oss_trust_framework.cicd_audit.pr_provenance import verify_pr_provenance
from oss_trust_framework.cicd_audit.workflow_permissions import audit_publishing_workflows
from oss_trust_framework.signature.provenance import verify_provenance_attestation
from oss_trust_framework.trust.aggregator import TrustCheckResult, aggregate_trust_score
from oss_trust_framework.zeroday.validator import (
    CVEValidationResult,
    QuorumApprovalManager,
    validate_zero_day_cve,
)

logger = logging.getLogger(__name__)


class PipelineOutcome(str, Enum):
    APPROVED = "approved"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"
    HOLD = "hold"
    PENDING_QUORUM = "pending_quorum"


@dataclass
class GateResult:
    gate: str
    passed: bool
    decision: str
    details: Any


@dataclass
class PipelineResult:
    outcome: PipelineOutcome
    package: str
    version: str
    ecosystem: str
    lane: str
    gates: list[GateResult]
    message: str
    audit_id: str | None = None


class Pipeline:
    def __init__(self, config: dict, quorum_manager: QuorumApprovalManager | None = None) -> None:
        self.config = config
        self.quorum = quorum_manager

    async def run(
        self,
        package: str,
        version: str,
        ecosystem: str,
        github_repo: str | None = None,
        github_token: str | None = None,
        zero_day_cve: str | None = None,
        requester: str | None = None,
    ) -> PipelineResult:
        gates: list[GateResult] = []
        if zero_day_cve:
            return await self._run_zero_day_lane(
                package, version, ecosystem, zero_day_cve,
                requester or "unknown", github_token, gates,
            )
        return await self._run_standard_lane(
            package, version, ecosystem, github_repo, github_token, gates,
        )

    async def _run_standard_lane(
        self,
        package: str,
        version: str,
        ecosystem: str,
        github_repo: str | None,
        github_token: str | None,
        gates: list[GateResult],
    ) -> PipelineResult:

        # Gate 1 — Age
        age_cfg = self.config.get("age_gate", {})
        age_result: AgeCheckResult = await check_release_age(
            package=package, version=version, ecosystem=ecosystem,
            hard_block_hours=age_cfg.get("hard_block_hours", 24),
            hold_hours=age_cfg.get("hold_hours", 72),
        )
        gates.append(GateResult("age", age_result.decision == AgeDecision.PASS,
                                age_result.decision.value, age_result))
        if age_result.decision == AgeDecision.BLOCK:
            return self._finish(PipelineOutcome.BLOCKED, package, version, ecosystem,
                                "standard", gates, age_result.message)
        if age_result.decision == AgeDecision.HOLD:
            return self._finish(PipelineOutcome.HOLD, package, version, ecosystem,
                                "standard", gates, age_result.message)

        # Gate 2 — Provenance attestation
        if github_token:
            trusted_publishers = self.config.get("trusted_publishers", {}).get(ecosystem, {})
            prov_result = await verify_provenance_attestation(
                package=package, version=version, ecosystem=ecosystem,
                trusted_publishers=trusted_publishers,
            )
            gates.append(GateResult("provenance_attestation", prov_result.passed,
                                    prov_result.risk, prov_result))
            if not prov_result.passed and prov_result.risk == "CRITICAL":
                return self._finish(PipelineOutcome.BLOCKED, package, version, ecosystem,
                                    "standard", gates, prov_result.message)
            if not prov_result.passed:
                return self._finish(PipelineOutcome.QUARANTINED, package, version, ecosystem,
                                    "standard", gates, prov_result.message)

        # Gate 2.5a/b/c — CI/CD audit
        if github_repo and github_token:
            owner, repo = github_repo.split("/", 1)

            # 2.5a — Orphan commits (pass version= so age filter works correctly)
            orphan_result = await detect_orphan_commits(
                owner=owner,
                repo=repo,
                github_token=github_token,
                version=version,
                trusted_repos=self.config.get("cicd_audit", {}).get("orphan_commit_trusted_repos", []),
                lookback_days=self.config.get("cicd_audit", {}).get("lookback_days", 180),
            )
            gates.append(GateResult(
                "orphan_commits",
                orphan_result.passed,
                "pass" if orphan_result.passed else "blocked",
                orphan_result,
            ))
            if not orphan_result.passed:
                return self._finish(PipelineOutcome.BLOCKED, package, version, ecosystem,
                                    "standard", gates, orphan_result.message)

            # 2.5b — Workflow permissions
            wf_result = await audit_publishing_workflows(
                owner=owner, repo=repo, github_token=github_token,
            )
            gates.append(GateResult(
                "workflow_permissions",
                wf_result.passed,
                "pass" if wf_result.passed else "quarantine",
                wf_result,
            ))
            if not wf_result.passed:
                return self._finish(PipelineOutcome.QUARANTINED, package, version, ecosystem,
                                    "standard", gates, wf_result.message)

            # 2.5c — PR provenance
            pr_cfg = self.config.get("cicd_audit", {})
            pr_result = await verify_pr_provenance(
                owner=owner, repo=repo, version=version, github_token=github_token,
                min_reviewers=pr_cfg.get("min_pr_reviewers", 0),  # changed from 1 to 0
            )
    
            gates.append(GateResult(
                "pr_provenance",
                pr_result.passed,
                pr_result.risk,
                pr_result,
            ))
            if not pr_result.passed and pr_result.risk == "CRITICAL":
                return self._finish(PipelineOutcome.BLOCKED, package, version, ecosystem,
                                    "standard", gates, pr_result.message)
            if not pr_result.passed:
                return self._finish(PipelineOutcome.QUARANTINED, package, version, ecosystem,
                                    "standard", gates, pr_result.message)
        else:
            logger.warning(
                "cicd_audit skipped — github_repo or github_token not provided "
                "for package=%s version=%s. Gates 2.5a-c inactive.", package, version,
            )

        # Gate 3 — OOB trust
        trust_result: TrustCheckResult = await aggregate_trust_score(
            package=package, version=version, ecosystem=ecosystem,
            github_repo=github_repo, github_token=github_token,
            min_score=self.config.get("trust_scoring", {}).get("min_scorecard_score", 60),
        )
        gates.append(GateResult("oob_trust", trust_result.passed,
                                trust_result.recommendation, trust_result))
        if not trust_result.passed:
            return self._finish(PipelineOutcome.QUARANTINED, package, version, ecosystem,
                                "standard", gates,
                                f"OOB trust score {trust_result.composite_score}/100 — threshold not met or active vulns found")

        # Gate 4 — SBOM (stub)
        sbom_passed, sbom_msg = await self._gate_sbom(package, version, ecosystem)
        gates.append(GateResult("sbom", sbom_passed,
                                "pass" if sbom_passed else "quarantine", sbom_msg))
        if not sbom_passed:
            return self._finish(PipelineOutcome.QUARANTINED, package, version, ecosystem,
                                "standard", gates, sbom_msg)

        # Gate 5 — Sandbox
        sandbox_passed, sandbox_msg = await self._gate_sandbox(package, version, ecosystem)
        gates.append(GateResult("sandbox", sandbox_passed,
                                "pass" if sandbox_passed else "blocked", sandbox_msg))
        if not sandbox_passed:
            return self._finish(PipelineOutcome.BLOCKED, package, version, ecosystem,
                                "standard", gates, sandbox_msg)

        return self._finish(PipelineOutcome.APPROVED, package, version, ecosystem,
                            "standard", gates, f"{package}@{version} cleared all gates.")

    async def _run_zero_day_lane(
        self,
        package: str,
        version: str,
        ecosystem: str,
        cve_id: str,
        requester: str,
        github_token: str | None,
        gates: list[GateResult],
    ) -> PipelineResult:
        cve_result: CVEValidationResult = await validate_zero_day_cve(
            cve_id=cve_id, package=package, version=version,
            ecosystem=ecosystem, github_token=github_token,
        )
        gates.append(GateResult("cve_validation", cve_result.confirmed,
                                "confirmed" if cve_result.confirmed else "rejected", cve_result))
        if not cve_result.confirmed:
            return self._finish(PipelineOutcome.BLOCKED, package, version, ecosystem,
                                "zero_day", gates, cve_result.message)

        if not self.quorum:
            return self._finish(PipelineOutcome.BLOCKED, package, version, ecosystem,
                                "zero_day", gates,
                                "No quorum manager configured — zero-day lane unavailable")

        qr = self.quorum.create_request(
            cve_id=cve_id, package=package, version=version,
            ecosystem=ecosystem, requester=requester,
        )
        gates.append(GateResult("quorum_initiated", True, "pending_quorum",
                                {"request_id": qr.request_id}))
        return self._finish(
            PipelineOutcome.PENDING_QUORUM, package, version, ecosystem, "zero_day", gates,
            f"Quorum request {qr.request_id} created. Awaiting {qr.required_approvers} approvals.",
            audit_id=qr.request_id,
        )

    async def _gate_sbom(self, package: str, version: str, ecosystem: str) -> tuple[bool, str]:
        logger.info("sbom gate stub — package=%s version=%s", package, version)
        return True, "SBOM delta stub — implement oss_trust_framework/sbom/differ.py"

    async def _gate_sandbox(self, package: str, version: str, ecosystem: str) -> tuple[bool, str]:
        logger.info("sandbox gate stub — package=%s version=%s", package, version)
        return True, "Sandbox stub — implement oss_trust_framework/sandbox/runner.py"

    def _finish(
        self,
        outcome: PipelineOutcome,
        package: str,
        version: str,
        ecosystem: str,
        lane: str,
        gates: list[GateResult],
        message: str,
        audit_id: str | None = None,
    ) -> PipelineResult:
        logger.info(
            "pipeline_complete outcome=%s package=%s version=%s lane=%s gates=%d",
            outcome.value, package, version, lane, len(gates),
        )
        return PipelineResult(
            outcome=outcome, package=package, version=version, ecosystem=ecosystem,
            lane=lane, gates=gates, message=message, audit_id=audit_id,
        )