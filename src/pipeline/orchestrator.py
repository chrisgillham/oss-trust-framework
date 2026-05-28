"""
Pipeline orchestrator — runs all gates in sequence and routes zero-day requests
through the expedited lane.

Standard flow:    Age → Sig → OOB Trust → SBOM → Sandbox → Rollout
Zero-day flow:    CVE Validate → Quorum → Sig (+timing) → OOB Trust → SBOM → Sandbox → Immediate rollout
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

from oss_trust_framework.age_check.checker import AgeCheckResult, AgeDecision, check_release_age
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
    HOLD = "hold"                   # Awaiting human approval (standard lane, 24–72 h)
    PENDING_QUORUM = "pending_quorum"  # Awaiting zero-day quorum approval


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
    lane: str               # "standard" | "zero_day"
    gates: list[GateResult]
    message: str
    audit_id: str | None = None


class Pipeline:
    """
    Orchestrates the full validation pipeline.

    Usage:
        pipeline = Pipeline(config=load_config("config/pipeline.yaml"))

        # Standard check
        result = await pipeline.run(package="requests", version="2.32.3", ecosystem="PyPI")

        # Zero-day expedited lane
        result = await pipeline.run(
            package="requests",
            version="2.32.4",
            ecosystem="PyPI",
            zero_day_cve="CVE-2024-XXXXX",
            requester="security@yourorg.com",
        )
    """

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
        """
        Execute the full pipeline. If zero_day_cve is provided, routes through
        the expedited lane (age gate bypassed, all other gates mandatory).
        """
        gates: list[GateResult] = []

        if zero_day_cve:
            return await self._run_zero_day_lane(
                package, version, ecosystem, zero_day_cve,
                requester or "unknown", github_token, gates,
            )
        else:
            return await self._run_standard_lane(
                package, version, ecosystem, github_repo, github_token, gates,
            )

    # ------------------------------------------------------------------
    # Standard lane
    # ------------------------------------------------------------------

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
            package=package,
            version=version,
            ecosystem=ecosystem,
            hard_block_hours=age_cfg.get("hard_block_hours", 24),
            hold_hours=age_cfg.get("hold_hours", 72),
        )
        gates.append(GateResult("age", age_result.decision == AgeDecision.PASS, age_result.decision.value, age_result))

        if age_result.decision == AgeDecision.BLOCK:
            return self._finish(PipelineOutcome.BLOCKED, package, version, ecosystem, "standard", gates, age_result.message)
        if age_result.decision == AgeDecision.HOLD:
            return self._finish(PipelineOutcome.HOLD, package, version, ecosystem, "standard", gates, age_result.message)

        # Gate 2 — Signature (stubbed: implement with sigstore/gpg module)
        sig_passed, sig_msg = await self._gate_signature(package, version, ecosystem)
        gates.append(GateResult("signature", sig_passed, "pass" if sig_passed else "rejected", sig_msg))
        if not sig_passed:
            return self._finish(PipelineOutcome.BLOCKED, package, version, ecosystem, "standard", gates, sig_msg)

        # Gate 3 — Out-of-band trust
        trust_result: TrustCheckResult = await aggregate_trust_score(
            package=package,
            version=version,
            ecosystem=ecosystem,
            github_repo=github_repo,
            github_token=github_token,
            min_score=self.config.get("trust_scoring", {}).get("min_scorecard_score", 60),
        )
        gates.append(GateResult("oob_trust", trust_result.passed, trust_result.recommendation, trust_result))
        if not trust_result.passed:
            return self._finish(PipelineOutcome.QUARANTINED, package, version, ecosystem, "standard", gates, f"OOB trust score {trust_result.composite_score}/100 — threshold not met or active vulns found")

        # Gate 4 — SBOM (stubbed: implement with sbom/differ.py)
        sbom_passed, sbom_msg = await self._gate_sbom(package, version, ecosystem)
        gates.append(GateResult("sbom", sbom_passed, "pass" if sbom_passed else "quarantine", sbom_msg))
        if not sbom_passed:
            return self._finish(PipelineOutcome.QUARANTINED, package, version, ecosystem, "standard", gates, sbom_msg)

        # Gate 5 — Sandbox (stubbed: implement with sandbox/runner.py)
        sandbox_passed, sandbox_msg = await self._gate_sandbox(package, version, ecosystem)
        gates.append(GateResult("sandbox", sandbox_passed, "pass" if sandbox_passed else "blocked", sandbox_msg))
        if not sandbox_passed:
            return self._finish(PipelineOutcome.BLOCKED, package, version, ecosystem, "standard", gates, sandbox_msg)

        return self._finish(PipelineOutcome.APPROVED, package, version, ecosystem, "standard", gates, f"{package}@{version} cleared all gates.")

    # ------------------------------------------------------------------
    # Zero-day expedited lane
    # ------------------------------------------------------------------

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

        # ZD Step 1 — Machine-verified CVE validation
        cve_result: CVEValidationResult = await validate_zero_day_cve(
            cve_id=cve_id,
            package=package,
            version=version,
            ecosystem=ecosystem,
            github_token=github_token,
        )
        gates.append(GateResult("cve_validation", cve_result.confirmed, "confirmed" if cve_result.confirmed else "rejected", cve_result))
        if not cve_result.confirmed:
            return self._finish(PipelineOutcome.BLOCKED, package, version, ecosystem, "zero_day", gates, cve_result.message)

        # ZD Step 2 — Quorum approval
        if not self.quorum:
            return self._finish(PipelineOutcome.BLOCKED, package, version, ecosystem, "zero_day", gates, "No quorum manager configured — zero-day lane unavailable")

        qr = self.quorum.create_request(
            cve_id=cve_id,
            package=package,
            version=version,
            ecosystem=ecosystem,
            requester=requester,
        )
        gates.append(GateResult("quorum_initiated", True, "pending_quorum", {"request_id": qr.request_id}))

        # Return PENDING_QUORUM — caller polls get_status() until approved
        # then calls run() again with the same args to continue the pipeline.
        # In a real deployment this would be an async webhook-driven flow.
        return self._finish(
            PipelineOutcome.PENDING_QUORUM,
            package, version, ecosystem, "zero_day", gates,
            f"Quorum request {qr.request_id} created. Awaiting {qr.required_approvers} approvals.",
            audit_id=qr.request_id,
        )

    async def _run_zero_day_post_quorum(
        self,
        package: str,
        version: str,
        ecosystem: str,
        cve_id: str,
        cve_published_at: str | None,
        github_token: str | None,
        gates: list[GateResult],
    ) -> PipelineResult:
        """Run the remaining gates after quorum approval."""

        # Gate 2 — Signature + timing check
        sig_passed, sig_msg = await self._gate_signature(
            package, version, ecosystem, cve_published_at=cve_published_at
        )
        gates.append(GateResult("signature_timing", sig_passed, "pass" if sig_passed else "rejected", sig_msg))
        if not sig_passed:
            return self._finish(PipelineOutcome.BLOCKED, package, version, ecosystem, "zero_day", gates, sig_msg)

        # Gate 3 — OOB trust (CVE context noted — score may be lower during active incident)
        trust_result: TrustCheckResult = await aggregate_trust_score(
            package=package, version=version, ecosystem=ecosystem, github_token=github_token
        )
        gates.append(GateResult("oob_trust", trust_result.passed, trust_result.recommendation, trust_result))
        if not trust_result.passed:
            return self._finish(PipelineOutcome.QUARANTINED, package, version, ecosystem, "zero_day", gates, f"OOB trust check failed even in zero-day context — score {trust_result.composite_score}/100")

        # Gate 4 — SBOM
        sbom_passed, sbom_msg = await self._gate_sbom(package, version, ecosystem)
        gates.append(GateResult("sbom", sbom_passed, "pass" if sbom_passed else "quarantine", sbom_msg))
        if not sbom_passed:
            return self._finish(PipelineOutcome.QUARANTINED, package, version, ecosystem, "zero_day", gates, sbom_msg)

        # Gate 5 — Sandbox
        sandbox_passed, sandbox_msg = await self._gate_sandbox(package, version, ecosystem)
        gates.append(GateResult("sandbox", sandbox_passed, "pass" if sandbox_passed else "blocked", sandbox_msg))
        if not sandbox_passed:
            return self._finish(PipelineOutcome.BLOCKED, package, version, ecosystem, "zero_day", gates, sandbox_msg)

        return self._finish(
            PipelineOutcome.APPROVED, package, version, ecosystem, "zero_day", gates,
            f"{package}@{version} approved via zero-day lane. Immediate full-fleet deploy. 48 h alert window active.",
        )

    # ------------------------------------------------------------------
    # Stub gates (implement in respective modules)
    # ------------------------------------------------------------------

    async def _gate_signature(
        self,
        package: str,
        version: str,
        ecosystem: str,
        cve_published_at: str | None = None,
    ) -> tuple[bool, str]:
        """
        Stub — implement in src/signature/verifier.py.
        Should call cosign/sigstore and optionally check timing against cve_published_at.
        """
        logger.info("signature gate stub — package=%s version=%s", package, version)
        return True, "Signature verification stub — implement src/signature/verifier.py"

    async def _gate_sbom(self, package: str, version: str, ecosystem: str) -> tuple[bool, str]:
        """Stub — implement in src/sbom/differ.py."""
        logger.info("sbom gate stub — package=%s version=%s", package, version)
        return True, "SBOM delta stub — implement src/sbom/differ.py"

    async def _gate_sandbox(self, package: str, version: str, ecosystem: str) -> tuple[bool, str]:
        """Stub — implement in src/sandbox/runner.py."""
        logger.info("sandbox gate stub — package=%s version=%s", package, version)
        return True, "Sandbox stub — implement src/sandbox/runner.py"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

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
            outcome=outcome,
            package=package,
            version=version,
            ecosystem=ecosystem,
            lane=lane,
            gates=gates,
            message=message,
            audit_id=audit_id,
        )
