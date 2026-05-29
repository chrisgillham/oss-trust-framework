"""
OSS Trust Framework — Pipeline Orchestrator
Runs all nine gates in sequence and returns a structured TrustResult.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from oss_trust.age_check import AgeGate
from oss_trust.signature import SignatureGate
from oss_trust.slsa import SLSAGate
from oss_trust.trust import OOBTrustGate
from oss_trust.reachability import ReachabilityGate
from oss_trust.license import LicenseGate
from oss_trust.sbom import SBOMGate
from oss_trust.sandbox import SandboxGate
from oss_trust.ai_hallucination import AIHallucinationGate
from oss_trust.cicd_audit import CICDAuditGate
from oss_trust.policy import PolicyEngine
from oss_trust.runtime import RuntimeTelemetry
from oss_trust.registry import PublicTrustRegistry

log = logging.getLogger(__name__)

# ── Outcome constants ─────────────────────────────────────────────────────────

class Outcome:
    APPROVED    = "approved"
    HOLD        = "hold"
    QUARANTINE  = "quarantined"
    BLOCKED     = "blocked"
    REJECTED    = "rejected"   # Hard cryptographic failure — no override path

# Ordered severity for merging multiple gate outcomes
SEVERITY = {
    Outcome.APPROVED:   0,
    Outcome.HOLD:       1,
    Outcome.QUARANTINE: 2,
    Outcome.BLOCKED:    3,
    Outcome.REJECTED:   4,
}


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class GateResult:
    gate: str
    outcome: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0


@dataclass
class TrustResult:
    # Package identity
    package: str
    version: str
    ecosystem: str
    source_repository: str = ""

    # Pipeline outcome
    outcome: str = Outcome.APPROVED
    message: str = ""
    gate_results: list[GateResult] = field(default_factory=list)

    # Trust scoring
    trust_score: int = 100
    trust_level: str = "HIGH"
    trust_deductions: list[str] = field(default_factory=list)
    historical_prior_denials: int = 0
    community_score_band: str = ""

    # Signal blocks (populated by individual gates)
    signature: dict[str, Any]   = field(default_factory=dict)
    checksum: dict[str, Any]    = field(default_factory=dict)
    slsa: dict[str, Any]        = field(default_factory=dict)
    license: dict[str, Any]     = field(default_factory=dict)
    flags: dict[str, bool]      = field(default_factory=dict)

    # Policy
    policy_applied: str = "default"
    effective_threshold: float = 0.5
    required_members_met: bool = True

    # Runtime
    runtime_monitoring_expires: str = ""

    # Metadata
    evaluated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    pipeline_version: str = "2.0.0"

    def merge_outcome(self, gate_outcome: str) -> None:
        """Escalate overall outcome to the more severe gate result."""
        if SEVERITY.get(gate_outcome, 0) > SEVERITY.get(self.outcome, 0):
            self.outcome = gate_outcome

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


# ── Pipeline ──────────────────────────────────────────────────────────────────

class Pipeline:
    """
    Nine-gate OSS trust validation pipeline.

    Gates run in strict sequence. Each gate can:
      - APPROVED  → continue to next gate
      - HOLD      → continue but flag; accumulates
      - QUARANTINE → skip remaining except SBOM, sandbox, and sandbox gates still run
      - BLOCKED   → continue only through remaining non-skippable gates
      - REJECTED  → stop immediately (cryptographic failure)
    """

    def __init__(self, config_path: str | Path = "config/pipeline.yaml") -> None:
        with open(config_path) as f:
            self.cfg = yaml.safe_load(f)

        self.age          = AgeGate(self.cfg.get("age_gate", {}))
        self.signature    = SignatureGate(self.cfg.get("slsa", {}))
        self.slsa         = SLSAGate(self.cfg.get("slsa", {}))
        self.oob          = OOBTrustGate(self.cfg.get("out_of_band_trust", {}),
                                          self.cfg.get("trust_scoring", {}))
        self.reachability = ReachabilityGate(self.cfg.get("reachability", {}))
        self.license      = LicenseGate(self.cfg.get("license", {}))
        self.sbom         = SBOMGate(self.cfg.get("sbom", {}))
        self.sandbox      = SandboxGate(self.cfg.get("sandbox", {}))
        self.ai_hall      = AIHallucinationGate(self.cfg.get("ai_hallucination", {}))
        self.cicd         = CICDAuditGate(self.cfg.get("cicd_audit", {}))
        self.policy       = PolicyEngine("config/policy.yaml")
        self.telemetry    = RuntimeTelemetry(self.cfg.get("runtime", {}))
        self.pub_registry = PublicTrustRegistry(self.cfg.get("public_registry", {}))

    async def run(
        self,
        package: str,
        version: str,
        ecosystem: str,
        registry_url: str = "",
        reachability_context: dict | None = None,
    ) -> TrustResult:
        result = TrustResult(
            package=package,
            version=version,
            ecosystem=ecosystem,
            source_repository=registry_url,
        )

        log.info(f"[pipeline] Starting evaluation: {package}@{version} ({ecosystem})")

        # ── Fetch historical reputation from audit log ──────────────────────
        await self._apply_historical_modifier(result)

        # ── Fetch community score ───────────────────────────────────────────
        await self._apply_community_score(result)

        # ── Gate 1: Age ─────────────────────────────────────────────────────
        gr = await self._run_gate("Gate 1: Age", self.age.evaluate, package, version, ecosystem)
        result.gate_results.append(gr)
        result.merge_outcome(gr.outcome)
        if gr.outcome == Outcome.REJECTED:
            result.message = gr.message
            return await self._finalize(result)

        # ── Gate 2: Signature ───────────────────────────────────────────────
        gr = await self._run_gate("Gate 2: Signature", self.signature.evaluate,
                                   package, version, ecosystem)
        result.gate_results.append(gr)
        result.signature = gr.details.get("signature", {})
        result.checksum  = gr.details.get("checksum", {})
        result.merge_outcome(gr.outcome)
        if gr.outcome == Outcome.REJECTED:
            result.message = gr.message
            return await self._finalize(result)

        # ── Gate 3: SLSA Provenance ─────────────────────────────────────────
        gr = await self._run_gate("Gate 3: SLSA", self.slsa.evaluate,
                                   package, version, ecosystem)
        result.gate_results.append(gr)
        result.slsa = gr.details.get("slsa", {})
        result.merge_outcome(gr.outcome)

        # ── Gate 4: OOB Trust ───────────────────────────────────────────────
        gr = await self._run_gate("Gate 4: OOB Trust", self.oob.evaluate,
                                   package, version, ecosystem)
        result.gate_results.append(gr)
        result.flags.update(gr.details.get("flags", {}))
        result.trust_score, result.trust_deductions = self._compute_trust_score(result)
        result.trust_level = self._score_band(result.trust_score)
        result.merge_outcome(gr.outcome)

        # ── Gate 4.5: Reachability ──────────────────────────────────────────
        # Only runs if current outcome is QUARANTINE — may downgrade to HOLD
        if result.outcome == Outcome.QUARANTINE:
            gr = await self._run_gate(
                "Gate 4.5: Reachability",
                self.reachability.evaluate,
                package, version,
                context=reachability_context or {},
                advisory_ids=self._extract_advisory_ids(result),
            )
            result.gate_results.append(gr)
            if gr.details.get("reachable") is False:
                log.info(f"[pipeline] {package}@{version} downgraded QUARANTINE→HOLD "
                         "(flagged code unreachable in call graph)")
                result.outcome = Outcome.HOLD
                result.gate_results[-1].message += " [QUARANTINE downgraded to HOLD]"
            else:
                result.merge_outcome(gr.outcome)

        # ── Gate 5: License ─────────────────────────────────────────────────
        gr = await self._run_gate("Gate 5: License", self.license.evaluate,
                                   package, version, ecosystem)
        result.gate_results.append(gr)
        result.license = gr.details.get("license", {})
        result.flags["license_changed"]  = gr.details.get("license_changed", False)
        result.flags["license_copyleft"] = gr.details.get("license_copyleft", False)
        result.merge_outcome(gr.outcome)

        # ── Gate 6: SBOM Delta (recursive) ─────────────────────────────────
        gr = await self._run_gate("Gate 6: SBOM Delta", self.sbom.evaluate,
                                   package, version, ecosystem)
        result.gate_results.append(gr)
        result.merge_outcome(gr.outcome)

        # ── Gate 7: Sandbox ─────────────────────────────────────────────────
        # Always runs regardless of current outcome — behavioral evidence is
        # unconditionally required
        gr = await self._run_gate("Gate 7: Sandbox", self.sandbox.evaluate,
                                   package, version, ecosystem)
        result.gate_results.append(gr)
        result.flags["behavior_change"] = gr.details.get("behavior_change", False)
        result.merge_outcome(gr.outcome)

        # ── Gate 8: AI Hallucination ────────────────────────────────────────
        gr = await self._run_gate("Gate 8: AI Hallucination", self.ai_hall.evaluate,
                                   package, version, ecosystem)
        result.gate_results.append(gr)
        result.flags["ai_hallucination"] = gr.details.get("hallucination_detected", False)
        result.merge_outcome(gr.outcome)

        # ── Gate 9: CI/CD Self-Audit ────────────────────────────────────────
        gr = await self._run_gate("Gate 9: CI/CD Audit", self.cicd.evaluate)
        result.gate_results.append(gr)
        result.merge_outcome(gr.outcome)

        # ── Recompute trust score after all flags are set ───────────────────
        result.trust_score, result.trust_deductions = self._compute_trust_score(result)
        result.trust_level = self._score_band(result.trust_score)

        # ── Policy evaluation ───────────────────────────────────────────────
        policy_result = self.policy.evaluate(result)
        result.policy_applied      = policy_result.rule_name
        result.effective_threshold = policy_result.threshold

        # ── Compose final message ───────────────────────────────────────────
        if not result.message:
            worst = next(
                (gr for gr in reversed(result.gate_results)
                 if gr.outcome not in (Outcome.APPROVED, Outcome.HOLD)),
                None,
            )
            result.message = worst.message if worst else "All gates passed"

        log.info(f"[pipeline] Result: {package}@{version} → {result.outcome} "
                 f"(score={result.trust_score}, policy={result.policy_applied})")

        return await self._finalize(result)

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _run_gate(self, name: str, fn, *args, **kwargs) -> GateResult:
        t0 = time.perf_counter()
        try:
            result = await fn(*args, **kwargs)
        except Exception as exc:
            log.error(f"[pipeline] {name} raised exception: {exc}")
            result = GateResult(
                gate=name,
                outcome=Outcome.QUARANTINE,
                message=f"{name} error (fail-closed): {exc}",
            )
        result.duration_ms = (time.perf_counter() - t0) * 1000
        log.debug(f"[pipeline] {name}: {result.outcome} in {result.duration_ms:.0f}ms")
        return result

    async def _apply_historical_modifier(self, result: TrustResult) -> None:
        """Query audit log for prior quorum events on this package."""
        try:
            from oss_trust.registry import AuditLogClient
            client = AuditLogClient()
            history = await client.get_package_history(result.package, result.version)
            result.historical_prior_denials = history.get("prior_denials", 0)
        except Exception as exc:
            log.warning(f"[pipeline] Historical modifier unavailable: {exc}")

    async def _apply_community_score(self, result: TrustResult) -> None:
        """Fetch community trust score band from public registry."""
        if not self.pub_registry.enabled:
            return
        try:
            community = await self.pub_registry.get_score(
                result.package, result.version, result.ecosystem
            )
            result.community_score_band = community.get("band", "")
        except Exception as exc:
            log.warning(f"[pipeline] Community score unavailable: {exc}")

    def _compute_trust_score(self, result: TrustResult) -> tuple[int, list[str]]:
        """Compute the composite 0–100 trust score from all signal categories."""
        score = 100
        deductions: list[str] = []

        sig = result.signature
        chk = result.checksum
        slsa = result.slsa
        flags = result.flags
        license_data = result.license

        # ── Cryptographic integrity ─────────────────────────────────────────
        if not sig.get("present"):
            score -= 40
            deductions.append("-40 no cryptographic signature")
        elif sig.get("strength") == "weak":
            score -= 20
            deductions.append("-20 weak signature algorithm")
        if sig.get("present") and sig.get("verified") is False:
            score -= 10
            deductions.append("-10 signature verification failed")

        if not chk.get("present"):
            score -= 15
            deductions.append("-15 no published checksum")
        elif chk.get("verified") is False:
            score -= 15
            deductions.append("-15 checksum mismatch — possible tampering")

        # ── SLSA provenance ─────────────────────────────────────────────────
        slsa_level = slsa.get("level", 0)
        slsa_critical = slsa.get("is_critical_path", False)
        if slsa_level == 0 and slsa_critical:
            score -= 30
            deductions.append("-30 SLSA 0 in critical dependency position")
        elif slsa_level == 0:
            score -= 15
            deductions.append("-15 SLSA 0 — no provenance attestation")
        elif slsa_level <= 2:
            score -= 5
            deductions.append(f"-5 SLSA {slsa_level} (non-hermetic build)")

        # ── Supply-chain flags ──────────────────────────────────────────────
        if flags.get("typosquatting"):
            score -= 25
            deductions.append("-25 typosquatting — name resembles known package")
        if flags.get("behavior_change"):
            score -= 20
            deductions.append("-20 behavior change — new permissions or network access")
        if flags.get("author_reputation"):
            score -= 15
            deductions.append("-15 author reputation — new maintainer / inactivity surge")
        if flags.get("provenance_activity"):
            score -= 10
            deductions.append("-10 provenance — no commit history or SLSA attestation")
        if flags.get("ai_hallucination"):
            score -= 30
            deductions.append("-30 AI hallucination — name matches fabricated package list")

        # ── License ─────────────────────────────────────────────────────────
        if license_data.get("changed"):
            score -= 15
            deductions.append("-15 license changed between versions")
        if license_data.get("copyleft"):
            score -= 35
            deductions.append("-35 license changed to copyleft")
        elif license_data.get("not_on_allowlist"):
            score -= 25
            deductions.append("-25 license not on organizational allowlist")

        # ── Historical reputation modifier ──────────────────────────────────
        prior_denials = result.historical_prior_denials
        if prior_denials >= 2:
            score -= 20
            deductions.append(f"-20 historical: {prior_denials} prior denials")
        elif prior_denials == 1:
            score -= 15
            deductions.append("-15 historical: 1 prior denial")

        # ── Community registry modifier ─────────────────────────────────────
        if result.community_score_band == "LOW":
            score -= 10
            deductions.append("-10 community registry: LOW band from peer organizations")

        return max(0, score), deductions

    def _score_band(self, score: int) -> str:
        if score >= 80:
            return "HIGH"
        if score >= 50:
            return "MEDIUM"
        return "LOW"

    def _extract_advisory_ids(self, result: TrustResult) -> list[str]:
        """Extract OSV advisory IDs from OOB trust gate details."""
        advisories = []
        for gr in result.gate_results:
            if gr.gate == "Gate 4: OOB Trust":
                advisories = gr.details.get("advisory_ids", [])
        return advisories

    async def _finalize(self, result: TrustResult) -> TrustResult:
        """Emit telemetry and contribute to public registry."""
        await self.telemetry.emit_gate_event(result)
        if self.pub_registry.enabled and result.outcome in (
            Outcome.APPROVED, Outcome.QUARANTINE, Outcome.BLOCKED
        ):
            await self.pub_registry.contribute(result)
        return result
