"""
Gate 4.5 — Reachability Analysis
Determines whether flagged vulnerable code paths are actually reachable
from this application's execution paths. Downgrade QUARANTINE → HOLD
when the vulnerable function is unreachable (dead code in dependency tree).
"""
from __future__ import annotations

import logging
import os

import httpx

from oss_trust.pipeline import GateResult, Outcome

log = logging.getLogger(__name__)


class ReachabilityGate:
    def __init__(self, cfg: dict) -> None:
        self.enabled            = cfg.get("enabled", True)
        self.adapter            = cfg.get("adapter", "endor_labs")
        self.on_unreachable     = cfg.get("on_unreachable", "hold")
        self.on_adapter_failure = cfg.get("on_adapter_failure", "quarantine")
        self.adapter_cfg        = cfg.get("adapter_config", {})

    async def evaluate(
        self,
        package: str,
        version: str,
        context: dict | None = None,
        advisory_ids: list[str] | None = None,
    ) -> GateResult:
        if not self.enabled:
            return GateResult(
                gate="Gate 4.5: Reachability",
                outcome=Outcome.QUARANTINE,
                message="Reachability analysis disabled — maintaining QUARANTINE",
                details={"reachable": None, "skipped": True},
            )

        advisory_ids = advisory_ids or []
        if not advisory_ids:
            return GateResult(
                gate="Gate 4.5: Reachability",
                outcome=Outcome.QUARANTINE,
                message="No advisory IDs to check reachability against",
                details={"reachable": None, "advisory_ids": []},
            )

        try:
            reachable, details = await self._check(package, version, advisory_ids, context or {})
        except Exception as exc:
            log.warning(f"[reachability] Adapter '{self.adapter}' failed: {exc}")
            outcome = self._outcome(self.on_adapter_failure)
            return GateResult(
                gate="Gate 4.5: Reachability",
                outcome=outcome,
                message=f"Reachability adapter failure ({self.adapter}): {exc} — {self.on_adapter_failure}",
                details={"reachable": None, "error": str(exc)},
            )

        if not reachable:
            return GateResult(
                gate="Gate 4.5: Reachability",
                outcome=Outcome.HOLD,
                message=(
                    f"Flagged code in {package}@{version} is NOT reachable "
                    f"from application call graph — downgrading to HOLD"
                ),
                details={"reachable": False, **details},
            )

        return GateResult(
            gate="Gate 4.5: Reachability",
            outcome=Outcome.QUARANTINE,
            message=(
                f"Flagged code in {package}@{version} IS reachable "
                f"— maintaining QUARANTINE"
            ),
            details={"reachable": True, **details},
        )

    async def _check(
        self,
        package: str,
        version: str,
        advisory_ids: list[str],
        context: dict,
    ) -> tuple[bool, dict]:
        if self.adapter == "endor_labs":
            return await self._endor_labs(package, version, advisory_ids, context)
        if self.adapter == "snyk":
            return await self._snyk(package, version, advisory_ids, context)
        if self.adapter == "none":
            # Conservative: assume reachable
            return True, {"source": "none", "assumed_reachable": True}
        raise ValueError(f"Unknown reachability adapter: {self.adapter}")

    async def _endor_labs(
        self,
        package: str,
        version: str,
        advisory_ids: list[str],
        context: dict,
    ) -> tuple[bool, dict]:
        api_key      = os.environ.get("ENDOR_LABS_API_KEY", "")
        project_uuid = os.environ.get("ENDOR_LABS_PROJECT_UUID", "")

        if not api_key or not project_uuid:
            raise RuntimeError("ENDOR_LABS_API_KEY and ENDOR_LABS_PROJECT_UUID must be set")

        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                "https://api.endorlabs.com/v1/reachability/check",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "project_uuid":  project_uuid,
                    "package":       package,
                    "version":       version,
                    "advisory_ids":  advisory_ids,
                },
            )
            r.raise_for_status()
            data = r.json()

        reachable = data.get("reachable", True)
        call_paths = data.get("call_paths", [])

        return reachable, {
            "source":      "endor_labs",
            "call_paths":  call_paths[:3],   # Surface top 3 paths for embed display
            "advisory_ids": advisory_ids,
        }

    async def _snyk(
        self,
        package: str,
        version: str,
        advisory_ids: list[str],
        context: dict,
    ) -> tuple[bool, dict]:
        token  = os.environ.get("SNYK_TOKEN", "")
        org_id = os.environ.get("SNYK_ORG_ID", "")

        if not token or not org_id:
            raise RuntimeError("SNYK_TOKEN and SNYK_ORG_ID must be set")

        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                f"https://api.snyk.io/rest/orgs/{org_id}/packages/issues",
                headers={"Authorization": f"token {token}"},
                json={
                    "data": {
                        "attributes": {
                            "package": {"name": package, "version": version},
                            "issue_ids": advisory_ids,
                        }
                    }
                },
            )
            r.raise_for_status()
            data = r.json()

        issues   = data.get("data", {}).get("attributes", {}).get("issues", [])
        reachable_issues = [
            i for i in issues
            if i.get("attributes", {}).get("reachability") == "reachable"
        ]

        return len(reachable_issues) > 0, {
            "source":            "snyk",
            "reachable_count":   len(reachable_issues),
            "total_issues":      len(issues),
            "advisory_ids":      advisory_ids,
        }

    def _outcome(self, action: str) -> str:
        return {
            "quarantine": Outcome.QUARANTINE,
            "hold":       Outcome.HOLD,
            "block":      Outcome.BLOCKED,
        }.get(action, Outcome.QUARANTINE)
