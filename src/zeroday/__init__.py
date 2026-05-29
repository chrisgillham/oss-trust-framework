"""
Zero-Day Expedited Lane
Validates CVE authenticity across NVD, OSV, and GHSA (2-of-3 required),
issues a time-limited exception token, and enforces circuit breakers.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

log = logging.getLogger(__name__)

STATE_PATH = Path(".oss-trust-cache/zeroday-state.json")


class ZeroDayLane:
    def __init__(self, cfg: dict) -> None:
        self.required_approvers   = cfg.get("required_approvers", 2)
        self.token_ttl_hours      = cfg.get("token_ttl_hours", 6)
        self.max_per_24h          = cfg.get("max_exceptions_per_24h", 3)
        self.require_ticket       = cfg.get("require_ticket", True)
        self.cve_sources_required = cfg.get("cve_sources_required", 2)
        self._state               = self._load_state()

    async def request_exception(
        self,
        cve_id: str,
        package: str,
        version: str,
        requester: str,
        ticket_url: str = "",
    ) -> dict:
        """
        Validate CVE, check circuit breakers, and issue an exception token.
        Returns a dict with 'approved', 'token', and 'message'.
        """
        # ── Circuit breakers ───────────────────────────────────────────────
        cb_result = self._check_circuit_breakers(requester)
        if not cb_result["ok"]:
            return {"approved": False, "token": None, "message": cb_result["reason"]}

        # ── Require ticket link ────────────────────────────────────────────
        if self.require_ticket and not ticket_url:
            return {
                "approved": False,
                "token":    None,
                "message":  "Ticket URL is required for zero-day exceptions (require_ticket=true)",
            }

        # ── CVE validation ─────────────────────────────────────────────────
        cve_result = await self._validate_cve(cve_id, package, version)
        if not cve_result["valid"]:
            return {
                "approved": False,
                "token":    None,
                "message":  (
                    f"CVE {cve_id} not confirmed by minimum {self.cve_sources_required} sources "
                    f"(confirmed by: {', '.join(cve_result['confirmed_by']) or 'none'})"
                ),
            }

        # ── Issue exception token ──────────────────────────────────────────
        token = secrets.token_urlsafe(32)
        expires_at = (
            datetime.now(timezone.utc) + timedelta(hours=self.token_ttl_hours)
        ).isoformat()

        record = {
            "token":       token,
            "cve_id":      cve_id,
            "package":     package,
            "version":     version,
            "requester":   requester,
            "ticket_url":  ticket_url,
            "expires_at":  expires_at,
            "confirmed_by": cve_result["confirmed_by"],
            "issued_at":   datetime.now(timezone.utc).isoformat(),
        }

        self._state.setdefault("tokens", []).append(record)
        self._state.setdefault("requests_24h", []).append({
            "requester": requester,
            "issued_at": record["issued_at"],
        })
        self._save_state()

        log.info(
            f"[zeroday] Exception token issued for {package}@{version} "
            f"({cve_id}) — expires {expires_at}"
        )

        return {
            "approved":    True,
            "token":       token,
            "expires_at":  expires_at,
            "cve_id":      cve_id,
            "confirmed_by": cve_result["confirmed_by"],
            "message":     f"Exception approved for {package}@{version} via {cve_id}",
        }

    async def validate_token(self, token: str, package: str) -> bool:
        """Verify an exception token is valid and not expired."""
        for record in self._state.get("tokens", []):
            if record.get("token") != token:
                continue
            if record.get("package") != package:
                continue
            expires = datetime.fromisoformat(record["expires_at"])
            if datetime.now(timezone.utc) > expires:
                log.warning(f"[zeroday] Token expired for {package}")
                return False
            return True
        return False

    async def _validate_cve(
        self, cve_id: str, package: str, version: str
    ) -> dict:
        """Query NVD, OSV, and GHSA. Require at least N sources to confirm."""
        import asyncio
        results = await asyncio.gather(
            self._check_nvd(cve_id),
            self._check_osv(cve_id, package),
            self._check_ghsa(cve_id),
            return_exceptions=True,
        )

        source_names  = ["NVD", "OSV", "GHSA"]
        confirmed_by  = []
        for name, result in zip(source_names, results):
            if isinstance(result, bool) and result:
                confirmed_by.append(name)
            elif isinstance(result, Exception):
                log.debug(f"[zeroday] {name} check failed: {result}")

        return {
            "valid":        len(confirmed_by) >= self.cve_sources_required,
            "confirmed_by": confirmed_by,
            "checked":      source_names,
        }

    async def _check_nvd(self, cve_id: str) -> bool:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
            )
            r.raise_for_status()
            vulns = r.json().get("vulnerabilities", [])
            return len(vulns) > 0

    async def _check_osv(self, cve_id: str, package: str) -> bool:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                "https://api.osv.dev/v1/query",
                json={"package": {"name": package}},
            )
            r.raise_for_status()
            vulns = r.json().get("vulns", [])
            return any(
                cve_id in json.dumps(v.get("aliases", []) + [v.get("id", "")])
                for v in vulns
            )

    async def _check_ghsa(self, cve_id: str) -> bool:
        token = os.environ.get("GITHUB_TOKEN", "")
        headers = {"X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        async with httpx.AsyncClient(timeout=10, headers=headers) as client:
            r = await client.get(
                "https://api.github.com/advisories",
                params={"cve_id": cve_id, "per_page": 5},
            )
            if r.status_code in (401, 403):
                raise RuntimeError("GHSA requires GITHUB_TOKEN")
            r.raise_for_status()
            return len(r.json()) > 0

    def _check_circuit_breakers(self, requester: str) -> dict:
        """Enforce rate limits and escalation rules."""
        now = time.time()
        window_start = now - 86400  # 24h window

        # Prune old records
        recent = [
            r for r in self._state.get("requests_24h", [])
            if datetime.fromisoformat(r["issued_at"]).timestamp() > window_start
        ]
        self._state["requests_24h"] = recent

        # Global 24h limit
        if len(recent) >= self.max_per_24h:
            return {
                "ok":     False,
                "reason": (
                    f"Circuit breaker: {len(recent)} exceptions issued in last 24h "
                    f"(maximum {self.max_per_24h}). Lane suspended."
                ),
            }

        # Per-requester 48h limit
        window_48h = now - 172800
        requester_recent = [
            r for r in self._state.get("requests_24h", [])
            if (
                r.get("requester") == requester
                and datetime.fromisoformat(r["issued_at"]).timestamp() > window_48h
            )
        ]
        if len(requester_recent) >= 2:
            return {
                "ok":     False,
                "reason": (
                    f"Circuit breaker: {requester} has filed {len(requester_recent)} "
                    f"exceptions in 48h — escalating to CISO"
                ),
            }

        return {"ok": True, "reason": ""}

    def _load_state(self) -> dict:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        if STATE_PATH.exists():
            try:
                return json.loads(STATE_PATH.read_text())
            except Exception:
                pass
        return {}

    def _save_state(self) -> None:
        STATE_PATH.write_text(json.dumps(self._state, indent=2))
